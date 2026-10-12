import { verifySigned, type PublicKeyJwk, type Signed } from "./keys.ts";
import { buildReport, type OutcomeReport } from "./report.ts";
import type { Checkpoint, WitnessStatement } from "./statements.ts";
import { replay, type StoredEvent, type TransactionState } from "./transaction.ts";

/** Everything needed to check a transaction's outcome offline: the full log, the coordinator's signed checkpoint, and any independent witnesses' statements. */
export interface OutcomeBundle {
  type: "agentmesh.outcome-bundle";
  version: 0;
  events: StoredEvent[];
  checkpoint: Signed<Checkpoint>;
  witnessings?: Signed<WitnessStatement>[];
}

export function makeBundle(events: StoredEvent[], checkpoint: Signed<Checkpoint>, witnessings: Signed<WitnessStatement>[] = []): OutcomeBundle {
  return { type: "agentmesh.outcome-bundle", version: 0, events, checkpoint, ...(witnessings.length ? { witnessings } : {}) };
}

export interface BundleVerification {
  ok: boolean;
  problems: string[];
  state?: TransactionState;
  report?: OutcomeReport;
  /** Independent witnesses whose statements match this log. */
  witnessed?: string[];
}

export interface BundleTrust {
  coordinatorKeys: readonly PublicKeyJwk[];
  /** Also require that the contract was approved by the person you expect. */
  principalKeys?: readonly PublicKeyJwk[];
  /**
   * Checkpoints you received earlier, directly from the coordinator or from wherever it published them. The log must still
   * contain exactly the history they committed to; if the operator rewrote or cut it, this is how you find out.
   */
  anchors?: readonly Signed<Checkpoint>[];
  /** Require statements from at least `required` distinct independent witnesses you trust. */
  witnesses?: { keys: readonly PublicKeyJwk[]; required: number };
}

/**
 * Re-derives the outcome from the raw log with the same rules the coordinator used. Fails if any entry was altered,
 * removed or reordered, if any submission broke the contract (unapproved, over budget, out of order, after
 * revocation...), or if the checkpoint isn't signed by a coordinator you trust. Anchors and witnesses extend that
 * to the operator themselves: a log that was replaced wholesale and re-signed no longer matches what they saw.
 */
export function verifyBundle(b: OutcomeBundle, trust: BundleTrust): BundleVerification {
  const problems: string[] = [];
  let state: TransactionState | undefined;
  try {
    state = replay(b.events);
  } catch (err) {
    return { ok: false, problems: [`log does not replay: ${(err as Error).message}`] };
  }
  const cp = b.checkpoint;
  if (!verifySigned(cp, trust.coordinatorKeys)) problems.push("checkpoint is not signed by a trusted coordinator key");
  if (!state.contract.coordinator.keys.some((k) => k.kid === cp.signature.kid)) problems.push("checkpoint signer is not the contract's coordinator");
  if (cp.payload.type !== "agentmesh.checkpoint" || cp.payload.transactionId !== state.id || cp.payload.seq !== state.seq || cp.payload.head !== state.head) {
    problems.push("checkpoint does not cover this log (entries were added or removed)");
  }
  if (trust.principalKeys) {
    if (!state.approval) problems.push("contract was never approved");
    else if (!verifySigned(state.approval, trust.principalKeys)) problems.push("contract was not approved by the expected principal");
  }

  const atSeq = (seq: number) => b.events[seq - 1]?.hash;
  for (const a of trust.anchors ?? []) {
    const p = a.payload;
    if (p.transactionId !== state.id) continue;
    if (!verifySigned(a, trust.coordinatorKeys)) { problems.push(`anchor at entry ${p.seq} is not signed by a trusted coordinator key`); continue; }
    if (p.seq > b.events.length) problems.push(`log has ${b.events.length} entries but a checkpoint was published at ${p.seq}: entries were removed`);
    else if (atSeq(p.seq) !== p.head) problems.push(`history was rewritten: entry ${p.seq} no longer matches the checkpoint published for it`);
  }

  let witnessed: string[] | undefined;
  if (trust.witnesses) {
    const agree = new Set<string>();
    for (const w of b.witnessings ?? []) {
      const p = w.payload;
      if (p.type !== "agentmesh.witness-statement" || p.transactionId !== state.id) continue;
      if (!verifySigned(w, trust.witnesses.keys)) continue;
      if (p.seq > b.events.length || atSeq(p.seq) !== p.head) problems.push(`witness ${w.signature.kid.slice(0, 8)} saw a different history at entry ${p.seq}`);
      else agree.add(w.signature.kid);
    }
    witnessed = [...agree];
    if (agree.size < trust.witnesses.required) problems.push(`needs ${trust.witnesses.required} independent witness${trust.witnesses.required === 1 ? "" : "es"}, found ${agree.size}`);
  }
  return { ok: problems.length === 0, problems, state, report: buildReport(state), witnessed };
}
