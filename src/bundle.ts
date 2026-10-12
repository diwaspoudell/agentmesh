import { verifySigned, type PublicKeyJwk, type Signed } from "./keys.ts";
import { buildReport, type OutcomeReport } from "./report.ts";
import type { Checkpoint } from "./statements.ts";
import { replay, type StoredEvent, type TransactionState } from "./transaction.ts";

/** Everything needed to check a transaction's outcome offline: the full log and the coordinator's signed checkpoint. */
export interface OutcomeBundle { type: "agentmesh.outcome-bundle"; version: 0; events: StoredEvent[]; checkpoint: Signed<Checkpoint> }

export function makeBundle(events: StoredEvent[], checkpoint: Signed<Checkpoint>): OutcomeBundle {
  return { type: "agentmesh.outcome-bundle", version: 0, events, checkpoint };
}

export interface BundleVerification {
  ok: boolean;
  problems: string[];
  state?: TransactionState;
  report?: OutcomeReport;
}

/**
 * Re-derives the outcome from the raw log with the same rules the coordinator used. Fails if any entry was altered,
 * removed or reordered, if any submission broke the contract (unapproved, over budget, out of order, after
 * revocation...), or if the checkpoint isn't signed by a coordinator you trust.
 * Pass `principalKeys` to also require that the contract was approved by the person you expect.
 */
export function verifyBundle(b: OutcomeBundle, trust: { coordinatorKeys: readonly PublicKeyJwk[]; principalKeys?: readonly PublicKeyJwk[] }): BundleVerification {
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
  return { ok: problems.length === 0, problems, state, report: buildReport(state) };
}
