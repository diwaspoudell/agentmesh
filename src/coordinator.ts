import { makeBundle, type OutcomeBundle } from "./bundle.ts";
import { canonicalize, type JsonObject } from "./canonical.ts";
import { contractHeader, operationCommitment, type OutcomeContract } from "./contract.ts";
import type { Signed, Signer } from "./keys.ts";
import type { Money } from "./money.ts";
import { buildReport, type OutcomeReport } from "./report.ts";
import type { ConnectorProfile, Evidence, SubmissionResult } from "./reconcile.ts";
import {
  detailsDigest, type Attestation, type ContractApproval, type ExecutionAuthorization, type Mandate, type Observation, type Phase,
  type ProviderReceipt, type Revocation, type StepUpApproval, type Checkpoint,
} from "./statements.ts";
import { ConflictError, type EventStore } from "./store/types.ts";
import { applyEvent, checkSubmission, eventHash, GENESIS, InvariantError, replay, type EventBody, type StoredEvent, type TransactionState } from "./transaction.ts";

// ── Provider connectors ────────────────────────────────────────────────────────

export interface ExecuteRequest {
  contractId: string;
  operationId: string;
  phase: Phase;
  attempt: number;
  action: string;
  params: JsonObject;
  /** Pass it to the provider. Retries after an ambiguous failure reuse it. */
  idempotencyKey: string;
  amount?: Money;
  details?: JsonObject;
  /** Proof the request is authorized, scoped to this operation. Providers can check it with verifyMandate. */
  mandate: Mandate;
}

export type ExecuteResult =
  | { outcome: "accepted"; providerRef?: string; observation?: Observation; receipt?: Signed<ProviderReceipt> }
  | { outcome: "rejected"; reason: string; receipt?: Signed<ProviderReceipt> }
  | { outcome: "not_executed"; reason: string; retryable: boolean }
  /** Use this (or throw) whenever you can't be sure. Never report rejected or not_executed unless the provider said so. */
  | { outcome: "unknown"; reason: string };

export interface LookupRequest { contractId: string; operationId: string; phase: Phase; idempotencyKey: string; providerRef?: string }
export type LookupResult =
  | { found: true; observation: Observation; receipt?: Signed<ProviderReceipt> }
  /** `definitive`: the provider guarantees a request with this key would be on record had it executed. */
  | { found: false; definitive: boolean };

/** The integration point for a provider: a direct API client, an MCP tool, or an A2A agent (kind "agent"). */
export interface ProviderConnector {
  kind: ConnectorProfile["kind"];
  idempotent: boolean;
  execute(req: ExecuteRequest): Promise<ExecuteResult>;
  /** Reads the provider's system of record. Omit it if the provider has no status API. */
  lookup?(req: LookupRequest): Promise<LookupResult>;
}

export interface CoordinatorOptions {
  store: EventStore;
  /** The coordinator's key; must be listed in each contract's `coordinator.keys`. */
  signer: Signer;
  /** By provider participant id. */
  connectors: Record<string, ProviderConnector>;
  clock?: () => Date;
  /** A submission with no recorded result after this long is treated as ambiguous (the process may have died mid-call). */
  staleAfterMs?: number;
}

export type SubmitResult = { ok: true; state: TransactionState } | { ok: false; reason: string; state: TransactionState };

/**
 * Enforces outcome contracts. All decisions go through the reducer's rules; every fact lands in a hash-chained log
 * before or right after the side effect it describes. Safe to run as several instances over one store: appends
 * are optimistic, so two coordinators can't both reserve the same budget or submit the same attempt.
 */
export class OutcomeCoordinator {
  readonly #o: Required<Omit<CoordinatorOptions, "clock">> & { clock: () => Date };

  constructor(o: CoordinatorOptions) {
    this.#o = { clock: () => new Date(), staleAfterMs: 120_000, ...o };
  }

  get id() { return this.#o.signer.kid; }

  async state(transactionId: string): Promise<TransactionState> {
    return replay(await this.#o.store.load(transactionId));
  }

  async events(transactionId: string): Promise<StoredEvent[]> {
    return this.#o.store.load(transactionId);
  }

  /** Registers a contract. Its id becomes the transaction id. */
  async open(contract: OutcomeContract): Promise<TransactionState> {
    if (!contract.coordinator.keys.some((k) => k.kid === this.#o.signer.kid)) throw new InvariantError("this coordinator's key is not listed in the contract");
    const existing = await this.#o.store.load(contract.id);
    if (existing.length) {
      const s = replay(existing);
      if (canonicalize(s.contract) !== canonicalize(contract)) throw new InvariantError(`transaction ${contract.id} already exists with a different contract`);
      return s;
    }
    return this.#commit(contract.id, () => [{ type: "contract.registered", contract }], true);
  }

  approve(transactionId: string, approval: Signed<ContractApproval>) {
    return this.#commit(transactionId, () => [{ type: "contract.approved", approval }]);
  }

  /** Stops all new submissions. Operations already in flight are still reconciled. */
  revoke(transactionId: string, revocation: Signed<Revocation>) {
    return this.#commit(transactionId, () => [{ type: "contract.revoked", revocation }]);
  }

  stepUp(transactionId: string, approval: Signed<StepUpApproval>) {
    return this.#commit(transactionId, () => [{ type: "operation.step_up", approval }]);
  }

  /** Records what an agent says happened. Kept for accountability; never counts as proof. */
  recordClaim(transactionId: string, operationId: string, claim: { agent: string; observation: Observation }) {
    return this.#commit(transactionId, () => [{ type: "evidence.recorded", operationId, phase: "execute", evidence: { source: "agent_claim", agent: claim.agent, observation: claim.observation } }]);
  }

  /** A provider pushed a signed receipt (e.g. by webhook). Invalid receipts are recorded as such, not trusted. */
  ingestReceipt(receipt: Signed<ProviderReceipt>) {
    const p = receipt.payload;
    return this.#commit(p.contractId, () => [{ type: "evidence.recorded", operationId: p.operationId, phase: p.phase, evidence: { source: "signed_receipt", receipt } }]);
  }

  /** A human's signed finding, usually to resolve an escalation. */
  attest(transactionId: string, attestation: Signed<Attestation>) {
    const p = attestation.payload;
    return this.#commit(transactionId, () => [{ type: "evidence.recorded", operationId: p.operationId, phase: p.phase, evidence: { source: "human_attestation", attestation } }]);
  }

  /**
   * An agent asks to carry out one operation. Refusals are recorded with their reason.
   * `amount` defaults to the operation's spend cap; the shared budget is reserved before the provider is called.
   */
  async submit(transactionId: string, operationId: string, req: { agent: string; amount?: Money; details?: JsonObject }): Promise<SubmitResult> {
    return this.#submit(transactionId, operationId, "execute", req);
  }

  async #submit(transactionId: string, operationId: string, phase: Phase, req: { agent: string; amount?: Money; details?: JsonObject }): Promise<SubmitResult> {
    let refusal: string | undefined;
    let request: ExecuteRequest | undefined;
    let connector: ProviderConnector | undefined;
    let state = await this.#commit(transactionId, (s, at) => {
      refusal = undefined;
      const op = s.ops[operationId];
      connector = op && this.#o.connectors[op.spec.provider];
      const check = checkSubmission(s, { operationId, phase, agent: req.agent, amount: req.amount, details: req.details, at });
      if (check.ok && !connector) refusal = `no connector for provider ${op!.spec.provider}`;
      else if (!check.ok) refusal = check.reason;
      if (refusal !== undefined) return op ? [{ type: "operation.refused", operationId, phase, agent: req.agent, reason: refusal }] : [];
      if (!check.ok || !op || !connector) return [];
      const c = s.contract;
      const auth: ExecutionAuthorization = {
        type: "agentmesh.execution-authorization", contractId: c.id, contractDigest: s.digest, operationId, operationCommitment: operationCommitment(op.spec),
        phase, attempt: check.attempt, idempotencyKey: check.idempotencyKey, agent: req.agent, amount: check.amount, detailsDigest: detailsDigest(req.details),
        issuedAt: at, expiresAt: phase === "execute" ? minIso(c.expiresAt, op.spec.deadline) : new Date(Date.parse(at) + 86_400_000).toISOString(),
      };
      const authorization = this.#o.signer.sign(auth);
      const spec = op.spec;
      request = {
        contractId: c.id, operationId, phase, attempt: check.attempt, idempotencyKey: check.idempotencyKey, amount: check.amount, details: req.details,
        action: phase === "execute" ? spec.action : spec.compensation!.action,
        params: phase === "execute" ? spec.params : spec.compensation!.params,
        mandate: { header: contractHeader(c), operation: spec, approval: s.approval!, stepUp: check.stepUp, authorization },
      };
      return [{
        type: "operation.submitting", operationId, phase, attempt: check.attempt, agent: req.agent, idempotencyKey: check.idempotencyKey,
        amount: check.amount, details: req.details, connector: profile(connector), authorization,
      }];
    });
    if (refusal !== undefined || !request || !connector) return { ok: false, reason: refusal ?? "refused", state };

    // The submission is on record before the provider hears about it, so a crash here is detectable as ambiguous.
    let res: ExecuteResult;
    try {
      res = await connector.execute(request);
      if (!res || typeof res !== "object" || !["accepted", "rejected", "not_executed", "unknown"].includes(res.outcome)) res = { outcome: "unknown", reason: "connector returned an unrecognized result" };
    } catch (err) {
      res = { outcome: "unknown", reason: (err as Error)?.message || "request failed" };
    }
    const r = request;
    const result: SubmissionResult = res.outcome === "unknown" ? { outcome: "ambiguous", reason: res.reason }
      : res.outcome === "accepted" ? { outcome: "accepted", providerRef: res.providerRef }
      : res.outcome === "rejected" ? { outcome: "rejected", reason: res.reason }
      : { outcome: "not_executed", reason: res.reason, retryable: res.retryable };
    const bodies: EventBody[] = [{ type: "operation.result", operationId, phase, attempt: r.attempt, result }];
    if ("receipt" in res && res.receipt) bodies.push({ type: "evidence.recorded", operationId, phase, evidence: { source: "signed_receipt", receipt: res.receipt } });
    if (res.outcome === "accepted" && res.observation) {
      const observation = { ...res.observation, idempotencyKey: res.observation.idempotencyKey ?? r.idempotencyKey };
      bodies.push({ type: "evidence.recorded", operationId, phase, evidence: recordOf(connector, "response", observation) });
    }
    state = await this.#commit(transactionId, () => bodies);
    return { ok: true, state };
  }

  /**
   * Moves time-based state forward and gathers evidence: marks expired contracts and deadlines, treats stale
   * submissions as ambiguous, reads providers' records for anything unconfirmed, and runs pre-approved
   * compensations when the contract's policy calls for them. Call it on a schedule (or from a workflow timer).
   */
  async reconcile(transactionId: string): Promise<TransactionState> {
    const now = this.#o.clock();
    let s = await this.#commit(transactionId, (st) => {
      const out: EventBody[] = [];
      if (!st.expiredAt && now.getTime() >= Date.parse(st.contract.expiresAt)) out.push({ type: "contract.expired" });
      for (const id of st.order) {
        const op = st.ops[id]!;
        if (op.spec.deadline && !op.expiredAt && now.getTime() >= Date.parse(op.spec.deadline) && !["verified", "compensating", "compensated", "waived", "cancelled", "rejected", "failed"].includes(op.status)) {
          out.push({ type: "operation.expired", operationId: id });
        }
        for (const phase of ["execute", "compensate"] as const) {
          const a = op[phase].attempts.at(-1);
          if (a && !a.result && now.getTime() - Date.parse(a.at) >= this.#o.staleAfterMs) {
            out.push({ type: "operation.result", operationId: id, phase, attempt: a.n, result: { outcome: "ambiguous", reason: "no response was recorded (the coordinator may have stopped mid-call)" } });
          }
        }
      }
      return out;
    });

    for (const id of s.order) {
      const op = s.ops[id]!;
      if (op.next !== "lookup") continue;
      const phase = op.nextPhase;
      const connector = this.#o.connectors[op.spec.provider];
      const last = op[phase].attempts.at(-1);
      if (!connector?.lookup || !last) continue;
      let res: LookupResult;
      try {
        res = await connector.lookup({ contractId: s.id, operationId: id, phase, idempotencyKey: last.idempotencyKey, providerRef: providerRef(op[phase].attempts) });
      } catch {
        continue;
      }
      const bodies: EventBody[] = [];
      const observation = res.found ? { ...res.observation, idempotencyKey: res.observation.idempotencyKey ?? last.idempotencyKey } : undefined;
      const notFound = res.found ? undefined : { definitive: res.definitive };
      if (res.found && res.receipt) bodies.push({ type: "evidence.recorded", operationId: id, phase, evidence: { source: "signed_receipt", receipt: res.receipt } });
      bodies.push({ type: "evidence.recorded", operationId: id, phase, evidence: recordOf(connector, "lookup", observation, notFound) });
      // Polling the same answer again adds nothing to the record.
      const prev = op[phase].evidence.filter((e) => e.via === "lookup" && e.seq > last.seq).at(-1);
      if (prev && canonicalize({ o: prev.observation ?? null, n: prev.notFound ?? null }) === canonicalize({ o: observation ?? null, n: notFound ?? null })) continue;
      s = await this.#commit(transactionId, () => bodies);
    }

    for (const id of s.order) {
      const op = s.ops[id]!;
      if (op.status === "compensating" && op.nextPhase === "compensate" && (op.next === "submit" || op.next === "retry_same_key" || op.next === "retry_new_key")) {
        s = (await this.#submit(transactionId, id, "compensate", { agent: s.contract.coordinator.id })).state;
      }
    }
    return s;
  }

  /**
   * Convenience loop for one agent: submits every operation it may run as soon as its dependencies are verified,
   * reconciles, and repeats until nothing changes. `plan` supplies the concrete amount and details per operation.
   */
  async run(transactionId: string, o: { agent: string; plan?: (operationId: string) => { amount?: Money; details?: JsonObject } | undefined; rounds?: number }): Promise<TransactionState> {
    let s = await this.state(transactionId);
    for (let round = 0; round < (o.rounds ?? 20); round++) {
      const before = s.seq;
      for (const id of s.order) {
        const op = s.ops[id]!;
        if (op.nextPhase !== "execute" || !op.spec.executors.includes(o.agent)) continue;
        const req = { agent: o.agent, ...o.plan?.(id) };
        if (!checkSubmission(s, { operationId: id, phase: "execute", ...req, at: this.#o.clock().toISOString() }).ok) continue;
        s = (await this.submit(transactionId, id, req)).state;
      }
      s = await this.reconcile(transactionId);
      if (s.seq === before) break;
    }
    return s;
  }

  /** The full log plus a signed checkpoint of its head; with the hash chain the signature covers the whole history. */
  async exportBundle(transactionId: string): Promise<OutcomeBundle> {
    const events = await this.#o.store.load(transactionId);
    const s = replay(events);
    const checkpoint: Signed<Checkpoint> = this.#o.signer.sign({ type: "agentmesh.checkpoint", transactionId, seq: s.seq, head: s.head, at: this.#o.clock().toISOString() });
    return makeBundle(events, checkpoint);
  }

  async report(transactionId: string): Promise<OutcomeReport> {
    return buildReport(await this.state(transactionId));
  }

  /** Decide → validate through the reducer → append; on a concurrent append, reload and decide again. */
  async #commit(transactionId: string, decide: (s: TransactionState, at: string) => EventBody[], create = false): Promise<TransactionState> {
    for (let i = 0; i < 50; i++) {
      const log = await this.#o.store.load(transactionId);
      let s = log.length ? replay(log) : undefined;
      if (!s && !create) throw new InvariantError(`no transaction ${transactionId}`);
      const now = this.#o.clock().toISOString();
      const at = s && Date.parse(s.lastAt) > Date.parse(now) ? s.lastAt : now;
      const bodies = decide(s!, at);
      if (!bodies.length) return s!;
      const events: StoredEvent[] = [];
      const base = s?.seq ?? 0;
      let prev = s?.head ?? GENESIS;
      for (const body of bodies) {
        const e = { transactionId, seq: base + events.length + 1, at, prev, body };
        const stored = { ...e, hash: eventHash(e) };
        s = applyEvent(s, stored);
        events.push(stored);
        prev = stored.hash;
      }
      try {
        await this.#o.store.append(transactionId, log.length, events);
        return s!;
      } catch (err) {
        if (!(err instanceof ConflictError)) throw err;
      }
    }
    throw new ConflictError(transactionId);
  }
}

function profile(c: ProviderConnector): ConnectorProfile {
  return { kind: c.kind, idempotent: c.idempotent, lookup: typeof c.lookup === "function" };
}

/** Connectors that relay through an agent produce claims, not records. */
function recordOf(c: ProviderConnector, via: "response" | "lookup", observation?: Observation, notFound?: { definitive: boolean }): Evidence {
  return c.kind === "api" ? { source: "provider_record", via, observation, notFound } : { source: "agent_claim", via, agent: `connector:${via}`, observation, notFound };
}

function providerRef(attempts: { result?: SubmissionResult }[]) {
  for (const a of [...attempts].reverse()) if (a.result?.outcome === "accepted" && a.result.providerRef) return a.result.providerRef;
  return undefined;
}

function minIso(a: string, b?: string) {
  return b && Date.parse(b) < Date.parse(a) ? b : a;
}
