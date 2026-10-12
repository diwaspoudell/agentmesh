import { canonicalize, digest, type JsonObject } from "./canonical.ts";
import { contractDigest, operationCommitment, parseContract, type EvidenceSource, type OperationSpec, type OutcomeContract } from "./contract.ts";
import { verifySigned, type Signed } from "./keys.ts";
import { formatMoney, type Money } from "./money.ts";
import {
  derivePhase, type Attempt, type ConnectorProfile, type Evidence, type EvidenceEntry, type NextStep, type PhaseVerdict, type SubmissionResult,
} from "./reconcile.ts";
import {
  detailsDigest, idempotencyKey, type ContractApproval, type ExecutionAuthorization, type Observation, type Phase, type Revocation, type StepUpApproval,
} from "./statements.ts";

// ── Events ─────────────────────────────────────────────────────────────────────
// Events are facts: what was approved, what was sent, what came back, what evidence was seen, what time it was.
// Every verdict (verified, unknown, disputed...) is derived from them, never stored, so replaying the log is how
// anyone checks the outcome.

export type EventBody =
  | { type: "contract.registered"; contract: OutcomeContract }
  | { type: "contract.approved"; approval: Signed<ContractApproval> }
  | { type: "contract.revoked"; revocation: Signed<Revocation> }
  | { type: "contract.expired" }
  | { type: "operation.step_up"; approval: Signed<StepUpApproval> }
  | { type: "operation.refused"; operationId: string; phase: Phase; agent: string; reason: string }
  | {
      type: "operation.submitting"; operationId: string; phase: Phase; attempt: number; agent: string; idempotencyKey: string;
      amount?: Money; details?: JsonObject; connector: ConnectorProfile; authorization: Signed<ExecutionAuthorization>;
    }
  | { type: "operation.result"; operationId: string; phase: Phase; attempt: number; result: SubmissionResult }
  | { type: "operation.expired"; operationId: string }
  | { type: "evidence.recorded"; operationId: string; phase: Phase; evidence: Evidence };

export interface StoredEvent { transactionId: string; seq: number; at: string; prev: string; hash: string; body: EventBody }

export const GENESIS = `sha256:${"0".repeat(64)}`;

export function eventHash(e: Omit<StoredEvent, "hash">) {
  return digest({ type: "agentmesh.event", transactionId: e.transactionId, seq: e.seq, at: e.at, prev: e.prev, body: e.body });
}

/** An event that would break the contract's rules. The coordinator never appends one; a log containing one fails verification. */
export class InvariantError extends Error {
  readonly seq?: number;
  constructor(message: string, seq?: number) {
    super(seq === undefined ? message : `event ${seq}: ${message}`);
    this.seq = seq;
  }
}

// ── State ──────────────────────────────────────────────────────────────────────

export type OperationStatus =
  | "planned" | "submitting" | "pending_verification" | "verified" | "rejected" | "failed" | "unknown"
  | "disputed" | "cancelled" | "waived" | "compensating" | "compensated";

export type OutcomeStatus =
  | "completed" | "partially_completed" | "in_progress" | "pending_verification" | "outcome_unknown" | "failed" | "disputed" | "requires_human_review";

export interface PhaseRecord { attempts: Attempt[]; evidence: EvidenceEntry[]; verdict: PhaseVerdict }

export interface OperationState {
  id: string;
  spec: OperationSpec;
  execute: PhaseRecord;
  compensate: PhaseRecord;
  stepUps: Signed<StepUpApproval>[];
  refusals: { at: string; agent: string; phase: Phase; reason: string }[];
  expiredAt?: string;
  // Derived on every event:
  status: OperationStatus;
  /** What the coordinator should do next, and in which phase. */
  next: NextStep;
  nextPhase: Phase;
  findings: string[];
  /** Why a planned operation isn't being submitted yet. */
  blockedBy?: string;
  /** Set while a human needs to look at it. Clears itself when new evidence settles the operation. */
  escalation?: string;
  /** Budget held for it (minor units) while its outcome is open, and budget spent once verified. */
  hold: number;
  spent: number;
  basis?: EvidenceSource;
  observation?: Observation;
  credits: Money[];
}

export interface TransactionState {
  id: string;
  contract: OutcomeContract;
  digest: string;
  seq: number;
  head: string;
  lastAt: string;
  approvedAt?: string;
  approval?: Signed<ContractApproval>;
  revoked?: { at: string; reason?: string };
  expiredAt?: string;
  /** The contract's compensate policy was triggered. */
  unwinding: boolean;
  /** Operations in dependency order. */
  order: string[];
  ops: Record<string, OperationState>;
}

const emptyVerdict = (): PhaseVerdict => ({ status: "planned", next: "submit", findings: [] });
const SUBMIT: NextStep[] = ["submit", "retry_same_key", "retry_new_key"];
const ms = (iso: string) => Date.parse(iso);

export function replay(events: readonly StoredEvent[]): TransactionState {
  let s: TransactionState | undefined;
  for (const e of events) s = applyMut(s, e);
  if (!s) throw new InvariantError("empty log");
  return s;
}

/** Pure: returns a new state, leaving `state` untouched. */
export function applyEvent(state: TransactionState | undefined, e: StoredEvent): TransactionState {
  return applyMut(state ? structuredClone(state) : undefined, e);
}

function applyMut(s: TransactionState | undefined, e: StoredEvent): TransactionState {
  const fail = (m: string): never => { throw new InvariantError(m, e.seq); };
  if (Number.isNaN(ms(e.at))) fail("invalid timestamp");
  if (e.hash !== eventHash(e)) fail("hash does not match the event");
  if (!s) {
    if (e.seq !== 1 || e.prev !== GENESIS || e.body.type !== "contract.registered") fail("a log must start with contract.registered");
    return register(e as StoredEvent & { body: { type: "contract.registered" } }, fail);
  }
  if (e.transactionId !== s.id) fail("event belongs to another transaction");
  if (e.seq !== s.seq + 1 || e.prev !== s.head) fail("event is out of sequence");
  if (ms(e.at) < ms(s.lastAt)) fail("time went backwards");
  const b = e.body;
  const c = s.contract;
  const opOf = (id: string) => s.ops[id] ?? fail(`unknown operation ${id}`);
  switch (b.type) {
    case "contract.registered":
      fail("contract already registered");
      break;
    case "contract.approved": {
      if (s.approvedAt) fail("contract already approved");
      const p = b.approval.payload;
      if (p.type !== "agentmesh.contract-approval" || p.contractId !== c.id || p.contractDigest !== s.digest) fail("approval is for a different contract");
      if (!verifySigned(b.approval, c.principal.keys)) fail("approval is not signed by the principal");
      s.approvedAt = e.at;
      s.approval = b.approval;
      break;
    }
    case "contract.revoked": {
      if (s.revoked) fail("contract already revoked");
      const p = b.revocation.payload;
      if (p.type !== "agentmesh.revocation" || p.contractId !== c.id || p.contractDigest !== s.digest) fail("revocation is for a different contract");
      if (!verifySigned(b.revocation, c.principal.keys)) fail("revocation is not signed by the principal");
      s.revoked = { at: e.at, reason: p.reason };
      break;
    }
    case "contract.expired":
      if (s.expiredAt) fail("contract already expired");
      if (ms(e.at) < ms(c.expiresAt)) fail("contract has not expired yet");
      s.expiredAt = e.at;
      break;
    case "operation.step_up": {
      const p = b.approval.payload;
      const op = opOf(p.operationId);
      if (p.type !== "agentmesh.step-up-approval" || p.contractId !== c.id || p.contractDigest !== s.digest) fail("step-up is for a different contract");
      if (!verifySigned(b.approval, c.principal.keys)) fail("step-up is not signed by the principal");
      op.stepUps.push(b.approval);
      break;
    }
    case "operation.refused":
      opOf(b.operationId).refusals.push({ at: e.at, agent: b.agent, phase: b.phase, reason: b.reason });
      break;
    case "operation.submitting": {
      const op = opOf(b.operationId);
      const check = checkSubmission(s, { operationId: b.operationId, phase: b.phase, agent: b.agent, amount: b.amount, details: b.details, at: e.at });
      if (!check.ok) fail(`unauthorized submission of ${b.operationId}: ${check.reason}`);
      const ok = check as SubmissionPlan;
      if (b.attempt !== ok.attempt || b.idempotencyKey !== ok.idempotencyKey || canonicalize(b.amount ?? null) !== canonicalize(ok.amount ?? null)) {
        fail(`submission of ${b.operationId} does not match its plan`);
      }
      const a = b.authorization.payload;
      if (!verifySigned(b.authorization, c.coordinator.keys)) fail("authorization is not signed by the coordinator");
      if (a.type !== "agentmesh.execution-authorization" || a.contractId !== c.id || a.contractDigest !== s.digest || a.operationId !== op.id ||
          a.operationCommitment !== operationCommitment(op.spec) || a.phase !== b.phase || a.attempt !== b.attempt || a.idempotencyKey !== b.idempotencyKey ||
          a.agent !== b.agent || canonicalize(a.amount ?? null) !== canonicalize(b.amount ?? null) || a.detailsDigest !== detailsDigest(b.details)) {
        fail("authorization does not match the submission");
      }
      op[b.phase].attempts.push({
        n: b.attempt, at: e.at, agent: b.agent, idempotencyKey: b.idempotencyKey, generation: ok.generation, amount: b.amount,
        detailsDigest: detailsDigest(b.details), connector: b.connector, seq: e.seq,
      });
      break;
    }
    case "operation.result": {
      const a = opOf(b.operationId)[b.phase].attempts.find((x) => x.n === b.attempt) ?? fail(`no attempt ${b.attempt}`);
      if (a.result && a.result.outcome !== "ambiguous") fail(`attempt ${b.attempt} already has a result`);
      a.result = b.result;
      a.resultAt = e.at;
      break;
    }
    case "operation.expired": {
      const op = opOf(b.operationId);
      if (!op.spec.deadline || ms(e.at) < ms(op.spec.deadline)) fail(`${op.id} has not reached its deadline`);
      if (op.expiredAt) fail(`${op.id} already expired`);
      op.expiredAt = e.at;
      break;
    }
    case "evidence.recorded": {
      const op = opOf(b.operationId);
      op[b.phase].evidence.push(checkEvidence(s, op, b.phase, b.evidence, e.seq, e.at));
      break;
    }
    default:
      fail(`unknown event type ${(b as { type: string }).type}`);
  }
  s.seq = e.seq;
  s.head = e.hash;
  s.lastAt = e.at;
  derive(s);
  return s;
}

function register(e: StoredEvent & { body: { type: "contract.registered" } }, fail: (m: string) => never): TransactionState {
  let contract: OutcomeContract;
  try { contract = parseContract(e.body.contract); } catch (err) { return fail((err as Error).message); }
  if (e.transactionId !== contract.id) fail("transaction id must be the contract id");
  const ops: Record<string, OperationState> = {};
  for (const spec of contract.operations) {
    ops[spec.id] = {
      id: spec.id, spec, stepUps: [], refusals: [], status: "planned", next: "submit", nextPhase: "execute", findings: [], hold: 0, spent: 0, credits: [],
      execute: { attempts: [], evidence: [], verdict: emptyVerdict() },
      compensate: { attempts: [], evidence: [], verdict: emptyVerdict() },
    };
  }
  const order: string[] = [];
  const seen = new Set<string>();
  const visit = (id: string) => {
    if (seen.has(id)) return;
    seen.add(id);
    for (const d of ops[id]!.spec.dependsOn) visit(d);
    order.push(id);
  };
  contract.operations.forEach((o) => visit(o.id));
  const s: TransactionState = { id: contract.id, contract, digest: contractDigest(contract), seq: 1, head: e.hash, lastAt: e.at, unwinding: false, order, ops };
  derive(s);
  return s;
}

/** Validates evidence against the contract: signatures, who signed, and that it is about this operation. */
function checkEvidence(s: TransactionState, op: OperationState, phase: Phase, ev: Evidence, seq: number, at: string): EvidenceEntry {
  const c = s.contract;
  const keys = new Set(op[phase].attempts.map((a) => a.idempotencyKey));
  const accepts = (src: EvidenceSource) => op.spec.evidence.includes(src);
  const entry = (valid: boolean, proof: boolean, problem?: string): EvidenceEntry => ({ ...ev, seq, at, valid, proof: valid && proof, problem });
  switch (ev.source) {
    case "agent_claim":
      return entry(true, false);
    case "provider_record": {
      const k = ev.observation?.idempotencyKey;
      if (!keys.size) return entry(false, false, "there is no submission for it to answer");
      if (k && !keys.has(k)) return entry(false, false, "idempotency key does not match any submission");
      if (!ev.observation && !ev.notFound) return entry(false, false, "no observation");
      return entry(true, !!ev.observation && accepts("provider_record"));
    }
    case "signed_receipt": {
      const r = ev.receipt;
      const provider = c.participants.find((p) => p.id === op.spec.provider);
      if (!r || !provider || !verifySigned(r, provider.keys)) return entry(false, false, "receipt is not signed by a key listed for the provider");
      const p = r.payload;
      if (p.type !== "agentmesh.provider-receipt" || p.provider !== op.spec.provider || p.contractId !== c.id || p.operationId !== op.id || p.phase !== phase) {
        return entry(false, false, "receipt is about a different operation");
      }
      if (!keys.has(p.idempotencyKey)) return entry(false, false, "receipt does not match any submission");
      return entry(true, accepts("signed_receipt"));
    }
    case "human_attestation": {
      const a = ev.attestation;
      if (!a) return entry(false, false, "no attestation");
      const byPrincipal = verifySigned(a, c.principal.keys);
      const byReviewer = verifySigned(a, c.participants.filter((p) => p.role === "reviewer").flatMap((p) => p.keys));
      const p = a.payload;
      if (!byPrincipal && !byReviewer) return entry(false, false, "attestation is not signed by the principal or a listed reviewer");
      if (p.type !== "agentmesh.attestation" || p.contractId !== c.id || p.contractDigest !== s.digest || p.operationId !== op.id || p.phase !== phase) {
        return entry(false, false, "attestation is about a different operation");
      }
      if (p.outcome === "waived") return byPrincipal ? entry(true, true) : entry(false, false, "only the principal can waive an operation");
      if (ms(p.attestedAt) > ms(at) + 5 * 60_000) return entry(false, false, "attestation is dated in the future");
      return entry(true, accepts("human_attestation"));
    }
  }
}

// ── Submission rules ───────────────────────────────────────────────────────────

export interface SubmissionRequest { operationId: string; phase: Phase; agent: string; amount?: Money; details?: JsonObject; at: string }
export interface SubmissionPlan { ok: true; attempt: number; generation: number; idempotencyKey: string; amount?: Money; stepUp?: Signed<StepUpApproval> }

/**
 * Every rule a submission must pass. The coordinator asks before calling a provider, and the reducer asks again
 * when the submission is recorded, so a log can't contain a submission that broke them.
 */
export function checkSubmission(s: TransactionState, r: SubmissionRequest): SubmissionPlan | { ok: false; reason: string } {
  const no = (reason: string) => ({ ok: false as const, reason });
  const c = s.contract;
  const op = s.ops[r.operationId];
  if (!op) return no(`no operation ${r.operationId}`);
  if (!s.approvedAt) return no("the principal has not approved the contract");
  if (s.revoked) return no("the principal revoked the contract");
  const ph = op[r.phase];
  const verdict = ph.verdict;
  if (r.phase === "execute") {
    if (!op.spec.executors.includes(r.agent)) return no(`agent ${r.agent} may not execute ${op.id}`);
    if (s.expiredAt || ms(r.at) >= ms(c.expiresAt)) return no("the contract has expired");
    if (op.expiredAt || (op.spec.deadline && ms(r.at) >= ms(op.spec.deadline))) return no("the operation's deadline has passed");
    if (s.unwinding) return no("the transaction is being unwound");
    if (op.status === "cancelled" || op.status === "waived") return no(`${op.id} is ${op.status}`);
    const waiting = op.spec.dependsOn.filter((d) => s.ops[d]!.execute.verdict.status !== "verified");
    if (waiting.length) return no(`waiting for ${waiting.join(", ")} to be verified`);
  } else {
    if (r.agent !== c.coordinator.id) return no("only the coordinator runs compensations");
    if (op.status !== "compensating") return no(`${op.id} is not being compensated`);
  }
  if (!SUBMIT.includes(verdict.next)) return no(`${op.id} is ${verdict.status}${verdict.next === "lookup" ? " (checking the provider's records first)" : ""}`);
  const last = ph.attempts.at(-1);
  const attempt = ph.attempts.length + 1;
  if (attempt > op.spec.maxAttempts) return no("no attempts left");
  const sameKey = verdict.next === "retry_same_key" && last;
  const generation = !last ? 0 : verdict.next === "retry_new_key" ? last.generation + 1 : last.generation;
  const key = idempotencyKey(c.id, op.id, r.phase, generation);
  const dd = detailsDigest(r.details);

  if (r.phase === "compensate") {
    if (r.amount) return no("a compensation may not charge anything");
    return { ok: true, attempt, generation, idempotencyKey: key };
  }
  let amount: Money | undefined;
  if (sameKey) {
    // Same key means same request: a retry may not change what was asked for.
    if ((r.amount && canonicalize(r.amount) !== canonicalize(last.amount ?? null)) || dd !== last.detailsDigest) return no("a retry must repeat the original request");
    amount = last.amount;
  } else {
    amount = r.amount ?? op.spec.spend;
    if (amount && amount.minor > 0) {
      if (!op.spec.spend) return no(`${op.id} may not spend anything`);
      if (amount.currency !== op.spec.spend.currency) return no(`amount must be in ${op.spec.spend.currency}`);
      if (amount.minor > op.spec.spend.minor) return no(`${formatMoney(amount)} is more than ${op.id} may spend (${formatMoney(op.spec.spend)})`);
    }
  }
  let stepUp: Signed<StepUpApproval> | undefined;
  const above = c.constraints.approvalAbove;
  if (op.spec.requiresApproval || (above && amount && amount.minor > above.minor)) {
    stepUp = op.stepUps.find((x) => x.payload.detailsDigest === dd && (!amount || (x.payload.amount?.currency === amount.currency && amount.minor <= x.payload.amount.minor)));
    if (!stepUp) return no(`needs the principal's approval${amount ? ` for ${formatMoney(amount)}` : ""}`);
  }
  const limit = c.constraints.budget;
  if (limit && amount && amount.minor > 0) {
    const b = budget(s)!;
    const available = b.available + (sameKey ? op.hold : 0);
    if (amount.minor > available) return no(`would exceed the shared budget (${formatMoney(amount)} requested, ${formatMoney({ currency: limit.currency, minor: available })} available)`);
  }
  return { ok: true, attempt, generation, idempotencyKey: key, amount, stepUp };
}

// ── Derivation ─────────────────────────────────────────────────────────────────

const CANCEL_NO_ESCALATION = ["the principal revoked the contract", "the transaction is being unwound"];

function derive(s: TransactionState) {
  if (s.contract.policy.onRequiredFailure === "compensate_completed" && !s.unwinding) {
    if (Object.values(s.ops).some((o) => o.compensate.attempts.length > 0)) s.unwinding = true;
    else {
      derivePass(s);
      const trigger = s.order.some((id) => {
        const o = s.ops[id]!;
        return o.spec.required && (o.status === "rejected" || o.status === "failed" || (o.status === "cancelled" && !CANCEL_NO_ESCALATION.includes(o.blockedBy ?? "")));
      });
      if (!trigger) return;
      s.unwinding = true;
    }
  }
  derivePass(s);
}

function derivePass(s: TransactionState) {
  const c = s.contract;
  const verifiedObs = (id: string) => (s.ops[id]?.execute.verdict.status === "verified" ? s.ops[id]!.execute.verdict.observation : undefined);
  const stopped = !!s.revoked;
  for (const id of s.order) {
    const op = s.ops[id]!;
    const spec = op.spec;
    const ex = derivePhase({ phase: "execute", spec, expectation: spec.expect, attempts: op.execute.attempts, evidence: op.execute.evidence, expired: !!op.expiredAt, refs: verifiedObs });
    const timeUp = !!s.expiredAt || !!op.expiredAt;
    if ((stopped || timeUp) && SUBMIT.includes(ex.next)) ex.next = null;
    op.execute.verdict = ex;
    op.findings = [...ex.findings];
    op.blockedBy = undefined;
    op.escalation = undefined;
    op.basis = ex.basis;
    op.observation = ex.observation;
    op.credits = [];
    op.next = ex.next;
    op.nextPhase = "execute";
    const lastAmount = op.execute.attempts.at(-1)?.amount?.minor ?? 0;
    op.hold = 0;
    op.spent = 0;

    switch (ex.status) {
      case "planned": {
        const deadDep = spec.dependsOn.find((d) => ["rejected", "failed", "cancelled", "waived", "compensated", "compensating"].includes(s.ops[d]!.status));
        const cancel = stopped ? CANCEL_NO_ESCALATION[0]
          : s.expiredAt ? "the contract expired before it was submitted"
          : op.expiredAt ? "the deadline passed before it was submitted"
          : s.unwinding ? CANCEL_NO_ESCALATION[1]
          : deadDep ? `${deadDep} did not complete`
          : undefined;
        if (cancel) {
          op.status = "cancelled";
          op.blockedBy = cancel;
          op.next = null;
          op.findings.push(cancel);
          if (spec.required && !CANCEL_NO_ESCALATION.includes(cancel) && !(deadDep && s.ops[deadDep]!.spec.required)) op.escalation = `required operation was cancelled: ${cancel}`;
        } else {
          op.status = "planned";
          const waiting = spec.dependsOn.filter((d) => s.ops[d]!.execute.verdict.status !== "verified");
          op.blockedBy = !s.approvedAt ? "awaiting the principal's approval" : waiting.length ? `waiting for ${waiting.join(", ")}` : undefined;
        }
        break;
      }
      case "submitting": op.status = "submitting"; op.hold = lastAmount; break;
      case "pending": op.status = "pending_verification"; op.hold = lastAmount; break;
      case "unknown":
        op.status = "unknown";
        op.hold = lastAmount;
        if (ex.next === null || timeUp) op.escalation = "outcome unknown: the request may have taken effect and it can't be confirmed automatically";
        break;
      case "disputed":
        op.status = "disputed";
        op.hold = Math.max(lastAmount, ex.observedDebit ?? 0);
        op.escalation = `evidence disputes the outcome: ${ex.findings.at(-1)}`;
        break;
      case "rejected":
      case "failed":
        op.status = ex.status;
        if (spec.required) op.escalation = `required operation was not achieved: ${ex.findings.at(-1)}`;
        break;
      case "waived": op.status = "waived"; break;
      case "verified": {
        op.status = "verified";
        op.spent = ex.settled?.minor ?? 0;
        if (ex.observation?.credit) op.credits.push(ex.observation.credit);
        if (!s.unwinding) break;
        const comp = spec.compensation;
        if (!comp) { op.escalation = "the transaction is being unwound but this operation can't be undone automatically"; break; }
        const cp = derivePhase({ phase: "compensate", spec, expectation: comp.expect, attempts: op.compensate.attempts, evidence: op.compensate.evidence, expired: false, refs: verifiedObs });
        if (stopped && SUBMIT.includes(cp.next)) cp.next = null;
        op.compensate.verdict = cp;
        op.findings.push(...cp.findings.map((f) => `compensation: ${f}`));
        op.next = cp.next;
        op.nextPhase = "compensate";
        if (cp.observation?.credit) op.credits.push(cp.observation.credit);
        if (cp.status === "verified") op.status = "compensated";
        else if (cp.status === "disputed") { op.status = "disputed"; op.escalation = `evidence disputes the compensation: ${cp.findings.at(-1)}`; }
        else if (cp.status === "rejected" || cp.status === "failed" || cp.status === "waived") {
          op.next = null;
          if (cp.status !== "waived") op.escalation = `compensation failed: ${cp.findings.at(-1)}`;
        } else {
          op.status = "compensating";
          if (cp.status === "unknown" && cp.next === null) op.escalation = "compensation outcome unknown and it can't be confirmed automatically";
        }
        break;
      }
    }
    // Agents' claims never decide anything, but contradictions are worth surfacing.
    for (const e of op.execute.evidence) {
      if (e.source !== "agent_claim" || !e.observation) continue;
      const said = e.observation.status;
      if (spec.expect.success.includes(said) && op.status !== "verified" && op.status !== "compensating" && op.status !== "compensated") {
        op.findings.push(`${e.agent ?? "an agent"} reported "${said}", which the evidence does not confirm`);
      }
    }
  }
}

// ── Outcome ────────────────────────────────────────────────────────────────────

export function budget(s: TransactionState) {
  const limit = s.contract.constraints.budget;
  if (!limit) return undefined;
  let held = 0, spent = 0;
  for (const o of Object.values(s.ops)) { held += o.hold; spent += o.spent; }
  return { limit, held, spent, available: Math.max(0, limit.minor - held - spent) };
}

export function outcome(s: TransactionState): { status: OutcomeStatus; counts: Partial<Record<OperationStatus, number>>; escalations: { operationId: string; reason: string }[] } {
  const ops = s.order.map((id) => s.ops[id]!);
  const counts: Partial<Record<OperationStatus, number>> = {};
  for (const o of ops) counts[o.status] = (counts[o.status] ?? 0) + 1;
  const escalations = ops.filter((o) => o.escalation).map((o) => ({ operationId: o.id, reason: o.escalation! }));
  const any = (...st: OperationStatus[]) => ops.some((o) => st.includes(o.status));
  let status: OutcomeStatus;
  if (any("disputed")) status = "disputed";
  else if (escalations.length) status = "requires_human_review";
  else if (any("unknown")) status = "outcome_unknown";
  else if (any("planned", "submitting", "compensating")) status = "in_progress";
  else if (any("pending_verification")) status = "pending_verification";
  else if (ops.filter((o) => o.spec.required).every((o) => o.status === "verified")) status = "completed";
  else if (any("verified")) status = "partially_completed";
  else status = "failed";
  return { status, counts, escalations };
}
