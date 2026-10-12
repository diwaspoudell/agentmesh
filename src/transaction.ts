import { canonicalize, digest, type JsonObject } from "./canonical.ts";
import { contractDigest, MoneySchema, operationCommitment, parseContract, type EvidenceSource, type OperationSpec, type OutcomeContract } from "./contract.ts";
import { verifySigned, type PublicKeyJwk, type Signed } from "./keys.ts";
import type { PolicyDecision } from "./policy.ts";
import { formatMoney, type Money } from "./money.ts";
import {
  derivePhase, type Attempt, type ConnectorProfile, type Evidence, type EvidenceEntry, type NextStep, type PhaseVerdict, type SubmissionResult,
} from "./reconcile.ts";
import {
  detailsDigest, idempotencyKey, type ContractApproval, type Endorsement, type ExecutionAuthorization, type IncidentReport, type Observation, type Phase,
  type Resumption, type Revocation, type StepUpApproval, type Suspension,
} from "./statements.ts";

// ── Events ─────────────────────────────────────────────────────────────────────
// Events are facts: what was approved, what was sent, what came back, what evidence was seen, what time it was.
// Every verdict (verified, unknown, disputed...) is derived from them, never stored, so replaying the log is how
// anyone checks the outcome.

export type EventBody =
  | { type: "contract.registered"; contract: OutcomeContract }
  | { type: "contract.approved"; approval: Signed<ContractApproval> }
  | { type: "contract.revoked"; revocation: Signed<Revocation> }
  | { type: "contract.suspended"; suspension: Signed<Suspension> }
  | { type: "contract.resumed"; resumption: Signed<Resumption> }
  | { type: "contract.expired" }
  | { type: "operation.step_up"; approval: Signed<StepUpApproval> }
  | { type: "operation.endorsed"; endorsement: Signed<Endorsement> }
  | { type: "operation.refused"; operationId: string; phase: Phase; agent: string; reason: string; kind: RefusalKind; policy?: PolicyDecision[] }
  | {
      type: "operation.submitting"; operationId: string; phase: Phase; attempt: number; agent: string; idempotencyKey: string;
      amount?: Money; details?: JsonObject; connector: ConnectorProfile; authorization: Signed<ExecutionAuthorization>; policy?: PolicyDecision[];
    }
  | { type: "incident.reported"; incident: Signed<IncidentReport> }
  | { type: "operation.result"; operationId: string; phase: Phase; attempt: number; result: SubmissionResult }
  | { type: "operation.expired"; operationId: string }
  | { type: "evidence.recorded"; operationId: string; phase: Phase; evidence: Evidence };

/** `violation`: the request itself broke the contract (wrong agent, over a cap, a changed retry). `blocked`: it just has to wait or needs something. Only violations feed the circuit breaker. */
export type RefusalKind = "violation" | "blocked";

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
  | "completed" | "partially_completed" | "in_progress" | "pending_verification" | "outcome_unknown" | "failed" | "disputed" | "requires_human_review"
  /** Every required operation was achieved and then unwound (compensated) or waived: nothing stands, and that is the verified outcome. */
  | "undone";

export interface SuspensionRecord { by: "principal" | "controller" | "coordinator"; at: string; reason?: string; agent?: string }
export interface IncidentRecord { at: string; by: SignerRole; report: Signed<IncidentReport> }

export interface PhaseRecord { attempts: Attempt[]; evidence: EvidenceEntry[]; verdict: PhaseVerdict }

export interface OperationState {
  id: string;
  spec: OperationSpec;
  execute: PhaseRecord;
  compensate: PhaseRecord;
  stepUps: Signed<StepUpApproval>[];
  endorsements: Signed<Endorsement>[];
  /** Log positions of the latest step-up and endorsement, so a view can tell whether a refusal has since been acted on. */
  lastStepUpSeq?: number;
  lastEndorsedSeq?: number;
  refusals: { at: string; seq: number; agent: string; phase: Phase; reason: string; kind: RefusalKind; policy?: PolicyDecision[] }[];
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
  revoked?: { at: string; reason?: string; by: "principal" | "controller" };
  /** Active suspensions: the whole transaction and/or individual agents. */
  suspended: { all?: SuspensionRecord; agents: Record<string, SuspensionRecord> };
  /** Log position of each agent's last resumption; the circuit breaker only counts violations after it. */
  resumedSeq: Record<string, number>;
  incidents: IncidentRecord[];
  expiredAt?: string;
  /** The contract's compensate policy was triggered. */
  unwinding: boolean;
  /** Operations in dependency order. */
  order: string[];
  ops: Record<string, OperationState>;
}

export type SignerRole = "principal" | "controller" | "coordinator" | "reviewer" | "auditor";

function keysFor(c: OutcomeContract, role: SignerRole): PublicKeyJwk[] {
  if (role === "principal") return c.principal.keys;
  if (role === "coordinator") return c.coordinator.keys;
  return c.participants.filter((p) => p.role === role).flatMap((p) => p.keys);
}

/** Which of the allowed roles signed this statement, judged only by the keys the contract names for each role. */
function signerRole<R extends SignerRole>(c: OutcomeContract, signed: Signed<{ type: string }>, allowed: readonly R[]): R | undefined {
  return allowed.find((r) => verifySigned(signed, keysFor(c, r)));
}

/** Violations by an agent inside the breaker's window and since it was last resumed. */
export function violationsByAgent(s: TransactionState, agent: string, at: string, windowSeconds: number): number {
  const from = ms(at) - windowSeconds * 1000;
  const after = s.resumedSeq[agent] ?? 0;
  let n = 0;
  for (const op of Object.values(s.ops)) for (const r of op.refusals) if (r.agent === agent && r.kind === "violation" && r.seq > after && ms(r.at) >= from) n++;
  return n;
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

/** Like `replay`, but calls back with the state after each event (the state object is reused, so don't keep it). */
export function replayWith(events: readonly StoredEvent[], each: (event: StoredEvent, after: TransactionState) => void): TransactionState {
  let s: TransactionState | undefined;
  for (const e of events) { s = applyMut(s, e); each(e, s); }
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
      const by = signerRole(c, b.revocation, ["principal", "controller"] as const) ?? fail("revocation is not signed by the principal or a controller");
      s.revoked = { at: e.at, reason: p.reason, by };
      break;
    }
    case "contract.suspended": {
      const p = b.suspension.payload;
      if (p.type !== "agentmesh.suspension" || p.contractId !== c.id || p.contractDigest !== s.digest) fail("suspension is for a different contract");
      const by = signerRole(c, b.suspension, ["principal", "controller", "coordinator"] as const) ?? fail("suspension is not signed by the principal, a controller or the coordinator");
      if (p.agent !== undefined && !c.participants.some((x) => x.id === p.agent && x.role === "agent")) fail(`unknown agent ${p.agent}`);
      if (by === "coordinator") {
        // The coordinator can pull one agent's plug only because the contract's own circuit breaker says so, and the log must show why.
        const br = c.policy.circuitBreaker;
        if (!br || p.agent === undefined) fail("the coordinator may suspend only a single agent, and only through the contract's circuit breaker");
        const n = violationsByAgent(s, p.agent!, e.at, br!.windowSeconds);
        if (n < br!.violations) fail(`circuit breaker has not tripped for ${p.agent} (${n} of ${br!.violations} violations)`);
      }
      if (p.agent === undefined ? s.suspended.all : s.suspended.agents[p.agent]) fail("already suspended");
      const rec: SuspensionRecord = { by, at: e.at, reason: p.reason, agent: p.agent };
      if (p.agent === undefined) s.suspended.all = rec;
      else s.suspended.agents[p.agent] = rec;
      break;
    }
    case "contract.resumed": {
      const p = b.resumption.payload;
      if (p.type !== "agentmesh.resumption" || p.contractId !== c.id || p.contractDigest !== s.digest) fail("resumption is for a different contract");
      const by = signerRole(c, b.resumption, ["principal", "controller"] as const) ?? fail("resumption is not signed by the principal or a controller");
      const rec = p.agent === undefined ? s.suspended.all : s.suspended.agents[p.agent];
      if (!rec) fail("there is no such suspension to lift");
      if (rec!.by === "controller" && by !== "controller") fail("a suspension placed by a controller can only be lifted by a controller");
      if (p.agent === undefined) delete s.suspended.all;
      else { delete s.suspended.agents[p.agent]; s.resumedSeq[p.agent] = e.seq; }
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
      op.lastStepUpSeq = e.seq;
      break;
    }
    case "operation.endorsed": {
      const p = b.endorsement.payload;
      const op = opOf(p.operationId);
      if (p.type !== "agentmesh.endorsement" || p.contractId !== c.id || p.contractDigest !== s.digest) fail("endorsement is for a different contract");
      const agent = c.participants.find((x) => x.role === "agent" && x.id === p.agent) ?? fail(`endorsement names unknown agent ${p.agent}`);
      if (!verifySigned(b.endorsement, agent.keys)) fail(`endorsement is not signed by ${p.agent}'s key`);
      op.endorsements.push(b.endorsement);
      op.lastEndorsedSeq = e.seq;
      break;
    }
    case "operation.refused":
      if (b.kind !== "violation" && b.kind !== "blocked") fail("refusal needs a kind");
      opOf(b.operationId).refusals.push({ at: e.at, seq: e.seq, agent: b.agent, phase: b.phase, reason: b.reason, kind: b.kind, policy: b.policy });
      break;
    case "incident.reported": {
      const p = b.incident.payload;
      if (p.type !== "agentmesh.incident" || p.contractId !== c.id) fail("incident is for a different contract");
      const by = signerRole(c, b.incident, ["principal", "controller", "coordinator", "reviewer", "auditor"] as const) ?? fail("incident is not signed by a key the contract names");
      if (s.incidents.some((i) => i.report.payload.id === p.id)) fail(`incident ${p.id} was already reported`);
      for (const id of p.affectedOperations) opOf(id);
      s.incidents.push({ at: e.at, by, report: b.incident });
      break;
    }
    case "operation.submitting": {
      const op = opOf(b.operationId);
      const denied = b.policy?.find((d) => d.effect === "deny");
      if (denied) fail(`submission of ${b.operationId} was denied by policy ${denied.policy}`);
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
      id: spec.id, spec, stepUps: [], endorsements: [], refusals: [], status: "planned", next: "submit", nextPhase: "execute", findings: [], hold: 0, spent: 0, credits: [],
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
  const s: TransactionState = { id: contract.id, contract, digest: contractDigest(contract), seq: 1, head: e.hash, lastAt: e.at, unwinding: false, suspended: { agents: {} }, resumedSeq: {}, incidents: [], order, ops };
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
export function checkSubmission(s: TransactionState, r: SubmissionRequest): SubmissionPlan | { ok: false; reason: string; kind: RefusalKind } {
  const no = (reason: string, kind: RefusalKind = "blocked") => ({ ok: false as const, reason, kind });
  // The amount comes from the (untrusted) agent: it must be well-formed money before any cap or budget math
  // touches it. A negative, fractional, or otherwise malformed amount must never reach the spend checks below,
  // which only constrain positive amounts.
  if (r.amount !== undefined) {
    const parsed = MoneySchema.safeParse(r.amount);
    if (!parsed.success) return no(`invalid amount: ${parsed.error.issues.map((i) => i.message).join("; ")}`, "violation");
    r = { ...r, amount: parsed.data };
  }
  const c = s.contract;
  const op = s.ops[r.operationId];
  if (!op) return no(`no operation ${r.operationId}`);
  if (!s.approvedAt) return no("the principal has not approved the contract");
  if (s.revoked) return no(`the ${s.revoked.by} revoked the contract`);
  const hold = (x: SuspensionRecord) => `suspended by the ${x.by}${x.reason ? ` (${x.reason})` : ""}`;
  if (s.suspended.all) return no(`the transaction is ${hold(s.suspended.all)}`);
  const agentHold = r.phase === "execute" ? s.suspended.agents[r.agent] : undefined;
  if (agentHold) return no(`agent ${r.agent} is ${hold(agentHold)}`);
  const ph = op[r.phase];
  const verdict = ph.verdict;
  if (r.phase === "execute") {
    if (!op.spec.executors.includes(r.agent)) return no(`agent ${r.agent} may not execute ${op.id}`, "violation");
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
    if (r.amount) return no("a compensation may not charge anything", "violation");
    return { ok: true, attempt, generation, idempotencyKey: key };
  }
  let amount: Money | undefined;
  if (sameKey) {
    // Same key means same request: a retry may not change what was asked for.
    if ((r.amount && canonicalize(r.amount) !== canonicalize(last.amount ?? null)) || dd !== last.detailsDigest) return no("a retry must repeat the original request", "violation");
    amount = last.amount;
  } else {
    amount = r.amount ?? op.spec.spend;
    if (amount && amount.minor > 0) {
      if (!op.spec.spend) return no(`${op.id} may not spend anything`, "violation");
      if (amount.currency !== op.spec.spend.currency) return no(`amount must be in ${op.spec.spend.currency}`, "violation");
      if (amount.minor > op.spec.spend.minor) return no(`${formatMoney(amount)} is more than ${op.id} may spend (${formatMoney(op.spec.spend)})`, "violation");
    }
  }
  let stepUp: Signed<StepUpApproval> | undefined;
  const above = c.constraints.approvalAbove;
  if (op.spec.requiresApproval || (above && amount && amount.minor > above.minor)) {
    stepUp = op.stepUps.find((x) => x.payload.detailsDigest === dd && (!amount || (x.payload.amount?.currency === amount.currency && amount.minor <= x.payload.amount.minor)));
    if (!stepUp) return no(`needs the principal's approval${amount ? ` for ${formatMoney(amount)}` : ""}`);
  }
  const cc = op.spec.crossCheck;
  if (cc && !sameKey) {
    const objection = op.endorsements.find((x) => x.payload.verdict === "object" && x.payload.detailsDigest === dd);
    if (objection) return no(`${objection.payload.agent} objected to this request${objection.payload.reason ? `: ${objection.payload.reason}` : ""}`);
    const vendorOf = (id: string) => c.participants.find((p) => p.id === id)?.vendor;
    const counted = new Set<string>();
    const vendors = new Set<string>();
    for (const x of op.endorsements) {
      const q = x.payload;
      if (q.verdict !== "concur" || q.detailsDigest !== dd || q.agent === r.agent || op.spec.executors.includes(q.agent) || counted.has(q.agent)) continue;
      if (amount && !(q.amount && q.amount.currency === amount.currency && amount.minor <= q.amount.minor)) continue;
      const v = vendorOf(q.agent);
      if (cc.distinctVendors && (!v || v === vendorOf(r.agent) || vendors.has(v))) continue;
      counted.add(q.agent);
      if (v) vendors.add(v);
    }
    if (counted.size < cc.min) return no(`needs ${cc.min} independent cross-check${cc.min > 1 ? "s" : ""}${cc.distinctVendors ? " from different vendors" : ""} (${counted.size} so far)`);
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
          op.blockedBy = !s.approvedAt ? "awaiting the principal's approval"
            : s.suspended.all ? "the transaction is suspended"
            : spec.executors.every((a) => s.suspended.agents[a]) ? "every agent that may run it is suspended"
            : waiting.length ? `waiting for ${waiting.join(", ")}` : undefined;
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
      case "waived": {
        op.status = "waived";
        // Keep holding the budget unless the provider definitively did nothing: the request may have been charged before it was waived.
        const last = op.execute.attempts.at(-1);
        const maybeCharged = !!last && (!last.result || last.result.outcome === "accepted" || last.result.outcome === "ambiguous" || last.connector.kind === "agent");
        op.hold = Math.max(maybeCharged ? lastAmount : 0, ex.observedDebit ?? 0);
        break;
      }
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
  const required = ops.filter((o) => o.spec.required);
  const settled = (o: OperationState) => o.status === "verified" || o.status === "compensated" || o.status === "waived";
  let status: OutcomeStatus;
  if (any("disputed")) status = "disputed";
  else if (escalations.length) status = "requires_human_review";
  else if (any("unknown")) status = "outcome_unknown";
  else if (any("planned", "submitting", "compensating")) status = "in_progress";
  else if (any("pending_verification")) status = "pending_verification";
  else if (required.every((o) => o.status === "verified")) status = "completed";
  else if (required.every(settled)) status = "undone";
  else if (any("verified")) status = "partially_completed";
  else status = "failed";
  return { status, counts, escalations };
}
