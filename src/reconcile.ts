import { canonicalize, getPath } from "./canonical.ts";
import type { EvidenceSource, Expectation, FieldCheck, OperationSpec } from "./contract.ts";
import type { Signed } from "./keys.ts";
import { formatMoney, type Money } from "./money.ts";
import type { Attestation, Observation, ProviderReceipt } from "./statements.ts";

/** How a connector reaches the provider, recorded with each submission. */
export interface ConnectorProfile {
  /** "api": the provider's own API, so responses are the provider's statements. "agent": relayed by an agent, so responses are claims. */
  kind: "api" | "agent";
  /** Re-sending the same idempotency key never repeats the effect. */
  idempotent: boolean;
  /** Can read the provider's system of record for an operation. */
  lookup: boolean;
}

export type SubmissionResult =
  | { outcome: "accepted"; providerRef?: string }
  /** The provider refused; nothing happened. */
  | { outcome: "rejected"; reason: string }
  /** Known not to have taken effect (validation error, rate limit before processing). */
  | { outcome: "not_executed"; reason: string; retryable: boolean }
  /** May or may not have taken effect: a timeout, a dropped connection, a crash mid-call. */
  | { outcome: "ambiguous"; reason: string };

export type EvidenceKind = EvidenceSource | "agent_claim";

export interface Evidence {
  source: EvidenceKind;
  /** For provider records: where the coordinator read it. */
  via?: "response" | "lookup";
  agent?: string;
  observation?: Observation;
  receipt?: Signed<ProviderReceipt>;
  attestation?: Signed<Attestation>;
  /** A status lookup found no record. `definitive`: the provider guarantees it would have one if the request had executed. */
  notFound?: { definitive: boolean };
}

export interface Attempt {
  n: number;
  at: string;
  agent: string;
  idempotencyKey: string;
  generation: number;
  amount?: Money;
  detailsDigest?: string;
  connector: ConnectorProfile;
  result?: SubmissionResult;
  resultAt?: string;
  seq: number;
}

export interface EvidenceEntry extends Evidence {
  seq: number;
  at: string;
  /** Signature and correlation checks passed. */
  valid: boolean;
  /** Valid and from a source this operation's contract accepts as proof. */
  proof: boolean;
  problem?: string;
}

export type PhaseStatus = "planned" | "submitting" | "pending" | "verified" | "rejected" | "failed" | "unknown" | "disputed" | "waived";
export type NextStep = "submit" | "retry_same_key" | "retry_new_key" | "lookup" | null;

export interface PhaseVerdict {
  status: PhaseStatus;
  next: NextStep;
  findings: string[];
  basis?: EvidenceSource;
  observation?: Observation;
  /** Debit shown by the verifying evidence. */
  settled?: Money;
  /** The largest debit any proof shows (used to hold budget while disputed). */
  observedDebit?: number;
}

const SOURCE_STRENGTH: EvidenceSource[] = ["signed_receipt", "provider_record", "human_attestation"];

/** The observation a proof carries, normalized across sources. */
export function proofObservation(e: Evidence, exp: Expectation): Observation | undefined {
  if (e.receipt) return e.receipt.payload.observation;
  if (e.attestation) {
    const a = e.attestation.payload;
    if (a.observation) return a.observation;
    if (a.outcome === "succeeded") return { status: exp.success[0]! };
    if (a.outcome === "failed") return { status: exp.failure[0] ?? "failed" };
    return undefined;
  }
  return e.observation;
}

type Cls = "success" | "pending" | "failure" | "unrecognized";
function classify(o: Observation, exp: Expectation, attestation?: Attestation): Cls {
  if (attestation?.outcome === "succeeded" && !attestation.observation) return "success";
  if (attestation?.outcome === "failed" && !attestation.observation) return "failure";
  if (exp.success.includes(o.status)) return "success";
  if (exp.pending.includes(o.status)) return "pending";
  if (exp.failure.includes(o.status)) return "failure";
  return "unrecognized";
}

function compare(actual: unknown, op: FieldCheck["op"], expected: unknown): boolean {
  if (op === "eq") return canonicalize(actual) === canonicalize(expected);
  if (op === "ne") return canonicalize(actual) !== canonicalize(expected);
  if (op === "in") return Array.isArray(expected) && expected.some((v) => canonicalize(v) === canonicalize(actual));
  let a: number, b: number;
  if (typeof actual === "number" && typeof expected === "number") { a = actual; b = expected; }
  else if (typeof actual === "string" && typeof expected === "string" && !Number.isNaN(Date.parse(actual)) && !Number.isNaN(Date.parse(expected))) {
    a = Date.parse(actual); b = Date.parse(expected);
  } else return false;
  return op === "lt" ? a < b : op === "lte" ? a <= b : op === "gt" ? a > b : a >= b;
}

/**
 * Checks a success observation against the approved terms.
 * `violations`: it happened, but not as approved (disputed). `missing`: the evidence can't show the terms were met yet.
 */
export function checkTerms(
  o: Observation, exp: Expectation, authorizedDebit: Money | undefined, refs: (operationId: string) => Observation | undefined,
): { violations: string[]; missing: string[] } {
  const violations: string[] = [];
  const missing: string[] = [];
  if (o.debit && o.debit.minor > 0) {
    if (!authorizedDebit) violations.push(`charged ${formatMoney(o.debit)} but no spending was approved`);
    else if (o.debit.currency !== authorizedDebit.currency) violations.push(`charged in ${o.debit.currency}, approved in ${authorizedDebit.currency}`);
    else if (o.debit.minor > authorizedDebit.minor) violations.push(`charged ${formatMoney(o.debit)}, approved up to ${formatMoney(authorizedDebit)}`);
  } else if (authorizedDebit && authorizedDebit.minor > 0 && !o.debit) missing.push("evidence does not show the amount charged");
  if (exp.credit) {
    if (!o.credit) missing.push("evidence does not show the amount returned");
    else {
      const { min, max } = exp.credit;
      const cur = (min ?? max)?.currency;
      if (cur && o.credit.currency !== cur) violations.push(`returned in ${o.credit.currency}, expected ${cur}`);
      else {
        if (min && o.credit.minor < min.minor) violations.push(`returned ${formatMoney(o.credit)}, expected at least ${formatMoney(min)}`);
        if (max && o.credit.minor > max.minor) violations.push(`returned ${formatMoney(o.credit)}, expected at most ${formatMoney(max)}`);
      }
    }
  }
  for (const ch of exp.checks) {
    const actual = getPath(o, ch.path);
    if (ch.op === "exists") {
      const want = ch.value ?? true;
      if ((actual !== undefined) !== want) (want ? missing : violations).push(`${ch.path} ${want ? "is missing" : "should not be present"}`);
      continue;
    }
    let expected: unknown = ch.value;
    if (ch.ref) {
      const other = refs(ch.ref.operation);
      expected = other && getPath(other, ch.ref.path);
      if (expected === undefined) { missing.push(`${ch.ref.operation}.${ch.ref.path} is not verified yet`); continue; }
    }
    if (actual === undefined) { missing.push(`evidence does not show ${ch.path}`); continue; }
    if (!compare(actual, ch.op, expected)) {
      violations.push(`${ch.path} is ${JSON.stringify(actual)}, expected ${ch.op} ${ch.ref ? `${ch.ref.operation}.${ch.ref.path} (${JSON.stringify(expected)})` : JSON.stringify(expected)}`);
    }
  }
  return { violations, missing };
}

export interface PhaseInput {
  phase: "execute" | "compensate";
  spec: OperationSpec;
  expectation: Expectation;
  attempts: Attempt[];
  evidence: EvidenceEntry[];
  /** The deadline passed before the outcome was confirmed. */
  expired: boolean;
  refs: (operationId: string) => Observation | undefined;
}

/**
 * The reconciliation rule for one phase of one operation. Deterministic in its inputs, so anyone replaying the
 * evidence log reaches the same verdict.
 */
export function derivePhase(p: PhaseInput): PhaseVerdict {
  const findings: string[] = [];
  const { attempts, evidence, expectation: exp, spec } = p;
  const authorized = p.phase === "execute" ? attempts.reduce<Money | undefined>((m, a) => (a.amount && (!m || a.amount.minor > m.minor) ? a.amount : m), undefined) : undefined;

  for (const e of evidence) if (!e.valid) findings.push(`ignored ${e.source.replace("_", " ")}: ${e.problem}`);

  if (evidence.some((e) => e.proof && e.attestation?.payload.outcome === "waived")) {
    // Waiving accepts that the step won't happen; it doesn't un-charge money a provider may already have taken.
    let charged = 0;
    for (const e of evidence) {
      const o = e.proof ? proofObservation(e, exp) : undefined;
      if (o?.debit) charged = Math.max(charged, o.debit.minor);
    }
    return { status: "waived", next: null, findings: [...findings, "waived by the principal"], observedDebit: charged };
  }

  // 1. What do the proofs say?
  const successes: { e: EvidenceEntry; o: Observation }[] = [];
  let failure: EvidenceEntry | undefined, pending = false, lastPending: string | undefined, unrecognized: string | undefined, observedDebit = 0;
  const missing = new Set<string>();
  const violations = new Set<string>();
  for (const e of evidence) {
    if (!e.proof) continue;
    const o = proofObservation(e, exp);
    if (!o) continue;
    if (o.debit) observedDebit = Math.max(observedDebit, o.debit.minor);
    const cls = classify(o, exp, e.attestation?.payload);
    if (cls === "success") {
      const t = checkTerms(o, exp, authorized, p.refs);
      t.violations.forEach((v) => violations.add(v));
      if (t.missing.length) { t.missing.forEach((m) => missing.add(m)); pending = true; }
      else successes.push({ e, o });
    } else if (cls === "failure") failure = e;
    else if (cls === "pending") { pending = true; lastPending = o.status; }
    else unrecognized = o.status;
  }

  if (violations.size) return { status: "disputed", next: null, findings: [...findings, ...violations], observedDebit };
  if (successes.length && failure) {
    return { status: "disputed", next: null, findings: [...findings, `authoritative sources disagree: ${describe(successes[0]!.e)} shows success, ${describe(failure)} shows "${proofObservation(failure, exp)?.status}"`], observedDebit };
  }
  if (successes.length) {
    const debits = new Set(successes.map((s) => s.o.debit?.minor ?? 0));
    if (debits.size > 1) return { status: "disputed", next: null, findings: [...findings, "proofs show different amounts charged"], observedDebit };
    const best = [...successes].sort((a, b) => SOURCE_STRENGTH.indexOf(a.e.source as EvidenceSource) - SOURCE_STRENGTH.indexOf(b.e.source as EvidenceSource))[0]!;
    return { status: "verified", next: null, findings, basis: best.e.source as EvidenceSource, observation: best.o, settled: best.o.debit, observedDebit };
  }
  if (failure) {
    return { status: "failed", next: null, findings: [...findings, `${describe(failure)} shows "${proofObservation(failure, exp)?.status}"`] };
  }
  findings.push(...missing);

  // 2. No conclusive proof yet: go by what happened to the submissions.
  const last = attempts.at(-1);
  if (!last) {
    return { status: "planned", next: p.expired ? null : "submit", findings };
  }
  const left = attempts.length < spec.maxAttempts;
  const lookupNext: NextStep = last.connector.lookup ? "lookup" : null;
  const notFoundAfter = evidence.some((e) => e.valid && e.source === "provider_record" && e.notFound?.definitive && e.seq > last.seq);
  const claim = last.connector.kind === "agent";

  let v: PhaseVerdict;
  if (pending || unrecognized) {
    if (unrecognized) findings.push(`provider reports unrecognized status "${unrecognized}"`);
    else if (lastPending) findings.push(`provider reports "${lastPending}"; awaiting confirmation`);
    v = { status: unrecognized && !pending ? "unknown" : "pending", next: lookupNext, findings };
  } else if (notFoundAfter && (!last.result || last.result.outcome === "ambiguous" || claim)) {
    // The provider guarantees it has no record: the request never executed, so it is safe to send again.
    findings.push("provider has no record of the request");
    v = left ? { status: "planned", next: "retry_same_key", findings } : { status: "failed", next: null, findings: [...findings, "no attempts left"] };
  } else if (!last.result) {
    v = { status: "submitting", next: null, findings };
  } else if (last.result.outcome === "accepted") {
    v = { status: "pending", next: lookupNext, findings: [...findings, claim ? "agent reports the request was accepted" : "provider accepted the request; awaiting confirmation"] };
  } else if (claim) {
    // An agent's account of a refusal is a claim too: it can't release budget or justify a retry.
    findings.push(`agent reports ${last.result.outcome.replace("_", " ")}: ${last.result.reason}`);
    v = { status: "unknown", next: lookupNext, findings };
  } else if (last.result.outcome === "rejected") {
    v = { status: "rejected", next: null, findings: [...findings, `provider rejected the request: ${last.result.reason}`] };
  } else if (last.result.outcome === "not_executed") {
    findings.push(`not executed: ${last.result.reason}`);
    v = last.result.retryable && left ? { status: "planned", next: "retry_new_key", findings } : { status: "failed", next: null, findings: [...findings, left ? "not retryable" : "no attempts left"] };
  } else {
    findings.push(`outcome uncertain: ${last.result.reason}`);
    if (last.connector.lookup) v = { status: "unknown", next: "lookup", findings };
    else if (last.connector.idempotent && left) v = { status: "unknown", next: "retry_same_key", findings };
    else {
      findings.push(last.connector.idempotent ? "no attempts left" : "provider offers no idempotency or status lookup, so it was not retried");
      v = { status: "unknown", next: null, findings };
    }
  }
  if (p.expired && (v.status === "pending" || v.status === "submitting" || v.status === "unknown")) {
    v = { ...v, status: "unknown", next: v.next === "lookup" ? "lookup" : null, findings: [...v.findings, `not confirmed by the deadline (${spec.deadline})`] };
  }
  if (p.expired && v.status === "planned") v = { ...v, next: null };
  return { ...v, observedDebit };
}

function describe(e: EvidenceEntry) {
  if (e.source === "signed_receipt") return "a signed receipt";
  if (e.source === "human_attestation") return "a human attestation";
  return e.via === "lookup" ? "the provider's records" : "the provider's response";
}
