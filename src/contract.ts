import { z } from "zod";
import { canonicalize, digest, randomId } from "./canonical.ts";

const Id = z.string().regex(/^[A-Za-z0-9][A-Za-z0-9._:@-]{0,127}$/, "ids are 1-128 chars of letters, digits and ._:@-");
const Timestamp = z.iso.datetime({ offset: true });
export const MoneySchema = z.strictObject({
  currency: z.string().regex(/^[A-Z]{3}$/),
  minor: z.number().int().min(0).max(Number.MAX_SAFE_INTEGER),
});
export const PublicKeySchema = z.strictObject({ kty: z.literal("OKP"), crv: z.literal("Ed25519"), x: z.string().min(1), kid: z.string().min(1) });
const Party = z.strictObject({ id: Id, keys: z.array(PublicKeySchema).min(1) });
const JsonRecord = z.record(z.string(), z.json());

/**
 * Where proof of an outcome may come from. Agent claims are deliberately not on the list:
 * an agent saying something happened is recorded, but never counts as evidence that it did.
 */
export const EvidenceSourceSchema = z.enum([
  "signed_receipt", //   signed by a key the contract lists for that provider; anyone can verify it later
  "provider_record", //  read from the provider's system of record by a trusted connector (API response or status lookup)
  "human_attestation", // signed by the principal or a reviewer the contract lists
]);

export const FieldCheckSchema = z.strictObject({
  /** Dotted path into the provider's observation, e.g. "effectiveAt" or "details.orderId". */
  path: z.string().min(1),
  op: z.enum(["eq", "ne", "in", "lt", "lte", "gt", "gte", "exists"]),
  value: z.json().optional(),
  /** Compare against a field of another operation's verified observation instead of a literal. */
  ref: z.strictObject({ operation: Id, path: z.string().min(1) }).optional(),
});

export const ExpectationSchema = z.strictObject({
  /** Provider statuses meaning the expected outcome happened, e.g. ["cancelled"]. */
  success: z.array(z.string().min(1)).min(1),
  /** Statuses meaning it is still in progress. */
  pending: z.array(z.string().min(1)).default([]),
  /** Statuses meaning it definitively did not happen. */
  failure: z.array(z.string().min(1)).default([]),
  /** Money expected back (a refund). Spending is governed by the operation's `spend`. */
  credit: z.strictObject({ min: MoneySchema.optional(), max: MoneySchema.optional() }).optional(),
  checks: z.array(FieldCheckSchema).default([]),
});

export const OperationSchema = z.strictObject({
  id: Id,
  /** The participant (role "provider") that performs it. */
  provider: Id,
  action: z.string().min(1).max(200),
  description: z.string().max(500).optional(),
  /** The approved terms, passed to the provider verbatim. */
  params: JsonRecord.default({}),
  /** Agents (role "agent") allowed to trigger it. */
  executors: z.array(Id).min(1),
  required: z.boolean().default(true),
  /** Operations that must be verified before this one may be submitted. */
  dependsOn: z.array(Id).default([]),
  /** The most this operation may charge. Reserved from the shared budget before submission. Absent = may not charge anything. */
  spend: MoneySchema.optional(),
  /** Always ask the principal to confirm the concrete request, whatever the amount. */
  requiresApproval: z.boolean().default(false),
  /** Must be verified by then; after it, a pending operation is reported as unknown. */
  deadline: Timestamp.optional(),
  expect: ExpectationSchema,
  evidence: z.array(EvidenceSourceSchema).min(1).default(["signed_receipt", "provider_record", "human_attestation"]),
  maxAttempts: z.number().int().min(1).max(10).default(3),
  /** A pre-approved way to undo it, used only when the contract's policy says to unwind. */
  compensation: z.strictObject({ action: z.string().min(1).max(200), params: JsonRecord.default({}), expect: ExpectationSchema }).optional(),
  /**
   * A second opinion before the request is sent: other agents (not the executor) must sign that they reviewed the
   * concrete amount and details and concur. With `distinctVendors`, each must come from a different vendor than the
   * executor and than each other, so one model family never both proposes and approves an important action.
   */
  crossCheck: z.strictObject({ min: z.number().int().min(1).max(5), distinctVendors: z.boolean().default(true) }).optional(),
  /** Random; keeps this operation's commitment from revealing its contents to other parties. */
  salt: z.string().min(16).default(() => randomId()),
});

export const ParticipantSchema = z.strictObject({
  id: Id,
  /**
   * agent: acts for the principal. provider: performs operations. reviewer: signs attestations about outcomes.
   * controller: an emergency-stop key that can suspend or revoke but never approve anything.
   * auditor: an independent witness; the contract names it so verifiers know who to ask.
   */
  role: z.enum(["agent", "provider", "reviewer", "controller", "auditor"]),
  name: z.string().max(200).optional(),
  /** Who supplies the model behind an agent. Cross-checks use it to require independent vendors. */
  vendor: z.string().min(1).max(100).optional(),
  /** Providers: keys that sign receipts. Reviewers: attestations. Controllers: suspensions. Auditors: witness statements. Agents: endorsements. */
  keys: z.array(PublicKeySchema).default([]),
});

export const ContractSchema = z.strictObject({
  type: z.literal("agentmesh.outcome-contract").default("agentmesh.outcome-contract"),
  version: z.literal(0).default(0),
  /** Also the transaction id: one contract, one transaction. */
  id: Id.default(() => randomId("oc")),
  createdAt: Timestamp.default(() => new Date().toISOString()),
  /** No submissions after this. */
  expiresAt: Timestamp,
  /** The user's request, for the record. */
  goal: z.string().min(1).max(4000),
  /** Who the agents act for; their keys sign approvals, step-ups and revocations. */
  principal: Party,
  /** The AgentMesh service that enforces the contract; its keys sign execution authorizations and log checkpoints. */
  coordinator: Party,
  participants: z.array(ParticipantSchema).default([]),
  constraints: z.strictObject({
    /** Shared across every operation: reserved + spent can never exceed it. */
    budget: MoneySchema.optional(),
    /** A request above this needs the principal's step-up approval. */
    approvalAbove: MoneySchema.optional(),
  }).prefault({}),
  policy: z.strictObject({
    /** What to do with completed operations when a required one can't be achieved. */
    onRequiredFailure: z.enum(["keep_completed", "compensate_completed"]).default("keep_completed"),
    /**
     * Automatically suspend an agent that makes this many requests the contract forbids (not the ones that merely
     * have to wait) within the window. Only a principal or controller can lift it. The log shows why it tripped.
     */
    circuitBreaker: z.strictObject({ violations: z.number().int().min(1).max(100), windowSeconds: z.number().int().min(1).max(86_400) }).optional(),
  }).prefault({}),
  operations: z.array(OperationSchema).min(1).max(200),
  salt: z.string().min(16).default(() => randomId()),
});

export type OutcomeContract = z.output<typeof ContractSchema>;
export type ContractInput = z.input<typeof ContractSchema>;
export type OperationSpec = z.output<typeof OperationSchema>;
export type Expectation = z.output<typeof ExpectationSchema>;
export type FieldCheck = z.output<typeof FieldCheckSchema>;
export type EvidenceSource = z.output<typeof EvidenceSourceSchema>;
export type Participant = z.output<typeof ParticipantSchema>;

export class ContractError extends Error {
  readonly problems: string[];
  constructor(problems: string[]) {
    super(`Invalid outcome contract: ${problems.join("; ")}`);
    this.problems = problems;
  }
}

/** Builds a normalized contract: fills defaults (ids, salts, timestamps) and checks it makes sense as a whole. */
export function defineContract(input: ContractInput): OutcomeContract {
  const r = ContractSchema.safeParse(input);
  if (!r.success) throw new ContractError(r.error.issues.map((i) => `${i.path.join(".") || "(root)"}: ${i.message}`));
  const problems = contractProblems(r.data);
  if (problems.length) throw new ContractError(problems);
  return r.data;
}

/**
 * Accepts a contract received from someone else. It must already be normalized (every default explicit),
 * because the approval signs exactly these bytes: filling a default here would change the digest.
 */
export function parseContract(json: unknown): OutcomeContract {
  const c = defineContract(json as ContractInput);
  if (canonicalize(c) !== canonicalize(json)) throw new ContractError(["contract is not in normalized form (defaults must be explicit)"]);
  return c;
}

export function contractProblems(c: OutcomeContract): string[] {
  const out: string[] = [];
  const parts = new Map(c.participants.map((p) => [p.id, p]));
  if (parts.size !== c.participants.length) out.push("participant ids must be unique");
  const ops = new Map(c.operations.map((o) => [o.id, o]));
  if (ops.size !== c.operations.length) out.push("operation ids must be unique");
  if (Date.parse(c.expiresAt) <= Date.parse(c.createdAt)) out.push("expiresAt must be after createdAt");
  const budget = c.constraints.budget;
  const currency = budget?.currency ?? c.operations.find((o) => o.spend)?.spend?.currency;
  if (c.constraints.approvalAbove && currency && c.constraints.approvalAbove.currency !== currency) out.push("approvalAbove must use the budget currency");
  for (const p of c.participants) {
    if ((p.role === "reviewer" || p.role === "controller" || p.role === "auditor") && !p.keys.length) out.push(`${p.role} ${p.id} needs a key`);
  }
  // Separation of duties: one key may hold only one role, and ids can't be shared across roles. Otherwise the party
  // that enforces the contract could also approve it, vouch for its results, or play the provider.
  const ids = [c.principal.id, c.coordinator.id, ...c.participants.map((p) => p.id)];
  if (new Set(ids).size !== ids.length) out.push("principal, coordinator and participant ids must all be different");
  const holders = new Map<string, string>();
  const groups: [string, readonly { kid: string }[]][] = [
    ["the principal", c.principal.keys], ["the coordinator", c.coordinator.keys],
    ...c.participants.map((p): [string, readonly { kid: string }[]] => [`${p.role} ${p.id}`, p.keys]),
  ];
  for (const [who, keys] of groups) {
    for (const k of keys) {
      const other = holders.get(k.kid);
      if (other && other !== who) out.push(`key ${k.kid.slice(0, 8)} is used by both ${other} and ${who}; one key may hold only one role`);
      holders.set(k.kid, who);
    }
  }
  const breaker = c.policy.circuitBreaker;
  if (breaker && !c.operations.some((o) => o.executors.length)) out.push("circuitBreaker needs at least one executor");
  for (const o of c.operations) {
    const at = `operation ${o.id}`;
    const prov = parts.get(o.provider);
    if (prov?.role !== "provider") out.push(`${at}: provider ${o.provider} is not a participant with role "provider"`);
    for (const e of o.executors) if (parts.get(e)?.role !== "agent") out.push(`${at}: executor ${e} is not a participant with role "agent"`);
    for (const d of o.dependsOn) {
      if (d === o.id) out.push(`${at}: depends on itself`);
      else if (!ops.has(d)) out.push(`${at}: depends on unknown operation ${d}`);
    }
    if (o.spend) {
      if (currency && o.spend.currency !== currency) out.push(`${at}: spend must use ${currency}`);
      if (budget && o.spend.minor > budget.minor) out.push(`${at}: spend exceeds the whole budget`);
    }
    if (o.deadline && Date.parse(o.deadline) > Date.parse(c.expiresAt)) out.push(`${at}: deadline is after the contract expires`);
    if (o.crossCheck) {
      const executorVendors = new Set(o.executors.map((e) => parts.get(e)?.vendor));
      const eligible = c.participants.filter((p) => p.role === "agent" && p.keys.length && !o.executors.includes(p.id) && (!o.crossCheck!.distinctVendors || (p.vendor && !executorVendors.has(p.vendor))));
      const capacity = o.crossCheck.distinctVendors ? new Set(eligible.map((p) => p.vendor)).size : eligible.length;
      if (capacity < o.crossCheck.min) out.push(`${at}: crossCheck needs ${o.crossCheck.min} ${o.crossCheck.distinctVendors ? "independent-vendor " : ""}agents with keys besides its executors, but only ${capacity} qualify`);
      if (o.crossCheck.distinctVendors && o.executors.some((e) => !parts.get(e)?.vendor)) out.push(`${at}: with distinctVendors every executor needs a vendor`);
    }
    if (o.evidence.length === 1 && o.evidence[0] === "signed_receipt" && !prov?.keys.length) out.push(`${at}: only signed receipts are accepted but ${o.provider} has no keys`);
    for (const [label, exp] of [["expect", o.expect], ["compensation.expect", o.compensation?.expect]] as const) {
      if (!exp) continue;
      const all = [...exp.success, ...exp.pending, ...exp.failure];
      if (new Set(all).size !== all.length) out.push(`${at}: ${label} status lists overlap`);
      for (const ch of exp.checks) {
        if (ch.ref && !(ch.ref.operation !== o.id && o.dependsOn.includes(ch.ref.operation))) out.push(`${at}: check on ${ch.path} may only reference an operation it depends on`);
        if (ch.op !== "exists" && ch.value === undefined && !ch.ref) out.push(`${at}: check on ${ch.path} needs a value or ref`);
      }
    }
  }
  // Dependencies must form a DAG.
  const state = new Map<string, 1 | 2>();
  const visit = (id: string, path: string[]): void => {
    if (state.get(id) === 2) return;
    if (state.get(id) === 1) { out.push(`dependency cycle: ${[...path, id].join(" -> ")}`); return; }
    state.set(id, 1);
    for (const d of ops.get(id)?.dependsOn ?? []) if (ops.has(d)) visit(d, [...path, id]);
    state.set(id, 2);
  };
  for (const o of c.operations) visit(o.id, []);
  return out;
}

// ── Commitments ────────────────────────────────────────────────────────────────
// The approval signs a header that commits to every part of the contract by salted hash. A provider receives the
// header plus only its own operation, so it can check that operation was approved without learning the user's goal,
// budget, or what other providers were asked to do.

export interface ContractHeader {
  type: "agentmesh.contract-header";
  version: 0;
  id: string;
  createdAt: string;
  expiresAt: string;
  principal: OutcomeContract["principal"];
  coordinator: OutcomeContract["coordinator"];
  commitments: { goal: string; participants: string; terms: string; operations: string[] };
}

export function operationCommitment(op: OperationSpec) {
  return digest({ type: "agentmesh.operation", operation: op });
}

export function contractHeader(c: OutcomeContract): ContractHeader {
  return {
    type: "agentmesh.contract-header",
    version: c.version,
    id: c.id,
    createdAt: c.createdAt,
    expiresAt: c.expiresAt,
    principal: c.principal,
    coordinator: c.coordinator,
    commitments: {
      goal: digest({ type: "agentmesh.goal", salt: c.salt, goal: c.goal }),
      participants: digest({ type: "agentmesh.participants", salt: c.salt, participants: c.participants }),
      terms: digest({ type: "agentmesh.terms", salt: c.salt, constraints: c.constraints, policy: c.policy }),
      operations: c.operations.map(operationCommitment),
    },
  };
}

/** What the principal signs. */
export function contractDigest(c: OutcomeContract | ContractHeader) {
  return digest(c.type === "agentmesh.contract-header" ? c : contractHeader(c));
}

export function getOperation(c: OutcomeContract, id: string): OperationSpec {
  const op = c.operations.find((o) => o.id === id);
  if (!op) throw new ContractError([`no operation ${id}`]);
  return op;
}
