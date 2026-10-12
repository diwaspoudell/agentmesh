import type { EvidenceSource, OutcomeContract } from "./contract.ts";
import type { Money } from "./money.ts";
import { buildReport } from "./report.ts";
import { outcome, replayWith, type OperationStatus, type StoredEvent, type TransactionState } from "./transaction.ts";

// The developer-facing shape: one object per business outcome, with one status you can switch on. Everything here is
// derived from the verified log, so it can't disagree with the evidence behind it.

/**
 * - requires_approval: the principal hasn't signed the contract.
 * - processing: agents are working, or the system is waiting for a provider's confirmation. Nothing needs you.
 * - requires_action: a person has to do something (see `next_actions`): approve a step, resume a suspension, review an unknown or disputed result.
 * - succeeded: every required step is verified (an optional step that failed is visible in `steps`).
 * - partially_succeeded: something is verified but a required step never happened and nobody needs to act, e.g. the intent was cancelled midway.
 * - failed: nothing required was achieved and nobody needs to act, e.g. after the principal waived a step that couldn't be done.
 * - canceled: revoked or never approved, with nothing verified.
 */
export type IntentStatus = "requires_approval" | "processing" | "requires_action" | "succeeded" | "partially_succeeded" | "failed" | "canceled";

/** waiting: not started or blocked. processing: sent, awaiting confirmation. unknown: may have happened, can't confirm. undone: reversed by its pre-approved compensation. */
export type StepStatus = "waiting" | "processing" | "succeeded" | "failed" | "unknown" | "disputed" | "canceled" | "undone";

/** What a person needs to do. Reflects each agent's most recent attempt: after you act, it clears until the agent tries again. */
export interface NextAction {
  type: "approve_intent" | "step_up" | "cross_check" | "review" | "resume";
  step?: string;
  agent?: string;
  reason: string;
}

export interface IntentStep {
  id: string;
  provider: string;
  action: string;
  description?: string;
  required: boolean;
  status: StepStatus;
  /** What the "succeeded" rests on: "signed_receipt" can be checked by anyone; "provider_record" relies on the coordinator; "human_attestation" on a person. */
  verified_by?: EvidenceSource;
  /** The provider's own reference (booking number, order id). */
  reference?: string;
  charged?: Money;
  refunded?: Money;
  effective_at?: string;
  attempts: number;
  waiting_on?: string;
  /** Why it isn't succeeded, in a sentence. */
  message?: string;
}

export interface OutcomeIntentView {
  id: string;
  object: "outcome_intent";
  status: IntentStatus;
  goal: string;
  created: string;
  expires: string;
  /** "3 of 4 confirmed · 1 unknown" */
  summary: string;
  steps: IntentStep[];
  amount?: { budget: Money; spent: Money; held: Money; available: Money };
  next_actions: NextAction[];
  suspended: { scope: string; by: string; reason?: string }[];
  incidents: number;
  evidence: { events: number; head: string; digest: string };
}

/** The intent plus the contract the principal signs (`approveContract(intent.contract, signer)`). */
export interface OutcomeIntent extends OutcomeIntentView { contract: OutcomeContract }

const STEP: Record<OperationStatus, StepStatus> = {
  planned: "waiting", submitting: "processing", pending_verification: "processing", compensating: "processing", verified: "succeeded", rejected: "failed",
  failed: "failed", unknown: "unknown", disputed: "disputed", cancelled: "canceled", waived: "canceled", compensated: "undone",
};

export function nextActions(s: TransactionState): NextAction[] {
  const out: NextAction[] = [];
  if (!s.approvedAt && !s.revoked) out.push({ type: "approve_intent", reason: "the principal has not approved the contract" });
  if (s.suspended.all) out.push({ type: "resume", reason: `the transaction is suspended by the ${s.suspended.all.by}${s.suspended.all.reason ? ` (${s.suspended.all.reason})` : ""}` });
  for (const [agent, x] of Object.entries(s.suspended.agents)) out.push({ type: "resume", agent, reason: `${agent} is suspended by the ${x.by}${x.reason ? ` (${x.reason})` : ""}` });
  for (const id of s.order) {
    const op = s.ops[id]!;
    if (op.escalation) out.push({ type: "review", step: id, reason: op.escalation });
    const last = op.refusals.at(-1);
    if (!last || op.status !== "planned" || s.revoked) continue;
    if (last.reason.startsWith("needs the principal's approval") && last.seq > (op.lastStepUpSeq ?? 0)) out.push({ type: "step_up", step: id, agent: last.agent, reason: last.reason });
    if (/^needs \d+ independent cross-check/.test(last.reason) && last.seq > (op.lastEndorsedSeq ?? 0)) out.push({ type: "cross_check", step: id, agent: last.agent, reason: last.reason });
  }
  return out;
}

export function intentView(s: TransactionState): OutcomeIntentView {
  const report = buildReport(s);
  const o = outcome(s);
  const actions = nextActions(s);
  const ops = s.order.map((id) => s.ops[id]!);
  const inFlight = ops.some((op) => ["submitting", "pending_verification", "compensating"].includes(op.status));

  let status: IntentStatus;
  if (!s.approvedAt) status = s.revoked ? "canceled" : "requires_approval";
  else if (o.status === "disputed" || o.status === "requires_human_review") status = "requires_action";
  else if (!inFlight && o.status === "in_progress" && actions.some((a) => a.type === "resume" || a.type === "step_up" || a.type === "cross_check")) status = "requires_action";
  else if (o.status === "completed") status = "succeeded";
  else if (o.status === "partially_completed") status = "partially_succeeded";
  else if (o.status === "undone") status = "canceled"; // everything required was unwound or waived: nothing stands
  else if (o.status === "failed") status = s.revoked ? "canceled" : "failed";
  else status = "processing"; // in_progress, pending_verification, or an unknown outcome the coordinator is still resolving on its own

  const steps: IntentStep[] = report.operations.map((line) => {
    const done = line.status === "verified" || line.status === "compensated" || line.status === "compensating";
    return {
      id: line.id, provider: line.provider, action: line.action, description: line.description, required: line.required, status: STEP[line.status],
      verified_by: done ? line.basis : undefined, reference: line.providerRef, charged: line.spent && line.spent.minor > 0 ? line.spent : undefined,
      refunded: line.credits[0], effective_at: line.effectiveAt, attempts: line.attempts, waiting_on: line.waitingOn,
      message: line.status === "verified" ? undefined : line.escalation ?? line.waitingOn ?? line.findings.at(-1),
    };
  });

  return {
    id: s.id, object: "outcome_intent", status, goal: s.contract.goal, created: s.contract.createdAt, expires: s.contract.expiresAt, summary: report.headline, steps,
    amount: report.budget && { budget: report.budget.limit, spent: report.budget.spent, held: report.budget.held, available: report.budget.available },
    next_actions: actions, suspended: report.suspensions.map(({ scope, by, reason }) => ({ scope, by, reason })), incidents: s.incidents.length,
    evidence: { events: s.seq, head: s.head, digest: s.digest },
  };
}

// ── Events ─────────────────────────────────────────────────────────────────────

export type IntentEventType =
  | "outcome_intent.created" | `outcome_intent.${IntentStatus}` | `outcome_intent.step.${StepStatus}`
  | "outcome_intent.refused" | "outcome_intent.suspended" | "outcome_intent.resumed" | "outcome_intent.incident";

export interface IntentEvent {
  /** Stable: the same log entry always yields the same id, so receivers can deduplicate redeliveries. */
  id: string;
  object: "event";
  type: IntentEventType;
  created: string;
  intent: string;
  /** Position of the log entry this came from. */
  seq: number;
  data: { object: OutcomeIntentView; step?: IntentStep; previous_status?: IntentStatus; reason?: string; agent?: string };
}

/**
 * The events a log implies: created, status changes, step changes, refusals, suspensions and incidents. Pure and
 * deterministic, so polling, in-process subscribers and webhooks all see the same stream.
 */
export function intentEvents(events: readonly StoredEvent[]): IntentEvent[] {
  const out: IntentEvent[] = [];
  let prev: OutcomeIntentView | undefined;
  replayWith(events, (e, s) => {
    const view = intentView(s);
    let n = 0;
    const emit = (type: IntentEventType, extra: Partial<IntentEvent["data"]> = {}) =>
      out.push({ id: `evt_${e.hash.slice(7, 23)}_${n++}`, object: "event", type, created: e.at, intent: s.id, seq: e.seq, data: { object: view, ...extra } });
    if (!prev) emit("outcome_intent.created");
    const b = e.body;
    if (b.type === "operation.refused") emit("outcome_intent.refused", { step: view.steps.find((x) => x.id === b.operationId), reason: b.reason, agent: b.agent });
    if (b.type === "contract.suspended") emit("outcome_intent.suspended", { agent: b.suspension.payload.agent, reason: b.suspension.payload.reason });
    if (b.type === "contract.resumed") emit("outcome_intent.resumed", { agent: b.resumption.payload.agent });
    if (b.type === "incident.reported") emit("outcome_intent.incident", { reason: b.incident.payload.summary });
    for (const step of view.steps) {
      const before = prev?.steps.find((x) => x.id === step.id);
      if (before && before.status !== step.status) emit(`outcome_intent.step.${step.status}`, { step });
    }
    if (prev && prev.status !== view.status) emit(`outcome_intent.${view.status}`, { previous_status: prev.status });
    prev = view;
  });
  return out;
}
