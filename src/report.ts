import type { EvidenceSource } from "./contract.ts";
import { formatMoney, type Money } from "./money.ts";
import { budget, outcome, type OperationStatus, type OutcomeStatus, type TransactionState } from "./transaction.ts";

export interface OperationLine {
  id: string;
  provider: string;
  action: string;
  description?: string;
  required: boolean;
  status: OperationStatus;
  /** How it was verified: "signed_receipt" is checkable by anyone; "provider_record" relies on the coordinator; "human_attestation" on a person. */
  basis?: EvidenceSource;
  providerRef?: string;
  spent?: Money;
  credits: Money[];
  effectiveAt?: string;
  attempts: number;
  findings: string[];
  waitingOn?: string;
  escalation?: string;
}

/** A consolidated, plain-data account of the transaction for the user, their agent, or an auditor. */
export interface OutcomeReport {
  transactionId: string;
  goal: string;
  status: OutcomeStatus;
  headline: string;
  counts: Partial<Record<OperationStatus, number>>;
  operations: OperationLine[];
  budget?: { limit: Money; spent: Money; held: Money; available: Money };
  escalations: { operationId: string; reason: string }[];
  refusals: { operationId: string; agent: string; reason: string; at: string }[];
  revoked: boolean;
  /** Active suspensions: the whole transaction ("transaction") and/or individual agents. */
  suspensions: { scope: string; by: string; reason?: string; at: string }[];
  incidents: { id: string; severity: string; category: string; summary: string; reportedBy: string }[];
  /** Which vendors' agents ran the operations. `singleVendor` flags a multi-step outcome that depends on one model family. */
  diversity: { vendors: Record<string, string[]>; singleVendor: boolean; crossChecked: string[] };
  evidence: { events: number; head: string };
}

const LABEL: Record<OperationStatus, string> = {
  planned: "planned", submitting: "submitting", pending_verification: "pending", verified: "confirmed", rejected: "rejected", failed: "failed",
  unknown: "unknown", disputed: "disputed", cancelled: "cancelled", waived: "waived", compensating: "being undone", compensated: "undone",
};
const ORDER: OperationStatus[] = ["verified", "compensated", "pending_verification", "submitting", "planned", "compensating", "rejected", "failed", "unknown", "disputed", "cancelled", "waived"];

export function buildReport(s: TransactionState): OutcomeReport {
  const o = outcome(s);
  const b = budget(s);
  const cur = b?.limit.currency;
  const ops = s.order.map((id) => s.ops[id]!);
  const total = ops.length;
  const vendors: Record<string, string[]> = {};
  for (const op of ops) {
    for (const agent of new Set(op.execute.attempts.map((a) => a.agent))) {
      const v = s.contract.participants.find((p) => p.id === agent)?.vendor;
      if (v) (vendors[v] ??= []).includes(op.id) || vendors[v]!.push(op.id);
    }
  }
  const parts = ORDER.filter((st) => o.counts[st]).map((st) => (st === "verified" ? `${o.counts[st]} of ${total} confirmed` : `${o.counts[st]} ${LABEL[st]}`));
  return {
    transactionId: s.id,
    goal: s.contract.goal,
    status: o.status,
    headline: parts.join(" · "),
    counts: o.counts,
    operations: ops.map((op) => {
      const accepted = [...op.execute.attempts].reverse().find((a) => a.result?.outcome === "accepted")?.result;
      return {
        id: op.id, provider: op.spec.provider, action: op.spec.action, description: op.spec.description, required: op.spec.required, status: op.status,
        basis: op.basis, providerRef: op.observation?.providerRef ?? (accepted?.outcome === "accepted" ? accepted.providerRef : undefined),
        spent: op.spent && cur ? { currency: cur, minor: op.spent } : op.observation?.debit, credits: op.credits, effectiveAt: op.observation?.effectiveAt,
        attempts: op.execute.attempts.length, findings: op.findings, waitingOn: op.status === "planned" ? op.blockedBy : undefined, escalation: op.escalation,
      };
    }),
    budget: b && { limit: b.limit, spent: { currency: cur!, minor: b.spent }, held: { currency: cur!, minor: b.held }, available: { currency: cur!, minor: b.available } },
    escalations: o.escalations,
    refusals: ops.flatMap((op) => op.refusals.map((r) => ({ operationId: op.id, agent: r.agent, reason: r.reason, at: r.at }))),
    revoked: !!s.revoked,
    suspensions: [
      ...(s.suspended.all ? [{ scope: "transaction", by: s.suspended.all.by, reason: s.suspended.all.reason, at: s.suspended.all.at }] : []),
      ...Object.entries(s.suspended.agents).map(([agent, x]) => ({ scope: agent, by: x.by, reason: x.reason, at: x.at })),
    ],
    incidents: s.incidents.map((i) => ({ id: i.report.payload.id, severity: i.report.payload.severity, category: i.report.payload.category, summary: i.report.payload.summary, reportedBy: i.by })),
    diversity: {
      vendors,
      singleVendor: ops.length > 1 && Object.keys(vendors).length === 1 && Object.values(vendors)[0]!.length === ops.filter((o) => o.execute.attempts.length).length && ops.filter((o) => o.execute.attempts.length).length > 1,
      crossChecked: ops.filter((o) => o.spec.crossCheck).map((o) => o.id),
    },
    evidence: { events: s.seq, head: s.head },
  };
}

const ICON: Record<OperationStatus, string> = {
  verified: "✓", compensated: "↺", pending_verification: "…", submitting: "…", planned: "·", compensating: "↺",
  rejected: "✗", failed: "✗", unknown: "?", disputed: "!", cancelled: "–", waived: "–",
};
const BASIS: Record<EvidenceSource, string> = { signed_receipt: "signed receipt", provider_record: "provider records", human_attestation: "human attestation" };

/** Plain-text rendering for terminals and logs. */
export function renderReport(r: OutcomeReport): string {
  const lines = [`${r.goal}`, `Status: ${r.status.replace(/_/g, " ").toUpperCase()} — ${r.headline}`];
  for (const x of r.suspensions) lines.push(`SUSPENDED: ${x.scope === "transaction" ? "the whole transaction" : `agent ${x.scope}`}, by the ${x.by}${x.reason ? ` (${x.reason})` : ""}`);
  lines.push("");
  const w = Math.max(...r.operations.map((o) => o.id.length));
  for (const o of r.operations) {
    let detail: string = LABEL[o.status];
    if (o.basis && (o.status === "verified" || o.status === "compensated" || o.status === "compensating")) detail += ` (${BASIS[o.basis]})`;
    const extra = [o.providerRef && `ref ${o.providerRef}`, o.spent && o.spent.minor > 0 && `charged ${formatMoney(o.spent)}`, ...o.credits.map((c) => `refunded ${formatMoney(c)}`), o.effectiveAt && `effective ${o.effectiveAt.slice(0, 10)}`].filter(Boolean);
    if (extra.length) detail += ` · ${extra.join(" · ")}`;
    lines.push(`  ${ICON[o.status]} ${o.id.padEnd(w)}  ${detail}${o.required ? "" : "  (optional)"}`);
    const why = o.escalation ?? o.waitingOn ?? (o.status === "verified" ? undefined : o.findings.at(-1));
    if (why) lines.push(`    ${" ".repeat(w)}  ${o.escalation ? "needs review: " : ""}${why}`);
    for (const f of o.findings.filter((f) => / reported "/.test(f))) lines.push(`    ${" ".repeat(w)}  note: ${f}`);
  }
  if (r.budget) lines.push("", `Budget: ${formatMoney(r.budget.spent)} spent, ${formatMoney(r.budget.held)} held, ${formatMoney(r.budget.available)} of ${formatMoney(r.budget.limit)} available`);
  const single = r.diversity.singleVendor ? Object.keys(r.diversity.vendors)[0] : undefined;
  if (single) lines.push(`Model diversity: every operation was run by agents from one vendor (${single}); ${r.diversity.crossChecked.length ? `${r.diversity.crossChecked.length} had a cross-check` : "none had a cross-check"}.`);
  for (const i of r.incidents) lines.push(`Incident ${i.id} (${i.severity}, ${i.category}): ${i.summary}`);
  if (r.refusals.length) lines.push(`Refused: ${r.refusals.map((x) => `${x.operationId} by ${x.agent} (${x.reason})`).join("; ")}`);
  lines.push(`Evidence: ${r.evidence.events} log entries, head ${r.evidence.head.slice(0, 19)}…`);
  return lines.join("\n");
}
