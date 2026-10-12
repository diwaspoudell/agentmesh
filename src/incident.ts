import { digest } from "./canonical.ts";
import { renderLog } from "./log.ts";
import type { IncidentCategory, IncidentSeverity } from "./statements.ts";
import { replay, type StoredEvent } from "./transaction.ts";

export type Audience = "affected" | "public";

/**
 * What to hand to others after something went wrong. Both versions carry the same lessons (which controls held or
 * failed, what was done, what changed at runtime, how to prevent it); they differ in how much of the transaction shows.
 */
export interface IncidentDisclosure {
  type: "agentmesh.incident-disclosure";
  version: 0;
  audience: Audience;
  /** "affected": the real transaction id. "public": a pseudonym that can't be traced back. */
  transaction: string;
  incident: {
    id: string;
    reportedAt: string;
    reportedBy: string;
    severity: IncidentSeverity;
    category: IncidentCategory;
    summary: string;
    controls: { control: string; held: boolean; detail?: string }[];
    affectedOperations: string[];
    actions: string[];
    runtimeChanges: { description: string; detail?: unknown }[];
    prevention: string[];
  };
  /** "affected": the log lines about the affected operations, plus suspensions and incidents. "public": only the shape of events, with pseudonyms and relative times. */
  timeline: string[];
  /** Lets an affected party match this against the full evidence bundle. Absent in public disclosures. */
  anchor?: { seq: number; hash: string; head: string };
}

/**
 * Builds a disclosure for one incident in a log. The "public" version replaces every identifier the contract knows
 * (agents, providers, operations, the principal, the transaction) with a pseudonym and drops the goal, amounts and
 * evidence details. Free text the incident's author wrote is passed through the same replacement but not otherwise
 * inspected, so authors should write summaries that don't contain personal data.
 */
export function discloseIncident(events: readonly StoredEvent[], incidentId: string, o: { audience: Audience }): IncidentDisclosure {
  const state = replay(events);
  const rec = state.incidents.find((i) => i.report.payload.id === incidentId);
  if (!rec) throw new RangeError(`no incident ${incidentId}`);
  const i = rec.report.payload;
  const idx = events.findIndex((e) => e.body.type === "incident.reported" && e.body.incident.payload.id === incidentId);
  const lines = renderLog(events.slice(0, idx + 1));
  const relevant = events.slice(0, idx + 1).flatMap((e, n) => {
    const b = e.body;
    const ops = "operationId" in b ? [b.operationId] : b.type === "operation.step_up" ? [b.approval.payload.operationId] : [];
    const about = ops.some((id) => i.affectedOperations.includes(id));
    return about || b.type === "contract.suspended" || b.type === "contract.resumed" || b.type === "contract.revoked" || b.type === "incident.reported" ? [n] : [];
  });

  if (o.audience === "affected") {
    return {
      type: "agentmesh.incident-disclosure", version: 0, audience: "affected", transaction: state.id,
      incident: { id: i.id, reportedAt: i.reportedAt, reportedBy: rec.by, severity: i.severity, category: i.category, summary: i.summary, controls: i.controls, affectedOperations: i.affectedOperations, actions: i.actions, runtimeChanges: i.runtimeChanges, prevention: i.prevention },
      timeline: relevant.map((n) => lines[n]!),
      anchor: { seq: events[idx]!.seq, hash: events[idx]!.hash, head: events[idx]!.hash },
    };
  }

  // Pseudonyms, stable within one disclosure.
  const alias = new Map<string, string>();
  const c = state.contract;
  const name = (id: string, prefix: string, n: number) => alias.set(id, `${prefix}-${n}`);
  c.operations.forEach((op, n) => name(op.id, "operation", n + 1));
  const providers = [...new Set(c.operations.map((op) => op.provider))];
  providers.forEach((p, n) => name(p, "provider", n + 1));
  c.participants.filter((p) => p.role === "agent").forEach((p, n) => name(p.id, "agent", n + 1));
  c.participants.filter((p) => p.role === "controller").forEach((p, n) => name(p.id, "controller", n + 1));
  name(c.principal.id, "principal", 1);
  name(c.coordinator.id, "coordinator", 1);
  name(c.id, "transaction", 1);
  const ids = [...alias.keys()].sort((a, b) => b.length - a.length);
  const scrub = (t: string) => ids.reduce((acc, id) => acc.split(id).join(alias.get(id)!), t);
  const scrubDeep = (v: unknown): unknown =>
    typeof v === "string" ? scrub(v) : Array.isArray(v) ? v.map(scrubDeep) : v && typeof v === "object" ? Object.fromEntries(Object.entries(v).map(([k, x]) => [k, scrubDeep(x)])) : v;
  const t0 = Date.parse(events[0]!.at);
  const shape = (e: StoredEvent) => {
    const b = e.body;
    const actor = "agent" in b && typeof b.agent === "string" ? scrub(b.agent) : undefined;
    const op = "operationId" in b ? scrub(b.operationId) : undefined;
    const what = b.type === "operation.refused" ? `${b.kind === "violation" ? "forbidden request" : "request"} refused`
      : b.type === "operation.submitting" ? "request authorized and sent"
      : b.type === "operation.result" ? `provider answered: ${b.result.outcome}`
      : b.type === "evidence.recorded" ? `${b.evidence.source.replace("_", " ")} recorded`
      : b.type.replace(".", " ").replace("_", " ");
    return `+${Math.round((Date.parse(e.at) - t0) / 1000)}s ${[actor, op, what].filter(Boolean).join(": ")}`;
  };
  return {
    type: "agentmesh.incident-disclosure", version: 0, audience: "public",
    transaction: `tx-${digest({ pseudonym: c.id, salt: c.salt }).slice(7, 19)}`,
    incident: {
      id: i.id, reportedAt: i.reportedAt, reportedBy: rec.by, severity: i.severity, category: i.category, summary: scrub(i.summary),
      controls: i.controls.map((x) => ({ ...x, control: scrub(x.control), detail: x.detail && scrub(x.detail) })),
      affectedOperations: i.affectedOperations.map(scrub), actions: i.actions.map(scrub),
      runtimeChanges: i.runtimeChanges.map((x) => ({ description: scrub(x.description), detail: scrubDeep(x.detail) })), prevention: i.prevention.map(scrub),
    },
    timeline: relevant.map((n) => shape(events[n]!)),
  };
}
