import { formatMoney, type Money } from "./money.ts";
import { replayWith, type StoredEvent } from "./transaction.ts";

const when = (at: string) => `${at.slice(0, 10)} ${at.slice(11, 19)}Z`;
const cap = (t: string, n = 90) => (t.length > n ? `${t.slice(0, n - 1)}…` : t);
const money = (m?: Money) => (m ? ` ${formatMoney(m)}` : "");

/**
 * One plain sentence per log entry, for people who need to read what happened without parsing JSON or trusting a
 * summary. Built by replaying the log, so each line reflects the verified state at that point (who signed, whether
 * evidence counted as proof). Anything the contract's rules rejected would stop the replay with an error, not a line.
 */
export function renderLog(events: readonly StoredEvent[]): string[] {
  const lines: string[] = [];
  replayWith(events, (e, s) => {
    const b = e.body;
    let text: string;
    switch (b.type) {
      case "contract.registered": {
        const c = b.contract;
        text = `Contract registered: "${cap(c.goal)}" (${c.operations.length} operation${c.operations.length === 1 ? "" : "s"}${c.constraints.budget ? `, shared budget${money(c.constraints.budget)}` : ""})`;
        break;
      }
      case "contract.approved": text = "The principal approved the contract."; break;
      case "contract.revoked": text = `The ${s.revoked?.by} revoked the contract${s.revoked?.reason ? `: ${s.revoked.reason}` : ""}. Nothing new will be sent.`; break;
      case "contract.suspended": {
        const a = b.suspension.payload.agent;
        const rec = a === undefined ? s.suspended.all : s.suspended.agents[a];
        text = `${a === undefined ? "The whole transaction" : `Agent ${a}`} was suspended by the ${rec?.by}${rec?.reason ? ` (${rec.reason})` : ""}.`;
        break;
      }
      case "contract.resumed": text = `${b.resumption.payload.agent === undefined ? "The transaction" : `Agent ${b.resumption.payload.agent}`} was resumed.`; break;
      case "contract.expired": text = "The contract expired."; break;
      case "operation.step_up": text = `The principal approved ${b.approval.payload.operationId}${money(b.approval.payload.amount)} (that exact request).`; break;
      case "operation.endorsed": {
        const q = b.endorsement.payload;
        const vendor = s.contract.participants.find((p) => p.id === q.agent)?.vendor;
        text = `${q.agent}${vendor ? ` (${vendor})` : ""} ${q.verdict === "concur" ? "concurred with" : "OBJECTED to"} ${q.operationId}${money(q.amount)}${q.reason ? `: ${q.reason}` : ""}.`;
        break;
      }
      case "operation.refused": {
        const denied = b.policy?.filter((d) => d.effect === "deny").map((d) => d.policy);
        text = `REFUSED: ${b.agent} → ${b.operationId} (${b.phase}): ${b.reason}${b.kind === "violation" ? " [violation]" : ""}${denied?.length ? ` [policy: ${denied.join(", ")}]` : ""}`;
        break;
      }
      case "operation.submitting": {
        const op = s.ops[b.operationId]!;
        const policy = b.policy?.length ? `; ${b.policy.length} polic${b.policy.length === 1 ? "y" : "ies"} allowed it` : "";
        text = `${b.agent} had ${op.spec.provider} ${b.phase === "execute" ? op.spec.action : op.spec.compensation?.action} for ${b.operationId}${money(b.amount)} (attempt ${b.attempt}, key ${b.idempotencyKey.slice(0, 10)}…)${policy}. Authorized and recorded before sending.`;
        break;
      }
      case "operation.result": {
        const r = b.result;
        const provider = s.ops[b.operationId]!.spec.provider;
        const what = r.outcome === "accepted" ? `accepted${r.providerRef ? ` (ref ${r.providerRef})` : ""}`
          : r.outcome === "rejected" ? `rejected: ${r.reason}`
          : r.outcome === "not_executed" ? `did not execute it: ${r.reason}${r.retryable ? " (retryable)" : ""}`
          : `UNCERTAIN, may or may not have happened: ${r.reason}`;
        text = `${provider} answered ${b.operationId} attempt ${b.attempt}: ${what}.`;
        break;
      }
      case "operation.expired": text = `${b.operationId} reached its deadline without being confirmed.`; break;
      case "evidence.recorded": {
        const ev = s.ops[b.operationId]![b.phase].evidence.at(-1)!;
        const status = ev.observation?.status ?? ev.receipt?.payload.observation.status ?? ev.attestation?.payload.outcome;
        const mark = !ev.valid ? ` [ignored: ${ev.problem}]` : ev.proof ? " [counts as proof]" : ev.source === "agent_claim" ? " [claim, not evidence]" : "";
        const what = ev.source === "signed_receipt" ? `Signed receipt from the provider: ${b.operationId} is "${status}"`
          : ev.source === "provider_record" ? (ev.notFound ? `Provider's records (${ev.via}) have no record of ${b.operationId}${ev.notFound.definitive ? " (definitively)" : ""}` : `Provider's records (${ev.via}): ${b.operationId} is "${status}"`)
          : ev.source === "human_attestation" ? `A person attested ${b.operationId}: ${status}${ev.attestation?.payload.note ? ` (${ev.attestation.payload.note})` : ""}`
          : `${ev.agent ?? "An agent"} reported ${b.operationId} is "${status}"`;
        text = what + mark;
        break;
      }
      case "incident.reported": {
        const i = b.incident.payload;
        text = `INCIDENT (${i.severity}, ${i.category}) reported by the ${s.incidents.at(-1)?.by}: ${i.summary}`;
        break;
      }
    }
    lines.push(`#${String(e.seq).padStart(3, "0")} ${when(e.at)}  ${text}`);
  });
  return lines;
}
