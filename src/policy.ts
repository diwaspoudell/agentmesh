import type { JsonObject } from "./canonical.ts";
import type { Money } from "./money.ts";
import type { Phase } from "./statements.ts";

/**
 * What a policy sees about a request. Deliberately excludes the user's goal and free-form contract text:
 * an organization's rules should not need, or be able to leak, what the user asked for.
 */
export interface PolicyContext {
  contractId: string;
  operationId: string;
  phase: Phase;
  provider: string;
  action: string;
  agent: string;
  amount?: Money;
  details?: JsonObject;
  at: string;
}

export interface PolicyDecision { policy: string; effect: "allow" | "deny"; reason?: string }

/**
 * A rule set an organization controls independently of any contract: it can only narrow what a contract allows.
 * Every decision is written into the log with the submission (or refusal) it governed. A gate that throws or
 * times out counts as a denial.
 */
export interface PolicyGate {
  name: string;
  evaluate(ctx: PolicyContext): PolicyDecision | Promise<PolicyDecision>;
}

const decide = (name: string, deny: string | undefined): PolicyDecision => (deny ? { policy: name, effect: "deny", reason: deny } : { policy: name, effect: "allow" });

/** Refuses these actions outright (e.g. "payment.transfer"). Entries ending in "*" match by prefix. */
export function denyActions(actions: string[], name = "deny-actions"): PolicyGate {
  const hit = (a: string) => actions.some((x) => (x.endsWith("*") ? a.startsWith(x.slice(0, -1)) : a === x));
  return { name, evaluate: (c) => decide(name, hit(c.action) ? `action ${c.action} is not permitted` : undefined) };
}

/** Allows only these providers. */
export function allowProviders(providers: string[], name = "allow-providers"): PolicyGate {
  return { name, evaluate: (c) => decide(name, providers.includes(c.provider) ? undefined : `provider ${c.provider} is not on the approved list`) };
}

/** Refuses any single request above a limit, whatever the contract says. */
export function maxAmount(limit: Money, name = "max-amount"): PolicyGate {
  return {
    name,
    evaluate: (c) => decide(name, c.amount && c.amount.minor > 0 && (c.amount.currency !== limit.currency || c.amount.minor > limit.minor) ? "amount is above the organization's limit" : undefined),
  };
}

/** Refuses these agents entirely (e.g. one a security team has pulled from service). */
export function denyAgents(agents: string[], name = "deny-agents"): PolicyGate {
  return { name, evaluate: (c) => decide(name, agents.includes(c.agent) ? `agent ${c.agent} is not permitted` : undefined) };
}

/**
 * Asks an OPA-compatible server (POST {url} with {"input": context}, answering {"result": true | {"allow": bool, "reason"?: string}}).
 * Fails closed: a timeout, a network error or an unreadable answer is a denial.
 */
export function httpPolicy(url: string, o: { name?: string; timeoutMs?: number; fetch?: typeof fetch; headers?: Record<string, string> } = {}): PolicyGate {
  const name = o.name ?? "http-policy";
  return {
    name,
    async evaluate(ctx) {
      try {
        const res = await (o.fetch ?? fetch)(url, {
          method: "POST",
          headers: { "content-type": "application/json", ...o.headers },
          body: JSON.stringify({ input: ctx }),
          signal: AbortSignal.timeout(o.timeoutMs ?? 2000),
        });
        if (!res.ok) return decide(name, `policy service answered ${res.status}`);
        const body = (await res.json()) as { result?: unknown };
        const r = body.result;
        if (r === true) return decide(name, undefined);
        if (r && typeof r === "object" && (r as { allow?: unknown }).allow === true) return decide(name, undefined);
        const reason = r && typeof r === "object" ? (r as { reason?: unknown }).reason : undefined;
        return decide(name, typeof reason === "string" ? reason : "denied by policy");
      } catch (err) {
        return decide(name, `policy service unavailable: ${(err as Error).message}`);
      }
    },
  };
}

/** Evaluates every gate. All must allow; a gate that throws counts as a denial. */
export async function evaluateGates(gates: readonly PolicyGate[], ctx: PolicyContext): Promise<PolicyDecision[]> {
  return Promise.all(gates.map(async (g) => {
    try {
      const d = await g.evaluate(ctx);
      return d.effect === "allow" || d.effect === "deny" ? { policy: g.name, effect: d.effect, reason: d.reason } : { policy: g.name, effect: "deny" as const, reason: "policy returned an invalid decision" };
    } catch (err) {
      return { policy: g.name, effect: "deny" as const, reason: `policy failed: ${(err as Error).message}` };
    }
  }));
}
