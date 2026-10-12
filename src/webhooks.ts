import { createHmac, timingSafeEqual } from "node:crypto";
import type { IntentEvent } from "./intents.ts";

/** `t=<unix seconds>,v1=<hex hmac-sha256 of "<t>.<body>">`, the same scheme webhook consumers already know. */
export function signWebhook(body: string, secret: string, t = Math.floor(Date.now() / 1000)): string {
  return `t=${t},v1=${createHmac("sha256", secret).update(`${t}.${body}`).digest("hex")}`;
}

/** For receivers: checks the signature in constant time and rejects old timestamps (replays). Pass the raw request body. */
export function verifyWebhook(
  body: string, header: string | null | undefined, secret: string, o: { toleranceSeconds?: number; now?: () => number } = {},
): { ok: boolean; reason?: string } {
  const parts = Object.fromEntries((header ?? "").split(",").map((p) => p.trim().split("=", 2) as [string, string]));
  const t = Number(parts.t);
  if (!Number.isInteger(t) || !parts.v1) return { ok: false, reason: "malformed signature header" };
  const now = o.now?.() ?? Math.floor(Date.now() / 1000);
  if (Math.abs(now - t) > (o.toleranceSeconds ?? 300)) return { ok: false, reason: "timestamp outside the tolerance window" };
  const expected = Buffer.from(signWebhook(body, secret, t).split("v1=")[1]!, "hex");
  const given = Buffer.from(parts.v1, "hex");
  return given.length === expected.length && timingSafeEqual(given, expected) ? { ok: true } : { ok: false, reason: "signature does not match" };
}

export interface WebhookEndpoint {
  url: string;
  /** Shared with the receiver; used to sign each delivery. */
  secret: string;
  /** Only deliver these event types (default: all). Entries ending in ".*" match by prefix, e.g. "outcome_intent.step.*". */
  types?: string[];
}

/**
 * Delivers events as signed POSTs. Use it with `intents.subscribe(...)`. A non-2xx answer, a timeout or a network
 * error throws, which makes the intent keep that event pending and try again on its next change (or `flush`):
 * delivery is at-least-once, and `event.id` is stable so receivers can deduplicate.
 */
export function webhookSink(o: { endpoints: WebhookEndpoint[]; fetch?: typeof fetch; timeoutMs?: number; now?: () => number }) {
  const matches = (types: string[] | undefined, type: string) => !types || types.some((t) => (t.endsWith(".*") ? type.startsWith(t.slice(0, -1)) : t === type));
  return async (event: IntentEvent): Promise<void> => {
    const body = JSON.stringify(event);
    const failures: string[] = [];
    await Promise.all(o.endpoints.filter((e) => matches(e.types, event.type)).map(async (e) => {
      try {
        const res = await (o.fetch ?? fetch)(e.url, {
          method: "POST",
          headers: { "content-type": "application/json", "agentmesh-signature": signWebhook(body, e.secret, o.now?.()) },
          body,
          signal: AbortSignal.timeout(o.timeoutMs ?? 5000),
        });
        if (!res.ok) failures.push(`${e.url} answered ${res.status}`);
      } catch (err) {
        failures.push(`${e.url}: ${(err as Error).message}`);
      }
    }));
    if (failures.length) throw new Error(`webhook delivery failed: ${failures.join("; ")}`);
  };
}
