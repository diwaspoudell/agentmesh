import { canonicalize, randomId } from "./canonical.ts";
import type { ExecuteRequest, ProviderConnector } from "./coordinator.ts";
import { verifySigned, type PublicKeyJwk } from "./keys.ts";

export interface ConformanceResult { ok: boolean; checks: { name: string; ok: boolean; detail?: string }[] }

/**
 * Checks that a connector keeps the promises the coordinator relies on. Run it against a provider's sandbox:
 * it executes `request()` for real (twice with one key, if the connector claims idempotency).
 */
export async function checkConnector(c: ProviderConnector, o: { request: () => ExecuteRequest; receiptKeys?: PublicKeyJwk[] }): Promise<ConformanceResult> {
  const checks: ConformanceResult["checks"] = [];
  const check = (name: string, ok: boolean, detail?: string) => checks.push({ name, ok, detail: ok ? undefined : detail });
  const req = o.request();

  const first = await c.execute(req).catch((e: Error) => ({ outcome: "threw" as const, reason: e.message }));
  check("execute returns a recognized outcome", ["accepted", "rejected", "not_executed", "unknown"].includes(first.outcome), `got ${first.outcome}`);
  if (first.outcome !== "accepted") {
    check("execute accepted the sample request", false, `${first.outcome}: ${"reason" in first ? first.reason : ""}`);
    return { ok: false, checks };
  }
  if (first.receipt) {
    check("receipt is signed by a declared provider key", !!o.receiptKeys && verifySigned(first.receipt, o.receiptKeys), "signature did not verify");
    const p = first.receipt.payload;
    check("receipt names the request it answers", p.idempotencyKey === req.idempotencyKey && p.operationId === req.operationId && p.contractId === req.contractId && p.phase === req.phase,
      "idempotency key, operation, contract or phase differ");
  }
  if (first.observation?.idempotencyKey) check("response observation carries the request's key", first.observation.idempotencyKey === req.idempotencyKey, "different key");

  if (c.idempotent) {
    const again = await c.execute(req).catch((e: Error) => ({ outcome: "threw" as const, reason: e.message }));
    check("same key, same result (idempotency)", again.outcome === "accepted" && (again as { providerRef?: string }).providerRef === first.providerRef,
      `second call: ${again.outcome} ${(again as { providerRef?: string }).providerRef ?? ""} vs ${first.providerRef ?? ""}`);
  }
  if (c.lookup) {
    const found = await c.lookup({ contractId: req.contractId, operationId: req.operationId, phase: req.phase, idempotencyKey: req.idempotencyKey, providerRef: first.providerRef })
      .catch((e: Error) => ({ found: "threw" as const, detail: e.message }));
    check("lookup finds an executed request by its key", found.found === true, `got ${canonicalize(found)}`);
    if (found.found === true) {
      check("lookup returns the same provider reference", !first.providerRef || !found.observation.providerRef || found.observation.providerRef === first.providerRef, "providerRef differs");
      if (found.receipt && o.receiptKeys) check("lookup receipt verifies", verifySigned(found.receipt, o.receiptKeys), "signature did not verify");
    }
    const missing = await c.lookup({ contractId: req.contractId, operationId: req.operationId, phase: req.phase, idempotencyKey: `am_${randomId("", 24)}` })
      .catch((e: Error) => ({ found: "threw" as const, detail: e.message }));
    check("lookup reports no record for a key it never saw", missing.found === false, `got ${canonicalize(missing)}`);
  }
  return { ok: checks.every((x) => x.ok), checks };
}
