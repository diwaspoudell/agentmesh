import { describe, expect, it } from "vitest";
import { attest, money } from "../src/index.ts";
import { contractFor, openApproved, sandboxProvider, world } from "./helpers.ts";

// Found by the fuzz harness: these stay pinned so they can't come back.
describe("waiving a step does not forgive money the provider may have taken", () => {
  const contractWith = (w: ReturnType<typeof world>) => contractFor(w, {
    goal: "Buy a replacement", participants: [{ id: "agent:a", role: "agent" }, { id: "shop", role: "provider" }], constraints: { budget: money("USD", 200) },
    operations: [{ id: "buy", provider: "shop", action: "order.create", executors: ["agent:a"], spend: money("USD", 150), expect: { success: ["confirmed"] } }],
  });

  it("keeps holding the budget when the outcome was unknown (the charge may have gone through)", async () => {
    const shop = sandboxProvider("shop", { status: "confirmed", modes: ["timeout_after"], idempotent: false, lookup: false });
    const w = world({ shop: shop.connector });
    const c = contractWith(w);
    await openApproved(w, c);
    await w.coordinator.run(c.id, { agent: "agent:a" });
    await w.coordinator.attest(c.id, attest(c, w.user, { operationId: "buy", outcome: "waived" }, w.clock.iso()));
    const report = await w.coordinator.report(c.id);
    expect(report.operations[0]!.status).toBe("waived");
    expect(shop.effects).toHaveLength(1);
    expect(report.budget).toMatchObject({ held: money("USD", 150), available: money("USD", 50) });
  });

  it("counts a charge the provider's own record shows", async () => {
    const shop = sandboxProvider("shop", { status: "confirmed", charge: () => money("USD", 190) });
    const w = world({ shop: shop.connector });
    const c = contractWith(w);
    await openApproved(w, c);
    await w.coordinator.run(c.id, { agent: "agent:a" }); // disputed: charged more than approved
    await w.coordinator.attest(c.id, attest(c, w.user, { operationId: "buy", outcome: "waived" }, w.clock.iso()));
    expect((await w.coordinator.report(c.id)).budget).toMatchObject({ held: money("USD", 190), available: money("USD", 10) });
  });

  it("releases the budget when the provider definitively refused it", async () => {
    const shop = sandboxProvider("shop", { status: "confirmed", modes: ["reject"] });
    const w = world({ shop: shop.connector });
    const c = contractWith(w);
    await openApproved(w, c);
    await w.coordinator.run(c.id, { agent: "agent:a" });
    await w.coordinator.attest(c.id, attest(c, w.user, { operationId: "buy", outcome: "waived" }, w.clock.iso()));
    expect((await w.coordinator.report(c.id)).budget).toMatchObject({ held: money("USD", 0), available: money("USD", 200) });
  });
});
