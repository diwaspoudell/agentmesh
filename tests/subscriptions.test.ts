import { describe, expect, it } from "vitest";
import { attest, generateSigner, renderReport, verifyBundle } from "../src/index.ts";
import { contractFor, DAY, openApproved, sandboxProvider, world } from "./helpers.ts";

// Section 8 of the plan: a personal agent cancels eight subscriptions. Submitting requests is not the same as
// cancelling them; the report must show what actually happened.
describe("cancel 8 subscriptions", () => {
  async function scenario() {
    const keys = Object.fromEntries("ABCDEFGH".split("").map((l) => [l, generateSigner()]));
    const base = { status: "cancelled", effectiveAt: "2026-10-31T00:00:00.000Z" };
    const providers = {
      A: sandboxProvider("sub-a", { ...base, signer: keys.A }),
      B: sandboxProvider("sub-b", { ...base, signer: keys.B }),
      C: sandboxProvider("sub-c", { ...base, signer: keys.C, pendingStatus: "cancellation_requested" }),
      D: sandboxProvider("sub-d", { ...base, signer: keys.D }),
      E: sandboxProvider("sub-e", { ...base, signer: keys.E, modes: ["reject"], rejectReason: "cancellation must be made by phone" }),
      F: sandboxProvider("sub-f", { ...base }), // no signed receipts: verified from the provider's records instead
      G: sandboxProvider("sub-g", { ...base, signer: keys.G }),
      H: sandboxProvider("sub-h", { ...base, modes: ["timeout_after"], idempotent: false, lookup: false }),
    };
    const w = world(Object.fromEntries(Object.values(providers).map((p) => [p.id, p.connector])));
    const contract = contractFor(w, {
      goal: "Cancel my eight unused subscriptions",
      participants: [
        { id: "agent:dots", role: "agent" },
        ...Object.entries(providers).map(([l, p]) => ({ id: p.id, role: "provider" as const, keys: l === "F" || l === "H" ? [] : [keys[l]!.publicKey] })),
      ],
      operations: Object.values(providers).map((p) => ({
        id: `cancel-${p.id}`, provider: p.id, action: "subscription.cancel", executors: ["agent:dots"], params: { account: "ana@example.com" },
        deadline: w.clock.iso(3 * DAY),
        expect: { success: ["cancelled"], pending: ["cancellation_requested"], failure: ["active"] },
      })),
    });
    await openApproved(w, contract);
    let s = await w.coordinator.run(contract.id, { agent: "agent:dots" });
    // The agent tells the user everything is done. That's a claim, not evidence.
    for (const id of s.order) await w.coordinator.recordClaim(contract.id, id, { agent: "agent:dots", observation: { status: "cancelled" } });
    s = await w.coordinator.state(contract.id);
    return { w, contract, providers, s };
  }

  it("reports 5 confirmed, 1 pending, 1 rejected, 1 unknown, and escalates", async () => {
    const { w, contract } = await scenario();
    const report = await w.coordinator.report(contract.id);
    expect(report.counts).toEqual({ verified: 5, pending_verification: 1, rejected: 1, unknown: 1 });
    expect(report.status).toBe("requires_human_review");
    expect(report.escalations.map((e) => e.operationId).sort()).toEqual(["cancel-sub-e", "cancel-sub-h"]);
    const byId = Object.fromEntries(report.operations.map((o) => [o.id, o]));
    expect(byId["cancel-sub-a"]!.basis).toBe("signed_receipt");
    expect(byId["cancel-sub-f"]!.basis).toBe("provider_record");
    expect(byId["cancel-sub-h"]!.escalation).toMatch(/may have taken effect/);
    // The agent's blanket "all cancelled" is called out where the evidence doesn't back it.
    expect(byId["cancel-sub-e"]!.findings.join()).toMatch(/agent:dots reported "cancelled", which the evidence does not confirm/);
    expect(byId["cancel-sub-a"]!.findings.join()).not.toMatch(/reported/);
    const text = renderReport(report);
    expect(text).toContain("5 of 8 confirmed · 1 pending · 1 rejected · 1 unknown");
  });

  it("does not retry the request whose confirmation was lost when the provider can't deduplicate", async () => {
    const { providers, w, contract } = await scenario();
    await w.coordinator.run(contract.id, { agent: "agent:dots" });
    expect(providers.H.executions("cancel-sub-h")).toHaveLength(1);
  });

  it("settles the pending one when the provider confirms, and resolves escalations from new evidence", async () => {
    const { w, contract, providers } = await scenario();
    providers.C.settle("cancel-sub-c");
    await w.coordinator.reconcile(contract.id);
    // The user phones provider E and checks provider H's portal, then attests.
    await w.coordinator.attest(contract.id, attest(contract, w.user, { operationId: "cancel-sub-e", outcome: "succeeded", note: "cancelled by phone, ref 99812" }, w.clock.iso()));
    await w.coordinator.attest(contract.id, attest(contract, w.user, { operationId: "cancel-sub-h", outcome: "succeeded" }, w.clock.iso()));
    const r = await w.coordinator.report(contract.id);
    expect(r.status).toBe("completed");
    expect(r.operations.find((o) => o.id === "cancel-sub-e")!.basis).toBe("human_attestation");
  });

  it("marks an unconfirmed operation unknown once its deadline passes", async () => {
    const { w, contract } = await scenario();
    w.clock.advance(4 * DAY);
    const s = await w.coordinator.reconcile(contract.id);
    expect(s.ops["cancel-sub-c"]!.status).toBe("unknown");
    expect(s.ops["cancel-sub-c"]!.escalation).toBeDefined();
  });

  it("exports a bundle anyone can verify, and detects tampering", async () => {
    const { w, contract } = await scenario();
    const bundle = await w.coordinator.exportBundle(contract.id);
    const v = verifyBundle(bundle, { coordinatorKeys: [w.mesh.publicKey], principalKeys: [w.user.publicKey] });
    expect(v.problems).toEqual([]);
    expect(v.report!.status).toBe("requires_human_review");

    const forged = structuredClone(bundle);
    const result = forged.events.find((e) => e.body.type === "operation.result" && e.body.operationId === "cancel-sub-e")!;
    (result.body as { result: unknown }).result = { outcome: "accepted" };
    expect(verifyBundle(forged, { coordinatorKeys: [w.mesh.publicKey] }).ok).toBe(false);

    const truncated = { ...bundle, events: bundle.events.slice(0, -3) };
    expect(verifyBundle(truncated, { coordinatorKeys: [w.mesh.publicKey] }).problems.join()).toMatch(/checkpoint does not cover/);
    expect(verifyBundle(bundle, { coordinatorKeys: [generateSigner().publicKey] }).ok).toBe(false);
  });
});
