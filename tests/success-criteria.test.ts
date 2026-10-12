import { describe, expect, it } from "vitest";
import {
  approveContract, approveStepUp, eventHash, generateSigner, money, replay, revokeContract, verifyMandate,
  type ExecutionAuthorization, type StoredEvent,
} from "../src/index.ts";
import { contractFor, DAY, HOUR, openApproved, sandboxProvider, world, type World } from "./helpers.ts";

// The plan's 90-day success criteria (section 14), each as executable checks.

function shop(w: World, o: { spend?: number; approvalAbove?: number; budget?: number; maxAttempts?: number } = {}) {
  return contractFor(w, {
    goal: "Buy a replacement under $200",
    participants: [{ id: "agent:muse", role: "agent" }, { id: "agent:gifts", role: "agent" }, { id: "agent:rogue", role: "agent" }, { id: "shop", role: "provider" }],
    constraints: { budget: money("USD", o.budget ?? 200), approvalAbove: o.approvalAbove ? money("USD", o.approvalAbove) : undefined },
    operations: [{
      id: "buy", provider: "shop", action: "order.create", executors: ["agent:muse"], spend: money("USD", o.spend ?? 200), maxAttempts: o.maxAttempts ?? 3,
      expect: { success: ["confirmed"], failure: ["declined"] },
    }, {
      id: "case", provider: "shop", action: "order.create", executors: ["agent:gifts"], required: false, spend: money("USD", 150), expect: { success: ["confirmed"] },
    }],
  });
}

describe("every action is linked to its authorization evidence", () => {
  it("records, before each provider call, a coordinator-signed authorization tied to the approved contract", async () => {
    const shopP = sandboxProvider("shop", { status: "confirmed" });
    const w = world({ shop: shopP.connector });
    const c = shop(w);
    let seen: Parameters<typeof shopP.connector.execute>[0] | undefined;
    const execute = shopP.connector.execute;
    shopP.connector.execute = async (req) => { seen = req; return execute(req); };
    await openApproved(w, c);
    await w.coordinator.submit(c.id, "buy", { agent: "agent:muse", amount: money("USD", 90) });

    const events = await w.coordinator.events(c.id);
    const types = events.map((e) => e.body.type);
    expect(types.indexOf("contract.approved")).toBeLessThan(types.indexOf("operation.submitting"));
    expect(types.indexOf("operation.submitting")).toBeLessThan(types.indexOf("operation.result"));
    const sub = events.find((e) => e.body.type === "operation.submitting")!.body as { authorization: { payload: ExecutionAuthorization } };
    expect(sub.authorization.payload).toMatchObject({ contractId: c.id, operationId: "buy", agent: "agent:muse", amount: money("USD", 90) });
    // What the provider received proves itself to the provider.
    expect(verifyMandate(seen!.mandate, { principalKeys: [w.user.publicKey], coordinatorKeys: [w.mesh.publicKey], now: w.clock.now() }).ok).toBe(true);
    expect(seen!.idempotencyKey).toBe(sub.authorization.payload.idempotencyKey);
  });
});

describe("no unauthorized actions", () => {
  async function refused(setup: (w: World, c: ReturnType<typeof shop>) => Promise<unknown>, req: { agent?: string; amount?: number } = {}, o: Parameters<typeof shop>[1] = {}) {
    const p = sandboxProvider("shop", { status: "confirmed" });
    const w = world({ shop: p.connector });
    const c = shop(w, o);
    await w.coordinator.open(c);
    await setup(w, c);
    const r = await w.coordinator.submit(c.id, "buy", { agent: req.agent ?? "agent:muse", amount: req.amount === undefined ? undefined : money("USD", req.amount) });
    expect(r.ok).toBe(false);
    expect(p.executions("buy")).toHaveLength(0);
    return r.ok ? "" : r.reason;
  }
  const approve = (w: World, c: ReturnType<typeof shop>) => w.coordinator.approve(c.id, approveContract(c, w.user, w.clock.iso()));

  it("before the principal approves", async () => expect(await refused(async () => {})).toMatch(/not approved/));
  it("by an agent the contract didn't delegate to", async () => expect(await refused(approve, { agent: "agent:rogue" })).toMatch(/may not execute/));
  it("above the operation's cap", async () => expect(await refused(approve, { amount: 201 })).toMatch(/more than buy may spend/));
  it("above what's left of the shared budget", async () => {
    const reason = await refused(async (w, c) => {
      await approve(w, c);
      await w.coordinator.submit(c.id, "case", { agent: "agent:gifts", amount: money("USD", 150) });
    }, { amount: 100 });
    expect(reason).toMatch(/would exceed the shared budget \(\$100.00 requested, \$50.00 available\)/);
  });
  it("above the approval threshold without a step-up", async () => expect(await refused(approve, { amount: 150 }, { approvalAbove: 100 })).toMatch(/needs the principal's approval for \$150/));
  it("after the principal revokes", async () => expect(await refused(async (w, c) => { await approve(w, c); await w.coordinator.revoke(c.id, revokeContract(c, w.user, "changed my mind", w.clock.iso())); })).toMatch(/revoked/));
  it("after the contract expires", async () => expect(await refused(async (w, c) => { await approve(w, c); w.clock.advance(8 * DAY); })).toMatch(/expired/));
  it("with an approval signed by someone else", async () => {
    const p = sandboxProvider("shop", { status: "confirmed" });
    const w = world({ shop: p.connector });
    const c = shop(w);
    await w.coordinator.open(c);
    await expect(w.coordinator.approve(c.id, approveContract(c, generateSigner()))).rejects.toThrow(/not signed by the principal/);
  });

  it("with a step-up for a different amount than requested", async () => {
    expect(await refused(async (w, c) => {
      await approve(w, c);
      await w.coordinator.stepUp(c.id, approveStepUp(c, w.user, "buy", { amount: money("USD", 120) }, w.clock.iso()));
    }, { amount: 150 }, { approvalAbove: 100 })).toMatch(/approval/);
  });

  it("allows the request once the principal steps up for exactly it", async () => {
    const p = sandboxProvider("shop", { status: "confirmed" });
    const w = world({ shop: p.connector });
    const c = shop(w, { approvalAbove: 100 });
    await openApproved(w, c);
    await w.coordinator.stepUp(c.id, approveStepUp(c, w.user, "buy", { amount: money("USD", 150) }, w.clock.iso()));
    expect((await w.coordinator.submit(c.id, "buy", { agent: "agent:muse", amount: money("USD", 150) })).ok).toBe(true);
    expect((await w.coordinator.state(c.id)).ops.buy!.status).toBe("verified");
  });

  it("records each refusal, so enforcement is part of the evidence", async () => {
    const w = world({ shop: sandboxProvider("shop", { status: "confirmed" }).connector });
    const c = shop(w);
    await openApproved(w, c);
    await w.coordinator.submit(c.id, "buy", { agent: "agent:rogue" });
    expect((await w.coordinator.report(c.id)).refusals).toMatchObject([{ operationId: "buy", agent: "agent:rogue" }]);
  });

  it("a log with an unauthorized submission written straight into the store does not replay", async () => {
    const w = world({ shop: sandboxProvider("shop", { status: "confirmed" }).connector });
    const c = shop(w);
    await w.coordinator.open(c); // never approved
    const [first] = await w.store.load(c.id);
    const auth = w.mesh.sign({ type: "agentmesh.execution-authorization" } as ExecutionAuthorization);
    const e = { transactionId: c.id, seq: 2, at: w.clock.iso(), prev: first!.hash, body: {
      type: "operation.submitting", operationId: "buy", phase: "execute", attempt: 1, agent: "agent:muse", idempotencyKey: "am_x",
      connector: { kind: "api", idempotent: true, lookup: true }, authorization: auth,
    } } as Omit<StoredEvent, "hash">;
    await w.store.append(c.id, 1, [{ ...e, hash: eventHash(e) }]);
    expect(() => replay(w.store.load(c.id) as never)).toThrow();
    await expect(w.coordinator.state(c.id)).rejects.toThrow(/unauthorized submission of buy: the principal has not approved/);
  });

  it("providers refuse requests minted by a coordinator they don't trust", async () => {
    const user = generateSigner();
    const p = sandboxProvider("shop", { status: "confirmed", verify: { principalKeys: [user.publicKey], coordinatorKeys: [generateSigner().publicKey] } });
    const w = world({ shop: p.connector });
    const c = shop(w);
    await openApproved(w, c);
    await w.coordinator.submit(c.id, "buy", { agent: "agent:muse" });
    expect(p.effects).toHaveLength(0);
    expect(p.rejections).toEqual(["approval is not signed by a trusted principal key", "authorization is not signed by a trusted coordinator key"]);
  });
});

describe("no unintended duplicate execution", () => {
  it("retries a lost confirmation with the same key, so an idempotent provider applies it once", async () => {
    const p = sandboxProvider("shop", { status: "confirmed", modes: ["timeout_after", "ok"], lookup: false });
    const w = world({ shop: p.connector });
    const c = shop(w);
    await openApproved(w, c);
    const s = await w.coordinator.run(c.id, { agent: "agent:muse" });
    expect(s.ops.buy!.execute.attempts.map((a) => a.idempotencyKey)).toHaveLength(2);
    expect(new Set(s.ops.buy!.execute.attempts.map((a) => a.idempotencyKey)).size).toBe(1);
    expect(p.executions("buy")).toHaveLength(1);
    expect(s.ops.buy!.status).toBe("verified");
  });

  it("checks the provider's records instead of retrying when it can", async () => {
    const p = sandboxProvider("shop", { status: "confirmed", modes: ["timeout_after"], idempotent: false });
    const w = world({ shop: p.connector });
    const c = shop(w);
    await openApproved(w, c);
    const s = await w.coordinator.run(c.id, { agent: "agent:muse" });
    expect(s.ops.buy!.execute.attempts).toHaveLength(1);
    expect(s.ops.buy!.status).toBe("verified");
    expect(p.executions("buy")).toHaveLength(1);
  });

  it("resends safely once the provider guarantees it never saw the request", async () => {
    const p = sandboxProvider("shop", { status: "confirmed", modes: ["timeout_before", "ok"], idempotent: false });
    const w = world({ shop: p.connector });
    const c = shop(w);
    await openApproved(w, c);
    const s = await w.coordinator.run(c.id, { agent: "agent:muse" });
    expect(s.ops.buy!.status).toBe("verified");
    expect(p.executions("buy")).toHaveLength(1);
    expect(s.ops.buy!.execute.evidence.some((e) => e.notFound?.definitive)).toBe(true);
  });

  it("uses a new key only after the provider said the request did not execute", async () => {
    const p = sandboxProvider("shop", { status: "confirmed", modes: ["not_executed", "ok"] });
    const w = world({ shop: p.connector });
    const c = shop(w);
    await openApproved(w, c);
    const s = await w.coordinator.run(c.id, { agent: "agent:muse" });
    const [a1, a2] = s.ops.buy!.execute.attempts;
    expect(a1!.idempotencyKey).not.toBe(a2!.idempotencyKey);
    expect(p.executions("buy")).toHaveLength(1);
  });

  it("lets only one of many concurrent submissions of the same operation through", async () => {
    const p = sandboxProvider("shop", { status: "confirmed", idempotent: false });
    const w = world({ shop: p.connector });
    const c = shop(w);
    await openApproved(w, c);
    const results = await Promise.all(Array.from({ length: 8 }, () => w.coordinator.submit(c.id, "buy", { agent: "agent:muse" })));
    expect(results.filter((r) => r.ok)).toHaveLength(1);
    expect(p.executions("buy")).toHaveLength(1);
  });
});

describe("correct reporting of unknown outcomes", () => {
  it("never calls an unconfirmable outcome done or failed, and holds its budget", async () => {
    const p = sandboxProvider("shop", { status: "confirmed", modes: ["timeout_after"], idempotent: false, lookup: false });
    const w = world({ shop: p.connector });
    const c = shop(w);
    await openApproved(w, c);
    const s = await w.coordinator.run(c.id, { agent: "agent:muse" });
    const r = await w.coordinator.report(c.id);
    expect(s.ops.buy!.status).toBe("unknown");
    expect(r.status).toBe("requires_human_review");
    expect(r.budget!.held.minor).toBe(20_000); // the money may be gone; don't let anything else spend it
    expect(p.executions("buy")).toHaveLength(1); // and no blind retry
  });

  it("treats an agent's account as a claim, not evidence", async () => {
    const p = sandboxProvider("shop", { status: "confirmed", kind: "agent", modes: ["claim_success"], lookup: false });
    const w = world({ shop: p.connector });
    const c = shop(w);
    await openApproved(w, c);
    const s = await w.coordinator.run(c.id, { agent: "agent:muse" });
    expect(s.ops.buy!.status).toBe("pending_verification");
    expect(s.ops.buy!.execute.evidence[0]).toMatchObject({ source: "agent_claim", proof: false });
    expect(p.effects).toHaveLength(0);
  });

  it("recovers from a coordinator that died mid-call by checking the provider", async () => {
    const p = sandboxProvider("shop", { status: "confirmed", idempotent: false });
    const w = world({ shop: p.connector }, { staleAfterMs: 5 * 60_000 });
    const c = shop(w);
    await openApproved(w, c);
    // Simulate a crash: the provider is called but the result is never recorded.
    const execute = p.connector.execute;
    p.connector.execute = async (req) => { await execute(req); return new Promise(() => {}); };
    void w.coordinator.submit(c.id, "buy", { agent: "agent:muse" });
    await new Promise((r) => setTimeout(r, 10));
    p.connector.execute = execute;
    expect((await w.coordinator.state(c.id)).ops.buy!.status).toBe("submitting");
    w.clock.advance(10 * 60_000);
    const s = await w.coordinator.run(c.id, { agent: "agent:muse" });
    expect(s.ops.buy!.status).toBe("verified");
    expect(p.executions("buy")).toHaveLength(1);
  });
});

describe("safe shared-budget reservations under concurrent requests", () => {
  function travel(w: World) {
    return contractFor(w, {
      goal: "Rebook my cancelled trip and keep additional spending below $500",
      participants: [
        { id: "agent:flights", role: "agent" }, { id: "agent:hotels", role: "agent" }, { id: "agent:cars", role: "agent" },
        { id: "airline", role: "provider" }, { id: "hotel", role: "provider" }, { id: "cars", role: "provider" },
      ],
      constraints: { budget: money("USD", 500) },
      operations: [
        { id: "flight", provider: "airline", action: "booking.create", executors: ["agent:flights"], spend: money("USD", 300), expect: { success: ["ticketed"] } },
        { id: "hotel", provider: "hotel", action: "booking.modify", executors: ["agent:hotels"], spend: money("USD", 150), expect: { success: ["confirmed"] } },
        { id: "car", provider: "cars", action: "booking.create", executors: ["agent:cars"], spend: money("USD", 100), expect: { success: ["confirmed"] } },
      ],
    });
  }

  it("never lets independent agents together exceed the budget", async () => {
    for (let round = 0; round < 25; round++) {
      const providers = { airline: sandboxProvider("airline", { status: "ticketed" }), hotel: sandboxProvider("hotel", { status: "confirmed" }), cars: sandboxProvider("cars", { status: "confirmed" }) };
      const w = world(Object.fromEntries(Object.entries(providers).map(([k, p]) => [k, p.connector])));
      const c = travel(w);
      await openApproved(w, c);
      const results = await Promise.all([
        w.coordinator.submit(c.id, "car", { agent: "agent:cars" }),
        w.coordinator.submit(c.id, "flight", { agent: "agent:flights" }),
        w.coordinator.submit(c.id, "hotel", { agent: "agent:hotels" }),
      ]);
      const spent = Object.values(providers).flatMap((p) => p.effects).reduce((n, e) => n + (e.debit?.minor ?? 0), 0);
      expect(spent).toBeLessThanOrEqual(50_000);
      expect(results.filter((r) => !r.ok)).toHaveLength(1); // $550 asked for, $500 allowed: exactly one waits
      const r = await w.coordinator.report(c.id);
      expect(r.budget!.spent.minor + r.budget!.held.minor).toBe(spent);
    }
  });

  it("holds across two coordinator instances sharing one store", async () => {
    const providers = { airline: sandboxProvider("airline", { status: "ticketed" }), hotel: sandboxProvider("hotel", { status: "confirmed" }), cars: sandboxProvider("cars", { status: "confirmed" }) };
    const connectors = Object.fromEntries(Object.entries(providers).map(([k, p]) => [k, p.connector]));
    const w = world(connectors);
    const { OutcomeCoordinator } = await import("../src/index.ts");
    const second = new OutcomeCoordinator({ store: w.store, signer: w.mesh, connectors, clock: w.clock.now });
    const c = travel(w);
    await openApproved(w, c);
    await Promise.all([
      w.coordinator.submit(c.id, "flight", { agent: "agent:flights" }),
      second.submit(c.id, "hotel", { agent: "agent:hotels" }),
      second.submit(c.id, "car", { agent: "agent:cars" }),
    ]);
    const spent = Object.values(providers).flatMap((p) => p.effects).reduce((n, e) => n + (e.debit?.minor ?? 0), 0);
    expect(spent).toBeLessThanOrEqual(50_000);
  });

  it("releases a reservation only when the provider confirms nothing was charged", async () => {
    const providers = { airline: sandboxProvider("airline", { status: "ticketed", modes: ["reject"] }), hotel: sandboxProvider("hotel", { status: "confirmed" }), cars: sandboxProvider("cars", { status: "confirmed" }) };
    const w = world(Object.fromEntries(Object.entries(providers).map(([k, p]) => [k, p.connector])));
    const c = travel(w);
    await openApproved(w, c);
    await w.coordinator.submit(c.id, "flight", { agent: "agent:flights" });
    expect((await w.coordinator.report(c.id)).budget!.available.minor).toBe(50_000);
  });
});

describe("verification compares outcomes with approved terms", () => {
  it("disputes an overcharge and counts the real charge against the budget", async () => {
    const p = sandboxProvider("shop", { status: "confirmed", charge: () => money("USD", 230) });
    const w = world({ shop: p.connector });
    const c = shop(w, { budget: 250, spend: 200 });
    await openApproved(w, c);
    const s = await w.coordinator.run(c.id, { agent: "agent:muse" });
    expect(s.ops.buy!.status).toBe("disputed");
    expect(s.ops.buy!.escalation).toMatch(/charged \$230.00, approved up to \$200.00/);
    expect((await w.coordinator.report(c.id)).budget!.held.minor).toBe(23_000);
  });

  it("ignores a receipt from the wrong key or for another operation", async () => {
    const shopKey = generateSigner();
    const p = sandboxProvider("shop", { status: "confirmed", signer: generateSigner(), pendingStatus: "processing", confirmInResponse: false, lookup: false });
    const w = world({ shop: p.connector });
    const c = contractFor(w, {
      goal: "x", participants: [{ id: "agent:muse", role: "agent" }, { id: "shop", role: "provider", keys: [shopKey.publicKey] }],
      operations: [{ id: "buy", provider: "shop", action: "order.create", executors: ["agent:muse"], expect: { success: ["confirmed"], pending: ["processing"] }, evidence: ["signed_receipt"] }],
    });
    await openApproved(w, c);
    const s = await w.coordinator.run(c.id, { agent: "agent:muse" });
    expect(s.ops.buy!.status).toBe("pending_verification");
    expect(s.ops.buy!.findings.join()).toMatch(/ignored signed receipt: receipt is not signed by a key listed for the provider/);
  });

  it("checks one operation's result against another's (no gap in coverage)", async () => {
    const insurer = (status: string, effectiveAt: string) => sandboxProvider(status === "active" ? "new-insurer" : "old-insurer", { status, effectiveAt });
    const run = async (newStart: string, oldEnd: string) => {
      const n = insurer("active", newStart), o = insurer("cancelled", oldEnd);
      const w = world({ "new-insurer": n.connector, "old-insurer": o.connector });
      const c = contractFor(w, {
        goal: "Switch to a cheaper insurance policy without losing coverage",
        participants: [{ id: "agent:muse", role: "agent" }, { id: "new-insurer", role: "provider" }, { id: "old-insurer", role: "provider" }],
        operations: [
          { id: "activate", provider: "new-insurer", action: "policy.activate", executors: ["agent:muse"], expect: { success: ["active"] } },
          { id: "cancel", provider: "old-insurer", action: "policy.cancel", executors: ["agent:muse"], dependsOn: ["activate"],
            expect: { success: ["cancelled"], checks: [{ path: "effectiveAt", op: "gte", ref: { operation: "activate", path: "effectiveAt" } }] } },
        ],
      });
      await openApproved(w, c);
      return w.coordinator.run(c.id, { agent: "agent:muse" });
    };
    expect((await run("2026-11-01T00:00:00Z", "2026-11-01T00:00:00Z")).ops.cancel!.status).toBe("verified");
    const gap = await run("2026-11-05T00:00:00Z", "2026-11-01T00:00:00Z");
    expect(gap.ops.cancel!.status).toBe("disputed");
    expect(gap.ops.cancel!.escalation).toMatch(/effectiveAt .* expected gte activate.effectiveAt/);
  });
});

describe("recovery", () => {
  function trip(w: World, policy: "keep_completed" | "compensate_completed") {
    return contractFor(w, {
      goal: "My flight was cancelled. Rebook it and adjust my hotel.",
      participants: [{ id: "agent:dots", role: "agent" }, { id: "airline", role: "provider" }, { id: "hotel", role: "provider" }],
      constraints: { budget: money("USD", 500) },
      policy: { onRequiredFailure: policy },
      operations: [
        { id: "flight", provider: "airline", action: "booking.create", executors: ["agent:dots"], spend: money("USD", 320), expect: { success: ["ticketed"] },
          compensation: { action: "booking.cancel", expect: { success: ["refunded"], credit: { min: money("USD", 320) } } } },
        { id: "hotel", provider: "hotel", action: "booking.modify", executors: ["agent:dots"], dependsOn: ["flight"], expect: { success: ["confirmed"] } },
      ],
    });
  }

  it("airline succeeds, hotel fails, policy keeps it: partial outcome escalated to the user", async () => {
    const airline = sandboxProvider("airline", { status: "ticketed" });
    const hotel = sandboxProvider("hotel", { status: "confirmed", modes: ["reject"], rejectReason: "no rooms on new dates" });
    const w = world({ airline: airline.connector, hotel: hotel.connector });
    const c = trip(w, "keep_completed");
    await openApproved(w, c);
    await w.coordinator.run(c.id, { agent: "agent:dots" });
    const r = await w.coordinator.report(c.id);
    expect(r.counts).toEqual({ verified: 1, rejected: 1 });
    expect(r.escalations).toEqual([{ operationId: "hotel", reason: "required operation was not achieved: provider rejected the request: no rooms on new dates" }]);
  });

  it("airline succeeds, hotel fails, policy unwinds: the flight is cancelled with its pre-approved compensation", async () => {
    const airline = sandboxProvider("airline", { status: "ticketed", compensation: { status: "refunded", refund: true } });
    const hotel = sandboxProvider("hotel", { status: "confirmed", modes: ["reject"] });
    const w = world({ airline: airline.connector, hotel: hotel.connector });
    const c = trip(w, "compensate_completed");
    await openApproved(w, c);
    await w.coordinator.run(c.id, { agent: "agent:dots" });
    const s = await w.coordinator.state(c.id);
    expect(s.ops.flight!.status).toBe("compensated");
    expect(s.ops.flight!.credits).toEqual([money("USD", 320)]);
    expect(s.ops.flight!.compensate.attempts[0]!.agent).toBe("agentmesh");
    const r = await w.coordinator.report(c.id);
    // The hotel failure still needs the user, but nothing is left half-done.
    expect(r.escalations.map((e) => e.operationId)).toEqual(["hotel"]);
  });

  it("a revoked contract stops new work but keeps reconciling what is in flight", async () => {
    const airline = sandboxProvider("airline", { status: "ticketed", pendingStatus: "on_hold", confirmInResponse: false });
    const hotel = sandboxProvider("hotel", { status: "confirmed" });
    const w = world({ airline: airline.connector, hotel: hotel.connector });
    const c = trip(w, "keep_completed");
    const withPending = { ...c, operations: c.operations.map((o) => (o.id === "flight" ? { ...o, expect: { ...o.expect, pending: ["on_hold"] } } : o)) };
    await openApproved(w, withPending);
    await w.coordinator.submit(c.id, "flight", { agent: "agent:dots" });
    await w.coordinator.revoke(c.id, revokeContract(withPending, w.user, "found my own flight", w.clock.iso()));
    airline.settle("flight");
    const s = await w.coordinator.run(c.id, { agent: "agent:dots" });
    expect(s.ops.flight!.status).toBe("verified"); // it happened, and the record says so
    expect(s.ops.hotel!.status).toBe("cancelled");
    expect(hotel.effects).toHaveLength(0);
    expect((await w.coordinator.report(c.id)).revoked).toBe(true);
  });

  it("cancels what never started once its deadline passes, and lets the principal waive it", async () => {
    const w = world({ shop: sandboxProvider("shop", { status: "confirmed" }).connector });
    const c = contractFor(w, {
      goal: "x", participants: [{ id: "agent:muse", role: "agent" }, { id: "shop", role: "provider" }],
      operations: [{ id: "buy", provider: "shop", action: "order.create", executors: ["agent:muse"], deadline: w.clock.iso(HOUR), expect: { success: ["confirmed"] } }],
    });
    await openApproved(w, c);
    w.clock.advance(2 * HOUR);
    let s = await w.coordinator.reconcile(c.id);
    expect(s.ops.buy!.status).toBe("cancelled");
    expect((await w.coordinator.report(c.id)).status).toBe("requires_human_review");
    const { attest } = await import("../src/index.ts");
    s = await w.coordinator.attest(c.id, attest(c, w.user, { operationId: "buy", outcome: "waived" }, w.clock.iso()));
    expect(s.ops.buy!.status).toBe("waived");
    expect((await w.coordinator.report(c.id)).status).toBe("failed");
  });
});
