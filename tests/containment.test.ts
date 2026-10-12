import { describe, expect, it } from "vitest";
import {
  approveContract, approveStepUp, ContractError, generateSigner, money, renderReport, resume, revokeContract, suspend, type ContractInput,
} from "../src/index.ts";
import { contractFor, openApproved, sandboxProvider, world, type World } from "./helpers.ts";

const base = (extra: Partial<ContractInput> = {}): Omit<ContractInput, "principal" | "coordinator" | "expiresAt" | "createdAt"> => ({
  goal: "Buy a replacement",
  participants: [{ id: "agent:a", role: "agent" }, { id: "agent:b", role: "agent" }, { id: "shop", role: "provider" }],
  operations: [
    { id: "buy", provider: "shop", action: "order.create", executors: ["agent:a"], expect: { success: ["confirmed"] } },
    { id: "gift", provider: "shop", action: "order.create", executors: ["agent:b"], expect: { success: ["confirmed"] } },
  ],
  ...extra,
});

function withController(w: World, extra: Partial<ContractInput> = {}) {
  const controller = generateSigner();
  const b = base(extra);
  const c = contractFor(w, { ...b, participants: [...b.participants!, { id: "security", role: "controller", keys: [controller.publicKey] }] });
  return { c, controller };
}

describe("role separation", () => {
  const w = world();
  const problems = (participants: NonNullable<ContractInput["participants"]>) => {
    try { contractFor(w, { ...base(), participants: [{ id: "agent:a", role: "agent" }, { id: "agent:b", role: "agent" }, ...participants] }); return ""; } catch (e) { return (e as ContractError).message; }
  };

  it("refuses a provider that signs with the principal's key", () => {
    expect(problems([{ id: "shop", role: "provider", keys: [w.user.publicKey] }])).toMatch(/used by both the principal and provider shop; one key may hold only one role/);
  });
  it("refuses a reviewer or auditor that holds the coordinator's key", () => {
    expect(problems([{ id: "shop", role: "provider" }, { id: "audit", role: "auditor", keys: [w.mesh.publicKey] }])).toMatch(/both the coordinator and auditor audit/);
  });
  it("refuses one key shared by a controller and a reviewer", () => {
    const k = generateSigner().publicKey;
    expect(problems([{ id: "shop", role: "provider" }, { id: "c", role: "controller", keys: [k] }, { id: "r", role: "reviewer", keys: [k] }])).toMatch(/one key may hold only one role/);
  });
  it("refuses duplicate ids across roles, and keyless controllers", () => {
    expect(problems([{ id: "shop", role: "provider" }, { id: "agentmesh", role: "reviewer", keys: [generateSigner().publicKey] }])).toMatch(/ids must all be different/);
    expect(problems([{ id: "shop", role: "provider" }, { id: "c", role: "controller" }])).toMatch(/controller c needs a key/);
  });
  it("allows one key to appear twice in the same role", () => {
    const k = generateSigner().publicKey;
    expect(problems([{ id: "shop", role: "provider", keys: [k, k] }])).toBe("");
  });
});

describe("suspend and resume", () => {
  async function setup(opts: { connectorStatus?: string } = {}) {
    const shop = sandboxProvider("shop", { status: "confirmed", pendingStatus: opts.connectorStatus });
    const w = world({ shop: shop.connector });
    const { c, controller } = withController(w, opts.connectorStatus ? {
      operations: [
        { id: "buy", provider: "shop", action: "order.create", executors: ["agent:a"], expect: { success: ["confirmed"], pending: [opts.connectorStatus] } },
        { id: "gift", provider: "shop", action: "order.create", executors: ["agent:b"], expect: { success: ["confirmed"], pending: [opts.connectorStatus] } },
      ],
    } : {});
    await openApproved(w, c);
    return { w, c, controller, shop };
  }

  it("pauses the whole transaction, blocks every agent, and lifts when resumed", async () => {
    const { w, c, shop } = await setup();
    await w.coordinator.suspend(c.id, suspend(c, w.user, { reason: "checking something" }, w.clock.iso()));
    const refused = await w.coordinator.submit(c.id, "buy", { agent: "agent:a" });
    expect(refused).toMatchObject({ ok: false, reason: "the transaction is suspended by the principal (checking something)" });
    expect((await w.coordinator.submit(c.id, "gift", { agent: "agent:b" })).ok).toBe(false);
    expect(shop.effects).toHaveLength(0);
    const report = await w.coordinator.report(c.id);
    expect(report.suspensions).toMatchObject([{ scope: "transaction", by: "principal", reason: "checking something" }]);
    expect(renderReport(report)).toMatch(/SUSPENDED: the whole transaction, by the principal \(checking something\)/);
    expect(report.operations[0]!.waitingOn).toBe("the transaction is suspended");

    await w.coordinator.resume(c.id, resume(c, w.user, {}, w.clock.iso()));
    expect((await w.coordinator.submit(c.id, "buy", { agent: "agent:a" })).ok).toBe(true);
  });

  it("keeps reconciling work that was already in flight while suspended", async () => {
    const { w, c, shop } = await setup({ connectorStatus: "working" });
    await w.coordinator.submit(c.id, "buy", { agent: "agent:a" });
    await w.coordinator.suspend(c.id, suspend(c, w.user, {}, w.clock.iso()));
    shop.settle("buy");
    const s = await w.coordinator.reconcile(c.id);
    expect(s.ops.buy!.status).toBe("verified");
    expect(s.ops.gift!.status).toBe("planned");
  });

  it("can suspend a single agent without touching the others", async () => {
    const { w, c } = await setup();
    await w.coordinator.suspend(c.id, suspend(c, w.user, { agent: "agent:a", reason: "odd behavior" }, w.clock.iso()));
    expect(await w.coordinator.submit(c.id, "buy", { agent: "agent:a" })).toMatchObject({ ok: false, reason: "agent agent:a is suspended by the principal (odd behavior)" });
    expect((await w.coordinator.submit(c.id, "gift", { agent: "agent:b" })).ok).toBe(true);
    const report = await w.coordinator.report(c.id);
    expect(report.operations.find((o) => o.id === "buy")!.waitingOn).toBe("every agent that may run it is suspended");
    await w.coordinator.resume(c.id, resume(c, w.user, { agent: "agent:a" }, w.clock.iso()));
    expect((await w.coordinator.submit(c.id, "buy", { agent: "agent:a" })).ok).toBe(true);
  });

  it("only a controller can lift a controller's suspension, so the principal can't undo the organization's stop", async () => {
    const { w, c, controller } = await setup();
    await w.coordinator.suspend(c.id, suspend(c, controller, { reason: "security hold" }, w.clock.iso()));
    await expect(w.coordinator.resume(c.id, resume(c, w.user, {}, w.clock.iso()))).rejects.toThrow(/can only be lifted by a controller/);
    expect((await w.coordinator.submit(c.id, "buy", { agent: "agent:a" })).ok).toBe(false);
    await w.coordinator.resume(c.id, resume(c, controller, {}, w.clock.iso()));
    expect((await w.coordinator.submit(c.id, "buy", { agent: "agent:a" })).ok).toBe(true);
  });

  it("rejects suspensions and resumptions from anyone the contract doesn't name", async () => {
    const { w, c } = await setup();
    await expect(w.coordinator.suspend(c.id, suspend(c, generateSigner(), {}, w.clock.iso()))).rejects.toThrow(/not signed by the principal, a controller or the coordinator/);
    await expect(w.coordinator.suspend(c.id, suspend(c, w.user, { agent: "agent:ghost" }, w.clock.iso()))).rejects.toThrow(/unknown agent/);
    await expect(w.coordinator.resume(c.id, resume(c, w.user, {}, w.clock.iso()))).rejects.toThrow(/no such suspension/);
    await w.coordinator.suspend(c.id, suspend(c, w.user, {}, w.clock.iso()));
    await expect(w.coordinator.suspend(c.id, suspend(c, w.user, {}, w.clock.iso()))).rejects.toThrow(/already suspended/);
    await expect(w.coordinator.resume(c.id, resume(c, generateSigner(), {}, w.clock.iso()))).rejects.toThrow(/not signed by the principal or a controller/);
  });
});

describe("controller", () => {
  it("can revoke, but can never approve, step up, or waive", async () => {
    const shop = sandboxProvider("shop", { status: "confirmed" });
    const w = world({ shop: shop.connector });
    const { c, controller } = withController(w);
    await w.coordinator.open(c);
    await expect(w.coordinator.approve(c.id, approveContract(c, controller, w.clock.iso()))).rejects.toThrow(/not signed by the principal/);
    await w.coordinator.approve(c.id, approveContract(c, w.user, w.clock.iso()));
    await w.coordinator.revoke(c.id, revokeContract(c, controller, "emergency stop", w.clock.iso()));
    const refused = await w.coordinator.submit(c.id, "buy", { agent: "agent:a" });
    expect(refused).toMatchObject({ ok: false, reason: "the controller revoked the contract" });
    expect((await w.coordinator.report(c.id)).revoked).toBe(true);
    expect(shop.effects).toHaveLength(0);
  });

  it("a stranger's revocation is rejected", async () => {
    const w = world({ shop: sandboxProvider("shop", { status: "confirmed" }).connector });
    const { c } = withController(w);
    await openApproved(w, c);
    await expect(w.coordinator.revoke(c.id, revokeContract(c, generateSigner(), "x", w.clock.iso()))).rejects.toThrow(/not signed by the principal or a controller/);
  });
});

describe("circuit breaker", () => {
  const breaker = { circuitBreaker: { violations: 3, windowSeconds: 60 } };
  async function setup() {
    const shop = sandboxProvider("shop", { status: "confirmed" });
    const w = world({ shop: shop.connector });
    const b = base();
    const c = contractFor(w, { ...b, policy: breaker, constraints: { approvalAbove: money("USD", 10) }, operations: [
      { ...b.operations![0]!, spend: money("USD", 50) }, b.operations![1]!,
    ] });
    await openApproved(w, c);
    return { w, c, shop };
  }

  it("suspends an agent after repeated forbidden requests, files the incident, and leaves other agents alone", async () => {
    const { w, c, shop } = await setup();
    for (let i = 0; i < 2; i++) await w.coordinator.submit(c.id, "buy", { agent: "agent:b" }); // agent b isn't delegated to buy
    expect((await w.coordinator.state(c.id)).suspended.agents["agent:b"]).toBeUndefined();
    await w.coordinator.submit(c.id, "buy", { agent: "agent:b" });
    const s = await w.coordinator.state(c.id);
    expect(s.suspended.agents["agent:b"]).toMatchObject({ by: "coordinator", reason: "circuit breaker: 3 forbidden requests in 60s" });
    expect(s.incidents).toHaveLength(1);
    expect(s.incidents[0]!.report.payload).toMatchObject({ category: "unauthorized_attempt", severity: "high", actions: ["suspended agent:b"] });

    // Even its legitimate operation is now blocked, but agent a carries on.
    expect(await w.coordinator.submit(c.id, "gift", { agent: "agent:b" })).toMatchObject({ ok: false, reason: expect.stringMatching(/agent agent:b is suspended by the coordinator/) });
    await w.coordinator.stepUp(c.id, approveStepUp(c, w.user, "buy", { amount: money("USD", 50) }, w.clock.iso()));
    expect((await w.coordinator.submit(c.id, "buy", { agent: "agent:a", amount: money("USD", 50) })).ok).toBe(true);
    expect(shop.effects).toHaveLength(1);
    expect((await w.coordinator.report(c.id)).incidents).toHaveLength(1);
  });

  it("doesn't count requests that merely have to wait", async () => {
    const { w, c } = await setup();
    for (let i = 0; i < 6; i++) await w.coordinator.submit(c.id, "buy", { agent: "agent:a", amount: money("USD", 50) }); // needs step-up each time
    const s = await w.coordinator.state(c.id);
    expect(s.ops.buy!.refusals).toHaveLength(6);
    expect(s.ops.buy!.refusals.every((r) => r.kind === "blocked")).toBe(true);
    expect(s.suspended.agents["agent:a"]).toBeUndefined();
  });

  it("forgets violations outside the window, and starts over after a resume", async () => {
    const { w, c } = await setup();
    await w.coordinator.submit(c.id, "buy", { agent: "agent:b" });
    await w.coordinator.submit(c.id, "buy", { agent: "agent:b" });
    w.clock.advance(120_000);
    await w.coordinator.submit(c.id, "buy", { agent: "agent:b" });
    expect((await w.coordinator.state(c.id)).suspended.agents["agent:b"]).toBeUndefined();
    await w.coordinator.submit(c.id, "buy", { agent: "agent:b" });
    await w.coordinator.submit(c.id, "buy", { agent: "agent:b" });
    expect((await w.coordinator.state(c.id)).suspended.agents["agent:b"]).toBeDefined();
    await w.coordinator.resume(c.id, resume(c, w.user, { agent: "agent:b" }, w.clock.iso()));
    await w.coordinator.submit(c.id, "buy", { agent: "agent:b" });
    await w.coordinator.submit(c.id, "buy", { agent: "agent:b" });
    expect((await w.coordinator.state(c.id)).suspended.agents["agent:b"]).toBeUndefined(); // two since the resume is not three
  });

  it("is not something the coordinator can use on a whim: the log must justify every automatic suspension", async () => {
    const { w, c } = await setup();
    await expect(w.coordinator.suspend(c.id, suspend(c, w.mesh, { agent: "agent:a", reason: "because" }, w.clock.iso()))).rejects.toThrow(/circuit breaker has not tripped for agent:a \(0 of 3 violations\)/);
    await expect(w.coordinator.suspend(c.id, suspend(c, w.mesh, {}, w.clock.iso()))).rejects.toThrow(/only a single agent, and only through the contract's circuit breaker/);
  });

  it("does nothing when the contract has no breaker configured", async () => {
    const w = world({ shop: sandboxProvider("shop", { status: "confirmed" }).connector });
    const c = contractFor(w, base());
    await openApproved(w, c);
    for (let i = 0; i < 10; i++) await w.coordinator.submit(c.id, "buy", { agent: "agent:b" });
    expect((await w.coordinator.state(c.id)).suspended.agents).toEqual({});
    await expect(w.coordinator.suspend(c.id, suspend(c, w.mesh, { agent: "agent:b" }, w.clock.iso()))).rejects.toThrow(/circuit breaker/);
  });
});

