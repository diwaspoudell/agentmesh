import { describe, expect, it } from "vitest";
import {
  allowProviders, approveContract, ContractError, denyActions, denyAgents, endorse, eventHash, generateSigner, httpPolicy, maxAmount, money, OutcomeCoordinator,
  renderLog, replay, renderReport, type ContractInput, type PolicyGate, type StoredEvent,
} from "../src/index.ts";
import { contractFor, openApproved, sandboxProvider, world } from "./helpers.ts";

describe("cross-check by independent vendors", () => {
  const claude = generateSigner(), gemini = generateSigner(), sameVendor = generateSigner();
  const participants: NonNullable<ContractInput["participants"]> = [
    { id: "agent:gpt", role: "agent", vendor: "openai" },
    { id: "agent:claude", role: "agent", vendor: "anthropic", keys: [claude.publicKey] },
    { id: "agent:gemini", role: "agent", vendor: "google", keys: [gemini.publicKey] },
    { id: "agent:gpt-mini", role: "agent", vendor: "openai", keys: [sameVendor.publicKey] },
    { id: "shop", role: "provider" },
  ];
  const op = (min = 1, distinctVendors = true) => ({
    id: "buy", provider: "shop", action: "order.create", executors: ["agent:gpt"], spend: money("USD", 100), crossCheck: { min, distinctVendors }, expect: { success: ["confirmed"] },
  });
  const details = { sku: "HP-300" };
  const request = { agent: "agent:gpt", amount: money("USD", 100), details };

  async function setup(min = 1) {
    const shop = sandboxProvider("shop", { status: "confirmed" });
    const w = world({ shop: shop.connector });
    const c = contractFor(w, { goal: "Buy headphones", participants, constraints: { budget: money("USD", 300) }, operations: [op(min)] });
    await openApproved(w, c);
    return { w, c, shop };
  }

  it("won't send a request until another vendor's agent has reviewed that exact request", async () => {
    const { w, c, shop } = await setup();
    expect(await w.coordinator.submit(c.id, "buy", request)).toMatchObject({ ok: false, reason: "needs 1 independent cross-check from different vendors (0 so far)" });
    expect(shop.effects).toHaveLength(0);
    await w.coordinator.endorse(c.id, endorse(c, claude, { agent: "agent:claude", operationId: "buy", amount: money("USD", 100), details }, w.clock.iso()));
    expect((await w.coordinator.submit(c.id, "buy", request)).ok).toBe(true);
    expect(shop.effects).toHaveLength(1);
    expect(renderLog(await w.coordinator.events(c.id)).join("\n")).toMatch(/agent:claude \(anthropic\) concurred with buy \$100\.00/);
  });

  it("doesn't count a second opinion from the same vendor as the executor", async () => {
    const { w, c } = await setup();
    await w.coordinator.endorse(c.id, endorse(c, sameVendor, { agent: "agent:gpt-mini", operationId: "buy", amount: money("USD", 100), details }, w.clock.iso()));
    expect((await w.coordinator.submit(c.id, "buy", request)).ok).toBe(false);
  });

  it("needs the review to cover this amount and these details", async () => {
    const { w, c } = await setup();
    await w.coordinator.endorse(c.id, endorse(c, claude, { agent: "agent:claude", operationId: "buy", amount: money("USD", 60), details }, w.clock.iso()));
    expect((await w.coordinator.submit(c.id, "buy", request)).ok).toBe(false); // reviewed $60, asked for $100
    await w.coordinator.endorse(c.id, endorse(c, gemini, { agent: "agent:gemini", operationId: "buy", amount: money("USD", 100), details: { sku: "OTHER" } }, w.clock.iso()));
    expect((await w.coordinator.submit(c.id, "buy", request)).ok).toBe(false); // reviewed a different item
    // A review of exactly this request ($60, same details) does cover it.
    expect((await w.coordinator.submit(c.id, "buy", { ...request, amount: money("USD", 60) })).ok).toBe(true);
  });

  it("lets one objection stop it, even when others concur", async () => {
    const { w, c, shop } = await setup(1);
    await w.coordinator.endorse(c.id, endorse(c, gemini, { agent: "agent:gemini", operationId: "buy", amount: money("USD", 100), details }, w.clock.iso()));
    await w.coordinator.endorse(c.id, endorse(c, claude, { agent: "agent:claude", operationId: "buy", verdict: "object", details, reason: "price is 3x the usual" }, w.clock.iso()));
    expect(await w.coordinator.submit(c.id, "buy", request)).toMatchObject({ ok: false, reason: "agent:claude objected to this request: price is 3x the usual" });
    expect(shop.effects).toHaveLength(0);
  });

  it("requires distinct vendors among the reviewers when several are needed", async () => {
    const { w, c } = await setup(2);
    const cc = (key: typeof claude, agent: string) => w.coordinator.endorse(c.id, endorse(c, key, { agent, operationId: "buy", amount: money("USD", 100), details }, w.clock.iso()));
    await cc(claude, "agent:claude");
    expect((await w.coordinator.submit(c.id, "buy", request)).ok).toBe(false);
    await cc(gemini, "agent:gemini");
    expect((await w.coordinator.submit(c.id, "buy", request)).ok).toBe(true);
  });

  it("rejects endorsements signed with the wrong key, and contracts that can't be cross-checked", async () => {
    const { w, c } = await setup();
    await expect(w.coordinator.endorse(c.id, endorse(c, gemini, { agent: "agent:claude", operationId: "buy", details }, w.clock.iso()))).rejects.toThrow(/not signed by agent:claude's key/);
    await expect(w.coordinator.endorse(c.id, endorse(c, claude, { agent: "agent:nobody", operationId: "buy", details }, w.clock.iso()))).rejects.toThrow(/unknown agent/);
    const w2 = world();
    const build = (parts: NonNullable<ContractInput["participants"]>, min: number) => () => contractFor(w2, { goal: "x", participants: parts, operations: [op(min)] });
    expect(build(participants, 3)).toThrow(/needs 3 independent-vendor agents with keys besides its executors, but only 2 qualify/);
    expect(build(participants.filter((p) => p.id !== "agent:claude" && p.id !== "agent:gemini"), 1)).toThrow(ContractError);
    expect(build(participants.map((p) => (p.id === "agent:gpt" ? { ...p, vendor: undefined } : p)), 1)).toThrow(/every executor needs a vendor/);
  });

  it("is carried through replay: a log with the review removed doesn't verify", async () => {
    const { w, c } = await setup();
    await w.coordinator.endorse(c.id, endorse(c, claude, { agent: "agent:claude", operationId: "buy", amount: money("USD", 100), details }, w.clock.iso()));
    await w.coordinator.submit(c.id, "buy", request);
    const events = await w.coordinator.events(c.id);
    const at = events.findIndex((e) => e.body.type === "operation.endorsed");
    const without: StoredEvent[] = events.filter((_, i) => i !== at).map((e) => structuredClone(e));
    let prev = without[at - 1]!.hash;
    without.slice(at).forEach((e, i) => { e.seq = at + 1 + i; e.prev = prev; e.hash = eventHash({ transactionId: e.transactionId, seq: e.seq, at: e.at, prev, body: e.body }); prev = e.hash; });
    expect(() => replay(without)).toThrow(/unauthorized submission of buy: needs 1 independent cross-check/);
  });

  it("is reported when a multi-step outcome rests on one vendor", async () => {
    const shop = sandboxProvider("shop", { status: "confirmed" });
    const w = world({ shop: shop.connector });
    const c = contractFor(w, {
      goal: "x", participants: [{ id: "agent:gpt", role: "agent", vendor: "openai" }, { id: "shop", role: "provider" }],
      operations: ["one", "two"].map((id) => ({ id, provider: "shop", action: "x", executors: ["agent:gpt"], expect: { success: ["confirmed"] } })),
    });
    await openApproved(w, c);
    await w.coordinator.run(c.id, { agent: "agent:gpt" });
    const report = await w.coordinator.report(c.id);
    expect(report.diversity).toMatchObject({ singleVendor: true, vendors: { openai: ["one", "two"] }, crossChecked: [] });
    expect(renderReport(report)).toMatch(/Model diversity: every operation was run by agents from one vendor \(openai\); none had a cross-check\./);
  });
});

describe("organization policy gates", () => {
  async function setup(policy: PolicyGate[], spend = 100) {
    const shop = sandboxProvider("shop", { status: "confirmed" });
    const w = world({ shop: shop.connector });
    const coordinator = new OutcomeCoordinator({ store: w.store, signer: w.mesh, connectors: { shop: shop.connector }, clock: w.clock.now, policy });
    const c = contractFor(w, {
      goal: "Private errand the organization must not see", participants: [{ id: "agent:a", role: "agent" }, { id: "shop", role: "provider" }],
      operations: [{ id: "buy", provider: "shop", action: "order.create", executors: ["agent:a"], spend: money("USD", spend), expect: { success: ["confirmed"] } }],
    });
    await coordinator.open(c);
    await coordinator.approve(c.id, approveContract(c, w.user, w.clock.iso()));
    return { w, c, shop, coordinator };
  }

  it("can only narrow what the contract allows, and records every decision with the submission", async () => {
    const { c, shop, coordinator } = await setup([allowProviders(["shop"]), maxAmount(money("USD", 500))]);
    expect((await coordinator.submit(c.id, "buy", { agent: "agent:a" })).ok).toBe(true);
    const sub = (await coordinator.events(c.id)).find((e) => e.body.type === "operation.submitting")!.body as { policy: unknown };
    expect(sub.policy).toEqual([{ policy: "allow-providers", effect: "allow" }, { policy: "max-amount", effect: "allow" }]);
    expect(shop.effects).toHaveLength(1);
    expect(renderLog(await coordinator.events(c.id)).join("\n")).toMatch(/2 policies allowed it/);
  });

  it("refuses what a rule forbids even though the contract allows it, and logs why", async () => {
    for (const [gate, reason] of [
      [denyActions(["order.*"]), "action order.create is not permitted"],
      [maxAmount(money("USD", 50)), "amount is above the organization's limit"],
      [denyAgents(["agent:a"]), "agent agent:a is not permitted"],
      [allowProviders(["other"]), "provider shop is not on the approved list"],
    ] as const) {
      const { c, shop, coordinator } = await setup([gate]);
      const r = await coordinator.submit(c.id, "buy", { agent: "agent:a" });
      expect(r).toMatchObject({ ok: false, reason: `denied by policy ${gate.name}: ${reason}` });
      expect(shop.effects).toHaveLength(0);
      const refusal = (await coordinator.events(c.id)).find((e) => e.body.type === "operation.refused")!.body as { policy: unknown; kind: string };
      expect(refusal.policy).toEqual([{ policy: gate.name, effect: "deny", reason }]);
      expect(refusal.kind).toBe("blocked");
    }
  });

  it("fails closed when a rule errors, and sees only what the request needs, never the user's goal", async () => {
    const seen: unknown[] = [];
    const spy: PolicyGate = { name: "spy", evaluate: (ctx) => { seen.push(ctx); return { policy: "spy", effect: "allow" }; } };
    const broken: PolicyGate = { name: "broken", evaluate: () => { throw new Error("rules engine down"); } };
    const a = await setup([spy]);
    await a.coordinator.submit(a.c.id, "buy", { agent: "agent:a", details: { sku: "X" } });
    expect(JSON.stringify(seen)).not.toContain("Private errand");
    expect(seen[0]).toMatchObject({ operationId: "buy", provider: "shop", action: "order.create", agent: "agent:a", amount: money("USD", 100), details: { sku: "X" } });
    const b = await setup([spy, broken]);
    expect(await b.coordinator.submit(b.c.id, "buy", { agent: "agent:a" })).toMatchObject({ ok: false, reason: "denied by policy broken: policy failed: rules engine down" });
    expect(b.shop.effects).toHaveLength(0);
  });

  it("can't be bypassed by a log that records a submission the policy denied", async () => {
    const { w, c, coordinator } = await setup([allowProviders(["shop"])]);
    await coordinator.submit(c.id, "buy", { agent: "agent:a" });
    const events = await coordinator.events(c.id);
    const at = events.findIndex((e) => e.body.type === "operation.submitting");
    const forged = structuredClone(events);
    (forged[at]!.body as { policy: unknown }).policy = [{ policy: "allow-providers", effect: "deny", reason: "x" }];
    let prev = forged[at - 1]!.hash;
    for (let i = at; i < forged.length; i++) { forged[i]!.prev = prev; forged[i]!.hash = eventHash({ transactionId: c.id, seq: forged[i]!.seq, at: forged[i]!.at, prev, body: forged[i]!.body }); prev = forged[i]!.hash; }
    expect(() => replay(forged)).toThrow(/denied by policy allow-providers/);
    expect(w.clock.iso()).toBeTruthy();
  });

  describe("OPA-compatible http policy", () => {
    const answer = (body: unknown, status = 200) => (async () => new Response(JSON.stringify(body), { status })) as unknown as typeof fetch;
    const ctx = { contractId: "c", operationId: "o", phase: "execute" as const, provider: "p", action: "a", agent: "x", at: "2026-10-12T09:00:00Z" };

    it("allows, denies with a reason, and fails closed on errors", async () => {
      expect((await httpPolicy("http://opa/v1/data/agentmesh/allow", { fetch: answer({ result: true }) }).evaluate(ctx)).effect).toBe("allow");
      expect((await httpPolicy("http://opa/x", { fetch: answer({ result: { allow: true } }) }).evaluate(ctx)).effect).toBe("allow");
      expect(await httpPolicy("http://opa/x", { fetch: answer({ result: { allow: false, reason: "outside business hours" } }) }).evaluate(ctx)).toMatchObject({ effect: "deny", reason: "outside business hours" });
      expect((await httpPolicy("http://opa/x", { fetch: answer({}) }).evaluate(ctx)).effect).toBe("deny"); // no result
      expect((await httpPolicy("http://opa/x", { fetch: answer({ result: true }, 500) }).evaluate(ctx)).reason).toMatch(/answered 500/);
      const down = (async () => { throw new Error("ECONNREFUSED"); }) as unknown as typeof fetch;
      expect((await httpPolicy("http://opa/x", { fetch: down }).evaluate(ctx)).reason).toMatch(/unavailable: ECONNREFUSED/);
    });

    it("posts the request context as OPA input", async () => {
      let sent: { url: string; body: unknown } | undefined;
      const f = (async (url: string, init: RequestInit) => { sent = { url, body: JSON.parse(init.body as string) }; return new Response(JSON.stringify({ result: true })); }) as unknown as typeof fetch;
      await httpPolicy("http://opa/v1/data/agentmesh/allow", { fetch: f, headers: { authorization: "Bearer t" } }).evaluate(ctx);
      expect(sent).toEqual({ url: "http://opa/v1/data/agentmesh/allow", body: { input: ctx } });
    });
  });
});
