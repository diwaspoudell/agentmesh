import { describe, expect, it } from "vitest";
import {
  approveContract, approveStepUp, attest, endorse, generateSigner, Intents, intentView, money, replay, resume, revokeContract, signWebhook, suspend, verifyBundle,
  verifyWebhook, webhookSink, type CreateIntent, type IntentEvent, type IntentStatus,
} from "../src/index.ts";
import { DAY, sandboxProvider, world } from "./helpers.ts";

type Providers = Record<string, ReturnType<typeof sandboxProvider>>;

function setup(providers: Providers, receiptKeys: Record<string, ReturnType<typeof generateSigner>> = {}, extra: ConstructorParameters<typeof Intents>[1] = {}) {
  const w = world(Object.fromEntries(Object.entries(providers).map(([k, p]) => [k, p.connector])));
  const intents = new Intents(w.coordinator, {
    providers: Object.fromEntries(Object.keys(providers).map((k) => [k, { keys: receiptKeys[k] ? [receiptKeys[k]!.publicKey] : [] }])), ...extra,
  });
  const create = (over: Partial<CreateIntent> & Pick<CreateIntent, "steps">) =>
    intents.create({ goal: "Buy a monitor and have it shipped", principal: { id: "user:ana", key: w.user.publicKey }, agents: ["agent:a"], ...over });
  const approve = async (id: string) => intents.approve(id, approveContract((await intents.retrieve(id)).contract, w.user, w.clock.iso()));
  return { w, intents, create, approve };
}

const buy = { provider: "shop", action: "order.create", spend: money("USD", 100), expect: "confirmed" };
const ship = { provider: "courier", action: "shipment.book", dependsOn: ["step_1"], expect: "booked" };

describe("an outcome intent end to end", () => {
  const shopKey = generateSigner();
  const build = () => setup({ shop: sandboxProvider("shop", { status: "confirmed", signer: shopKey }), courier: sandboxProvider("courier", { status: "booked" }) }, { shop: shopKey });

  it("starts as requires_approval with the contract to sign, then runs to succeeded with evidence for every step", async () => {
    const { w, create, approve, intents } = build();
    const created = await create({ budget: money("USD", 200), steps: [buy, ship] });
    expect(created).toMatchObject({ object: "outcome_intent", status: "requires_approval", summary: "2 planned" });
    expect(created.next_actions).toEqual([{ type: "approve_intent", reason: "the principal has not approved the contract" }]);
    expect(created.steps.map((s) => [s.id, s.status])).toEqual([["step_1", "waiting"], ["step_2", "waiting"]]);
    expect(created.contract.id).toBe(created.id);
    expect(created.evidence.digest).toMatch(/^sha256:/);

    expect((await approve(created.id)).status).toBe("processing");
    const done = await intents.run(created.id, { agent: "agent:a" });
    expect(done).toMatchObject({ status: "succeeded", summary: "2 of 2 confirmed", next_actions: [] });
    expect(done.steps[0]).toMatchObject({ status: "succeeded", verified_by: "signed_receipt", reference: "shop-1", charged: money("USD", 100) });
    expect(done.steps[1]).toMatchObject({ status: "succeeded", verified_by: "provider_record" });
    expect(done.amount).toEqual({ budget: money("USD", 200), spent: money("USD", 100), held: money("USD", 0), available: money("USD", 100) });

    const bundle = await intents.bundle(created.id);
    expect(verifyBundle(bundle, { coordinatorKeys: [w.mesh.publicKey], principalKeys: [w.user.publicKey] }).ok).toBe(true);
    expect((await intents.log(created.id)).length).toBe(bundle.events.length);
    expect((await intents.report(created.id)).status).toBe("completed");
  });

  it("derives the view from the verified log, so replaying the bundle gives the same intent", async () => {
    const { create, approve, intents } = build();
    const c = await create({ steps: [buy, ship] });
    await approve(c.id);
    const final = await intents.run(c.id, { agent: "agent:a" });
    const { contract: _c, ...view } = final;
    expect(intentView(replay((await intents.bundle(c.id)).events))).toEqual(view);
  });
});

describe("status", () => {
  const status = (i: { status: IntentStatus }) => i.status;

  it("is requires_action, with the reason and the step, when an outcome is unknown", async () => {
    const { create, approve, intents } = setup({ shop: sandboxProvider("shop", { status: "confirmed", modes: ["timeout_after"], idempotent: false, lookup: false }) });
    const c = await create({ steps: [{ ...buy, spend: undefined }] });
    await approve(c.id);
    const i = await intents.run(c.id, { agent: "agent:a" });
    expect(status(i)).toBe("requires_action");
    expect(i.steps[0]).toMatchObject({ status: "unknown", message: expect.stringMatching(/may have taken effect/) });
    expect(i.next_actions).toEqual([{ type: "review", step: "step_1", reason: expect.stringMatching(/outcome unknown/) }]);
  });

  it("is requires_action for a disputed overcharge, and a person's attestation doesn't paper over the provider's conflicting record", async () => {
    const { w, create, approve, intents } = setup({ shop: sandboxProvider("shop", { status: "confirmed", charge: () => money("USD", 130) }) });
    const c = await create({ budget: money("USD", 200), steps: [buy] });
    await approve(c.id);
    const i = await intents.run(c.id, { agent: "agent:a" });
    expect(i).toMatchObject({ status: "requires_action", steps: [{ status: "disputed" }] });
    expect(i.next_actions[0]).toMatchObject({ type: "review", reason: expect.stringMatching(/charged \$130\.00, approved up to \$100\.00/) });
    // A person looks at the order and records what they found.
    const settled = await intents.attest(c.id, attest(i.contract, w.user, { operationId: "step_1", outcome: "succeeded", observation: { status: "confirmed", debit: money("USD", 100) } }, w.clock.iso()));
    expect(settled.status).toBe("requires_action"); // the provider's own record still shows $130; waiving would be the way to stop expecting it, and it keeps the $130 counted
  });

  it("asks for approval of the exact request, clears once given, and then succeeds", async () => {
    const { w, create, approve, intents } = setup({ shop: sandboxProvider("shop", { status: "confirmed" }) });
    const c = await create({ approveAbove: money("USD", 50), steps: [buy] });
    await approve(c.id);
    const waiting = await intents.run(c.id, { agent: "agent:a" });
    expect(waiting.status).toBe("requires_action");
    expect(waiting.next_actions).toEqual([{ type: "step_up", step: "step_1", agent: "agent:a", reason: "needs the principal's approval for $100.00" }]);
    // Asking again doesn't pile up duplicate refusals.
    await intents.run(c.id, { agent: "agent:a" });
    expect((await intents.report(c.id)).refusals).toHaveLength(1);

    const after = await intents.stepUp(c.id, approveStepUp(c.contract, w.user, "step_1", { amount: money("USD", 100) }, w.clock.iso()));
    expect(after.next_actions).toEqual([]);
    expect(after.status).toBe("processing");
    expect((await intents.run(c.id, { agent: "agent:a" })).status).toBe("succeeded");
  });

  it("asks for a second opinion from another vendor, and clears when it arrives", async () => {
    const reviewer = generateSigner();
    const shop = sandboxProvider("shop", { status: "confirmed" });
    const { w, create, approve, intents } = setup({ shop });
    const c = await create({
      agents: [{ id: "agent:a", vendor: "openai" }, { id: "agent:r", vendor: "anthropic", key: reviewer.publicKey }],
      steps: [{ ...buy, agent: "agent:a", crossCheck: { min: 1 } }],
    });
    await approve(c.id);
    const waiting = await intents.run(c.id, { agent: "agent:a" });
    expect(waiting).toMatchObject({ status: "requires_action", next_actions: [{ type: "cross_check", step: "step_1" }] });
    const reviewed = await intents.endorse(c.id, endorse(c.contract, reviewer, { agent: "agent:r", operationId: "step_1", amount: money("USD", 100) }, w.clock.iso()));
    expect(reviewed.next_actions).toEqual([]);
    expect((await intents.run(c.id, { agent: "agent:a" })).status).toBe("succeeded");
    expect(shop.effects).toHaveLength(1);
  });

  it("is requires_action while suspended, naming who must resume it", async () => {
    const { w, create, approve, intents } = setup({ shop: sandboxProvider("shop", { status: "confirmed" }) });
    const c = await create({ steps: [{ ...buy, spend: undefined }] });
    await approve(c.id);
    const held = await intents.suspend(c.id, suspend(c.contract, w.user, { reason: "checking the order" }, w.clock.iso()));
    expect(held).toMatchObject({ status: "requires_action", suspended: [{ scope: "transaction", by: "principal", reason: "checking the order" }] });
    expect(held.next_actions).toEqual([{ type: "resume", reason: "the transaction is suspended by the principal (checking the order)" }]);
    const back = await intents.resume(c.id, resume(c.contract, w.user, {}, w.clock.iso()));
    expect(back).toMatchObject({ status: "processing", next_actions: [], suspended: [] });
  });

  it("is canceled when revoked before approval or before anything happened", async () => {
    const { w, create, approve, intents } = setup({ shop: sandboxProvider("shop", { status: "confirmed" }) });
    const a = await create({ steps: [buy] });
    expect((await intents.cancel(a.id, revokeContract(a.contract, w.user, "changed my mind", w.clock.iso()))).status).toBe("canceled");
    const b = await create({ steps: [buy] });
    await approve(b.id);
    expect((await intents.cancel(b.id, revokeContract(b.contract, w.user, "changed my mind", w.clock.iso()))).status).toBe("canceled");
  });

  it("is partially_succeeded when cancelled midway with something already confirmed", async () => {
    const shop = sandboxProvider("shop", { status: "confirmed", pendingStatus: "processing" });
    const { w, create, approve, intents } = setup({ shop, courier: sandboxProvider("courier", { status: "booked" }) });
    const c = await create({ steps: [{ ...buy, expect: { success: "confirmed", pending: ["processing"] } }, ship] });
    await approve(c.id);
    expect((await intents.run(c.id, { agent: "agent:a" })).status).toBe("processing");
    await intents.cancel(c.id, revokeContract(c.contract, w.user, "stop", w.clock.iso()));
    shop.settle("step_1");
    const i = await intents.refresh(c.id);
    expect(i.status).toBe("partially_succeeded");
    expect(i.steps.map((s) => s.status)).toEqual(["succeeded", "canceled"]);
    expect(i.next_actions).toEqual([]);
  });

  it("is failed once the principal waives a step that could not be done", async () => {
    const { w, create, approve, intents } = setup({ shop: sandboxProvider("shop", { status: "confirmed" }) });
    const c = await create({ steps: [{ ...buy, deadline: { inMs: 3_600_000 } }] });
    await approve(c.id);
    w.clock.advance(2 * 3_600_000);
    const lapsed = await intents.refresh(c.id);
    expect(lapsed.status).toBe("requires_action");
    expect(lapsed.steps[0]).toMatchObject({ status: "canceled", message: expect.stringMatching(/deadline passed before it was submitted/) });
    const waived = await intents.attest(c.id, attest(c.contract, w.user, { operationId: "step_1", outcome: "waived" }, w.clock.iso()));
    expect(waived).toMatchObject({ status: "failed", next_actions: [] });
  });
});

describe("creating intents", () => {
  const providers = () => ({ shop: sandboxProvider("shop", { status: "confirmed" }) });

  it("is safe to retry with your own id, and refuses a different request under the same id", async () => {
    const { create, intents } = setup(providers());
    const a = await create({ id: "order-1001", steps: [buy] });
    const again = await create({ id: "order-1001", steps: [buy] });
    expect(again.id).toBe(a.id);
    expect((await intents.events(a.id)).length).toBe(1);
    await expect(create({ id: "order-1001", goal: "Something else", steps: [buy] })).rejects.toThrow(/already exists with a different goal or steps/);
    await expect(create({ id: "order-1001", steps: [{ ...buy, action: "order.refund" }] })).rejects.toThrow(/already exists/);
  });

  it("rejects what can't work: unknown providers or agents, no agents, bad contracts", async () => {
    const { create, intents } = setup(providers());
    await expect(create({ steps: [{ ...buy, provider: "nowhere" }] })).rejects.toThrow(/unknown provider nowhere/);
    await expect(create({ steps: [{ ...buy, agent: "agent:ghost" }] })).rejects.toThrow(/not one of the intent's agents/);
    await expect(create({ agents: [], steps: [buy] })).rejects.toThrow(/at least one agent/);
    await expect(create({ steps: [{ ...buy, dependsOn: ["step_9"] }] })).rejects.toThrow(/depends on unknown operation/);
    await expect(intents.retrieve("oc_missing")).rejects.toThrow(/no outcome intent oc_missing/);
  });

  it("accepts shorthand for expectations and the full form, and maps undo to a pre-approved compensation", async () => {
    const { create } = setup(providers());
    const a = await create({ steps: [{ ...buy, expect: ["confirmed", "shipped"], undo: { action: "order.cancel", expect: "cancelled" } }] });
    expect(a.contract.operations[0]).toMatchObject({ expect: { success: ["confirmed", "shipped"] }, compensation: { action: "order.cancel", expect: { success: ["cancelled"] } } });
    const b = await create({ onRequiredFailure: "undo", steps: [{ ...buy, expect: { success: "confirmed", pending: ["processing"], failure: ["declined"] } }] });
    expect(b.contract.operations[0]!.expect).toMatchObject({ success: ["confirmed"], pending: ["processing"], failure: ["declined"] });
    expect(b.contract.policy.onRequiredFailure).toBe("compensate_completed");
  });

  it("answers a refused submit without hiding it", async () => {
    const { create, approve, intents } = setup(providers());
    const c = await create({ steps: [buy], budget: money("USD", 100) });
    await approve(c.id);
    const r = await intents.submit(c.id, "step_1", { agent: "agent:other" });
    expect(r).toMatchObject({ ok: false, reason: "agent agent:other may not execute step_1" });
    expect((await intents.events(c.id)).map((e) => e.type)).toContain("outcome_intent.refused");
  });
});

describe("events", () => {
  const build = async () => {
    const x = setup({ shop: sandboxProvider("shop", { status: "confirmed" }), courier: sandboxProvider("courier", { status: "booked" }) });
    const c = await x.create({ steps: [buy, ship] });
    return { ...x, c };
  };

  it("form a stable, ordered stream: created, status changes, each step, and the outcome", async () => {
    const { c, approve, intents } = await build();
    await approve(c.id);
    await intents.run(c.id, { agent: "agent:a" });
    const events = await intents.events(c.id);
    const types = events.map((e) => e.type);
    expect(types[0]).toBe("outcome_intent.created");
    expect(types).toEqual(expect.arrayContaining(["outcome_intent.processing", "outcome_intent.step.processing", "outcome_intent.step.succeeded", "outcome_intent.succeeded"]));
    expect(types.filter((t) => t === "outcome_intent.step.succeeded")).toHaveLength(2);
    expect(types.at(-1)).toBe("outcome_intent.succeeded");
    expect(events.at(-1)!.data.previous_status).toBe("processing");
    expect(events.at(-1)!.data.object.status).toBe("succeeded");
    expect(new Set(events.map((e) => e.id)).size).toBe(events.length);
    expect(await intents.events(c.id)).toEqual(events); // deterministic
    expect(await intents.events(c.id, { after: events.length - 1 })).toEqual([events.at(-1)]);
    expect(JSON.stringify(events)).not.toContain('"contract"');
    expect(events.find((e) => e.type === "outcome_intent.step.succeeded")!.data.step).toMatchObject({ id: "step_1", verified_by: "provider_record" });
  });

  it("report suspensions, incidents and requires_action transitions with what to do", async () => {
    const { w, c, approve, intents } = await build();
    await approve(c.id);
    await intents.suspend(c.id, suspend(c.contract, w.user, { reason: "hold" }, w.clock.iso()));
    const events = await intents.events(c.id);
    const act = events.find((e) => e.type === "outcome_intent.requires_action")!;
    expect(act.data.object.next_actions[0]).toMatchObject({ type: "resume" });
    expect(events.find((e) => e.type === "outcome_intent.suspended")!.data.reason).toBe("hold");
  });

  it("are delivered to subscribers exactly once, in order, across changes", async () => {
    const { w, c, approve, intents } = await build();
    const got: IntentEvent[] = [];
    const off = intents.subscribe((e) => { got.push(e); });
    await approve(c.id);
    await intents.run(c.id, { agent: "agent:a" });
    expect(got.map((e) => e.id)).toEqual((await intents.events(c.id)).map((e) => e.id));
    // A subscriber that joined after create still gets that event on the intent's next change; once unsubscribed, it hears nothing more.
    off();
    const seen = got.length;
    await intents.suspend(c.id, suspend(c.contract, w.user, {}, w.clock.iso()));
    expect(got.length).toBe(seen);
    expect((await intents.events(c.id)).length).toBeGreaterThan(seen);
  });

  it("are redelivered after a subscriber fails, without skipping or reordering anything", async () => {
    const errors: unknown[] = [];
    const x = setup({ shop: sandboxProvider("shop", { status: "confirmed" }), courier: sandboxProvider("courier", { status: "booked" }) }, {}, { onError: (e) => errors.push(e) });
    const received: string[] = [];
    let failures = 1;
    x.intents.subscribe(async (e) => {
      if (e.type === "outcome_intent.step.succeeded" && failures-- > 0) throw new Error("receiver down");
      received.push(e.type);
    });
    const c = await x.create({ steps: [buy, ship] });
    await x.approve(c.id);
    await x.intents.run(c.id, { agent: "agent:a" });
    expect(errors).toHaveLength(1);
    const beforeFlush = received.length;
    expect(received).not.toContain("outcome_intent.succeeded"); // held back behind the failed event, not skipped
    await x.intents.flush(c.id);
    const all = (await x.intents.events(c.id)).map((e) => e.type);
    expect(received).toEqual(all);
    expect(received.length).toBeGreaterThan(beforeFlush);
  });
});

describe("signed webhooks", () => {
  const secret = "whsec_test";
  const body = JSON.stringify({ hello: "world" });

  it("verify with the right secret, and reject tampering, the wrong secret, replays and junk", () => {
    const header = signWebhook(body, secret, 1_800_000_000);
    const now = () => 1_800_000_100;
    expect(verifyWebhook(body, header, secret, { now })).toEqual({ ok: true });
    expect(verifyWebhook(body + " ", header, secret, { now })).toMatchObject({ ok: false, reason: "signature does not match" });
    expect(verifyWebhook(body, header, "whsec_other", { now }).ok).toBe(false);
    expect(verifyWebhook(body, header, secret, { now: () => 1_800_001_000 })).toMatchObject({ ok: false, reason: "timestamp outside the tolerance window" });
    expect(verifyWebhook(body, header, secret, { now: () => 1_800_001_000, toleranceSeconds: 3600 }).ok).toBe(true);
    for (const junk of [undefined, "", "t=abc,v1=00", "v1=00", "t=1"]) expect(verifyWebhook(body, junk, secret, { now }).ok).toBe(false);
  });

  async function wired(respond: (url: string) => number) {
    const x = setup({ shop: sandboxProvider("shop", { status: "confirmed" }) });
    const posts: { url: string; body: string; sig: string }[] = [];
    const fetcher = (async (url: string, init: RequestInit) => {
      posts.push({ url, body: init.body as string, sig: (init.headers as Record<string, string>)["agentmesh-signature"]! });
      return new Response("", { status: respond(url) });
    }) as unknown as typeof fetch;
    const errors: unknown[] = [];
    const intents = new Intents(x.w.coordinator, { providers: { shop: {} }, onError: (e) => errors.push(e) });
    intents.subscribe(webhookSink({
      fetch: fetcher,
      endpoints: [{ url: "https://a.example/hooks", secret }, { url: "https://b.example/steps", secret: "whsec_b", types: ["outcome_intent.step.*"] }],
    }));
    const c = await intents.create({ goal: "g", principal: { id: "user:ana", key: x.w.user.publicKey }, agents: ["agent:a"], steps: [{ ...buy, spend: undefined }] });
    await intents.approve(c.id, approveContract(c.contract, x.w.user, x.w.clock.iso()));
    await intents.run(c.id, { agent: "agent:a" });
    return { intents, c, posts, errors };
  }

  it("deliver every event as a signed POST, honoring each endpoint's type filter", async () => {
    const { intents, c, posts, errors } = await wired(() => 200);
    expect(errors).toEqual([]);
    const events = await intents.events(c.id);
    const toA = posts.filter((p) => p.url.startsWith("https://a."));
    const toB = posts.filter((p) => p.url.startsWith("https://b."));
    expect(toA.map((p) => (JSON.parse(p.body) as IntentEvent).id)).toEqual(events.map((e) => e.id));
    expect(toB.every((p) => (JSON.parse(p.body) as IntentEvent).type.startsWith("outcome_intent.step."))).toBe(true);
    expect(toB.length).toBeGreaterThan(0);
    for (const p of toA) expect(verifyWebhook(p.body, p.sig, secret).ok).toBe(true);
    for (const p of toB) expect(verifyWebhook(p.body, p.sig, "whsec_b").ok).toBe(true);
    expect(verifyWebhook(toA[0]!.body, toA[0]!.sig, "whsec_b").ok).toBe(false);
  });

  it("treat a non-2xx answer as a failure and keep the event pending for retry", async () => {
    let up = false;
    const { intents, c, errors, posts } = await wired(() => (up ? 200 : 503));
    expect(errors.length).toBeGreaterThan(0);
    expect(String(errors[0])).toMatch(/answered 503/);
    const postedBefore = posts.length;
    up = true;
    await intents.flush(c.id);
    expect(posts.length).toBeGreaterThan(postedBefore);
    const delivered = new Set(posts.filter((p) => p.url.startsWith("https://a.")).map((p) => (JSON.parse(p.body) as IntentEvent).id));
    expect([...delivered].sort()).toEqual((await intents.events(c.id)).map((e) => e.id).sort()); // everything arrived at least once
  });
});
