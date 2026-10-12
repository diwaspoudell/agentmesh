import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import {
  createWitness, discloseIncident, eventHash, generateSigner, makeBundle, money, OutcomeCoordinator, providerPack, renderLog, replay, reportIncident,
  suspend, verifyBundle, verifyProviderPack, withWitnessings, type Checkpoint, type OutcomeBundle, type Signed, type StoredEvent,
} from "../src/index.ts";
import { run as runCli } from "../src/cli.ts";
import { contractFor, openApproved, sandboxProvider, world, type World } from "./helpers.ts";

/** What an operator holding the coordinator's key could do: change history, rebuild the hash chain, and sign the result. */
function rewrite(w: World, events: StoredEvent[], index: number, mutate: (body: any) => void, keep?: number): OutcomeBundle {
  const out = structuredClone(events);
  mutate(out[index]!.body);
  let prev = index === 0 ? out[0]!.prev : out[index - 1]!.hash;
  for (let i = index; i < out.length; i++) {
    out[i]!.prev = prev;
    out[i]!.hash = eventHash({ transactionId: out[i]!.transactionId, seq: out[i]!.seq, at: out[i]!.at, prev, body: out[i]!.body });
    prev = out[i]!.hash;
  }
  const kept = out.slice(0, keep ?? out.length);
  const last = kept.at(-1)!;
  return makeBundle(kept, w.mesh.sign({ type: "agentmesh.checkpoint", transactionId: last.transactionId, seq: last.seq, head: last.hash, at: w.clock.iso() }));
}

async function scenario(every = 4) {
  const shop = sandboxProvider("shop", { status: "confirmed" });
  const w = world({ shop: shop.connector });
  const published: Signed<Checkpoint>[] = [];
  const errors: unknown[] = [];
  const coordinator = new OutcomeCoordinator({
    store: w.store, signer: w.mesh, connectors: { shop: shop.connector }, clock: w.clock.now,
    checkpoints: { every, publish: (cp) => { published.push(cp); }, onError: (e) => errors.push(e) },
  });
  const c = contractFor(w, {
    goal: "Buy a replacement under $200", constraints: { budget: money("USD", 200) },
    participants: [{ id: "agent:a", role: "agent" }, { id: "agent:rogue", role: "agent" }, { id: "shop", role: "provider" }],
    operations: [{ id: "buy", provider: "shop", action: "order.create", executors: ["agent:a"], spend: money("USD", 150), expect: { success: ["confirmed"] } }],
  });
  await coordinator.open(c);
  await coordinator.approve(c.id, (await import("../src/index.ts")).approveContract(c, w.user, w.clock.iso()));
  await coordinator.submit(c.id, "buy", { agent: "agent:rogue" }); // refused: not delegated
  await coordinator.submit(c.id, "buy", { agent: "agent:a" });
  await coordinator.reconcile(c.id);
  return { w, c, coordinator, published, errors, shop };
}

describe("periodic checkpoints and anchors", () => {
  it("publishes a signed checkpoint each time the log grows past a multiple of N", async () => {
    const { coordinator, published, c } = await scenario(4);
    const events = await coordinator.events(c.id);
    expect(published.length).toBe(Math.floor(events.length / 4));
    for (const cp of published) expect(events[cp.payload.seq - 1]!.hash).toBe(cp.payload.head);
  });

  it("never lets a failing publisher stop a transaction, and reports the failure", async () => {
    const shop = sandboxProvider("shop", { status: "confirmed" });
    const w = world({ shop: shop.connector });
    const errors: unknown[] = [];
    const coordinator = new OutcomeCoordinator({
      store: w.store, signer: w.mesh, connectors: { shop: shop.connector }, clock: w.clock.now,
      checkpoints: { every: 1, publish: () => { throw new Error("archive offline"); }, onError: (e) => errors.push(e) },
    });
    const c = contractFor(w, { goal: "x", participants: [{ id: "agent:a", role: "agent" }, { id: "shop", role: "provider" }], operations: [{ id: "buy", provider: "shop", action: "x", executors: ["agent:a"], expect: { success: ["confirmed"] } }] });
    await coordinator.open(c);
    expect(errors.length).toBeGreaterThan(0);
    expect((await coordinator.state(c.id)).seq).toBe(1);
  });

  it("catches a history rewrite that the operator re-signed, which plain verification cannot", async () => {
    const { w, c, coordinator, published } = await scenario(4);
    const events = await coordinator.events(c.id);
    const refusalAt = events.findIndex((e) => e.body.type === "operation.refused");
    const forged = rewrite(w, events, refusalAt, (b) => { b.reason = "everything was fine"; });

    const trust = { coordinatorKeys: [w.mesh.publicKey] };
    expect(verifyBundle(forged, trust).ok).toBe(true); // internally consistent, signed by the real key
    const caught = verifyBundle(forged, { ...trust, anchors: published });
    expect(caught.ok).toBe(false);
    expect(caught.problems.join()).toMatch(/history was rewritten: entry \d+ no longer matches the checkpoint published for it/);
    expect(verifyBundle(await coordinator.exportBundle(c.id), { ...trust, anchors: published }).ok).toBe(true);
  });

  it("catches truncation, and ignores anchors signed by an untrusted key", async () => {
    const { w, c, coordinator, published } = await scenario(2);
    const events = await coordinator.events(c.id);
    const cut = rewrite(w, events, events.length - 1, () => {}, events.length - 3);
    const trust = { coordinatorKeys: [w.mesh.publicKey] };
    expect(verifyBundle(cut, { ...trust, anchors: published }).problems.join()).toMatch(/entries were removed|rewritten/);
    const fake = generateSigner().sign({ ...published[0]!.payload });
    expect(verifyBundle(cut, { ...trust, anchors: [fake] }).problems.join()).toMatch(/not signed by a trusted coordinator key/);
  });
});

describe("independent witnesses", () => {
  it("co-sign what they saw, and refuse to sign a history that conflicts with it", async () => {
    const { w, c, coordinator } = await scenario();
    const auditor = generateSigner();
    const witness = createWitness(auditor, { coordinatorKeys: [w.mesh.publicKey], clock: w.clock.now });
    const first = await coordinator.exportBundle(c.id);
    const seen = witness.observe(first);
    expect(seen.ok).toBe(true);

    // The log grows legitimately and is witnessed again.
    await coordinator.attest(c.id, (await import("../src/index.ts")).attest(c, w.user, { operationId: "buy", outcome: "succeeded" }, w.clock.iso()));
    const second = await coordinator.exportBundle(c.id);
    expect(witness.observe(second).ok).toBe(true);

    // A rewritten history, validly signed by the coordinator, is refused.
    const events = await coordinator.events(c.id);
    const refusalAt = events.findIndex((e) => e.body.type === "operation.refused");
    const forged = rewrite(w, events, refusalAt, (b) => { b.reason = "fine"; });
    expect(witness.observe(forged)).toMatchObject({ ok: false, problems: [expect.stringMatching(/history was rewritten/)] });
    const truncated = rewrite(w, events, events.length - 1, () => {}, 5);
    expect(witness.observe(truncated).problems.join()).toMatch(/truncated/);
  });

  it("are required by verifyBundle when you ask for them, and can't be forged or reused across histories", async () => {
    const { w, c, coordinator } = await scenario();
    const a1 = generateSigner(), a2 = generateSigner();
    const wit1 = createWitness(a1, { coordinatorKeys: [w.mesh.publicKey] }), wit2 = createWitness(a2, { coordinatorKeys: [w.mesh.publicKey] });
    const bundle = await coordinator.exportBundle(c.id);
    const s1 = wit1.observe(bundle).statement!, s2 = wit2.observe(bundle).statement!;
    const trust = { coordinatorKeys: [w.mesh.publicKey], witnesses: { keys: [a1.publicKey, a2.publicKey], required: 2 } };

    expect(verifyBundle(bundle, trust).problems.join()).toMatch(/needs 2 independent witnesses, found 0/);
    expect(verifyBundle(withWitnessings(bundle, [s1]), trust).problems.join()).toMatch(/found 1/);
    const both = verifyBundle(withWitnessings(bundle, [s1, s2]), trust);
    expect(both.problems).toEqual([]);
    expect(both.witnessed).toHaveLength(2);
    // A witness nobody trusts doesn't count.
    const stranger = createWitness(generateSigner(), { coordinatorKeys: [w.mesh.publicKey] }).observe(bundle).statement!;
    expect(verifyBundle(withWitnessings(bundle, [s1, stranger]), trust).problems.join()).toMatch(/found 1/);
    // Real statements attached to a rewritten log contradict it.
    const events = await coordinator.events(c.id);
    const forged = rewrite(w, events, events.findIndex((e) => e.body.type === "operation.refused"), (b) => { b.reason = "fine"; });
    expect(verifyBundle(withWitnessings(forged, [s1, s2]), trust).problems.join()).toMatch(/saw a different history at entry \d+/);
  });
});

describe("readable log", () => {
  it("describes each entry in a sentence, including refusals, proof and what didn't count", async () => {
    const { c, coordinator, w } = await scenario();
    await coordinator.recordClaim(c.id, "buy", { agent: "agent:a", observation: { status: "confirmed" } });
    const lines = renderLog(await coordinator.events(c.id));
    expect(lines).toHaveLength((await coordinator.events(c.id)).length);
    const text = lines.join("\n");
    expect(text).toMatch(/#001 2026-10-12 09:00:00Z {2}Contract registered: "Buy a replacement under \$200" \(1 operation, shared budget \$200\.00\)/);
    expect(text).toMatch(/The principal approved the contract\./);
    expect(text).toMatch(/REFUSED: agent:rogue → buy \(execute\): agent agent:rogue may not execute buy \[violation\]/);
    expect(text).toMatch(/agent:a had shop order\.create for buy \$150\.00 \(attempt 1, key am_/);
    expect(text).toMatch(/Authorized and recorded before sending\./);
    expect(text).toMatch(/Provider's records \(response\): buy is "confirmed"/);
    expect(text).toMatch(/\[counts as proof\]/);
    expect(text).toMatch(/agent:a reported buy is "confirmed" \[claim, not evidence\]/);
    expect(w.clock.iso()).toBeTruthy();
  });

  it("refuses to render a log that breaks the contract's rules", async () => {
    const { w, c, coordinator } = await scenario();
    const events = await coordinator.events(c.id);
    const forged = rewrite(w, events, events.findIndex((e) => e.body.type === "operation.submitting"), (b) => { b.agent = "agent:rogue"; });
    expect(() => renderLog(forged.events)).toThrow();
  });
});

describe("incidents and disclosure", () => {
  async function withIncident() {
    const x = await scenario();
    const { c, coordinator, w } = x;
    await coordinator.suspend(c.id, suspend(c, w.user, { agent: "agent:rogue", reason: "tried to buy without delegation" }, w.clock.iso()));
    await coordinator.reportIncident(c.id, reportIncident(c, w.user, {
      id: "inc_test1", severity: "high", category: "unauthorized_attempt",
      summary: "agent:rogue tried to place an order for buy on shop for a goal it was never delegated.",
      controls: [{ control: "executor delegation", held: true, detail: "refused before reaching shop" }, { control: "prompt hardening", held: false, detail: "agent:rogue followed an injected instruction" }],
      affectedOperations: ["buy"], actions: ["suspended agent:rogue"],
      runtimeChanges: [{ description: "agent:rogue now needs principal approval for any purchase", detail: { rule: "purchase requires step-up", scope: "agent:rogue" } }],
      prevention: ["strip tool instructions from retrieved web pages before the agent sees them"],
    }, w.clock.iso()));
    return x;
  }

  it("accepts signed incident accounts only from keys the contract names, once per id", async () => {
    const { c, coordinator, w } = await withIncident();
    await expect(coordinator.reportIncident(c.id, reportIncident(c, generateSigner(), { severity: "low", category: "other", summary: "x" }, w.clock.iso()))).rejects.toThrow(/not signed by a key the contract names/);
    await expect(coordinator.reportIncident(c.id, reportIncident(c, w.user, { id: "inc_test1", severity: "low", category: "other", summary: "x" }, w.clock.iso()))).rejects.toThrow(/already reported/);
    await expect(coordinator.reportIncident(c.id, reportIncident(c, w.user, { severity: "low", category: "other", summary: "x", affectedOperations: ["nope"] }, w.clock.iso()))).rejects.toThrow(/unknown operation/);
    expect((await coordinator.report(c.id)).incidents.map((i) => i.id)).toEqual(["inc_test1"]);
  });

  it("gives affected parties the full account with a way to match it to the evidence", async () => {
    const { c, coordinator } = await withIncident();
    const events = await coordinator.events(c.id);
    const d = discloseIncident(events, "inc_test1", { audience: "affected" });
    expect(d.transaction).toBe(c.id);
    expect(d.incident.controls).toContainEqual({ control: "prompt hardening", held: false, detail: "agent:rogue followed an injected instruction" });
    expect(d.timeline.join("\n")).toMatch(/REFUSED: agent:rogue → buy/);
    expect(d.anchor!.hash).toBe(events.find((e) => e.body.type === "incident.reported")!.hash);
  });

  it("shares the lessons publicly without the transaction, people, or identifiers", async () => {
    const { c, coordinator } = await withIncident();
    const d = discloseIncident(await coordinator.events(c.id), "inc_test1", { audience: "public" });
    const text = JSON.stringify(d);
    for (const secret of [c.id, "agent:rogue", "agent:a", "shop", "user:ana", "Buy a replacement", "150", "buy"]) expect(text).not.toContain(secret);
    expect(d.transaction).toMatch(/^tx-[0-9a-f]{12}$/);
    expect(d.incident.summary).toBe("agent-2 tried to place an order for operation-1 on provider-1 for a goal it was never delegated.");
    expect(d.incident.runtimeChanges[0]).toEqual({
      description: "agent-2 now needs principal approval for any purchase", detail: { rule: "purchase requires step-up", scope: "agent-2" },
    });
    expect(d.incident.prevention).toEqual(["strip tool instructions from retrieved web pages before the agent sees them"]);
    expect(d.anchor).toBeUndefined();
    expect(d.timeline.every((t) => /^\+\d+s /.test(t))).toBe(true);
  });
});

describe("provider evidence packs", () => {
  async function twoProviders() {
    const aKey = generateSigner();
    const airline = sandboxProvider("airline", { status: "ticketed", signer: aKey });
    const hotel = sandboxProvider("hotel", { status: "confirmed" });
    const w = world({ airline: airline.connector, hotel: hotel.connector });
    const c = contractFor(w, {
      goal: "Rebook my cancelled trip to Lisbon for the funeral", constraints: { budget: money("USD", 500) },
      participants: [{ id: "agent:a", role: "agent" }, { id: "airline", role: "provider", keys: [aKey.publicKey] }, { id: "hotel", role: "provider" }],
      operations: [
        { id: "flight", provider: "airline", action: "booking.create", executors: ["agent:a"], spend: money("USD", 300), expect: { success: ["ticketed"] }, params: { route: "SFO-LIS" } },
        { id: "room", provider: "hotel", action: "booking.modify", executors: ["agent:a"], spend: money("USD", 150), expect: { success: ["confirmed"] }, params: { nights: 3 } },
      ],
    });
    await openApproved(w, c);
    await w.coordinator.run(c.id, { agent: "agent:a" });
    return { w, c, aKey };
  }

  it("contains only what that provider may see, and verifies with keys it already trusts", async () => {
    const { w, c, aKey } = await twoProviders();
    const pack = providerPack(await w.coordinator.events(c.id), "airline");
    const text = JSON.stringify(pack);
    for (const hidden of ["Lisbon", "funeral", "hotel", "room", "booking.modify", "nights", "500"]) expect(text).not.toContain(hidden);
    expect(pack.operations.map((o) => o.operation.id)).toEqual(["flight"]);
    expect(pack.operations[0]!.submissions[0]!.result).toMatchObject({ outcome: "accepted" });
    const trust = { principalKeys: [w.user.publicKey], coordinatorKeys: [w.mesh.publicKey], receiptKeys: [aKey.publicKey] };
    expect(verifyProviderPack(pack, trust)).toEqual({ ok: true, problems: [] });
  });

  it("detects altered terms, wrong principals, and receipts that aren't the provider's", async () => {
    const { w, c, aKey } = await twoProviders();
    const pack = providerPack(await w.coordinator.events(c.id), "airline");
    const trust = { principalKeys: [w.user.publicKey], coordinatorKeys: [w.mesh.publicKey], receiptKeys: [aKey.publicKey] };
    const tampered = structuredClone(pack);
    tampered.operations[0]!.operation.params = { route: "SFO-NYC" };
    expect(verifyProviderPack(tampered, trust).problems.join()).toMatch(/not part of the approved contract/);
    expect(verifyProviderPack(pack, { ...trust, principalKeys: [generateSigner().publicKey] }).problems.join()).toMatch(/approval is not signed by a trusted principal key/);
    expect(verifyProviderPack(pack, { ...trust, coordinatorKeys: [generateSigner().publicKey] }).problems.join()).toMatch(/authorization is not signed by a trusted coordinator key/);
    expect(verifyProviderPack(pack, { ...trust, receiptKeys: [generateSigner().publicKey] }).problems.join()).toMatch(/receipt does not verify with your key/);
    expect(() => providerPack([], "nobody")).toThrow();
  });
});

describe("agentmesh-verify", () => {
  it("verifies a bundle from files, prints the log and report, and fails on tampering", async () => {
    const { w, c, coordinator, published } = await scenario(3);
    const dir = mkdtempSync(join(tmpdir(), "agentmesh-cli-"));
    const bundle = await coordinator.exportBundle(c.id);
    const write = (name: string, v: unknown) => { const f = join(dir, name); writeFileSync(f, JSON.stringify(v)); return f; };
    const files = { bundle: write("bundle.json", bundle), mesh: write("mesh.json", w.mesh.publicKey), user: write("user.json", w.user.publicKey), anchor: write("anchor.json", published[0]) };

    const out: string[] = [];
    expect(runCli([files.bundle, "--coordinator-key", files.mesh, "--principal-key", files.user, "--anchor", files.anchor, "--log", "--report"], (l) => out.push(l))).toBe(0);
    const text = out.join("\n");
    expect(text).toMatch(/^VERIFIED/);
    expect(text).toMatch(/#001 .*Contract registered/);
    expect(text).toMatch(/Status: COMPLETED/);

    const events = await coordinator.events(c.id);
    const forged = rewrite(w, events, events.findIndex((e) => e.body.type === "operation.refused"), (b) => { b.reason = "fine"; });
    const bad: string[] = [];
    expect(runCli([write("forged.json", forged), "--coordinator-key", files.mesh, "--anchor", files.anchor], (l) => bad.push(l))).toBe(1);
    expect(bad.join("\n")).toMatch(/FAILED[\s\S]*history was rewritten/);

    const json: string[] = [];
    expect(runCli([files.bundle, "--coordinator-key", JSON.stringify(w.mesh.publicKey), "--json"], (l) => json.push(l))).toBe(0);
    expect(JSON.parse(json.join("\n"))).toMatchObject({ ok: true, outcome: "completed" });
    expect(runCli([], () => {})).toBe(2);
    expect(runCli([files.bundle], () => {})).toBe(2);
    expect(runCli([files.bundle, "--coordinator-key", files.mesh, "--bogus"], () => {})).toBe(2);
    expect(replay(events).seq).toBe(events.length);
  });
});
