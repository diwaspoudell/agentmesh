// The safety controls working together: separation of duties, an independent cross-check, an organization policy,
// a circuit breaker, an emergency stop, a witnessed log that a re-signing operator can't rewrite, and a public
// incident write-up. Run: npm run demo:safety
import {
  approveContract, createWitness, defineContract, denyActions, discloseIncident, endorse, eventHash, generateSigner, makeBundle, memoryStore,
  money, OutcomeCoordinator, renderLog, renderReport, resume, sandboxProvider, suspend, verifyBundle, withWitnessings, type StoredEvent,
} from "../src/index.ts";

let now = Date.parse("2026-10-12T09:00:00.000Z");
const iso = () => new Date(now).toISOString();
const say = (s: string) => { now += 7_000; console.log(`\n▸ ${s}`); };

const user = generateSigner(), mesh = generateSigner(), security = generateSigner(), claudeKey = generateSigner(), auditorKey = generateSigner();
const shop = sandboxProvider("shop", { status: "confirmed" });
const wire = sandboxProvider("wire", { status: "confirmed" });

const published: Awaited<ReturnType<OutcomeCoordinator["exportBundle"]>>["checkpoint"][] = [];
const coordinator = new OutcomeCoordinator({
  store: memoryStore(), signer: mesh, clock: () => new Date(now), connectors: { shop: shop.connector, wire: wire.connector },
  policy: [denyActions(["payment.*"], "no-direct-payments")], // the organization's rule, whatever any contract says
  checkpoints: { every: 5, publish: (cp) => { published.push(cp); } }, // handed to someone the operator can't rewrite
});

say("A contract where one vendor's agent proposes and another vendor's agent must concur");
const contract = defineContract({
  createdAt: iso(), expiresAt: new Date(now + 7 * 86_400_000).toISOString(), goal: "Buy a $120 replacement monitor",
  principal: { id: "user:ana", keys: [user.publicKey] }, coordinator: { id: "agentmesh", keys: [mesh.publicKey] },
  participants: [
    { id: "agent:buyer", role: "agent", vendor: "openai" },
    { id: "agent:reviewer", role: "agent", vendor: "anthropic", keys: [claudeKey.publicKey] },
    { id: "agent:rogue", role: "agent", vendor: "openai" },
    { id: "shop", role: "provider" }, { id: "wire", role: "provider" },
    { id: "security", role: "controller", keys: [security.publicKey] },
    { id: "audit", role: "auditor", keys: [auditorKey.publicKey] },
  ],
  constraints: { budget: money("USD", 200) },
  policy: { circuitBreaker: { violations: 3, windowSeconds: 300 } },
  operations: [
    { id: "buy", provider: "shop", action: "order.create", executors: ["agent:buyer"], spend: money("USD", 120), crossCheck: { min: 1, distinctVendors: true }, expect: { success: ["confirmed"] } },
    { id: "pay", provider: "wire", action: "payment.transfer", executors: ["agent:buyer"], spend: money("USD", 80), expect: { success: ["confirmed"] } },
  ],
});
await coordinator.open(contract);
await coordinator.approve(contract.id, approveContract(contract, user, iso()));
try {
  defineContract({ ...contract, id: undefined, participants: contract.participants.map((p) => (p.id === "audit" ? { ...p, keys: [mesh.publicKey] } : p)) });
} catch (e) { console.log(`  an auditor holding the coordinator's key is refused: ${(e as Error).message.replace(/^Invalid outcome contract: /, "")}`); }

say("The buyer agent tries to order; nobody has reviewed the exact request yet");
const order = { agent: "agent:buyer", amount: money("USD", 120), details: { sku: "MON-27" } };
console.log(`  refused: ${(await coordinator.submit(contract.id, "buy", order) as { reason: string }).reason}`);
say("An agent from a different vendor reviews it and concurs, then the order goes through");
await coordinator.endorse(contract.id, endorse(contract, claudeKey, { agent: "agent:reviewer", operationId: "buy", amount: money("USD", 120), details: order.details }, iso()));
console.log(`  submitted: ${(await coordinator.submit(contract.id, "buy", order)).ok}`);

say("The organization's own policy blocks a payment, though the contract allows it");
console.log(`  refused: ${(await coordinator.submit(contract.id, "pay", { agent: "agent:buyer" }) as { reason: string }).reason}`);

say("A rogue agent starts probing; the circuit breaker suspends it after three forbidden requests");
for (let i = 0; i < 3; i++) await coordinator.submit(contract.id, "buy", { agent: "agent:rogue" });
console.log(renderReport(await coordinator.report(contract.id)).split("\n").filter((l) => /SUSPENDED|Incident/.test(l)).map((l) => `  ${l}`).join("\n"));

say("Security pulls the emergency brake; the principal cannot undo the organization's stop");
await coordinator.suspend(contract.id, suspend(contract, security, { reason: "investigating rogue agent" }, iso()));
try { await coordinator.resume(contract.id, resume(contract, user, {}, iso())); } catch (e) { console.log(`  principal tried to resume: ${(e as Error).message.replace(/^event \d+: /, "")}`); }
await coordinator.resume(contract.id, resume(contract, security, {}, iso()));

say("An independent auditor witnesses the log");
const witness = createWitness(auditorKey, { coordinatorKeys: [mesh.publicKey], clock: () => new Date(now) });
const bundle = await coordinator.exportBundle(contract.id);
const statement = witness.observe(bundle).statement!;

say("An operator with the coordinator's key rewrites history and re-signs it");
const events: StoredEvent[] = structuredClone(await coordinator.events(contract.id));
const refusal = events.findIndex((e) => e.body.type === "operation.refused");
(events[refusal]!.body as { reason: string }).reason = "everything was fine";
let prev = events[refusal - 1]!.hash;
for (let i = refusal; i < events.length; i++) { events[i]!.prev = prev; events[i]!.hash = eventHash({ transactionId: events[i]!.transactionId, seq: events[i]!.seq, at: events[i]!.at, prev, body: events[i]!.body }); prev = events[i]!.hash; }
const last = events.at(-1)!;
const forged = makeBundle(events, mesh.sign({ type: "agentmesh.checkpoint", transactionId: last.transactionId, seq: last.seq, head: last.hash, at: iso() }));
const trust = { coordinatorKeys: [mesh.publicKey] };
console.log(`  plain verification:          ${verifyBundle(forged, trust).ok ? "passes (the forgery is internally consistent)" : "fails"}`);
console.log(`  against published anchors:   ${verifyBundle(forged, { ...trust, anchors: published }).problems[0] ?? "passes"}`);
console.log(`  with the witness's statement: ${verifyBundle(withWitnessings(forged, [statement]), { ...trust, witnesses: { keys: [auditorKey.publicKey], required: 1 } }).problems[0]}`);
console.log(`  the real log, witnessed:     ${verifyBundle(withWitnessings(bundle, [statement]), { ...trust, anchors: published, witnesses: { keys: [auditorKey.publicKey], required: 1 } }).ok ? "verified" : "failed"}`);

say("What the log says, in plain sentences (last few entries)");
console.log(renderLog(await coordinator.events(contract.id)).slice(-6).map((l) => `  ${l}`).join("\n"));

say("The lessons, shareable publicly without the transaction, the people, or the identifiers");
const incident = (await coordinator.state(contract.id)).incidents[0]!.report.payload.id;
console.log(JSON.stringify(discloseIncident(await coordinator.events(contract.id), incident, { audience: "public" }), null, 2).replace(/^/gm, "  "));
console.log(`\n  ground truth: the shop took ${shop.effects.length} order and the wire took ${wire.effects.length} payments.`);
