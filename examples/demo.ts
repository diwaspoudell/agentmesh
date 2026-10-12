// The plan's first reference workflow: "Return my damaged headphones, obtain the refund, and purchase a
// replacement under $200." Two independent merchants, a shared budget, a step-up approval, a refund that settles
// days later, and an evidence bundle anyone can check. Run: npm run demo
import {
  approveContract, approveStepUp, contractDigest, defineContract, generateSigner, memoryStore, money, OutcomeCoordinator,
  renderReport, sandboxProvider, verifyBundle,
} from "../src/index.ts";

const DAY = 86_400_000;
let now = Date.parse("2026-10-12T09:00:00.000Z");
const clock = () => new Date(now);
const iso = (offset = 0) => new Date(now + offset).toISOString();
const say = (s: string) => console.log(`\n▸ ${s}`);

const user = generateSigner(); //   on the user's phone
const mesh = generateSigner(); //   the AgentMesh coordinator
const acmeKey = generateSigner(); // the merchant that sold the damaged pair
const soundKey = generateSigner(); // the merchant selling the replacement

// Providers check every request's mandate against keys they already trust, as a real integration would.
const trust = { principalKeys: [user.publicKey], coordinatorKeys: [mesh.publicKey] };
const acme = sandboxProvider("acme-audio", {
  signer: acmeKey, verify: trust, status: "received",
  actions: {
    "order.return": { pendingStatus: "return_authorized", status: "received" },
    "order.refund": { pendingStatus: "refund_issued", status: "refund_settled", credit: money("USD", "149.99") },
  },
});
const sound = sandboxProvider("soundhub", { signer: soundKey, verify: trust, status: "confirmed", details: { sku: "HP-300", carrier: "UPS" } });

const coordinator = new OutcomeCoordinator({ store: memoryStore(), signer: mesh, clock, connectors: { "acme-audio": acme.connector, soundhub: sound.connector } });

say("The personal agent turns the request into an outcome contract");
const contract = defineContract({
  createdAt: iso(),
  expiresAt: iso(30 * DAY),
  goal: "Return my damaged headphones, obtain the refund, and purchase a replacement under $200.",
  principal: { id: "user:ana", keys: [user.publicKey] },
  coordinator: { id: "agentmesh", keys: [mesh.publicKey] },
  participants: [
    { id: "agent:muse", role: "agent", name: "Ana's personal agent" },
    { id: "acme-audio", role: "provider", keys: [acmeKey.publicKey] },
    { id: "soundhub", role: "provider", keys: [soundKey.publicKey] },
  ],
  constraints: { budget: money("USD", 200), approvalAbove: money("USD", 100) },
  operations: [
    {
      id: "return", provider: "acme-audio", action: "order.return", executors: ["agent:muse"], description: "Return the damaged HP-200",
      params: { orderId: "A-1001", sku: "HP-200", reason: "damaged" }, deadline: iso(14 * DAY),
      expect: { success: ["received"], pending: ["return_authorized"], failure: ["return_denied"] },
    },
    {
      id: "refund", provider: "acme-audio", action: "order.refund", executors: ["agent:muse"], dependsOn: ["return"], description: "Refund to the original card",
      params: { orderId: "A-1001" }, deadline: iso(21 * DAY),
      expect: { success: ["refund_settled"], pending: ["refund_issued"], failure: ["refund_denied"], credit: { min: money("USD", "149.99") } },
    },
    {
      id: "replacement", provider: "soundhub", action: "order.create", executors: ["agent:muse"], description: "Buy a replacement pair",
      params: { category: "over-ear headphones" }, spend: money("USD", 200),
      expect: { success: ["confirmed"], failure: ["declined"], checks: [{ path: "details.sku", op: "exists" }] },
      evidence: ["signed_receipt"],
    },
  ],
});
console.log(`  contract ${contract.id}\n  digest   ${contractDigest(contract)}`);
await coordinator.open(contract);

say("Ana approves it on her phone (her key signs the digest)");
await coordinator.approve(contract.id, approveContract(contract, user, iso()));

say("The agent starts the return and tries to buy a $179.99 replacement");
const replacement = { amount: money("USD", "179.99"), details: { sku: "HP-300", merchant: "soundhub" } };
await coordinator.submit(contract.id, "return", { agent: "agent:muse" });
const attempt = await coordinator.submit(contract.id, "replacement", { agent: "agent:muse", ...replacement });
console.log(`  replacement: ${attempt.ok ? "submitted" : `refused: ${attempt.reason}`}`);

say("Ana confirms the exact purchase; the agent retries");
await coordinator.stepUp(contract.id, approveStepUp(contract, user, "replacement", replacement, iso()));
await coordinator.submit(contract.id, "replacement", { agent: "agent:muse", ...replacement });
console.log(renderReport(await coordinator.report(contract.id)).replace(/^(?=.)/gm, "  "));

say("Three days later the merchant receives the return, and the refund can start");
now += 3 * DAY;
acme.settle("return");
await coordinator.run(contract.id, { agent: "agent:muse" });

say("Five days after that the card processor settles the refund (pushed as a signed webhook)");
now += 5 * DAY;
acme.settle("refund");
await coordinator.ingestReceipt(acme.receiptFor("refund")!);

say("Final outcome");
console.log(renderReport(await coordinator.report(contract.id)).replace(/^(?=.)/gm, "  "));

say("Anyone with the coordinator's public key can re-derive that from the evidence bundle");
const bundle = await coordinator.exportBundle(contract.id);
const v = verifyBundle(bundle, { coordinatorKeys: [mesh.publicKey], principalKeys: [user.publicKey] });
console.log(`  ${bundle.events.length} events · verified: ${v.ok} · outcome: ${v.report?.status}`);
const forged = structuredClone(bundle);
const charge = forged.events.find((e) => e.body.type === "operation.submitting" && e.body.operationId === "replacement" && e.body.amount);
if (charge && charge.body.type === "operation.submitting") charge.body.amount = money("USD", "250.00");
console.log(`  after changing the approved amount to $250: verified: ${verifyBundle(forged, { coordinatorKeys: [mesh.publicKey] }).ok}`);
console.log(`  requests the merchants refused as unauthorized: ${acme.rejections.length + sound.rejections.length}`);
