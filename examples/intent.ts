// The developer view: one object per business outcome, one status to switch on, and what a person has to do.
// "Return my damaged headphones, get the refund, and buy a replacement under $200." Run: npm run demo:intent
import {
  approveContract, approveStepUp, generateSigner, Intents, memoryStore, money, OutcomeCoordinator, sandboxProvider, verifyBundle, webhookSink, verifyWebhook,
} from "../src/index.ts";

let now = Date.parse("2026-10-12T09:00:00.000Z");
const user = generateSigner(), mesh = generateSigner(), acmeKey = generateSigner();
const acme = sandboxProvider("acme", {
  signer: acmeKey, status: "received",
  actions: { "order.refund": { status: "refunded", credit: money("USD", "149.99") } },
});
const soundhub = sandboxProvider("soundhub", { status: "confirmed" });

const coordinator = new OutcomeCoordinator({
  store: memoryStore(), signer: mesh, clock: () => new Date(now),
  connectors: { acme: acme.connector, soundhub: soundhub.connector },
});
const intents = new Intents(coordinator, { providers: { acme: { keys: [acmeKey.publicKey] }, soundhub: {} } });

// Events arrive as signed webhooks (here to an in-memory receiver that checks the signature).
const secret = "whsec_demo";
const received: string[] = [];
intents.subscribe(webhookSink({
  now: () => Math.floor(now / 1000), // the demo runs on a simulated clock; real deployments leave this out
  endpoints: [{ url: "https://app.example/hooks", secret }],
  fetch: (async (_url: string, init: RequestInit) => {
    const ok = verifyWebhook(init.body as string, (init.headers as Record<string, string>)["agentmesh-signature"], secret, { now: () => Math.floor(now / 1000) }).ok;
    received.push(`${JSON.parse(init.body as string).type}${ok ? "" : " (BAD SIGNATURE)"}`);
    return new Response("", { status: ok ? 200 : 400 });
  }) as unknown as typeof fetch,
}));

const show = (label: string, i: Awaited<ReturnType<typeof intents.retrieve>>) => {
  console.log(`\n${label}\n  status: ${i.status}   (${i.summary})`);
  for (const s of i.steps) console.log(`  - ${s.id.padEnd(12)} ${s.status.padEnd(10)}${s.verified_by ? ` via ${s.verified_by}` : ""}${s.charged ? `, charged $${s.charged.minor / 100}` : ""}${s.refunded ? `, refunded $${s.refunded.minor / 100}` : ""}`);
  for (const a of i.next_actions) console.log(`  → needs you: ${a.type}${a.step ? ` (${a.step})` : ""}: ${a.reason}`);
};

let intent = await intents.create({
  goal: "Return my damaged headphones, get the refund, and buy a replacement under $200.",
  principal: { id: "user:ana", key: user.publicKey },
  agents: ["agent:muse"],
  budget: money("USD", 200),
  approveAbove: money("USD", 100),
  steps: [
    { id: "return", provider: "acme", action: "order.return", params: { orderId: "A-1001" }, expect: "received" },
    { id: "refund", provider: "acme", action: "order.refund", dependsOn: ["return"], expect: { success: "refunded", credit: { min: money("USD", "149.99") } } },
    { id: "replacement", provider: "soundhub", action: "order.create", spend: money("USD", 180), expect: "confirmed" },
  ],
});
show("1. Created. Nothing happens until the user signs it.", intent);

intent = await intents.approve(intent.id, approveContract(intent.contract, user, new Date(now).toISOString()));
intent = await intents.run(intent.id, { agent: "agent:muse" });
show("2. Approved and run: the $180 purchase is above the $100 threshold, so it waits for the user's say-so.", intent);

intent = await intents.stepUp(intent.id, approveStepUp(intent.contract, user, "replacement", { amount: money("USD", 180) }, new Date(now).toISOString()));
intent = await intents.run(intent.id, { agent: "agent:muse" });
show("3. The user approved that exact purchase; the agent finished.", intent);

const bundle = await intents.bundle(intent.id);
const v = verifyBundle(bundle, { coordinatorKeys: [mesh.publicKey], principalKeys: [user.publicKey] });
console.log(`\n4. Evidence: ${bundle.events.length} log entries, independently verified: ${v.ok}`);
console.log(`\n5. Webhooks delivered, in order: ${received.length}\n  ${received.join("\n  ")}`);
