# AgentMesh

**Stripe-like OutcomeIntents for AI agents.**

An *outcome intent* is one object for one business outcome that spans several agents and services. You create it, the user authorizes it, agents carry it out, and you read one status plus what (if anything) needs a person. Behind that status is evidence, not an agent's say-so: what was authorized, what was committed, what the providers actually did, and what is still unresolved.

| For | The promise | What backs it today |
| --- | --- | --- |
| **Developers** | One API to create, authorize, track, verify, and recover a business outcome spanning multiple agents and services. | `Intents`: `create`, `approve`, `run`, `retrieve`, `events` and signed webhooks, with a single status (`requires_approval`, `processing`, `requires_action`, `succeeded`, `partially_succeeded`, `failed`, `canceled`) and a `next_actions` list. |
| **Enterprises** | A neutral transaction assurance layer that makes agent-driven operations easier to audit, reconcile, and recover. | A tamper-evident evidence log that anyone can re-verify offline; reconciliation against providers' own records and signed receipts; independent witnesses and published checkpoints; role separation, policy gates, emergency stop, incident disclosure. |
| **Consumers** | Your agent doesn't just report that a task is done. You can see what actually happened, what was verified, and what still needs attention. | Every step reports whether it is confirmed, by what (a signed receipt, the provider's records, or a person), and what it cost; anything unconfirmed is surfaced as `unknown`, `disputed` or a task for you, never as "done". |

What to expect, plainly:

- **This is a library today, not a hosted service.** You run the coordinator (`OutcomeCoordinator`) and decide who holds the checkpoints and witness keys. "Neutral" is a property of how it is deployed: one operator is a single point of trust unless independent witnesses hold the history.
- **Verification has levels, and the status says which.** A signed receipt can be checked by anyone; a provider's records rely on the coordinator; a human attestation relies on a person. Where nothing can confirm an outcome, it is reported as unknown and handed to a person, not guessed.
- **Unlike a payment, the providers did not integrate with you.** Outcomes are only as verifiable as what each provider exposes: idempotency keys, a status lookup, signed receipts. The connector conformance checks tell you what a provider actually offers.
- **Consumers need an app.** Approving a step or reading the result assumes a signing key on the user's device and a surface that shows the intent. The SDK produces the data and the contract to sign; it does not ship that UI.

It is not an LLM framework, a gateway, a protocol, an identity provider, a payment network or a workflow engine. It sits beside those.

## An outcome intent in a few lines

```ts
import { approveContract, Intents, money, OutcomeCoordinator, memoryStore } from "@agentmesh/outcome-sdk";

const intents = new Intents(coordinator, { providers: { acme: { keys: [acmeReceiptKey] }, soundhub: {} } });

let intent = await intents.create({
  goal: "Return my damaged headphones, get the refund, and buy a replacement under $200.",
  principal: { id: "user:ana", key: userPublicKey },   // the user's device holds the private key
  agents: ["agent:muse"],
  budget: money("USD", 200),                           // shared by every step
  approveAbove: money("USD", 100),                     // a bigger request needs the user's OK for that exact request
  steps: [
    { id: "return", provider: "acme", action: "order.return", params: { orderId: "A-1001" }, expect: "received" },
    { id: "refund", provider: "acme", action: "order.refund", dependsOn: ["return"], expect: { success: "refunded", credit: { min: money("USD", "149.99") } } },
    { id: "replacement", provider: "soundhub", action: "order.create", spend: money("USD", 180), expect: "confirmed" },
  ],
});                                                    // intent.status === "requires_approval"; sign intent.contract

intent = await intents.approve(intent.id, approveContract(intent.contract, userSigner));
intent = await intents.run(intent.id, { agent: "agent:muse" });
// intent.status === "requires_action"
// intent.next_actions → [{ type: "step_up", step: "replacement", reason: "needs the principal's approval for $180.00" }]
```

`npm run demo:intent` runs this end to end, including the signed webhooks.

### Status

| Status | Meaning | Who acts |
| --- | --- | --- |
| `requires_approval` | The principal hasn't signed the contract. | The user |
| `processing` | Agents are working, or a provider's confirmation is pending. | No one |
| `requires_action` | A person has to do something; see `next_actions`. | A person |
| `succeeded` | Every required step is verified. An optional step that failed is visible in `steps`. | No one |
| `partially_succeeded` | Something is verified, a required step never happened, and nobody needs to act (e.g. cancelled midway). | No one |
| `failed` | Nothing required was achieved and nobody needs to act (e.g. after the user waived a step that couldn't be done). | No one |
| `canceled` | Revoked, or never approved, with nothing verified. | No one |

Each step has its own status (`waiting`, `processing`, `succeeded`, `failed`, `unknown`, `disputed`, `canceled`, `undone`), what verified it (`verified_by`), the provider's `reference`, what it `charged` or `refunded`, and a one-sentence `message` when it isn't done.

`next_actions` types: `approve_intent`, `step_up` (approve this exact request), `cross_check` (a second opinion from another vendor's agent is needed), `review` (an unknown or disputed outcome, or a missed deadline), `resume` (suspended). They reflect each agent's most recent attempt: once you act, the item clears until the agent tries again.

### Events and webhooks

`intents.events(id)` returns the stream a log implies (`outcome_intent.created`, `.processing`, `.requires_action`, `.succeeded`, `.step.succeeded`, `.step.unknown`, `.refused`, `.suspended`, `.incident`, …). It is derived from the verified log, so polling, in-process subscribers and webhooks all see the same events with stable ids.

```ts
intents.subscribe(webhookSink({ endpoints: [{ url: "https://app.example/hooks", secret: "whsec_…" }] }));
// receiver: verifyWebhook(rawBody, request.headers["agentmesh-signature"], "whsec_…")  →  { ok: true }
```

Delivery is at-least-once and in order: if a receiver fails, that event stays pending (and later events wait behind it) until the intent's next change or `intents.flush(id)`. Signatures are `t=<unix>,v1=<hmac-sha256>` with a timestamp tolerance. Persist the `cursors` option to survive restarts; redelivery is harmless because event ids are stable.

```bash
npm install
npm run demo:intent # the example above: create, approve, step-up, succeed, webhooks, verified evidence
npm run demo        # return + refund + replacement with the lower-level API
npm run demo:safety # cross-check, org policy, circuit breaker, emergency stop, witnessed log, incident write-up
npm test            # 130+ tests, organized around the plan's success criteria and the safety principles
npm run fuzz        # 2000 random scenarios checked against the providers' ground truth
npm run typecheck && npm run build
```

Requires Node 22.18+ (the demos run TypeScript directly). The only runtime dependency is `zod`; `postgres` is an optional peer for the Postgres store.

## Under the hood

The intent API is a thin layer over outcome contracts, a coordinator and an evidence log. Use those directly when you need more control.

### How it works

```
user goal ──► Outcome contract ──► principal signs its digest
                 │  operations, providers, executors, shared budget, approval threshold,
                 │  dependencies, deadlines, expected outcomes, accepted evidence, compensations
                 ▼
agent asks to run an operation ──► OutcomeCoordinator ──► checks every rule ──► records "submitting"
                                         │  (budget reserved, signed authorization, idempotency key)
                                         ▼
                                  provider connector ──► provider verifies the scoped mandate, acts
                                         │
          response / status lookup / signed receipt / human attestation ──► evidence log (hash-chained)
                                         ▼
                      reconciler: verified · pending · unknown · failed · rejected · disputed
                                         ▼
               outcome report  +  escalations  +  evidence bundle anyone can re-verify
```

### 1. Outcome contracts (`defineContract`)

A portable, schema-validated description of a goal: who the principal is, which agents may do what, which providers take part, a shared **budget**, an **approval threshold**, per-operation **spend caps**, **dependencies** ("cancel the old plan only after the new one is verified"), **deadlines**, what success looks like (`expect`), which **evidence** counts, retries, and an optional pre-approved **compensation**. It defines *what* success means, not *how* agents reason.

The principal signs a digest of a header that commits to every part of the contract by salted hash. Each provider receives only the header and **its own operation** (a *mandate*). It can verify that its operation was approved without learning the user's goal, budget, or what other providers were asked to do (`verifyMandate`). The normalized format is published as JSON Schema in [`schema/outcome-contract.v0.schema.json`](schema/outcome-contract.v0.schema.json).

### 2. Shared constraints

Enforced by the coordinator as a trusted service, never by LLM instructions:

- **Shared budget across agents.** Each submission reserves its amount first. Concurrent agents, and several coordinator processes sharing one store, can never together exceed it (optimistic appends, tested under concurrency and against Postgres).
- **Step-up approval.** A request above `approvalAbove` (or any request for an operation marked `requiresApproval`) needs the principal's signature over that exact amount and those details.
- **Delegated authority.** Only listed `executors` may trigger an operation, only up to its `spend` cap, and only once its dependencies are verified.
- **Revocation and expiry.** After the principal revokes, or the contract expires, nothing new is sent. What is already in flight is still reconciled.
- **Budget held while uncertain.** A reservation is released only when the provider confirms nothing was charged. An outcome that is unknown keeps holding its budget, and an overcharge counts in full.

### 3. Transaction coordination (`OutcomeCoordinator`)

- One transaction per contract, with deterministic, opaque **idempotency keys** per operation and phase.
- The submission is **recorded before the provider is called**, so a crash mid-call is detected later and treated as ambiguous, never forgotten.
- **Retry rules that can't double-execute:** after an ambiguous failure, the coordinator first reads the provider's records. If the provider has none, it resends **with the same key**, and only to an idempotent provider. A new key is used only after the provider said the request did not execute. If a provider offers neither idempotency nor lookups, the operation is reported **unknown** and escalated, and is **not** retried.
- **Partial completion** is reported as such. If the contract's policy is `compensate_completed`, completed operations are undone with their **pre-approved** compensations, so recovery never creates actions the user didn't approve.
- `run()` drives one agent's operations. `reconcile()` (call it on a schedule, or from a workflow timer) handles deadlines, stale submissions, status lookups and compensations. Providers can push signed receipts with `ingestReceipt()`.

### 4. Verification and reconciliation

Each operation's verdict is derived from evidence, never from an agent saying "done":

| Source | Counts as proof? | Checkable by a third party? |
| --- | --- | --- |
| `signed_receipt` (provider key listed in the contract) | yes, if accepted by the operation | yes, offline |
| `provider_record` (API response or status lookup through an `api` connector) | yes, if accepted by the operation | relies on the coordinator |
| `human_attestation` (principal or listed reviewer) | yes, if accepted by the operation | yes (signed) |
| `agent_claim` (an agent's account, or anything relayed by an `agent` connector) | **never** | recorded for accountability |

Evidence is compared with the approved terms: statuses are read through the contract's success, pending and failure lists, and the amount charged is compared with the authorized amount. Refunds are compared with the expected credit, and field checks can reference another operation (e.g. "the new policy starts no later than the old one ends"). Results per operation: `verified`, `pending_verification`, `unknown`, `rejected`, `failed`, `disputed`, `cancelled`, `waived`, `compensating`, `compensated`. Per transaction: `completed`, `partially_completed`, `in_progress`, `pending_verification`, `outcome_unknown`, `failed`, `disputed`, `requires_human_review`. When an agent's claim isn't backed by evidence, the report says so.

### 5. Evidence and recovery

Every fact (approval, step-up, refusal, submission, response, evidence, deadline, revocation) is appended to a **hash-chained log**. Verdicts are never stored. They are re-derived from the facts, so `verifyBundle()` can replay an exported bundle with the same rules and check the coordinator's signed checkpoint. Altering, dropping or reordering any entry fails verification, and so does a submission that broke the contract (unapproved, over budget, out of order, after revocation). Escalations clear themselves when new evidence settles an operation, or when a human attests or the principal waives it.

### 6. Containment, independence and disclosure

Built on the premise that an agent (or a model behind it) may be compromised, and that the party enforcing the rules must not be the only one who can vouch for the record.

- **Emergency brake.** The principal or a **controller** (a stop-only key that can suspend or revoke but never approve) can *suspend* the whole transaction or a single agent, and *resume* it later. Suspension blocks new submissions and keeps reconciling what is in flight. A suspension placed by a controller can only be lifted by a controller, so the user can't undo the organization's stop. Revocation stays permanent and is available to both.
- **Circuit breaker.** A contract can say "suspend any agent after N forbidden requests in W seconds". Only requests that break the contract count (wrong agent, over a cap, a changed retry), not ones that merely have to wait. The suspension and an incident report are written to the log, and the reducer rejects an automatic suspension the log doesn't justify, so the coordinator can't use it on a whim.
- **Separation of duties.** One key can hold only one role (principal, coordinator, controller, reviewer, auditor, each provider, each agent), and ids can't be shared across roles. The party that enforces a contract can't also approve it, vouch for results, or play the provider.
- **Independent second opinion.** An operation can require a `crossCheck`: other agents, optionally from different vendors than the executor and each other, must sign that they reviewed the exact amount and details. One objection blocks it. No single model family both proposes and approves an important action, and the report flags multi-step outcomes that rest on one vendor.
- **Organization policy.** `PolicyGate`s (a few built in, plus an OPA-compatible HTTP adapter) are asked before every submission. They can only narrow what a contract allows, fail closed, never see the user's goal, and every decision is written into the log. A log that records a submission a policy denied doesn't verify.
- **History an operator can't quietly rewrite.** The coordinator hands out signed **checkpoints** as the log grows (`checkpoints: { every, publish }`). Point `publish` at something the operator can't alter. `verifyBundle` takes those as `anchors`, and an independent **witness** (`createWitness`) co-signs what it saw and refuses any history that conflicts with it, so an operator who rewrites the log and re-signs it with their own key is caught. Verifiers can require k witnesses.
- **Readable evidence.** `renderLog()` turns the log into one plain sentence per entry (refusals, what counted as proof, what didn't). `npx agentmesh-verify bundle.json --coordinator-key …` re-derives and checks a bundle from the command line, with `--log`, `--report`, anchors and witnesses.
- **Incident disclosure.** Signed `incident` entries record severity, which controls held or failed, what was done, what changed at runtime and how to prevent a repeat. `discloseIncident()` produces a full version for affected parties (with an anchor into the evidence) and a public version with every identifier pseudonymized and the goal, amounts and evidence removed. Provider-scoped **evidence packs** (`providerPack`, `verifyProviderPack`) give each provider what it needs to prove or dispute its own part, and nothing more.
- **Continuous verification.** `tests/fuzz.test.ts` generates random contracts, provider faults, concurrent agents and operator interventions, then checks invariants against what providers really did: the budget held, no duplicate effects, nothing "verified" without a real effect, nothing sent while suspended or revoked, and any tampering is detected even when re-signed. A scheduled workflow runs thousands of seeds daily. Failures name a seed (`FUZZ_SEED=<n> npm run fuzz`).

### Lower-level quick start

```ts
import { approveContract, defineContract, generateSigner, memoryStore, OutcomeCoordinator, renderReport, type ProviderConnector } from "@agentmesh/outcome-sdk";

const user = generateSigner(); // in practice: a key on the user's device
const mesh = generateSigner(); // the coordinator's key

const contract = defineContract({
  expiresAt: "2026-11-12T00:00:00Z",
  goal: "Cancel my unused streaming subscription",
  principal: { id: "user:ana", keys: [user.publicKey] },
  coordinator: { id: "agentmesh", keys: [mesh.publicKey] },
  participants: [{ id: "agent:dots", role: "agent" }, { id: "streamflix", role: "provider", keys: [/* provider's receipt key */] }],
  operations: [{
    id: "cancel", provider: "streamflix", action: "subscription.cancel", executors: ["agent:dots"],
    params: { account: "ana@example.com" },
    expect: { success: ["cancelled"], pending: ["cancellation_requested"], failure: ["active"] },
  }],
});

const coordinator = new OutcomeCoordinator({ store: memoryStore(), signer: mesh, connectors: { streamflix: myStreamflixConnector } });
await coordinator.open(contract);
await coordinator.approve(contract.id, approveContract(contract, user));
await coordinator.run(contract.id, { agent: "agent:dots" });
console.log(renderReport(await coordinator.report(contract.id)));
```

A connector is the integration point for a provider: a direct API client, an MCP tool backed by the provider's API (`kind: "api"`), or an A2A-style remote agent (`kind: "agent"`, whose answers are treated as claims):

```ts
const myStreamflixConnector: ProviderConnector = {
  kind: "api",
  idempotent: true, // the provider honors idempotency keys
  async execute(req) {  // req.idempotencyKey, req.params, req.amount, req.mandate (for the provider to verify)
    // Return accepted / rejected / not_executed only when the provider said so; otherwise throw or return { outcome: "unknown" }.
  },
  async lookup(q) {     // read the provider's system of record by q.idempotencyKey
    // { found: true, observation } or { found: false, definitive }
  },
};
```

`checkConnector(connector, { request })` runs the conformance checks the coordinator relies on (idempotency, lookups, receipt signatures) against a provider's sandbox.

For persistence across processes, use the Postgres store:

```ts
import postgres from "postgres";
import { postgresStore } from "@agentmesh/outcome-sdk/postgres";
const store = postgresStore(postgres(process.env.DATABASE_URL!)); // tables live in their own "agentmesh" schema
```

## The plan's success criteria, and where they are tested

| Criterion (plan §14) | Tests |
| --- | --- |
| Every test action linked to its authorization evidence | `success-criteria.test.ts` › every action is linked… |
| No unauthorized actions | › no unauthorized actions (unapproved, wrong agent, over cap, over budget, no step-up, revoked, expired, forged approval, untrusted coordinator, hand-written log entries) |
| No unintended duplicate execution for idempotent operations | › no unintended duplicate execution (lost confirmations, crash mid-call, concurrent duplicates) |
| Correct reporting of unknown outcomes | › correct reporting of unknown outcomes; `subscriptions.test.ts` |
| Safe shared-budget reservations under concurrent requests | › safe shared-budget reservations (25 concurrent rounds, two coordinators); `postgres.test.ts` (two connection pools) |
| Cancel 8 subscriptions → 5 confirmed, 1 pending, 1 rejected, 1 unknown (§8) | `subscriptions.test.ts` |
| Airline succeeds, hotel fails (§3, question 4) | › recovery |

The last two criteria (less custom integration work, three organizations evaluating) can only be measured with design partners.

Postgres tests run when you point them at a database: `AGENTMESH_TEST_DATABASE_URL=postgres://... npm test`.

## How this lines up with the observability principles

| Principle | What the SDK does | What it can't do |
| --- | --- | --- |
| Model diversity | Verification contains no model. `crossCheck` requires reviewers from other vendors; the report flags single-vendor outcomes. | It can't tell whether a vendor's agent is honest or independent in fact, only that the keys and declared vendors differ. |
| Observe everything | Every mediated action is a hash-chained, signed-checkpoint log, replayable without trusting any model, and readable via `renderLog`. | It sees only what passes through the coordinator. An agent's reasoning, reads and unmediated tool calls are invisible unless the host routes them through it or emits independently verified traces. |
| Verifiability | Directed tests, a seeded fuzz harness checked against ground truth, mutation-checked guards, connector conformance checks, a daily run. | Only as good as the scenarios and invariants written; it doesn't test your providers or your agents' behavior. |
| Independent controls | Contracts, org policy gates, delegation, caps, budgets, step-ups, provider-side mandate checks. | Governs actions, not data access. Policy rules are the organization's to write, host and keep available. |
| Independent auditability | Roles are separated; receipts, attestations, witnesses and anchored checkpoints come from other signers. | The checkpoints and witnesses only help if someone other than the operator holds them. |
| Containment | Suspend/resume, per-agent suspension, a stop-only controller key, a circuit breaker, revocation, expiry, budget caps. | It can't recall a request already sent. A compromised coordinator key is made detectable, not impossible. |
| Incident disclosure | Signed incident entries, full and public disclosure formats, provider-scoped packs. | It defines the record, not the channel or the duty to disclose. Free-text fields are only scrubbed of known identifiers. |

## What it does not guarantee

- **Exactly-once external effects** without the provider's cooperation. With idempotency keys or status lookups it avoids duplicates. Without either, it reports the outcome as unknown and asks a human, rather than guessing.
- **Truth from a dishonest provider.** It proves what a provider *said* (and, with signed receipts, that the provider said it). Disagreements between sources are surfaced as disputes.
- **Agent or principal authentication to the coordinator.** That belongs to the host (OAuth/OIDC). Providers must take the principal's and coordinator's keys from their own records, never from the mandate.
- **Spending limits across contracts.** The budget is per contract. Refunds don't expand it, which is conservative by design.
- **Tamper-proof storage.** The log is tamper-*evident*. Detecting a wholesale, re-signed rewrite needs checkpoints or witness statements held by someone other than the operator.
- **A rogue or compromised coordinator key.** Role separation, anchors and witnesses make misuse detectable, and providers independently check mandates, but nothing here stops a holder of that key from signing authorizations until someone notices.

See [`docs/DESIGN.md`](docs/DESIGN.md) for the state machine, trust model and rules in detail.

## Next steps

1. Run the reconcile loop under Temporal (activities = connector calls; the reducer is deterministic) instead of a cron.
2. A2A, MCP and AP2 connector adapters.
3. Federation: several coordinators exchanging checkpoints and scoped evidence, with no central store; a hosted, third-party witness and a transparency-log publisher for checkpoints.
4. Capturing agent actions that don't pass through the coordinator (OpenTelemetry traces verified out of band).
5. Pilot the return/refund/replacement workflow with real merchants and measure the recovery logic it replaces.

License: [Apache-2.0](LICENSE).
