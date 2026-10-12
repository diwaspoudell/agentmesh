# AgentMesh Outcome SDK

Personal agents understand what users want, and enterprise agents carry out business operations. This SDK establishes what was **authorized**, what was **committed**, what **actually happened**, and what **remains to be resolved** when one user goal spans several independent agents and providers.

It is the MVP from the AgentMesh Trust plan: **outcome contracts**, an **outcome reconciler**, and an **evidence and recovery API**, plus the shared-constraint ledger and transaction state machine they need. It is not an LLM framework, a gateway, a protocol, an identity provider, a payment network or a workflow engine. It sits beside those.

```bash
npm install
npm run demo        # return + refund + replacement across two merchants, end to end
npm test            # 60+ tests, organized around the plan's success criteria
npm run typecheck && npm run build
```

Requires Node 22.18+ (the demo runs TypeScript directly). The only runtime dependency is `zod`; `postgres` is an optional peer for the Postgres store.

## What it does

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

## Quick start

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

## What it does not guarantee

- **Exactly-once external effects** without the provider's cooperation. With idempotency keys or status lookups it avoids duplicates. Without either, it reports the outcome as unknown and asks a human, rather than guessing.
- **Truth from a dishonest provider.** It proves what a provider *said* (and, with signed receipts, that the provider said it). Disagreements between sources are surfaced as disputes.
- **Agent or principal authentication to the coordinator.** That belongs to the host (OAuth/OIDC). Providers must take the principal's and coordinator's keys from their own records, never from the mandate.
- **Spending limits across contracts.** The budget is per contract. Refunds don't expand it, which is conservative by design.

See [`docs/DESIGN.md`](docs/DESIGN.md) for the state machine, trust model and rules in detail.

## Next steps

1. Run the reconcile loop under Temporal (activities = connector calls; the reducer is deterministic) instead of a cron.
2. A2A, MCP and AP2 connector adapters, plus a scoped evidence export for each provider.
3. Federation: several coordinators exchanging checkpoints and scoped evidence, with no central store.
4. Pilot the return/refund/replacement workflow with real merchants and measure the recovery logic it replaces.

License: the plan proposes Apache-2.0, subject to dependency and legal review. No license file is included until that review is done.
