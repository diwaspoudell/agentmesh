# Design

## Facts in, verdicts out

The log stores **facts** only:

| Event | Meaning |
| --- | --- |
| `contract.registered` | the normalized contract (its id is the transaction id) |
| `contract.approved` / `contract.revoked` | principal-signed, over the contract digest |
| `contract.expired`, `operation.expired` | the coordinator's clock passed `expiresAt` / a `deadline` (validated against the event time) |
| `operation.step_up` | principal-signed approval of one concrete request (amount and details digest) |
| `operation.refused` | an agent asked and a rule said no (kept for audit) |
| `operation.submitting` | about to call the provider: attempt, idempotency key, amount, connector profile, coordinator-signed authorization |
| `operation.result` | what the call returned: `accepted`, `rejected`, `not_executed`, or `ambiguous` |
| `evidence.recorded` | a provider record, signed receipt, human attestation or agent claim |

Containment and oversight add more facts:

| Event | Meaning |
| --- | --- |
| `contract.suspended` / `contract.resumed` | a pause on the whole transaction or one agent; signed by the principal, a controller, or (suspend only, via the contract's circuit breaker) the coordinator |
| `operation.endorsed` | another agent's signed review (concur or object) of one concrete request |
| `operation.refused` | now carries `kind` (`violation` or `blocked`) and any policy decisions |
| `operation.submitting` | now carries the organization policy decisions that allowed it |
| `incident.reported` | a signed incident account from the principal, a controller, the coordinator, a reviewer or an auditor |

Each event is hashed with its predecessor's hash (`prev`). `replay(events)` folds them with a pure reducer that:

1. re-checks each event's hash, sequence and time order;
2. **re-validates every submission with `checkSubmission`**, the same rules the coordinator applied (approved, not revoked or expired, agent delegated, dependencies verified, within cap, step-up present, budget available, idempotency key and attempt number as derived, authorization signed by the coordinator and matching);
3. validates evidence (signature by a key the contract lists, correlation to a real submission by idempotency key, operation and phase);
4. derives every operation's status, the budget, escalations and the transaction outcome.

Live coordination and offline verification therefore cannot disagree. A log that contains a rule-breaking submission does not replay.

## Operation lifecycle

```
planned ──submit──► submitting ──accepted──► pending_verification ──proof──► verified ──(unwind)──► compensating ──► compensated
   ▲                   │  │                         │
   │ not_executed      │  └─ambiguous─► unknown ◄───┘ deadline passed
   │ (new key)         │                  │  lookup found / definitive not-found / same-key retry
   └───────────────────┘                  ▼
                       rejected · failed · disputed · cancelled · waived
```

Next-step rules after a submission (`derivePhase`):

| Result | Next |
| --- | --- |
| accepted | look up the provider's records (or wait for a receipt) |
| rejected (api connector) | stop; required → escalate |
| not executed, retryable, attempts left | resend with a **new** key |
| ambiguous, lookup available | look up; a definitive "no record" allows a same-key resend |
| ambiguous, no lookup, idempotent | resend with the **same** key |
| ambiguous, neither | **unknown**, escalate, never resend |
| anything via an `agent` connector | a claim: unknown until a record or receipt confirms it |

## Verdicts from evidence

For each phase, consider only proofs: entries that are valid and from a source the operation accepts. Then:

1. Any proof shows success but violates the approved terms (overcharge, charge with no spend approved, refund below expectation, a failed field check) → **disputed**.
2. Proofs show both success and failure → **disputed**. Two success proofs with different charges → **disputed**.
3. A success proof whose terms are all shown → **verified** (the basis is the strongest source: signed receipt, then provider record, then human attestation).
4. A failure proof → **failed**.
5. A success proof that lacks something it must show (e.g. the amount) → stays **pending** with a finding.
6. Otherwise fall back to the submission results above. An unrecognized status → **unknown**.

## Transaction outcome

Precedence: `disputed` › `requires_human_review` (any open escalation) › `outcome_unknown` › `in_progress` (anything planned, submitting or being compensated) › `pending_verification` › `completed` (every required operation verified) › `partially_completed` (something verified) › `failed`.

Escalations are derived, not stored: a required operation rejected, failed or cancelled by its deadline; an unknown outcome with no automatic path or past its deadline; any dispute; a failed compensation; a verified operation that can't be undone while unwinding. Each clears itself when evidence, an attestation or a waiver settles the operation.

## Budget

Integer minor units only. While an operation's outcome is open (submitting, pending, unknown), its amount is **held**. When verified, the **settled** debit counts as spent. When disputed, the larger of the authorized amount and any observed charge is held. A reservation is released only on a definitive "nothing happened": a rejection or not-executed answer through an `api` connector, a failure status in a provider record or receipt, or a definitive not-found lookup. Credits (refunds) are reported but never add to the budget.

## Commitments and mandates

```
digest = sha256(canonical(header))
header = { id, createdAt, expiresAt, principal, coordinator,
           commitments: { goal:         H(salt, goal),
                          participants: H(salt, participants),
                          terms:        H(salt, constraints, policy),
                          operations:   [ H(operation incl. its own salt), … ] } }
```

A provider receives `{ header, its operation, principal approval, step-up?, coordinator authorization }`. Per-operation salts stop a provider from confirming guesses about other operations. `verifyMandate` requires each signature to be by a key the provider trusts **and** that the header names for that role.

Canonical JSON follows RFC 8785 (sorted keys, ECMAScript number formatting). Signatures are Ed25519 over the canonical bytes, and key ids are RFC 7638 thumbprints. Every signed payload carries a `type`, so a signature can't be replayed as a different kind of statement.

## Concurrency

`EventStore.append(id, afterSeq, events)` writes only if the log still ends at `afterSeq`. The coordinator loads the log, decides, validates through the reducer, and appends. On a conflict it reloads and decides again. Side effects happen only after a `submitting` event is durably appended, so a decision that loses a race never reaches a provider. In Postgres the `(transaction_id, seq)` primary key enforces this across processes. Event bodies are stored as the exact JSON text that was hashed.

## Running under a workflow engine

The reducer is deterministic and the only side effects are connector calls, so the coordinator maps onto Temporal: a workflow per transaction that calls `submit` / `reconcile` as activities on timers, with the event store as the source of truth. That's deliberately left to the host rather than rebuilt here.

## Containment

`checkSubmission` is the single gate, used live and on replay. After approval and revocation it checks, in order: whole-transaction suspension, per-agent suspension (execute phase), delegation, expiry and deadlines, unwinding, dependencies, cap and currency, step-up approval, **cross-check**, and the shared budget. Each refusal is a `violation` (the request itself broke the contract) or `blocked` (it has to wait or needs something). Only violations feed the breaker.

- **Who can do what.** Principal: approve, step up, suspend, resume (except a controller's suspension), revoke, waive. Controller: suspend, resume its own or anyone's suspension, revoke. Never approve, step up, waive or attest. Coordinator: sign authorizations, checkpoints, incidents, and a single-agent suspension *only* when the contract's breaker has tripped.
- **Breaker validation.** The reducer counts `violation` refusals by that agent inside the window since its last resumption and rejects a coordinator-signed suspension if the count is short. The coordinator appends refusal, suspension and incident in one atomic commit so the log is self-justifying.
- **What suspension does not do.** It does not cancel anything already sent; lookups, receipts and attestations still count, and deadlines still pass.

## Independence

- **Roles.** `contractProblems` rejects a key in two roles (principal, coordinator, or any participant) and ids shared across roles.
- **Cross-check.** `crossCheck: { min, distinctVendors }` on an operation. A request is released when `min` distinct agents, none of them an executor, have concurred with an endorsement whose `detailsDigest` matches the request and whose `amount` covers it. With `distinctVendors`, each endorser's declared vendor must differ from the submitting agent's and from the others'. Any `object` endorsement for the same details blocks it. Retries with the same key skip the check (the request was already released).
- **Policy.** The coordinator asks each `PolicyGate` for the exact request after `checkSubmission` passes on a preliminary state, then re-validates in the commit. If the request changed in between (for example the amount), the decision is stale and the request is refused (fail closed). Decisions are stored with the event; the reducer refuses a `submitting` event that carries a denial. Gates see operation, provider, action, agent, amount and details, never the goal.

## Transparency

- `checkpoints: { every, publish }` signs the head each time `seq` crosses a multiple of `every`. `publish` should write somewhere the operator can't edit.
- `verifyBundle(bundle, { anchors, witnesses })`: an anchor must match `events[seq-1].hash` (a shorter log or a different hash is a rewrite); witness statements must match too, from `required` distinct trusted keys.
- `createWitness(signer, { coordinatorKeys })` verifies a bundle fully, checks it extends everything previously witnessed (same hash at the previous position, not shorter), and signs `{ transactionId, seq, head }`. Its `seen` map is the only state; persist it.
- `renderLog` replays the log and prints one sentence per entry using the verified state at that point.

## Disclosure

`discloseIncident(events, id, { audience })`. *affected*: the incident, the log lines about its operations plus suspensions, and an anchor (`seq`, event hash) so the recipient can find it in the evidence bundle. *public*: agents, providers, operations, principal, coordinator and the transaction id are replaced with stable pseudonyms, the transaction id becomes a salted digest, the timeline is reduced to event shapes at relative times, and amounts, goal and evidence are dropped. Known identifiers inside the incident's free text and `runtimeChanges.detail` are replaced; anything else in free text is the author's responsibility. `providerPack` hands a provider the approved header, its own operations and the signed statements about them, which `verifyProviderPack` checks with keys the provider already trusts.

## Continuous verification

`tests/fuzz.test.ts` runs a seeded scenario generator: random contracts (budgets, dependencies, deadlines, step-up thresholds, breaker settings), providers with random idempotency, lookup and fault sequences, and random interleavings of submits (some concurrent), reconciliation, clock jumps, receipts, suspensions, resumptions, step-ups and revocations. Invariants are checked against the providers' ground truth (`sandboxProvider(...).effects`), not against the coordinator's own books: the bundle verifies, live state equals replay, actual charges stay within the budget and within what the books account for, no operation ran twice, nothing verified without a real effect, nothing was sent while suspended or revoked, and re-signed tampering (changed timestamp, removed or reordered entry) fails verification. The sandbox models providers faithfully: an idempotent provider answers a repeated request with its original result.

## Outcome intents

`Intents` (src/outcome-intents.ts) turns a request into a normalized contract (`create`) and wraps the coordinator; `intentView` (src/intents.ts) is a pure function of verified state. Nothing about an intent is stored separately: its status, steps and `next_actions` are recomputed from the log, so a replayed bundle yields the same intent.

Status, in order of precedence: no approval → `requires_approval` (or `canceled` if revoked); any dispute or open escalation → `requires_action`; nothing in flight and something waiting on a person (suspension, step-up, cross-check) → `requires_action`; completed → `succeeded`; partially completed → `partially_succeeded`; failed → `failed` (or `canceled` if revoked); otherwise `processing`. An unknown outcome the coordinator is still resolving by itself (a status lookup pending, before its deadline) is `processing`, not a request for a person.

`next_actions` come from the log, not from guesses: escalations, suspensions, and the most recent refusal of a step whose reason says it needs approval or a cross-check, shown only if no step-up or endorsement has been recorded since that refusal. `OutcomeCoordinator.run` logs such a refusal once per distinct reason, so a step waiting on a person is visible without the agent hammering the coordinator.

Events (`intentEvents`) are produced by replaying the log and diffing the intent after each entry: `created`, status changes, step changes, refusals, suspensions, resumptions, incidents. The id is derived from the log entry's hash and the event's position within it, so the stream is deterministic and redeliveries carry identical ids. `subscribe` delivers in order and advances a per-intent cursor only after every handler accepted an event; a failing handler holds that event and everything behind it until the next change or `flush` (at-least-once, in order). Deliveries for one intent are serialized.

Waiving: `waived` accepts that a step won't happen but never un-charges it. A waived step keeps holding its budget unless the provider definitively did nothing (a rejection or "not executed" through an API connector), and a charge visible in a provider record or receipt is always counted. (Found by the fuzz harness.)
