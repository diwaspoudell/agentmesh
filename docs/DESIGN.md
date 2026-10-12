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
