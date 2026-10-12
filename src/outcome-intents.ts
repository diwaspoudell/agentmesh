import type { OutcomeBundle } from "./bundle.ts";
import { canonicalize, type JsonObject } from "./canonical.ts";
import { defineContract, type ContractInput, type EvidenceSource, type OutcomeContract } from "./contract.ts";
import type { OutcomeCoordinator } from "./coordinator.ts";
import { intentEvents, intentView, type IntentEvent, type OutcomeIntent } from "./intents.ts";
import type { PublicKeyJwk, Signed } from "./keys.ts";
import { renderLog } from "./log.ts";
import type { Money } from "./money.ts";
import type { OutcomeReport } from "./report.ts";
import type { Attestation, ContractApproval, Endorsement, ProviderReceipt, Resumption, Revocation, StepUpApproval, Suspension } from "./statements.ts";
import { InvariantError, type TransactionState } from "./transaction.ts";

type ExpectInput = NonNullable<ContractInput["operations"]>[number]["expect"];
/** "cancelled", ["cancelled", "closed"], or the full form with pending/failure statuses, refunds and field checks. */
export type ExpectShorthand = string | string[] | (Omit<ExpectInput, "success"> & { success: string | string[] });

export interface StepInput {
  /** Defaults to step_1, step_2, … in order. */
  id?: string;
  /** A provider id the `Intents` instance was given (and the coordinator has a connector for). */
  provider: string;
  action: string;
  description?: string;
  params?: JsonObject;
  /** The agent that runs it. Defaults to the first agent. */
  agent?: string;
  /** The most it may charge; reserved from the budget before it is sent. */
  spend?: Money;
  dependsOn?: string[];
  /** Default true. An optional step that fails leaves the intent partially_succeeded, not requires_action. */
  required?: boolean;
  /** Always ask the principal to confirm the exact request. */
  requiresApproval?: boolean;
  /** ISO time, or milliseconds from now. */
  deadline?: string | { inMs: number };
  expect: ExpectShorthand;
  maxAttempts?: number;
  crossCheck?: { min: number; distinctVendors?: boolean };
  evidence?: EvidenceSource[];
  /** A pre-approved way to undo it, used only if `onRequiredFailure: "undo"` unwinds the intent. */
  undo?: { action: string; params?: JsonObject; expect: ExpectShorthand };
}

export interface CreateIntent {
  /** Supply your own id to make creation safe to retry: the same id with the same goal and steps returns the existing intent. */
  id?: string;
  goal: string;
  /** Whose behalf the agents act on, and the public key that signs approvals. */
  principal: { id: string; key: PublicKeyJwk | PublicKeyJwk[] };
  agents: (string | { id: string; vendor?: string; key?: PublicKeyJwk })[];
  steps: StepInput[];
  /** Shared across every step. */
  budget?: Money;
  /** A request above this needs the principal's approval of that exact request. */
  approveAbove?: Money;
  /** Default seven days. */
  expiresInMs?: number;
  /** "keep" (default) leaves completed steps in place when a required one fails; "undo" reverses them with their `undo` actions. */
  onRequiredFailure?: "keep" | "undo";
  circuitBreaker?: { violations: number; windowSeconds: number };
  /** Stop-only keys: can suspend or revoke, never approve. */
  controllers?: { id: string; key: PublicKeyJwk }[];
  reviewers?: { id: string; key: PublicKeyJwk }[];
  auditors?: { id: string; key: PublicKeyJwk }[];
}

export interface IntentsOptions {
  /** Provider ids → the keys they sign receipts with (omit if they don't). */
  providers?: Record<string, { keys?: PublicKeyJwk[]; name?: string }>;
  /** Default "agentmesh". */
  coordinatorId?: string;
  /** Remembers how many events each intent's subscribers have received. Default: in memory. Persist it to survive restarts (redelivery is harmless: ids are stable). */
  cursors?: { get(id: string): number | undefined | Promise<number | undefined>; set(id: string, delivered: number): void | Promise<void> };
  /** Told when a subscriber throws; that event stays pending and is retried on the intent's next change or `flush`. */
  onError?: (err: unknown, event: IntentEvent) => void;
}

const expectOf = (x: ExpectShorthand): ExpectInput => (typeof x === "string" ? { success: [x] } : Array.isArray(x) ? { success: x } : { ...x, success: [x.success].flat() });

/**
 * One object per business outcome spanning several agents and services: create it, have the principal approve it,
 * let agents run it, and read one status plus what (if anything) needs a person. Everything is derived from the
 * verified evidence log; `bundle()` exports it for anyone to check.
 */
export class Intents {
  readonly #c: OutcomeCoordinator;
  readonly #o: IntentsOptions;
  readonly #handlers = new Set<(event: IntentEvent) => void | Promise<void>>();
  readonly #queue = new Map<string, Promise<void>>();
  readonly #memory = new Map<string, number>();

  constructor(coordinator: OutcomeCoordinator, o: IntentsOptions = {}) {
    this.#c = coordinator;
    this.#o = o;
  }

  async create(req: CreateIntent): Promise<OutcomeIntent> {
    const contract = this.#contract(req);
    if (req.id) {
      const existing = await this.#state(req.id).catch(() => undefined);
      if (existing) {
        const same = existing.contract.goal === contract.goal && canonicalize(existing.contract.operations.map((o) => [o.id, o.provider, o.action])) === canonicalize(contract.operations.map((o) => [o.id, o.provider, o.action]));
        if (!same) throw new RangeError(`outcome intent ${req.id} already exists with a different goal or steps`);
        return this.#intent(existing);
      }
    }
    const state = await this.#c.open(contract);
    return this.#after(contract.id, state);
  }

  async retrieve(id: string): Promise<OutcomeIntent> {
    return this.#intent(await this.#state(id));
  }

  /** The principal's signature over the contract (`approveContract(intent.contract, signer)`). */
  async approve(id: string, approval: Signed<ContractApproval>) { return this.#after(id, await this.#c.approve(id, approval)); }
  /** The principal's approval of one exact request (amount and details), for steps above `approveAbove` or marked `requiresApproval`. */
  async stepUp(id: string, approval: Signed<StepUpApproval>) { return this.#after(id, await this.#c.stepUp(id, approval)); }
  /** Another agent's signed review, for steps with a `crossCheck`. */
  async endorse(id: string, endorsement: Signed<Endorsement>) { return this.#after(id, await this.#c.endorse(id, endorsement)); }
  /** A person's signed finding, usually to settle a step that came back unknown or disputed. */
  async attest(id: string, attestation: Signed<Attestation>) { return this.#after(id, await this.#c.attest(id, attestation)); }
  /** A receipt pushed by a provider (e.g. a webhook). */
  async ingestReceipt(receipt: Signed<ProviderReceipt>) { return this.#after(receipt.payload.contractId, await this.#c.ingestReceipt(receipt)); }
  /** Stops new work, permanently, from the principal or a controller. Work already sent is still reconciled. */
  async cancel(id: string, revocation: Signed<Revocation>) { return this.#after(id, await this.#c.revoke(id, revocation)); }
  /** Pauses new work (the whole intent, or one agent). Reversible with `resume`. */
  async suspend(id: string, suspension: Signed<Suspension>) { return this.#after(id, await this.#c.suspend(id, suspension)); }
  async resume(id: string, resumption: Signed<Resumption>) { return this.#after(id, await this.#c.resume(id, resumption)); }

  /** Asks to run one step now. A refusal comes back as `{ ok: false, reason }` with the intent unchanged apart from the logged refusal. */
  async submit(id: string, step: string, req: { agent: string; amount?: Money; details?: JsonObject }): Promise<{ ok: boolean; reason?: string; intent: OutcomeIntent }> {
    const r = await this.#c.submit(id, step, req);
    return { ok: r.ok, reason: r.ok ? undefined : r.reason, intent: await this.#after(id, r.state) };
  }

  /** Lets one agent run every step it may, as soon as each step's dependencies are verified, reconciling as it goes. */
  async run(id: string, o: { agent: string; plan?: Record<string, { amount?: Money; details?: JsonObject }> | ((step: string) => { amount?: Money; details?: JsonObject } | undefined); rounds?: number }) {
    const plan = typeof o.plan === "function" ? o.plan : o.plan ? (step: string) => (o.plan as Record<string, { amount?: Money; details?: JsonObject }>)[step] : undefined;
    return this.#after(id, await this.#c.run(id, { agent: o.agent, plan, rounds: o.rounds }));
  }

  /** Checks providers' records, expires deadlines and runs approved compensations. Call it on a schedule. */
  async refresh(id: string) { return this.#after(id, await this.#c.reconcile(id)); }

  /** The detailed report, the plain-sentence log, and the full evidence bundle anyone can verify. */
  report(id: string): Promise<OutcomeReport> { return this.#c.report(id); }
  async log(id: string): Promise<string[]> { return renderLog(await this.#c.events(id)); }
  bundle(id: string): Promise<OutcomeBundle> { return this.#c.exportBundle(id); }

  /** Every event for an intent, oldest first. Pass how many you've already seen as `after` to get only newer ones. */
  async events(id: string, o: { after?: number } = {}): Promise<IntentEvent[]> {
    return intentEvents(await this.#c.events(id)).slice(o.after ?? 0);
  }

  /**
   * Calls `handler` once per event, in order, after each change made through this object (create, approve, run, …).
   * If it throws, that event stays pending and delivery resumes from it on the intent's next change or `flush`.
   */
  subscribe(handler: (event: IntentEvent) => void | Promise<void>): () => void {
    this.#handlers.add(handler);
    return () => { this.#handlers.delete(handler); };
  }

  /** Retries delivery of anything pending for this intent. */
  flush(id: string): Promise<void> { return this.#deliver(id); }

  // ── internals ────────────────────────────────────────────────────────────────

  async #state(id: string): Promise<TransactionState> {
    try {
      return await this.#c.state(id);
    } catch (err) {
      if (err instanceof InvariantError && /empty log|no transaction/.test(err.message)) throw new RangeError(`no outcome intent ${id}`);
      throw err;
    }
  }

  #intent(s: TransactionState): OutcomeIntent {
    return { ...intentView(s), contract: s.contract };
  }

  async #after(id: string, s: TransactionState): Promise<OutcomeIntent> {
    await this.#deliver(id);
    return this.#intent(s);
  }

  #deliver(id: string): Promise<void> {
    const run = (this.#queue.get(id) ?? Promise.resolve()).then(async () => {
      if (!this.#handlers.size) return;
      const events = intentEvents(await this.#c.events(id));
      const cursors = this.#o.cursors ?? { get: (k: string) => this.#memory.get(k), set: (k: string, n: number) => void this.#memory.set(k, n) };
      let delivered = (await cursors.get(id)) ?? 0;
      for (const event of events.slice(delivered)) {
        try {
          for (const h of this.#handlers) await h(event);
        } catch (err) {
          this.#o.onError?.(err, event);
          return;
        }
        await cursors.set(id, ++delivered);
      }
    });
    const settled = run.catch(() => {});
    this.#queue.set(id, settled);
    return run;
  }

  #contract(req: CreateIntent): OutcomeContract {
    const now = this.#c.now();
    const agents = req.agents.map((a) => (typeof a === "string" ? { id: a } : a));
    if (!agents.length) throw new RangeError("an outcome intent needs at least one agent");
    const used = [...new Set(req.steps.map((s) => s.provider))];
    const unknown = used.filter((p) => !this.#o.providers || !(p in this.#o.providers));
    if (unknown.length) throw new RangeError(`unknown provider${unknown.length > 1 ? "s" : ""} ${unknown.join(", ")}; list ${unknown.length > 1 ? "them" : "it"} in the Intents providers option`);
    const ids = req.steps.map((s, i) => s.id ?? `step_${i + 1}`);
    const operations = req.steps.map((s, i) => {
      const agent = s.agent ?? agents[0]!.id;
      if (!agents.some((a) => a.id === agent)) throw new RangeError(`step ${ids[i]} names agent ${agent}, which is not one of the intent's agents`);
      return {
        id: ids[i]!, provider: s.provider, action: s.action, description: s.description, params: s.params, executors: [agent], spend: s.spend, dependsOn: s.dependsOn,
        required: s.required, requiresApproval: s.requiresApproval, maxAttempts: s.maxAttempts, evidence: s.evidence,
        crossCheck: s.crossCheck && { min: s.crossCheck.min, distinctVendors: s.crossCheck.distinctVendors ?? true },
        deadline: typeof s.deadline === "object" ? new Date(now.getTime() + s.deadline.inMs).toISOString() : s.deadline,
        expect: expectOf(s.expect),
        compensation: s.undo && { action: s.undo.action, params: s.undo.params, expect: expectOf(s.undo.expect) },
      };
    });
    const keys = (k: PublicKeyJwk | PublicKeyJwk[]) => [k].flat();
    return defineContract({
      id: req.id,
      createdAt: now.toISOString(),
      expiresAt: new Date(now.getTime() + (req.expiresInMs ?? 7 * 86_400_000)).toISOString(),
      goal: req.goal,
      principal: { id: req.principal.id, keys: keys(req.principal.key) },
      coordinator: { id: this.#o.coordinatorId ?? "agentmesh", keys: [this.#c.publicKey] },
      participants: [
        ...agents.map((a) => ({ id: a.id, role: "agent" as const, vendor: "vendor" in a ? a.vendor : undefined, keys: "key" in a && a.key ? [a.key] : [] })),
        ...used.map((p) => ({ id: p, role: "provider" as const, name: this.#o.providers![p]!.name, keys: this.#o.providers![p]!.keys ?? [] })),
        ...(req.controllers ?? []).map((c) => ({ id: c.id, role: "controller" as const, keys: [c.key] })),
        ...(req.reviewers ?? []).map((c) => ({ id: c.id, role: "reviewer" as const, keys: [c.key] })),
        ...(req.auditors ?? []).map((c) => ({ id: c.id, role: "auditor" as const, keys: [c.key] })),
      ],
      constraints: { budget: req.budget, approvalAbove: req.approveAbove },
      policy: { onRequiredFailure: req.onRequiredFailure === "undo" ? "compensate_completed" : "keep_completed", circuitBreaker: req.circuitBreaker },
      operations,
    });
  }
}
