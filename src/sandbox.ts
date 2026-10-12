import type { JsonObject } from "./canonical.ts";
import type { ExecuteRequest, ExecuteResult, LookupResult, ProviderConnector } from "./coordinator.ts";
import type { PublicKeyJwk, Signer } from "./keys.ts";
import type { Money } from "./money.ts";
import { signReceipt, verifyMandate, type Observation, type Phase } from "./statements.ts";

/**
 * How a simulated provider answers one request:
 * - ok: does it and says so
 * - reject: refuses; nothing happens
 * - not_executed: says it couldn't process the request (retryable); nothing happens
 * - timeout_before: the call fails before the provider sees it
 * - timeout_after: the provider does it, then the response is lost
 * - claim_success: an agent says it's done; nothing happened (use with kind "agent")
 */
export type SandboxMode = "ok" | "reject" | "not_executed" | "timeout_before" | "timeout_after" | "claim_success";

export interface SandboxOptions {
  kind?: "api" | "agent";
  /** Honors idempotency keys (default true). When false, every request that gets through repeats the effect. */
  idempotent?: boolean;
  /** Offers a status lookup (default true). */
  lookup?: boolean;
  /** "Not found" from the lookup is guaranteed (default true). */
  definitiveLookup?: boolean;
  /** Signs receipts with this key. */
  signer?: Signer;
  /** Answers per call, in order; the last one repeats. Default "ok". */
  modes?: SandboxMode[];
  /** Status right after execution, e.g. "cancelled" or "confirmed". */
  status: string;
  /** If set, the operation starts in this status and moves to `status` when you call settle(). */
  pendingStatus?: string;
  /** What it actually charges (default: the authorized amount). */
  charge?: (req: ExecuteRequest) => Money | undefined;
  credit?: Money;
  effectiveAt?: string;
  details?: JsonObject;
  rejectReason?: string;
  /** Include the provider's record in the execute response (default true). */
  confirmInResponse?: boolean;
  /** Refuse requests whose mandate doesn't verify against these keys, as a real provider should. */
  verify?: { principalKeys: PublicKeyJwk[]; coordinatorKeys: PublicKeyJwk[] };
  /** Compensation (undo) behavior. */
  compensation?: { status: string; refund?: boolean; modes?: SandboxMode[] };
  /** Overrides for particular actions, when one provider handles several (returns and refunds, say). */
  actions?: Record<string, Partial<Omit<SandboxOptions, "actions" | "kind" | "idempotent" | "lookup" | "signer" | "verify">>>;
}

export interface SandboxEffect {
  ref: string;
  idempotencyKey: string;
  contractId: string;
  operationId: string;
  phase: Phase;
  status: string;
  /** Where settle() moves it. */
  finalStatus: string;
  debit?: Money;
  credit?: Money;
  effectiveAt?: string;
  details?: JsonObject;
}

/** A simulated provider with fault injection. `effects` is ground truth: every time it actually did something. */
export function sandboxProvider(id: string, o: SandboxOptions) {
  const idempotent = o.idempotent ?? true;
  const effects: SandboxEffect[] = [];
  const byKey = new Map<string, SandboxEffect>();
  const calls = new Map<string, number>();
  const rejections: string[] = [];

  const observe = (e: SandboxEffect): Observation => ({
    status: e.status, providerRef: e.ref, idempotencyKey: e.idempotencyKey, debit: e.debit, credit: e.credit, effectiveAt: e.effectiveAt, details: e.details,
  });
  const receipt = (e: SandboxEffect) => o.signer && signReceipt(o.signer, {
    provider: id, contractId: e.contractId, operationId: e.operationId, phase: e.phase, idempotencyKey: e.idempotencyKey, observation: observe(e),
  });
  const mode = (req: ExecuteRequest, a: SandboxOptions): SandboxMode => {
    const list = (req.phase === "execute" ? a.modes : a.compensation?.modes) ?? ["ok"];
    const k = `${req.phase}:${req.action}`;
    const n = calls.get(k) ?? 0;
    calls.set(k, n + 1);
    return list[Math.min(n, list.length - 1)]!;
  };

  const connector: ProviderConnector = {
    kind: o.kind ?? "api",
    idempotent,
    async execute(req): Promise<ExecuteResult> {
      const a: SandboxOptions = { ...o, ...o.actions?.[req.action] };
      const m = mode(req, a);
      if (o.verify) {
        const v = verifyMandate(req.mandate, { ...o.verify, idempotencyKey: req.idempotencyKey });
        if (!v.ok) { rejections.push(...v.errors); return { outcome: "rejected", reason: `unauthorized: ${v.errors.join("; ")}` }; }
      }
      if (m === "timeout_before") throw new Error("request timed out");
      if (m === "reject") return { outcome: "rejected", reason: a.rejectReason ?? "declined by provider" };
      if (m === "not_executed") return { outcome: "not_executed", reason: "service temporarily unavailable", retryable: true };
      if (m === "claim_success") return { outcome: "accepted", observation: { status: a.status } };
      let e = idempotent ? byKey.get(req.idempotencyKey) : undefined;
      if (!e) {
        const comp = req.phase === "compensate";
        const original = comp ? effects.find((x) => x.contractId === req.contractId && x.operationId === req.operationId && x.phase === "execute") : undefined;
        e = {
          ref: `${id}-${effects.length + 1}`, idempotencyKey: req.idempotencyKey, contractId: req.contractId, operationId: req.operationId, phase: req.phase,
          status: comp ? a.compensation?.status ?? "cancelled" : a.pendingStatus ?? a.status,
          finalStatus: comp ? a.compensation?.status ?? "cancelled" : a.status,
          debit: comp ? undefined : a.charge ? a.charge(req) : req.amount,
          credit: comp ? (a.compensation?.refund ? original?.debit : undefined) : a.credit,
          effectiveAt: comp ? undefined : a.effectiveAt,
          details: comp ? undefined : a.details,
        };
        effects.push(e);
        byKey.set(req.idempotencyKey, e);
      }
      if (m === "timeout_after") throw new Error("connection reset after the provider processed the request");
      return { outcome: "accepted", providerRef: e.ref, observation: a.confirmInResponse === false ? undefined : observe(e), receipt: receipt(e) };
    },
  };
  if (o.lookup ?? true) {
    connector.lookup = async (req): Promise<LookupResult> => {
      const e = byKey.get(req.idempotencyKey);
      if (!e) return { found: false, definitive: o.definitiveLookup ?? true };
      return { found: true, observation: observe(e), receipt: receipt(e) };
    };
  }

  return {
    id,
    connector,
    effects,
    /** Errors from mandates it refused. */
    rejections,
    /** Effects of the execute phase for one operation (more than one means a duplicate). */
    executions: (operationId: string) => effects.filter((e) => e.operationId === operationId && e.phase === "execute"),
    /** Moves a pending effect to its final status (or another), as the provider's back office eventually would. */
    settle(operationId: string, patch: Partial<Pick<SandboxEffect, "status" | "debit" | "credit" | "effectiveAt" | "details">> = {}) {
      for (const e of effects) if (e.operationId === operationId && e.phase === "execute") Object.assign(e, { status: e.finalStatus }, patch);
    },
    /** A signed receipt for the current state, as a webhook would push it. */
    receiptFor(operationId: string) {
      const e = effects.filter((x) => x.operationId === operationId).at(-1);
      return e && receipt(e);
    },
  };
}
