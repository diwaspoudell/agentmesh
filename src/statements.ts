import { createHash } from "node:crypto";
import { canonicalize, digest, type JsonObject } from "./canonical.ts";
import { contractDigest, operationCommitment, type ContractHeader, type OperationSpec, type OutcomeContract } from "./contract.ts";
import { verifySigned, type PublicKeyJwk, type Signed, type Signer } from "./keys.ts";
import type { Money } from "./money.ts";

export type Phase = "execute" | "compensate";

/** What a provider's system of record says about one operation, normalized. */
export interface Observation {
  /** Provider-native status, interpreted through the operation's expectation lists. */
  status: string;
  /** The provider's own transaction id (booking ref, order id, refund id). */
  providerRef?: string;
  idempotencyKey?: string;
  /** Money taken from the principal by this operation. */
  debit?: Money;
  /** Money returned to the principal (a refund). */
  credit?: Money;
  effectiveAt?: string;
  details?: JsonObject;
}

export interface ContractApproval { type: "agentmesh.contract-approval"; contractId: string; contractDigest: string; approvedAt: string }

/** The principal confirms one concrete request (amount and details) for an operation that needs it. */
export interface StepUpApproval {
  type: "agentmesh.step-up-approval";
  contractId: string;
  contractDigest: string;
  operationId: string;
  amount?: Money;
  detailsDigest?: string;
  approvedAt: string;
}

export interface Revocation { type: "agentmesh.revocation"; contractId: string; contractDigest: string; revokedAt: string; reason?: string }

/** The coordinator's statement that one submission passed every shared constraint. Providers can require it. */
export interface ExecutionAuthorization {
  type: "agentmesh.execution-authorization";
  contractId: string;
  contractDigest: string;
  operationId: string;
  operationCommitment: string;
  phase: Phase;
  attempt: number;
  idempotencyKey: string;
  agent: string;
  amount?: Money;
  detailsDigest?: string;
  issuedAt: string;
  expiresAt: string;
}

/** A provider's signed statement about an operation's state. */
export interface ProviderReceipt {
  type: "agentmesh.provider-receipt";
  provider: string;
  contractId: string;
  operationId: string;
  phase: Phase;
  idempotencyKey: string;
  observation: Observation;
  issuedAt: string;
}

/** A human (the principal or a listed reviewer) states what they found, e.g. after checking a provider's portal. "waived" (principal only) accepts that the operation won't happen. */
export interface Attestation {
  type: "agentmesh.attestation";
  contractId: string;
  contractDigest: string;
  operationId: string;
  phase: Phase;
  outcome: "succeeded" | "failed" | "waived";
  observation?: Observation;
  note?: string;
  attestedAt: string;
}

/** The coordinator signs the head of the evidence log; because the log is hash-chained, this covers every earlier entry. */
export interface Checkpoint { type: "agentmesh.checkpoint"; transactionId: string; seq: number; head: string; at: string }

const nowIso = () => new Date().toISOString();

export function detailsDigest(details: JsonObject | undefined) {
  return details === undefined ? undefined : digest({ type: "agentmesh.details", details });
}

/**
 * Deterministic and opaque: the same operation, phase and generation always get the same key, so a retry after an
 * ambiguous failure reuses it and an idempotent provider applies the effect once. The generation only advances
 * after a provider said the request definitively did not execute.
 */
export function idempotencyKey(contractId: string, operationId: string, phase: Phase, generation: number) {
  const h = createHash("sha256").update(canonicalize(["agentmesh.idempotency", contractId, operationId, phase, generation])).digest("base64url");
  return `am_${h.slice(0, 32)}`;
}

export function approveContract(c: OutcomeContract, principal: Signer, at = nowIso()): Signed<ContractApproval> {
  return principal.sign({ type: "agentmesh.contract-approval", contractId: c.id, contractDigest: contractDigest(c), approvedAt: at });
}

export function approveStepUp(
  c: OutcomeContract, principal: Signer, operationId: string, req: { amount?: Money; details?: JsonObject }, at = nowIso(),
): Signed<StepUpApproval> {
  return principal.sign({
    type: "agentmesh.step-up-approval", contractId: c.id, contractDigest: contractDigest(c), operationId,
    amount: req.amount, detailsDigest: detailsDigest(req.details), approvedAt: at,
  });
}

export function revokeContract(c: OutcomeContract, principal: Signer, reason?: string, at = nowIso()): Signed<Revocation> {
  return principal.sign({ type: "agentmesh.revocation", contractId: c.id, contractDigest: contractDigest(c), revokedAt: at, reason });
}

export function attest(
  c: OutcomeContract, signer: Signer, a: { operationId: string; phase?: Phase; outcome: Attestation["outcome"]; observation?: Observation; note?: string }, at = nowIso(),
): Signed<Attestation> {
  return signer.sign({
    type: "agentmesh.attestation", contractId: c.id, contractDigest: contractDigest(c), operationId: a.operationId, phase: a.phase ?? "execute",
    outcome: a.outcome, observation: a.observation, note: a.note, attestedAt: at,
  });
}

export function signReceipt(provider: Signer, r: Omit<ProviderReceipt, "type" | "issuedAt"> & { issuedAt?: string }): Signed<ProviderReceipt> {
  return provider.sign({ ...r, type: "agentmesh.provider-receipt", issuedAt: r.issuedAt ?? nowIso() });
}

// ── Provider side ──────────────────────────────────────────────────────────────

/** Everything a provider needs to check a request, scoped to its own operation. */
export interface Mandate {
  header: ContractHeader;
  operation: OperationSpec;
  approval: Signed<ContractApproval>;
  stepUp?: Signed<StepUpApproval>;
  authorization: Signed<ExecutionAuthorization>;
}

/**
 * Run by a provider before acting. The trusted keys must come from the provider's own records (the account the
 * user linked, the AgentMesh service it accepts), never from the mandate itself.
 */
export function verifyMandate(
  m: Mandate,
  trust: { principalKeys: readonly PublicKeyJwk[]; coordinatorKeys: readonly PublicKeyJwk[]; now?: Date; idempotencyKey?: string },
): { ok: boolean; errors: string[] } {
  const errors: string[] = [];
  const d = contractDigest(m.header);
  const commitment = operationCommitment(m.operation);
  const auth = m.authorization.payload;
  if (!m.header.commitments.operations.includes(commitment)) errors.push("operation is not part of the approved contract");
  if (m.approval.payload.contractDigest !== d || m.approval.payload.contractId !== m.header.id) errors.push("approval is for a different contract");
  // A signature must be both by a key the provider trusts and by a key the approved contract names for that role.
  const listed = (keys: readonly PublicKeyJwk[], kid: string) => keys.some((k) => k.kid === kid);
  if (!verifySigned(m.approval, trust.principalKeys) || !listed(m.header.principal.keys, m.approval.signature.kid)) errors.push("approval is not signed by a trusted principal key");
  if (!verifySigned(m.authorization, trust.coordinatorKeys) || !listed(m.header.coordinator.keys, m.authorization.signature.kid)) errors.push("authorization is not signed by a trusted coordinator key");
  if (auth.contractDigest !== d || auth.operationId !== m.operation.id || auth.operationCommitment !== commitment) errors.push("authorization does not match this operation");
  const now = (trust.now ?? new Date()).getTime();
  if (now >= Date.parse(auth.expiresAt)) errors.push("authorization has expired");
  if (trust.idempotencyKey && trust.idempotencyKey !== auth.idempotencyKey) errors.push("idempotency key does not match the authorization");
  if (auth.phase === "execute") {
    if (auth.amount && (!m.operation.spend || auth.amount.currency !== m.operation.spend.currency || auth.amount.minor > m.operation.spend.minor)) {
      errors.push("amount exceeds what the operation may spend");
    }
  } else if (!m.operation.compensation) errors.push("operation has no approved compensation");
  if (m.operation.requiresApproval && auth.phase === "execute" && !m.stepUp) errors.push("operation requires the principal's step-up approval");
  if (m.stepUp) {
    const s = m.stepUp.payload;
    if (!verifySigned(m.stepUp, trust.principalKeys) || !listed(m.header.principal.keys, m.stepUp.signature.kid)) errors.push("step-up is not signed by a trusted principal key");
    if (s.contractDigest !== d || s.operationId !== m.operation.id) errors.push("step-up is for a different operation");
    if (s.detailsDigest !== auth.detailsDigest) errors.push("step-up approved different details");
    if (auth.amount && (!s.amount || s.amount.currency !== auth.amount.currency || auth.amount.minor > s.amount.minor)) errors.push("amount exceeds the step-up approval");
  }
  return { ok: errors.length === 0, errors };
}
