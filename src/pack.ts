import { contractDigest, contractHeader, operationCommitment, type ContractHeader, type OperationSpec } from "./contract.ts";
import { verifySigned, type PublicKeyJwk, type Signed } from "./keys.ts";
import type { Evidence, SubmissionResult } from "./reconcile.ts";
import type { ContractApproval, ExecutionAuthorization, StepUpApproval } from "./statements.ts";
import { replay, type StoredEvent } from "./transaction.ts";

/**
 * Everything one provider is entitled to see about a transaction, and nothing else: the approved header, its own
 * operations, and the signed statements about them. Each piece is independently verifiable, so a provider can
 * dispute (or prove) its side without the user's goal, budget, or any other provider's work.
 */
export interface ProviderPack {
  type: "agentmesh.provider-pack";
  version: 0;
  provider: string;
  header: ContractHeader;
  approval: Signed<ContractApproval>;
  operations: {
    operation: OperationSpec;
    stepUps: Signed<StepUpApproval>[];
    submissions: { phase: "execute" | "compensate"; attempt: number; at: string; authorization: Signed<ExecutionAuthorization>; result?: SubmissionResult }[];
    /** Receipts, provider records and attestations about this operation. Agent claims and rejected evidence are left out. */
    evidence: Evidence[];
  }[];
}

export function providerPack(events: readonly StoredEvent[], provider: string): ProviderPack {
  const s = replay(events);
  if (!s.approval) throw new RangeError("the contract was never approved");
  const mine = s.contract.operations.filter((o) => o.provider === provider);
  if (!mine.length) throw new RangeError(`no operations for provider ${provider}`);
  return {
    type: "agentmesh.provider-pack", version: 0, provider, header: contractHeader(s.contract), approval: s.approval,
    operations: mine.map((operation) => {
      const op = s.ops[operation.id]!;
      const submissions: ProviderPack["operations"][number]["submissions"] = [];
      for (const e of events) {
        const b = e.body;
        if (b.type === "operation.submitting" && b.operationId === operation.id) submissions.push({ phase: b.phase, attempt: b.attempt, at: e.at, authorization: b.authorization });
        if (b.type === "operation.result" && b.operationId === operation.id) {
          const sub = submissions.find((x) => x.phase === b.phase && x.attempt === b.attempt);
          if (sub) sub.result = b.result;
        }
      }
      const evidence = [...op.execute.evidence, ...op.compensate.evidence]
        .filter((e) => e.valid && e.source !== "agent_claim")
        .map(({ seq: _s, at: _a, valid: _v, proof: _p, problem: _pr, ...rest }) => rest as Evidence);
      return { operation, stepUps: op.stepUps, submissions, evidence };
    }),
  };
}

/**
 * Checks a pack using only keys you already trust: the principal who approved, the coordinator that authorized, and
 * your own receipt key. Returns what's wrong, if anything.
 */
export function verifyProviderPack(pack: ProviderPack, trust: { principalKeys: readonly PublicKeyJwk[]; coordinatorKeys: readonly PublicKeyJwk[]; receiptKeys?: readonly PublicKeyJwk[] }) {
  const problems: string[] = [];
  const digest = contractDigest(pack.header);
  const listed = (keys: readonly PublicKeyJwk[], kid: string) => keys.some((k) => k.kid === kid);
  if (pack.approval.payload.contractDigest !== digest) problems.push("approval is for a different contract");
  if (!verifySigned(pack.approval, trust.principalKeys) || !listed(pack.header.principal.keys, pack.approval.signature.kid)) problems.push("approval is not signed by a trusted principal key");
  for (const { operation, stepUps, submissions, evidence } of pack.operations) {
    const at = `operation ${operation.id}`;
    if (!pack.header.commitments.operations.includes(operationCommitment(operation))) problems.push(`${at}: not part of the approved contract`);
    for (const x of stepUps) {
      if (x.payload.contractDigest !== digest || x.payload.operationId !== operation.id) problems.push(`${at}: step-up is for something else`);
      else if (!verifySigned(x, trust.principalKeys) || !listed(pack.header.principal.keys, x.signature.kid)) problems.push(`${at}: step-up is not signed by a principal key the contract names`);
    }
    for (const sub of submissions) {
      const a = sub.authorization;
      if (!verifySigned(a, trust.coordinatorKeys) || !listed(pack.header.coordinator.keys, a.signature.kid)) problems.push(`${at}: attempt ${sub.attempt} authorization is not signed by a trusted coordinator key`);
      else if (a.payload.contractDigest !== digest || a.payload.operationId !== operation.id || a.payload.operationCommitment !== operationCommitment(operation)) problems.push(`${at}: attempt ${sub.attempt} authorization is for something else`);
    }
    for (const e of evidence) {
      if (e.source === "signed_receipt" && trust.receiptKeys && (!e.receipt || !verifySigned(e.receipt, trust.receiptKeys))) problems.push(`${at}: a receipt does not verify with your key`);
    }
  }
  return { ok: problems.length === 0, problems };
}
