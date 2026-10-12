import { describe, expect, it } from "vitest";
import {
  approveContract, approveStepUp, canonicalize, ContractError, contractDigest, contractHeader, defineContract, generateSigner, idempotencyKey,
  money, operationCommitment, parseContract, verifyMandate, type ContractInput, type ExecutionAuthorization, type Mandate,
} from "../src/index.ts";

const user = generateSigner();
const mesh = generateSigner();

function input(over: Partial<ContractInput> = {}): ContractInput {
  return {
    createdAt: "2026-10-12T09:00:00.000Z",
    expiresAt: "2026-10-19T09:00:00.000Z",
    goal: "Rebook my cancelled trip and keep additional spending below $500",
    principal: { id: "user:ana", keys: [user.publicKey] },
    coordinator: { id: "agentmesh", keys: [mesh.publicKey] },
    participants: [
      { id: "agent:dots", role: "agent" },
      { id: "airline", role: "provider" },
      { id: "hotel", role: "provider" },
    ],
    constraints: { budget: money("USD", 500), approvalAbove: money("USD", 100) },
    operations: [
      { id: "flight", provider: "airline", action: "booking.create", executors: ["agent:dots"], spend: money("USD", 400), expect: { success: ["ticketed"] } },
      { id: "hotel", provider: "hotel", action: "booking.modify", executors: ["agent:dots"], dependsOn: ["flight"], spend: money("USD", 150), expect: { success: ["confirmed"] } },
    ],
    ...over,
  };
}

const problems = (over: Partial<ContractInput>) => {
  try { defineContract(input(over)); return []; } catch (e) { return (e as ContractError).problems; }
};

describe("outcome contracts", () => {
  it("fills defaults so the signed form is fully explicit", () => {
    const c = defineContract(input());
    expect(c.id).toMatch(/^oc_/);
    expect(c.operations[0]!.salt.length).toBeGreaterThanOrEqual(16);
    expect(c.operations[0]!.evidence).toEqual(["signed_receipt", "provider_record", "human_attestation"]);
    expect(c.policy.onRequiredFailure).toBe("keep_completed");
    expect(parseContract(JSON.parse(JSON.stringify(c)))).toEqual(c);
  });

  it("rejects contracts that don't make sense as a whole", () => {
    const ops = input().operations!;
    expect(problems({ operations: [{ ...ops[0]!, dependsOn: ["hotel"] }, ops[1]!] }).join()).toMatch(/cycle/);
    expect(problems({ operations: [{ ...ops[0]!, executors: ["airline"] }] }).join()).toMatch(/not a participant with role "agent"/);
    expect(problems({ operations: [{ ...ops[0]!, spend: money("USD", 600) }] }).join()).toMatch(/exceeds the whole budget/);
    expect(problems({ operations: [{ ...ops[0]!, spend: money("EUR", 10) }] }).join()).toMatch(/must use USD/);
    expect(problems({ operations: [{ ...ops[0]!, expect: { success: ["ok"], failure: ["ok"] } }] }).join()).toMatch(/overlap/);
    expect(problems({ operations: [{ ...ops[0]!, deadline: "2026-12-01T00:00:00.000Z" }] }).join()).toMatch(/after the contract expires/);
    expect(problems({ goal: "" }).join()).toMatch(/goal/);
  });

  it("refuses received contracts that aren't normalized or carry unknown fields", () => {
    const c = defineContract(input());
    const { policy: _, ...missingDefault } = c;
    expect(() => parseContract(missingDefault)).toThrow(/normalized/);
    expect(() => parseContract({ ...c, extra: 1 })).toThrow();
  });

  it("commits to every term, without revealing them in the header", () => {
    const c = defineContract(input());
    const d = contractDigest(c);
    expect(contractDigest({ ...c, constraints: { ...c.constraints, budget: money("USD", 501) } })).not.toBe(d);
    expect(contractDigest({ ...c, goal: c.goal + "!" })).not.toBe(d);
    const header = canonicalize(contractHeader(c));
    expect(header).not.toContain("Rebook");
    expect(header).not.toContain("booking.create");
    expect(header).not.toContain("50000");
  });
});

describe("mandates (provider-side checks)", () => {
  const c = defineContract(input());
  const flight = c.operations[0]!;
  const approval = approveContract(c, user);
  const auth = (over: Partial<ExecutionAuthorization> = {}, signer = mesh) => signer.sign<ExecutionAuthorization>({
    type: "agentmesh.execution-authorization", contractId: c.id, contractDigest: contractDigest(c), operationId: "flight", operationCommitment: operationCommitment(flight),
    phase: "execute", attempt: 1, idempotencyKey: idempotencyKey(c.id, "flight", "execute", 0), agent: "agent:dots", amount: money("USD", 80),
    issuedAt: "2026-10-12T09:00:00.000Z", expiresAt: "2026-10-19T09:00:00.000Z", ...over,
  });
  const trust = { principalKeys: [user.publicKey], coordinatorKeys: [mesh.publicKey], now: new Date("2026-10-12T10:00:00.000Z") };
  const mandate = (over: Partial<Mandate> = {}): Mandate => ({ header: contractHeader(c), operation: flight, approval, authorization: auth(), ...over });

  it("verifies a scoped mandate: the provider sees only its own operation", () => {
    expect(verifyMandate(mandate(), trust)).toEqual({ ok: true, errors: [] });
    expect(JSON.stringify(mandate())).not.toContain("booking.modify");
  });

  it("catches altered terms, forged signatures, expiry and overspending", () => {
    const errs = (m: Mandate, t: Parameters<typeof verifyMandate>[1] = trust) => verifyMandate(m, t).errors.join("; ");
    expect(errs(mandate({ operation: { ...flight, params: { seat: "1A" } } }))).toMatch(/not part of the approved contract/);
    expect(errs(mandate({ approval: approveContract(c, generateSigner()) }))).toMatch(/approval is not signed by a trusted principal/);
    expect(errs(mandate({ authorization: auth({}, generateSigner()) }))).toMatch(/not signed by a trusted coordinator/);
    expect(errs(mandate({ authorization: auth({ amount: money("USD", 401) }) }))).toMatch(/exceeds what the operation may spend/);
    expect(errs(mandate(), { ...trust, now: new Date("2026-10-20T00:00:00.000Z") })).toMatch(/expired/);
    expect(errs(mandate(), { ...trust, idempotencyKey: "am_other" })).toMatch(/idempotency key/);
    // Even a provider that trusts the wrong key won't accept an approval from a key the contract doesn't name.
    const attacker = generateSigner();
    expect(verifyMandate(mandate({ approval: approveContract(c, attacker) }), { ...trust, principalKeys: [attacker.publicKey] }).errors.join()).toMatch(/approval/);
  });

  it("checks step-ups against the exact amount and details", () => {
    const details = { flight: "UA 902" };
    const a = auth({ amount: money("USD", 300), detailsDigest: undefined });
    const stepUp = approveStepUp(c, user, "flight", { amount: money("USD", 250) });
    expect(verifyMandate(mandate({ authorization: a, stepUp }), trust).errors.join()).toMatch(/exceeds the step-up/);
    const ok = approveStepUp(c, user, "flight", { amount: money("USD", 300), details });
    expect(verifyMandate(mandate({ authorization: a, stepUp: ok }), trust).errors.join()).toMatch(/different details/);
  });
});
