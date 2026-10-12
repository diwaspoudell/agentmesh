import { describe, expect, it } from "vitest";
import { derivePhase, money, OperationSchema, type Attempt, type ConnectorProfile, type EvidenceEntry, type SubmissionResult } from "../src/index.ts";

const spec = OperationSchema.parse({
  id: "refund", provider: "shop", action: "order.refund", executors: ["agent:a"], maxAttempts: 2,
  expect: { success: ["settled"], pending: ["issued"], failure: ["denied"], credit: { min: money("USD", "149.99") } },
});
const api: ConnectorProfile = { kind: "api", idempotent: true, lookup: true };
const attempt = (result?: SubmissionResult, connector = api, n = 1): Attempt => ({ n, at: "2026-10-12T09:00:00Z", agent: "agent:a", idempotencyKey: "am_k", generation: 0, connector, result, seq: n + 1 });
const record = (status: string, extra: object = {}, seq = 10): EvidenceEntry => ({ source: "provider_record", via: "lookup", observation: { status, ...extra }, seq, at: "2026-10-12T10:00:00Z", valid: true, proof: true });
const verdict = (attempts: Attempt[], evidence: EvidenceEntry[] = []) => derivePhase({ phase: "execute", spec, expectation: spec.expect, attempts, evidence, expired: false, refs: () => undefined });

describe("reconciliation rules", () => {
  it("verifies only when the evidence shows the approved terms", () => {
    expect(verdict([attempt({ outcome: "accepted" })], [record("settled", { credit: money("USD", "149.99") })]).status).toBe("verified");
    const short = verdict([attempt({ outcome: "accepted" })], [record("settled", { credit: money("USD", 100) })]);
    expect(short.status).toBe("disputed");
    expect(short.findings.at(-1)).toBe("returned $100.00, expected at least $149.99");
    const unproven = verdict([attempt({ outcome: "accepted" })], [record("settled")]);
    expect(unproven.status).toBe("pending");
    expect(unproven.findings).toContain("evidence does not show the amount returned");
  });

  it("flags a charge on an operation that wasn't allowed to spend", () => {
    const v = verdict([attempt({ outcome: "accepted" })], [record("settled", { credit: money("USD", 150), debit: money("USD", 5) })]);
    expect(v.status).toBe("disputed");
    expect(v.findings.at(-1)).toMatch(/no spending was approved/);
  });

  it("disputes when authoritative sources disagree", () => {
    const v = verdict([attempt({ outcome: "accepted" })], [record("settled", { credit: money("USD", 150) }), { ...record("denied", {}, 11), source: "signed_receipt" }]);
    expect(v.status).toBe("disputed");
  });

  it("never lets a claim or invalid evidence decide", () => {
    const claim: EvidenceEntry = { ...record("settled", { credit: money("USD", 150) }), source: "agent_claim", proof: false };
    const forged: EvidenceEntry = { ...record("settled", { credit: money("USD", 150) }), source: "signed_receipt", valid: false, proof: false, problem: "bad signature" };
    const v = verdict([attempt({ outcome: "accepted" })], [claim, forged]);
    expect(v.status).toBe("pending");
    expect(v.findings).toContain("ignored signed receipt: bad signature");
  });

  it("reads statuses through the contract's lists", () => {
    expect(verdict([attempt({ outcome: "accepted" })], [record("issued")]).status).toBe("pending");
    expect(verdict([attempt({ outcome: "accepted" })], [record("denied")]).status).toBe("failed");
    expect(verdict([attempt({ outcome: "accepted" })], [record("on_hold")]).status).toBe("unknown");
  });

  it("chooses the safe next step after each kind of submission result", () => {
    expect(verdict([attempt({ outcome: "ambiguous", reason: "timeout" })]).next).toBe("lookup");
    expect(verdict([attempt({ outcome: "ambiguous", reason: "timeout" }, { ...api, lookup: false })]).next).toBe("retry_same_key");
    const stuck = verdict([attempt({ outcome: "ambiguous", reason: "timeout" }, { kind: "api", idempotent: false, lookup: false })]);
    expect([stuck.status, stuck.next]).toEqual(["unknown", null]);
    expect(verdict([attempt({ outcome: "not_executed", reason: "429", retryable: true })]).next).toBe("retry_new_key");
    const spent = verdict([attempt({ outcome: "not_executed", reason: "429", retryable: true }), attempt({ outcome: "not_executed", reason: "429", retryable: true }, api, 2)]);
    expect([spent.status, spent.findings.at(-1)]).toEqual(["failed", "no attempts left"]);
    expect(verdict([attempt({ outcome: "rejected", reason: "no" })]).status).toBe("rejected");
    // Through an agent, "it was rejected" is a claim: it can't release budget or justify a retry.
    expect(verdict([attempt({ outcome: "rejected", reason: "no" }, { kind: "agent", idempotent: false, lookup: false })]).status).toBe("unknown");
  });
});
