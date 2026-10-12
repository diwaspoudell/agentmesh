import { describe, expect, it } from "vitest";
import {
  approveContract, checkConnector, contractDigest, contractHeader, generateSigner, idempotencyKey, operationCommitment, randomId,
  type ExecuteRequest, type ProviderConnector,
} from "../src/index.ts";
import { contractFor, sandboxProvider, world } from "./helpers.ts";

const w = world();
const c = contractFor(w, {
  goal: "conformance", participants: [{ id: "agent:a", role: "agent" }, { id: "p", role: "provider" }],
  operations: [{ id: "op", provider: "p", action: "x.do", executors: ["agent:a"], expect: { success: ["done"] } }],
});
const request = (): ExecuteRequest => {
  const key = idempotencyKey(c.id, `op-${randomId()}`, "execute", 0);
  const authorization = w.mesh.sign({
    type: "agentmesh.execution-authorization" as const, contractId: c.id, contractDigest: contractDigest(c), operationId: "op", operationCommitment: operationCommitment(c.operations[0]!),
    phase: "execute" as const, attempt: 1, idempotencyKey: key, agent: "agent:a", issuedAt: w.clock.iso(), expiresAt: c.expiresAt,
  });
  return {
    contractId: c.id, operationId: "op", phase: "execute", attempt: 1, action: "x.do", params: {}, idempotencyKey: key,
    mandate: { header: contractHeader(c), operation: c.operations[0]!, approval: approveContract(c, w.user), authorization },
  };
};

describe("provider connector conformance", () => {
  it("passes for a provider that keeps its promises", async () => {
    const key = generateSigner();
    const r = await checkConnector(sandboxProvider("p", { status: "done", signer: key }).connector, { request, receiptKeys: [key.publicKey] });
    expect(r.checks.filter((x) => !x.ok)).toEqual([]);
    expect(r.checks.length).toBeGreaterThanOrEqual(7);
  });

  it("fails a provider that claims idempotency but repeats the effect", async () => {
    const real = sandboxProvider("p", { status: "done", idempotent: false });
    const liar: ProviderConnector = { ...real.connector, idempotent: true };
    const r = await checkConnector(liar, { request });
    expect(r.ok).toBe(false);
    expect(r.checks.find((x) => !x.ok)?.name).toBe("same key, same result (idempotency)");
  });

  it("fails a lookup that invents records", async () => {
    const p = sandboxProvider("p", { status: "done" });
    const lookup = p.connector.lookup!;
    const eager: ProviderConnector = { ...p.connector, lookup: async (q) => ((await lookup(q)).found ? lookup(q) : { found: true, observation: { status: "done" } }) };
    const r = await checkConnector(eager, { request });
    expect(r.checks.find((x) => !x.ok)?.name).toBe("lookup reports no record for a key it never saw");
  });

  it("fails receipts signed with an undeclared key", async () => {
    const r = await checkConnector(sandboxProvider("p", { status: "done", signer: generateSigner() }).connector, { request, receiptKeys: [generateSigner().publicKey] });
    expect(r.checks.filter((x) => !x.ok).map((x) => x.name)).toContain("receipt is signed by a declared provider key");
  });
});
