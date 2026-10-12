import { describe, expect, it } from "vitest";
import {
  approveContract, attest, budget, canonicalize, checkSubmission, contractProblems, createWitness, defineContract, derivePhase, digest,
  endorse, eventHash, generateSigner, idempotencyKey, InvariantError, makeBundle, money,
  parseContract, providerPack, signReceipt, signerFromPrivateKey, signWebhook, verifyBundle, verifyMandate, verifyProviderPack, verifySigned,
  verifyWebhook, ContractError, contractHeader, withWitnessings, OperationSchema,
  type Attempt, type ConnectorProfile, type EvidenceEntry, type ExecutionAuthorization, type Signed, type StoredEvent, type SubmissionResult,
} from "../src/index.ts";
import { sandboxProvider, contractFor, openApproved, world, T0, HOUR, DAY, type World } from "./helpers.ts";
import type { SandboxOptions } from "../src/index.ts";

/**
 * Adversarial stress tests for the AgentMesh outcome-reconciler SDK.
 * Each test is an attack, an abuse, or a hostile edge case against the
 * independent-verification thesis: an agent (or operator) must not be able
 * to fake, inflate, replay, or obscure what actually happened.
 *
 * Tests marked KNOWN BUG document behavior deliberately left as-is (hardening notes, not
 * vulnerabilities); every fixed finding now asserts the corrected behavior.
 */

function basicWorld(providerOpts: Partial<SandboxOptions> = {}, opExtra: Record<string, unknown> = {}) {
  const prov = sandboxProvider("air", { status: "confirmed", ...providerOpts });
  const w = world({ air: prov.connector });
  const contract = contractFor(w, {
    goal: "stress test",
    participants: [
      { id: "agent:a", role: "agent", vendor: "v1" },
      { id: "agent:b", role: "agent", vendor: "v2", keys: [generateSigner().publicKey] },
      { id: "air", role: "provider" },
    ],
    constraints: { budget: money("USD", 500) },
    operations: [
      { id: "book", provider: "air", action: "book", executors: ["agent:a"], spend: money("USD", 200), expect: { success: ["confirmed"], failure: ["rejected"] }, ...opExtra },
    ],
  });
  return { w, contract, prov };
}

async function approvedWorld(providerOpts: Partial<SandboxOptions> = {}, opExtra: Record<string, unknown> = {}) {
  const x = basicWorld(providerOpts, opExtra);
  await openApproved(x.w, x.contract);
  return x;
}

/** Narrows a SubmitResult known to be a refusal and returns its reason. */
function refused(r: { ok: boolean; reason?: string }) {
  expect(r.ok).toBe(false);
  if (r.ok) throw new Error("expected a refusal");
  return r.reason;
}

// ── 1. Signature attacks ─────────────────────────────────────────────────────

describe("signature attacks", () => {
  it("rejects a signature made by a different key", () => {
    const a = generateSigner(), b = generateSigner();
    const signed = a.sign({ type: "agentmesh.contract-approval", contractId: "x", contractDigest: "d", approvedAt: "t" });
    expect(verifySigned(signed, [b.publicKey])).toBe(false);
    expect(verifySigned(signed, [a.publicKey])).toBe(true);
  });

  it("rejects algorithm substitution and tampered alg fields", () => {
    const a = generateSigner();
    const signed = a.sign({ type: "t", contractId: "x", contractDigest: "d", approvedAt: "t" } as never);
    const tamperedAlg = { payload: signed.payload, signature: { ...signed.signature, alg: "EdDSA" } };
    expect(verifySigned(tamperedAlg as never, [a.publicKey])).toBe(false);
    const tamperedVal = { payload: signed.payload, signature: { ...signed.signature, value: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" } };
    expect(verifySigned(tamperedVal, [a.publicKey])).toBe(false);
  });

  it("rejects a key object whose kid does not match the key (key confusion)", () => {
    const a = generateSigner(), b = generateSigner();
    const signed = a.sign({ type: "t" } as never);
    // Attacker presents b's key material under a's kid.
    const confused = { ...b.publicKey, kid: a.publicKey.kid };
    expect(verifySigned({ payload: signed.payload, signature: { ...signed.signature, kid: a.publicKey.kid } }, [confused])).toBe(false);
  });

  it("rejects garbage and mismatched signature bytes without throwing", () => {
    const a = generateSigner();
    const signed = a.sign({ type: "t" } as never);
    for (const value of ["", "!!!not-base64!!!", "a".repeat(86)]) {
      expect(verifySigned({ payload: signed.payload, signature: { ...signed.signature, value } }, [a.publicKey])).toBe(false);
    }
    expect(verifySigned(null as never, [a.publicKey])).toBe(false);
    expect(verifySigned({} as never, [a.publicKey])).toBe(false);
  });

  it("a signed attestation cannot stand in as an execution authorization (type confusion)", async () => {
    const { w, contract } = await approvedWorld();
    const s = await w.coordinator.state(contract.id);
    const att = attest(contract, w.user, { operationId: "book", outcome: "succeeded" }, w.clock.iso());
    const v = verifyMandate(
      {
        header: contractHeader(contract),
        operation: contract.operations[0]!,
        approval: s.approval!,
        authorization: att as never,
      },
      { principalKeys: [w.user.publicKey], coordinatorKeys: [w.mesh.publicKey] },
    );
    expect(v.ok).toBe(false);
  });

  it("signerFromPrivateKey round-trips and keeps the same kid", () => {
    const a = generateSigner();
    const b = signerFromPrivateKey(a.exportPrivateKey());
    expect(b.kid).toBe(a.kid);
    const signed = b.sign({ type: "t" } as never);
    expect(verifySigned(signed, [a.publicKey])).toBe(true);
  });
});

// ── 2. Canonicalization ──────────────────────────────────────────────────────

describe("canonicalization", () => {
  it("is insensitive to key order, including nested", () => {
    expect(canonicalize({ b: 1, a: { d: 4, c: 3 } })).toBe(canonicalize({ a: { c: 3, d: 4 }, b: 1 }));
  });

  it("distinguishes float 1.5 from string \"1.5\" and int 1 from 1.0-text", () => {
    expect(canonicalize(1.5)).not.toBe(canonicalize("1.5"));
    expect(digest({ v: 1.5 })).not.toBe(digest({ v: "1.5" }));
  });

  it("drops undefined object members like JSON.stringify, but throws on undefined in arrays", () => {
    expect(canonicalize({ a: 1, b: undefined })).toBe('{"a":1}');
    expect(() => canonicalize([undefined])).toThrow(TypeError);
  });

  it("throws a typed error on non-finite numbers instead of producing bytes", () => {
    for (const n of [NaN, Infinity, -Infinity]) expect(() => canonicalize({ n })).toThrow(TypeError);
  });

  it("treats duplicate JSON keys as last-wins, consistently", () => {
    const parsed = JSON.parse('{"a":1,"a":2}');
    expect(canonicalize(parsed)).toBe('{"a":2}');
    expect(digest(parsed)).toBe(digest({ a: 2 }));
  });

  it("is stable: same value always hashes the same", () => {
    const v = { z: [3, 2, { b: "x", a: null }], a: true };
    expect(digest(v)).toBe(digest(JSON.parse(JSON.stringify(v))));
  });
});

// ── 3. Money ─────────────────────────────────────────────────────────────────

describe("money", () => {
  it("refuses sub-cent USD, sub-unit JPY, and over-precision KWD", () => {
    expect(() => money("USD", "149.995")).toThrow(RangeError);
    expect(() => money("JPY", "100.5")).toThrow(RangeError);
    expect(() => money("KWD", "1.2345")).toThrow(RangeError);
    expect(money("KWD", "1.234").minor).toBe(1234);
    expect(money("JPY", "100").minor).toBe(100);
  });

  it("refuses negatives, garbage text, and bad currency codes", () => {
    expect(() => money("USD", -5)).toThrow(RangeError);
    expect(() => money("USD", "-0.01")).toThrow(RangeError);
    expect(() => money("USD", "1,000")).toThrow(RangeError);
    expect(() => money("USD", " 5")).toThrow(RangeError);
    expect(() => money("USD", "")).toThrow(RangeError);
    expect(() => money("US", 5)).toThrow(RangeError);
    expect(() => money("usd", 5)).toThrow(RangeError);
    expect(money("USD", 0).minor).toBe(0);
  });

  it("refuses amounts that lose integer precision", () => {
    expect(() => money("USD", "90071992547409.93")).toThrow(RangeError); // *100 exceeds MAX_SAFE_INTEGER
    expect(() => money("USD", "90071992547409.92")).toThrow(RangeError); // 9007199254740992 > MAX_SAFE_INTEGER
    expect(money("USD", "90071992547409.91").minor).toBe(9007199254740991); // exactly MAX_SAFE_INTEGER: allowed
  });

  it("does not silently round: 149.9 stays exact", () => {
    expect(money("USD", 149.9).minor).toBe(14990);
    expect(() => money("USD", 0.1 + 0.2)).toThrow(RangeError); // 0.30000000000000004
  });
});

// ── 4. Unvalidated Money on the submit path ──────────────────────────────────

describe("untrusted amounts on submit()", () => {
  it("refuses a negative amount as a violation (never reaches the spend cap or budget math)", async () => {
    const { w, contract } = await approvedWorld();
    const r = await w.coordinator.submit(contract.id, "book", { agent: "agent:a", amount: { currency: "USD", minor: -50_000 } });
    expect(r.ok).toBe(false);
    if (r.ok) throw new Error("expected refusal");
    expect(r.reason).toMatch(/invalid amount/);
    const b = budget(r.state)!;
    expect(b.spent).toBe(0);
    expect(b.available).toBe(50_000); // the limit: the invariant "held + spent <= limit" holds
  });

  it("refuses a fractional minor unit, preserving the integer-minor invariant", async () => {
    const { w, contract } = await approvedWorld();
    const r = await w.coordinator.submit(contract.id, "book", { agent: "agent:a", amount: { currency: "USD", minor: 1.5 } });
    expect(r.ok).toBe(false);
    if (r.ok) throw new Error("expected refusal");
    expect(r.reason).toMatch(/invalid amount/);
    const s = await w.coordinator.state(contract.id);
    expect(s.ops.book!.execute.attempts).toHaveLength(0);
  });

  it("refuses a NaN amount with a typed refusal recorded in the log (not an untyped throw)", async () => {
    const { w, contract } = await approvedWorld();
    const r = await w.coordinator.submit(contract.id, "book", { agent: "agent:a", amount: { currency: "USD", minor: NaN } });
    expect(r.ok).toBe(false);
    if (r.ok) throw new Error("expected refusal");
    expect(r.reason).toMatch(/invalid amount/);
    const s = await w.coordinator.state(contract.id);
    expect(s.ops.book!.execute.attempts).toHaveLength(0);
    const events = await w.coordinator.events(contract.id);
    expect(events.some((e) => e.body.type === "operation.refused")).toBe(true);
  });

  it("a zero-minor amount with a junk currency is accepted but harmless", async () => {
    const { w, contract } = await approvedWorld();
    const r = await w.coordinator.submit(contract.id, "book", { agent: "agent:a", amount: { currency: "XXX", minor: 0 } });
    expect(r.ok).toBe(true); // minor is 0 so no spend checks fire; documents the gap (currency unchecked when minor is 0)
  });

  it("a positive amount in the wrong currency is refused as a violation", async () => {
    const { w, contract } = await approvedWorld();
    const r = await w.coordinator.submit(contract.id, "book", { agent: "agent:a", amount: { currency: "EUR", minor: 100 } });
    expect(r.ok).toBe(false);
    expect(refused(r)).toMatch(/must be in USD/);
  });
});

// ── 5. State-machine abuse ───────────────────────────────────────────────────

describe("state-machine abuse", () => {
  it("double approval, double revocation, double suspension are all rejected", async () => {
    const { w, contract } = await approvedWorld();
    await expect(w.coordinator.approve(contract.id, approveContract(contract, w.user, w.clock.iso()))).rejects.toThrow(/already approved/);
    const { revokeContract } = await import("../src/index.ts");
    await w.coordinator.revoke(contract.id, revokeContract(contract, w.user, "stop", w.clock.iso()));
    await expect(w.coordinator.revoke(contract.id, revokeContract(contract, w.user, "stop", w.clock.iso()))).rejects.toThrow(/already revoked/);
    // submit after revocation is refused, not recorded as a submission
    const r = await w.coordinator.submit(contract.id, "book", { agent: "agent:a" });
    expect(r.ok).toBe(false);
    expect(refused(r)).toMatch(/revoked/);
  });

  it("resuming without a suspension, and suspending twice, fail", async () => {
    const { w, contract } = await approvedWorld();
    const { suspend, resume } = await import("../src/index.ts");
    await expect(w.coordinator.resume(contract.id, resume(contract, w.user, {}, w.clock.iso()))).rejects.toThrow(/no such suspension/);
    await w.coordinator.suspend(contract.id, suspend(contract, w.user, { agent: "agent:a" }, w.clock.iso()));
    await expect(w.coordinator.suspend(contract.id, suspend(contract, w.user, { agent: "agent:a" }, w.clock.iso()))).rejects.toThrow(/already suspended/);
  });

  it("the coordinator cannot suspend the whole transaction or an agent without the breaker tripping", async () => {
    const prov = sandboxProvider("air", { status: "confirmed" });
    const w = world({ air: prov.connector });
    const contract = contractFor(w, {
      goal: "breaker",
      participants: [{ id: "agent:a", role: "agent" }, { id: "air", role: "provider" }],
      policy: { circuitBreaker: { violations: 3, windowSeconds: 600 } },
      operations: [{ id: "book", provider: "air", action: "book", executors: ["agent:a"], expect: { success: ["confirmed"] } }],
    });
    await openApproved(w, contract);
    const { suspend } = await import("../src/index.ts");
    await expect(w.coordinator.suspend(contract.id, suspend(contract, w.mesh, {}, w.clock.iso()))).rejects.toThrow(/only a single agent/);
    await expect(w.coordinator.suspend(contract.id, suspend(contract, w.mesh, { agent: "agent:a" }, w.clock.iso()))).rejects.toThrow(/circuit breaker has not tripped/);
  });

  it("suspension by an unknown agent id is rejected", async () => {
    const { w, contract } = await approvedWorld();
    const { suspend } = await import("../src/index.ts");
    await expect(w.coordinator.suspend(contract.id, suspend(contract, w.user, { agent: "agent:ghost" }, w.clock.iso()))).rejects.toThrow(/unknown agent/);
  });

  it("reconcile is idempotent: a second call changes nothing", async () => {
    const { w, contract } = await approvedWorld();
    await w.coordinator.submit(contract.id, "book", { agent: "agent:a" });
    const s1 = await w.coordinator.reconcile(contract.id);
    const s2 = await w.coordinator.reconcile(contract.id);
    expect(s2.seq).toBe(s1.seq);
    expect(s2.head).toBe(s1.head);
  });

  it("evidence recorded after the verdict can dispute it (a provider contradicting its own receipt)", async () => {
    const provSigner = generateSigner();
    const prov = sandboxProvider("air", { status: "confirmed", signer: provSigner });
    const w = world({ air: prov.connector });
    const contract = contractFor(w, {
      goal: "dispute",
      participants: [{ id: "agent:a", role: "agent" }, { id: "air", role: "provider", keys: [provSigner.publicKey] }],
      constraints: { budget: money("USD", 500) },
      operations: [{ id: "book", provider: "air", action: "book", executors: ["agent:a"], spend: money("USD", 200), expect: { success: ["confirmed"] } }],
    });
    await openApproved(w, contract);
    await w.coordinator.submit(contract.id, "book", { agent: "agent:a" });
    let s = await w.coordinator.state(contract.id);
    expect(s.ops.book!.status).toBe("verified");
    const key = s.ops.book!.execute.attempts[0]!.idempotencyKey;
    // The provider later signs a receipt for the same request showing a different charge.
    const contradicting = signReceipt(provSigner, {
      provider: "air", contractId: contract.id, operationId: "book", phase: "execute",
      idempotencyKey: key, observation: { status: "confirmed", debit: money("USD", 999) },
    });
    await w.coordinator.ingestReceipt(contradicting);
    s = await w.coordinator.state(contract.id);
    expect(s.ops.book!.status).toBe("disputed");
    expect(s.ops.book!.findings.some((f) => /different amounts charged|approved up to/.test(f))).toBe(true);
    expect(prov.effects).toHaveLength(1); // the provider really only acted once
  });

  it("a receipt signed by a key the contract does not list is recorded as invalid, never as proof", async () => {
    const { w, contract } = await approvedWorld();
    const rogue = generateSigner();
    const s0 = await w.coordinator.state(contract.id);
    const key = idempotencyKey(contract.id, "book", "execute", 0);
    await w.coordinator.ingestReceipt(signReceipt(rogue, {
      provider: "air", contractId: contract.id, operationId: "book", phase: "execute",
      idempotencyKey: key, observation: { status: "confirmed" },
    }));
    const s = await w.coordinator.state(contract.id);
    const ev = s.ops.book!.execute.evidence.at(-1)!;
    expect(ev.valid).toBe(false);
    expect(ev.proof).toBe(false);
    expect(ev.problem).toMatch(/not signed by a key listed for the provider/);
    expect(s.ops.book!.status).not.toBe("verified");
    expect(s0.seq + 1).toBe(s.seq);
  });

  it("an attestation by an unlisted key is recorded as invalid", async () => {
    const { w, contract } = await approvedWorld();
    const rogue = generateSigner();
    await w.coordinator.attest(contract.id, attest(contract, rogue, { operationId: "book", outcome: "succeeded" }, w.clock.iso()));
    const s = await w.coordinator.state(contract.id);
    const ev = s.ops.book!.execute.evidence.at(-1)!;
    expect(ev.valid).toBe(false);
    expect(ev.problem).toMatch(/not signed by the principal or a listed reviewer/);
  });

  it("only the principal can waive; a reviewer's waiver is invalid", async () => {
    const reviewer = generateSigner();
    const prov = sandboxProvider("air", { status: "confirmed" });
    const w = world({ air: prov.connector });
    const contract = contractFor(w, {
      goal: "waive", participants: [{ id: "agent:a", role: "agent" }, { id: "air", role: "provider" }, { id: "rev:r", role: "reviewer", keys: [reviewer.publicKey] }],
      operations: [{ id: "book", provider: "air", action: "book", executors: ["agent:a"], expect: { success: ["confirmed"] } }],
    });
    await openApproved(w, contract);
    await w.coordinator.attest(contract.id, attest(contract, reviewer, { operationId: "book", outcome: "waived" }, w.clock.iso()));
    const s = await w.coordinator.state(contract.id);
    const ev = s.ops.book!.execute.evidence.at(-1)!;
    expect(ev.valid).toBe(false);
    expect(ev.problem).toMatch(/only the principal can waive/);
    await w.coordinator.attest(contract.id, attest(contract, w.user, { operationId: "book", outcome: "waived" }, w.clock.iso()));
    const s2 = await w.coordinator.state(contract.id);
    expect(s2.ops.book!.status).toBe("waived");
  });

  it("a receipt for a different operation or phase does not verify the target", async () => {
    const provSigner = generateSigner();
    const prov = sandboxProvider("air", { status: "confirmed", signer: provSigner });
    const w = world({ air: prov.connector });
    const contract = contractFor(w, {
      goal: "x", participants: [{ id: "agent:a", role: "agent" }, { id: "air", role: "provider", keys: [provSigner.publicKey] }],
      operations: [
        { id: "op1", provider: "air", action: "a1", executors: ["agent:a"], expect: { success: ["confirmed"] } },
        { id: "op2", provider: "air", action: "a2", executors: ["agent:a"], expect: { success: ["confirmed"] } },
      ],
    });
    await openApproved(w, contract);
    await w.coordinator.submit(contract.id, "op1", { agent: "agent:a" });
    const s = await w.coordinator.state(contract.id);
    const key = s.ops.op1!.execute.attempts[0]!.idempotencyKey;
    // Receipt honestly signed by the provider, but about op2 while carrying op1's
    // idempotency key. ingestReceipt routes by the receipt's own operationId, so it
    // lands on op2 where the key check quarantines it as invalid.
    await w.coordinator.ingestReceipt(signReceipt(provSigner, {
      provider: "air", contractId: contract.id, operationId: "op2", phase: "execute", idempotencyKey: key, observation: { status: "confirmed" },
    }));
    const s2 = await w.coordinator.state(contract.id);
    const bad = s2.ops.op2!.execute.evidence.at(-1)!;
    expect(bad.valid).toBe(false);
    expect(bad.problem).toMatch(/does not match any submission/);
    expect(s2.ops.op2!.status).not.toBe("verified");
  });
});

// ── 6. Evidence-log tampering ────────────────────────────────────────────────

describe("evidence-log tampering", () => {
  async function log3() {
    const { w, contract } = await approvedWorld();
    await w.coordinator.submit(contract.id, "book", { agent: "agent:a" });
    return { w, contract, events: await w.coordinator.events(contract.id) };
  }

  it("tampering with any event body breaks replay", async () => {
    const { events } = await log3();
    const tampered = structuredClone(events) as StoredEvent[];
    (tampered[2]!.body as { type: string }).type = "contract.expired";
    const { replay } = await import("../src/index.ts");
    expect(() => replay(tampered)).toThrow(InvariantError);
    expect(() => replay(tampered)).toThrow(/hash does not match/);
  });

  it("dropping an event breaks the chain", async () => {
    const { events } = await log3();
    const { replay } = await import("../src/index.ts");
    expect(() => replay(events.filter((_, i) => i !== 1))).toThrow(/out of sequence/);
  });

  it("reordering events breaks the chain", async () => {
    const { events } = await log3();
    const { replay } = await import("../src/index.ts");
    const reordered = [events[0]!, events[2]!, events[1]!];
    expect(() => replay(reordered)).toThrow(InvariantError);
  });

  it("duplicating an event breaks the chain", async () => {
    const { events } = await log3();
    const { replay } = await import("../src/index.ts");
    expect(() => replay([...events, events[1]!])).toThrow(/out of sequence/);
  });

  it("a forked history with a valid internal chain is still caught by an earlier checkpoint anchor", async () => {
    const { w, contract, events } = await log3();
    // Anchor: the coordinator published a checkpoint at seq 2 (after approval).
    const anchor = w.mesh.sign({ type: "agentmesh.checkpoint" as const, transactionId: contract.id, seq: 2, head: events[1]!.hash, at: w.clock.iso() });
    // Operator presents a truncated log with a fresh checkpoint covering only what remains.
    const truncatedCp = w.mesh.sign({ type: "agentmesh.checkpoint" as const, transactionId: contract.id, seq: 1, head: events[0]!.hash, at: w.clock.iso() });
    const v = verifyBundle(makeBundle(events.slice(0, 1), truncatedCp), { coordinatorKeys: [w.mesh.publicKey], anchors: [anchor] });
    expect(v.ok).toBe(false);
    expect(v.problems.some((p) => p.includes("entries were removed"))).toBe(true);
  });

  it("a bundle checkpoint signed by an untrusted key is rejected", async () => {
    const { w, contract } = await approvedWorld();
    await w.coordinator.submit(contract.id, "book", { agent: "agent:a" });
    const bundle = await w.coordinator.exportBundle(contract.id);
    const v = verifyBundle(bundle, { coordinatorKeys: [generateSigner().publicKey] });
    expect(v.ok).toBe(false);
    expect(v.problems.some((p) => p.includes("not signed by a trusted coordinator key"))).toBe(true);
  });

  it("a witness refuses a rewritten history and signs a consistent one", async () => {
    const { w, contract } = await log3();
    const witSigner = generateSigner();
    const witness = createWitness(witSigner, { coordinatorKeys: [w.mesh.publicKey] });
    const bundle = await w.coordinator.exportBundle(contract.id);
    const seen = witness.observe(bundle);
    expect(seen.ok).toBe(true);
    expect(seen.statement).toBeDefined();
    // Fork: the SAME coordinator key signs a different history for the same transaction
    // id (the operator shows two histories). The witness must refuse the second.
    const { OutcomeCoordinator, memoryStore } = await import("../src/index.ts");
    const w2clock = { now: new Date(T0 + 1), advance: (ms: number) => { w2clock.now = new Date(w2clock.now.getTime() + ms); } };
    const w2store = memoryStore();
    const w2coord = new OutcomeCoordinator({ store: w2store, signer: w.mesh, connectors: { air2: sandboxProvider("air2", { status: "confirmed" }).connector }, clock: () => w2clock.now });
    const w2 = { user: w.user, mesh: w.mesh, clock: { now: () => w2clock.now, advance: w2clock.advance, iso: (o = 0) => new Date(w2clock.now.getTime() + o).toISOString() }, store: w2store, coordinator: w2coord };
    const c2 = contractFor(w2 as never, {
      goal: "stress test", participants: [{ id: "agent:a", role: "agent" }, { id: "air2", role: "provider" }],
      constraints: { budget: money("USD", 500) },
      operations: [{ id: "book", provider: "air2", action: "book", executors: ["agent:a"], spend: money("USD", 200), expect: { success: ["confirmed"] } }],
    });
    // Reuse the same transaction id to simulate the operator showing two histories for one id.
    const c2fixed = defineContract({ ...JSON.parse(JSON.stringify(c2)), id: contract.id });
    await w2.coordinator.open(c2fixed);
    await w2.coordinator.approve(c2fixed.id, approveContract(c2fixed, w2.user, w2.clock.iso()));
    const bundle2 = await w2.coordinator.exportBundle(c2fixed.id);
    expect(bundle2.checkpoint.payload.head).not.toBe(bundle.checkpoint.payload.head);
    const again = witness.observe(bundle2);
    expect(again.ok).toBe(false);
    expect(again.problems.some((p) => p.includes("rewritten") || p.includes("truncated"))).toBe(true);
  });

  it("withWitnessings attaches statements a later verifier can count", async () => {
    const { w, contract } = await approvedWorld();
    await w.coordinator.submit(contract.id, "book", { agent: "agent:a" });
    const bundle = await w.coordinator.exportBundle(contract.id);
    const wit = createWitness(generateSigner(), { coordinatorKeys: [w.mesh.publicKey] });
    const st = wit.observe(bundle).statement!;
    const v = verifyBundle(withWitnessings(bundle, [st]), { coordinatorKeys: [w.mesh.publicKey], witnesses: { keys: [wit.publicKey], required: 1 } });
    expect(v.ok).toBe(true);
    expect(v.witnessed).toEqual([wit.publicKey.kid]);
    const v2 = verifyBundle(withWitnessings(bundle, [st]), { coordinatorKeys: [w.mesh.publicKey], witnesses: { keys: [wit.publicKey], required: 2 } });
    expect(v2.ok).toBe(false);
    expect(v2.problems.some((p) => p.includes("needs 2 independent witnesses"))).toBe(true);
  });
});

// ── 7. Time attacks ──────────────────────────────────────────────────────────

describe("time attacks", () => {
  it("submit at exactly expiresAt is refused (boundary is exclusive)", async () => {
    const { w, contract } = await approvedWorld();
    w.clock.advance(Date.parse(contract.expiresAt) - T0);
    const r = await w.coordinator.submit(contract.id, "book", { agent: "agent:a" });
    expect(r.ok).toBe(false);
    expect(refused(r)).toMatch(/expired/);
  });

  it("a deadline reached exactly is treated as expired by reconcile", async () => {
    const { w, contract } = await approvedWorld(
      { pendingStatus: "working" },
      { deadline: new Date(T0 + 2 * HOUR).toISOString(), expect: { success: ["confirmed"], failure: ["rejected"], pending: ["working"] } },
    );
    await w.coordinator.submit(contract.id, "book", { agent: "agent:a" });
    let s = await w.coordinator.state(contract.id);
    expect(s.ops.book!.status).toBe("pending_verification");
    w.clock.advance(2 * HOUR);
    s = await w.coordinator.reconcile(contract.id);
    expect(s.ops.book!.expiredAt).toBeDefined();
    // No proof yet: pending past the deadline becomes unknown and escalates.
    expect(s.ops.book!.status).toBe("unknown");
    expect(s.ops.book!.escalation).toMatch(/unknown/);
  });

  it("an attestation dated in the future beyond 5 minutes is invalid", async () => {
    const { w, contract } = await approvedWorld();
    const future = new Date(T0 + 10 * 60_000).toISOString();
    await w.coordinator.attest(contract.id, attest(contract, w.user, { operationId: "book", outcome: "succeeded" }, future));
    const s = await w.coordinator.state(contract.id);
    expect(s.ops.book!.execute.evidence.at(-1)!.valid).toBe(false);
    expect(s.ops.book!.execute.evidence.at(-1)!.problem).toMatch(/in the future/);
  });

  it("KNOWN BUG?: a years-old backdated attestation is accepted as proof with no freshness check", async () => {
    const { w, contract } = await approvedWorld();
    await w.coordinator.attest(contract.id, attest(contract, w.user, { operationId: "book", outcome: "succeeded" }, "2020-01-01T00:00:00.000Z"));
    const s = await w.coordinator.state(contract.id);
    const ev = s.ops.book!.execute.evidence.at(-1)!;
    expect(ev.valid).toBe(true); // accepted: there is no lower bound on attestedAt
    expect(ev.proof).toBe(true);
  });

  it("events cannot go backwards in time even if the clock does", async () => {
    const { w, contract } = await approvedWorld();
    await w.coordinator.submit(contract.id, "book", { agent: "agent:a" });
    w.clock.advance(-1); // clock skew backwards
    const s = await w.coordinator.reconcile(contract.id);
    const events = await w.coordinator.events(contract.id);
    for (let i = 1; i < events.length; i++) {
      expect(Date.parse(events[i]!.at) >= Date.parse(events[i - 1]!.at)).toBe(true);
    }
    expect(s.seq).toBe(events.length);
  });
});

// ── 8. Claimed-done-but-not: the thesis core ─────────────────────────────────

describe("claimed-done-but-not", () => {
  it("an agent relaying 'it worked' never verifies the operation", async () => {
    const { w, contract } = await approvedWorld({ kind: "agent", lookup: false, idempotent: true, modes: ["claim_success"] });
    const r = await w.coordinator.submit(contract.id, "book", { agent: "agent:a" });
    expect(r.ok).toBe(true); // the request went out...
    const s = await w.coordinator.state(contract.id);
    expect(s.ops.book!.status).toBe("pending_verification"); // ...but nothing is confirmed
    expect(s.ops.book!.findings.some((f) => f.includes("agent reports the request was accepted"))).toBe(true);
    const { outcome } = await import("../src/index.ts");
    expect(outcome(s).status).toBe("pending_verification");
  });

  it("the reconciler catches an agent lying about success: provider proof of failure wins, lie is surfaced", async () => {
    const { w, contract } = await approvedWorld({ modes: ["reject"] });
    await w.coordinator.submit(contract.id, "book", { agent: "agent:a" });
    // The agent claims it succeeded anyway.
    await w.coordinator.recordClaim(contract.id, "book", { agent: "agent:a", observation: { status: "confirmed" } });
    const s = await w.coordinator.state(contract.id);
    expect(s.ops.book!.status).toBe("rejected"); // the provider's answer decides, not the agent's claim
    expect(s.ops.book!.findings.some((f) => f.includes('reported "confirmed"') && f.includes("does not confirm"))).toBe(true);
  });

  it("duplicate submit after acceptance is refused: no double execution", async () => {
    const { w, contract, prov } = await approvedWorld();
    const r1 = await w.coordinator.submit(contract.id, "book", { agent: "agent:a" });
    expect(r1.ok).toBe(true);
    const r2 = await w.coordinator.submit(contract.id, "book", { agent: "agent:a" });
    expect(r2.ok).toBe(false);
    expect(prov.executions("book")).toHaveLength(1);
  });

  it("KNOWN BUG (liveness): an agent connector's lookup polls forever and never settles", async () => {
    const { w, contract } = await approvedWorld({ kind: "agent", lookup: true, idempotent: true, modes: ["claim_success"] });
    await w.coordinator.submit(contract.id, "book", { agent: "agent:a" });
    const s1 = await w.coordinator.reconcile(contract.id);
    const seqAfterFirst = s1.seq;
    expect(s1.ops.book!.next).toBe("lookup");
    const s2 = await w.coordinator.reconcile(contract.id);
    // Identical lookup answers are deduped from the log, but the operation still wants another lookup:
    // without a deadline this never reaches a terminal state or an escalation.
    expect(s2.ops.book!.next).toBe("lookup");
    expect(s2.ops.book!.status).toBe("pending_verification");
    expect(s2.seq).toBe(seqAfterFirst); // log stopped growing, polling did not
  });
});

// ── 9. Cross-checks and budget ───────────────────────────────────────────────

describe("cross-checks and budget", () => {
  async function crossCheckWorld() {
    const agentA = generateSigner();
    const agentB = generateSigner();
    const prov = sandboxProvider("air", { status: "confirmed" });
    const w = world({ air: prov.connector });
    const contract = contractFor(w, {
      goal: "cc",
      participants: [
        { id: "agent:a", role: "agent", vendor: "v1", keys: [agentA.publicKey] },
        { id: "agent:b", role: "agent", vendor: "v2", keys: [agentB.publicKey] },
        { id: "air", role: "provider" },
      ],
      operations: [{
        id: "book", provider: "air", action: "book", executors: ["agent:a"], spend: money("USD", 200),
        expect: { success: ["confirmed"] }, crossCheck: { min: 1, distinctVendors: true },
      }],
    });
    await openApproved(w, contract);
    return { w, contract, agentA, agentB };
  }

  it("submission without the required cross-check is refused", async () => {
    const { w, contract } = await crossCheckWorld();
    const r = await w.coordinator.submit(contract.id, "book", { agent: "agent:a", details: { seat: "1A" } });
    expect(r.ok).toBe(false);
    expect(refused(r)).toMatch(/needs 1 independent cross-check/);
  });

  it("the executor cannot cross-check its own request, and a stale-details endorsement does not count", async () => {
    const { w, contract, agentA, agentB } = await crossCheckWorld();
    const details = { seat: "1A" };
    // Executor endorsing itself: the signature verifies (it is agent:a's key), but it must not count.
    await w.coordinator.endorse(contract.id, endorse(contract, agentA, { agent: "agent:a", operationId: "book", amount: money("USD", 200), details }, w.clock.iso()));
    const r1 = await w.coordinator.submit(contract.id, "book", { agent: "agent:a", details });
    expect(r1.ok).toBe(false);
    expect(refused(r1)).toMatch(/needs 1 independent cross-check/);
    // Endorsement for different details: does not count either.
    await w.coordinator.endorse(contract.id, endorse(contract, agentB, { agent: "agent:b", operationId: "book", amount: money("USD", 200), details: { seat: "2B" } }, w.clock.iso()));
    const r2 = await w.coordinator.submit(contract.id, "book", { agent: "agent:a", details });
    expect(r2.ok).toBe(false);
    // Correct endorsement: counts.
    await w.coordinator.endorse(contract.id, endorse(contract, agentB, { agent: "agent:b", operationId: "book", amount: money("USD", 200), details }, w.clock.iso()));
    const r3 = await w.coordinator.submit(contract.id, "book", { agent: "agent:a", details });
    expect(r3.ok).toBe(true);
  });

  it("an objection blocks the request until addressed", async () => {
    const { w, contract, agentB } = await crossCheckWorld();
    const details = { seat: "1A" };
    await w.coordinator.endorse(contract.id, endorse(contract, agentB, { agent: "agent:b", operationId: "book", verdict: "object", reason: "wrong flight", details }, w.clock.iso()));
    const r = await w.coordinator.submit(contract.id, "book", { agent: "agent:a", details });
    expect(r.ok).toBe(false);
    expect(refused(r)).toMatch(/objected/);
  });

  it("concurrent submits never exceed the shared budget", async () => {
    const providers = ["p1", "p2", "p3"].map((id) => sandboxProvider(id, { status: "confirmed" }));
    const w = world(Object.fromEntries(providers.map((p) => [p.id, p.connector])));
    const contract = contractFor(w, {
      goal: "budget race",
      participants: [{ id: "agent:a", role: "agent" }, ...providers.map((p) => ({ id: p.id, role: "provider" as const }))],
      constraints: { budget: money("USD", 500) },
      operations: providers.map((p, i) => ({
        id: `op${i}`, provider: p.id, action: "book", executors: ["agent:a"], spend: money("USD", 300), expect: { success: ["confirmed"] },
      })),
    });
    await openApproved(w, contract);
    const results = await Promise.all(providers.map((p, i) => w.coordinator.submit(contract.id, `op${i}`, { agent: "agent:a" })));
    const s = await w.coordinator.state(contract.id);
    const b = budget(s)!;
    expect(b.held + b.spent).toBeLessThanOrEqual(50_000);
    expect(b.available).toBeGreaterThanOrEqual(0);
    // 300 + 300 > 500, so at most one of the three could reserve.
    expect(results.filter((r) => r.ok).length).toBeLessThanOrEqual(1);
  });

  it("spending exactly the available budget is allowed; one cent over is refused", async () => {
    const providers = ["p1", "p2"].map((id) => sandboxProvider(id, { status: "confirmed" }));
    const w = world(Object.fromEntries(providers.map((p) => [p.id, p.connector])));
    const contract = contractFor(w, {
      goal: "boundary",
      participants: [{ id: "agent:a", role: "agent" }, ...providers.map((p) => ({ id: p.id, role: "provider" as const }))],
      constraints: { budget: money("USD", 500) },
      operations: providers.map((p, i) => ({
        id: `op${i}`, provider: p.id, action: "book", executors: ["agent:a"], spend: money("USD", 500), expect: { success: ["confirmed"] },
      })),
    });
    await openApproved(w, contract);
    const r1 = await w.coordinator.submit(contract.id, "op0", { agent: "agent:a", amount: money("USD", 300) });
    expect(r1.ok).toBe(true);
    // Exactly the remaining 200.00 is fine...
    const r2 = await w.coordinator.submit(contract.id, "op1", { agent: "agent:a", amount: money("USD", 200) });
    expect(r2.ok).toBe(true);
    expect(budget(await w.coordinator.state(contract.id))!.available).toBe(0);
  });

  it("one cent over the available budget is refused", async () => {
    const providers = ["p1", "p2"].map((id) => sandboxProvider(id, { status: "confirmed" }));
    const w = world(Object.fromEntries(providers.map((p) => [p.id, p.connector])));
    const contract = contractFor(w, {
      goal: "boundary2",
      participants: [{ id: "agent:a", role: "agent" }, ...providers.map((p) => ({ id: p.id, role: "provider" as const }))],
      constraints: { budget: money("USD", 500) },
      operations: providers.map((p, i) => ({
        id: `op${i}`, provider: p.id, action: "book", executors: ["agent:a"], spend: money("USD", 500), expect: { success: ["confirmed"] },
      })),
    });
    await openApproved(w, contract);
    expect((await w.coordinator.submit(contract.id, "op0", { agent: "agent:a", amount: money("USD", 300) })).ok).toBe(true);
    const r = await w.coordinator.submit(contract.id, "op1", { agent: "agent:a", amount: money("USD", 200.01) });
    expect(r.ok).toBe(false);
    expect(refused(r)).toMatch(/would exceed the shared budget/);
  });
});

// ── 10. Webhooks ─────────────────────────────────────────────────────────────

describe("webhooks", () => {
  const secret = "s3cret";
  const body = JSON.stringify({ id: "evt_1", type: "outcome_intent.created" });

  it("round-trips, and rejects tampered bodies, wrong secrets, and stale timestamps", () => {
    const t = 1_700_000_000;
    const h = signWebhook(body, secret, t);
    expect(verifyWebhook(body, h, secret, { now: () => t }).ok).toBe(true);
    expect(verifyWebhook(body + "x", h, secret, { now: () => t }).ok).toBe(false);
    expect(verifyWebhook(body, h, "wrong", { now: () => t }).ok).toBe(false);
    const stale = verifyWebhook(body, h, secret, { now: () => t + 301 });
    expect(stale.ok).toBe(false);
    expect(stale.reason).toMatch(/tolerance/);
    // Replays inside the window are accepted by design (at-least-once): receivers must dedupe on event.id.
    expect(verifyWebhook(body, h, secret, { now: () => t + 10 }).ok).toBe(true);
  });

  it("rejects malformed headers and future timestamps outside tolerance", () => {
    const t = 1_700_000_000;
    const h = signWebhook(body, secret, t);
    expect(verifyWebhook(body, null, secret, { now: () => t }).ok).toBe(false);
    expect(verifyWebhook(body, "garbage", secret, { now: () => t }).ok).toBe(false);
    expect(verifyWebhook(body, "t=abc,v1=00", secret, { now: () => t }).ok).toBe(false);
    expect(verifyWebhook(body, h, secret, { now: () => t + 10_000 }).ok).toBe(false);
    // Custom tolerance is honored.
    expect(verifyWebhook(body, h, secret, { now: () => t + 10_000, toleranceSeconds: 20_000 }).ok).toBe(true);
  });
});

// ── 11. Mandate / provider-pack verification gaps ────────────────────────────

describe("mandate and provider-pack verification", () => {
  async function approvedMandateWorld() {
    const agentA = generateSigner();
    const prov = sandboxProvider("air", { status: "confirmed" });
    const w = world({ air: prov.connector });
    const contract = contractFor(w, {
      goal: "mandate",
      participants: [
        { id: "agent:a", role: "agent", vendor: "v1", keys: [agentA.publicKey] },
        { id: "air", role: "provider" },
      ],
      constraints: { budget: money("USD", 1000), approvalAbove: money("USD", 100) },
      operations: [{
        id: "book", provider: "air", action: "book", executors: ["agent:a"], spend: money("USD", 500),
        expect: { success: ["confirmed"] }, requiresApproval: true,
      }],
    });
    await openApproved(w, contract);
    return { w, contract, prov };
  }

  it("a provider can verify a well-formed mandate", async () => {
    const { w, contract } = await approvedMandateWorld();
    const { approveStepUp } = await import("../src/index.ts");
    await w.coordinator.stepUp(contract.id, approveStepUp(contract, w.user, "book", { amount: money("USD", 500) }, w.clock.iso()));
    const r = await w.coordinator.submit(contract.id, "book", { agent: "agent:a", amount: money("USD", 400) });
    expect(r.ok).toBe(true);
    const events = await w.coordinator.events(contract.id);
    const sub = events.find((e) => e.body.type === "operation.submitting")!;
    const s = await w.coordinator.state(contract.id);
    const auth = (sub.body as unknown as { authorization: Signed<ExecutionAuthorization> }).authorization;
    const v = verifyMandate(
      { header: contractHeader(contract), operation: contract.operations[0]!, approval: s.approval!, stepUp: s.ops.book!.stepUps[0], authorization: auth },
      { principalKeys: [w.user.publicKey], coordinatorKeys: [w.mesh.publicKey] },
    );
    expect(v.ok).toBe(true);
    expect(v.errors).toEqual([]);
  });

  it("verifyProviderPack rejects a step-up signed by a trusted-but-unlisted key, like verifyMandate", async () => {
    const { w, contract } = await approvedMandateWorld();
    const { approveStepUp } = await import("../src/index.ts");
    await w.coordinator.stepUp(contract.id, approveStepUp(contract, w.user, "book", { amount: money("USD", 500) }, w.clock.iso()));
    await w.coordinator.submit(contract.id, "book", { agent: "agent:a", amount: money("USD", 400) });
    const events = await w.coordinator.events(contract.id);
    const pack = providerPack(events, "air");
    const rogue = generateSigner();
    // A malicious coordinator swaps in a step-up signed by a key that is trusted by the
    // provider out-of-band but was never listed in the contract's principal keys.
    const rogueStepUp = approveStepUp(contract, { ...w.user, kid: rogue.kid, publicKey: rogue.publicKey, sign: rogue.sign } as never, "book", { amount: money("USD", 500) }, w.clock.iso());
    const tampered = { ...pack, operations: pack.operations.map((o) => ({ ...o, stepUps: [rogueStepUp] })) };
    const packVerdict = verifyProviderPack(tampered, { principalKeys: [w.user.publicKey, rogue.publicKey], coordinatorKeys: [w.mesh.publicKey] });
    expect(packVerdict.ok).toBe(false); // the signer is not a principal key the contract names
    expect(packVerdict.problems.some((p) => p.includes("step-up"))).toBe(true);
    const s = await w.coordinator.state(contract.id);
    const sub = events.find((e) => e.body.type === "operation.submitting")!;
    const auth = (sub.body as unknown as { authorization: Signed<ExecutionAuthorization> }).authorization;
    const mandateVerdict = verifyMandate(
      { header: contractHeader(contract), operation: contract.operations[0]!, approval: s.approval!, stepUp: rogueStepUp, authorization: auth },
      { principalKeys: [w.user.publicKey, rogue.publicKey], coordinatorKeys: [w.mesh.publicKey] },
    );
    expect(mandateVerdict.ok).toBe(false); // verifyMandate requires the key to be listed in the contract
  });

  it("approvalAbove is visible to the provider: verifyMandate rejects a mandate above the threshold with no step-up", async () => {
    const prov = sandboxProvider("air", { status: "confirmed" });
    const w = world({ air: prov.connector });
    const contract = contractFor(w, {
      goal: "above",
      participants: [{ id: "agent:a", role: "agent" }, { id: "air", role: "provider" }],
      constraints: { budget: money("USD", 1000), approvalAbove: money("USD", 100) },
      operations: [{
        id: "book", provider: "air", action: "book", executors: ["agent:a"], spend: money("USD", 500),
        expect: { success: ["confirmed"] }, // note: NOT requiresApproval; the threshold alone triggers the step-up
      }],
    });
    await openApproved(w, contract);
    const { approveStepUp } = await import("../src/index.ts");
    await w.coordinator.stepUp(contract.id, approveStepUp(contract, w.user, "book", { amount: money("USD", 500) }, w.clock.iso()));
    const r = await w.coordinator.submit(contract.id, "book", { agent: "agent:a", amount: money("USD", 400) });
    expect(r.ok).toBe(true); // 400 > approvalAbove 100, so a step-up was required and used
    const events = await w.coordinator.events(contract.id);
    const s = await w.coordinator.state(contract.id);
    const sub = events.find((e) => e.body.type === "operation.submitting")!;
    const auth = (sub.body as unknown as { authorization: Signed<ExecutionAuthorization> }).authorization;
    const base = { header: contractHeader(contract), operation: contract.operations[0]!, approval: s.approval!, authorization: auth };
    const trust = { principalKeys: [w.user.publicKey], coordinatorKeys: [w.mesh.publicKey] };
    // With the step-up present the mandate verifies...
    expect(verifyMandate({ ...base, stepUp: s.ops.book!.stepUps[0] }, trust).ok).toBe(true);
    // ...but if the coordinator had "forgotten" it, the provider can now tell: the threshold
    // is in the header in the clear, bound by the principal's signature over the contract digest.
    const forgotten = verifyMandate(base, trust);
    expect(forgotten.ok).toBe(false); // 400 > approvalAbove 100 with no step-up
    expect(forgotten.errors.some((e) => e.includes("step-up"))).toBe(true);
  });

  it("an expired authorization is rejected by the provider", async () => {
    const { w, contract } = await approvedMandateWorld();
    const { approveStepUp } = await import("../src/index.ts");
    await w.coordinator.stepUp(contract.id, approveStepUp(contract, w.user, "book", { amount: money("USD", 500) }, w.clock.iso()));
    await w.coordinator.submit(contract.id, "book", { agent: "agent:a", amount: money("USD", 400) });
    const events = await w.coordinator.events(contract.id);
    const s = await w.coordinator.state(contract.id);
    const sub = events.find((e) => e.body.type === "operation.submitting")!;
    const auth = (sub.body as unknown as { authorization: Signed<ExecutionAuthorization> }).authorization;
    const v = verifyMandate(
      { header: contractHeader(contract), operation: contract.operations[0]!, approval: s.approval!, stepUp: s.ops.book!.stepUps[0], authorization: auth },
      { principalKeys: [w.user.publicKey], coordinatorKeys: [w.mesh.publicKey], now: new Date(Date.parse(contract.expiresAt) + 1000) },
    );
    expect(v.ok).toBe(false);
    expect(v.errors.some((e) => e.includes("expired"))).toBe(true);
  });
});

// ── 12. Intents.create idempotency semantics ─────────────────────────────────

describe("Intents.create retry semantics", () => {
  it("same id with changed financial terms is rejected instead of silently returning the old intent", async () => {
    const { Intents } = await import("../src/index.ts");
    const prov = sandboxProvider("air", { status: "confirmed" });
    const w = world({ air: prov.connector });
    const intents = new Intents(w.coordinator, { providers: { air: {} } });
    const base = {
      id: "intent-dup", goal: "book a flight", principal: { id: "user:ana", key: w.user.publicKey },
      agents: ["agent:a"], steps: [{ provider: "air", action: "book", expect: "confirmed" as const }],
    };
    const first = await intents.create({ ...base, steps: [{ provider: "air", action: "book", spend: money("USD", 100), expect: "confirmed" as const }], budget: money("USD", 100) });
    // The caller asked for a $999 budget: retry-safety must not silently hand back the $100 one.
    await expect(intents.create({ ...base, steps: [{ provider: "air", action: "book", spend: money("USD", 999), expect: "confirmed" as const }], budget: money("USD", 999) }))
      .rejects.toThrow(/different terms/);
    // An exact retry still dedups to the same intent.
    const retry = await intents.create({ ...base, steps: [{ provider: "air", action: "book", spend: money("USD", 100), expect: "confirmed" as const }], budget: money("USD", 100) });
    expect(retry.id).toBe(first.id);
    expect(retry.contract.operations[0]!.spend).toEqual(money("USD", 100));
  });

  it("same id with a different goal or different steps is rejected", async () => {
    const { Intents } = await import("../src/index.ts");
    const prov = sandboxProvider("air", { status: "confirmed" });
    const w = world({ air: prov.connector });
    const intents = new Intents(w.coordinator, { providers: { air: {} } });
    const base = {
      id: "intent-dup2", goal: "book a flight", principal: { id: "user:ana", key: w.user.publicKey },
      agents: ["agent:a"], steps: [{ provider: "air", action: "book", expect: "confirmed" as const }],
    };
    await intents.create(base);
    await expect(intents.create({ ...base, goal: "something else" })).rejects.toThrow(/different terms/);
  });
});

// ── 13. Unwind outcome reporting ─────────────────────────────────────────────

describe("unwind outcome reporting", () => {
  it("a fully compensated transaction reports 'undone', not 'failed'", async () => {
    const { outcome } = await import("../src/index.ts");
    const providers = ["p1", "p2"].map((id) => sandboxProvider(id, {
      status: "confirmed", compensation: { status: "refunded", refund: true },
    }));
    const w = world(Object.fromEntries(providers.map((p) => [p.id, p.connector])));
    const contract = contractFor(w, {
      goal: "unwind",
      participants: [{ id: "agent:a", role: "agent" }, ...providers.map((p) => ({ id: p.id, role: "provider" as const }))],
      policy: { onRequiredFailure: "compensate_completed" },
      operations: [
        {
          id: "pay", provider: "p1", action: "pay", executors: ["agent:a"], spend: money("USD", 100),
          expect: { success: ["confirmed"] },
          compensation: { action: "refund", expect: { success: ["refunded"] } },
        },
        { id: "ship", provider: "p2", action: "ship", executors: ["agent:a"], expect: { success: ["confirmed"], failure: ["rejected"] } },
      ],
    });
    // ship will fail; pay will be compensated.
    providers[1]!.connector.execute = async () => ({ outcome: "rejected", reason: "no stock" });
    await openApproved(w, contract);
    await w.coordinator.submit(contract.id, "pay", { agent: "agent:a" });
    await w.coordinator.submit(contract.id, "ship", { agent: "agent:a" });
    let s = await w.coordinator.reconcile(contract.id);
    expect(s.ops.pay!.status).toBe("compensated");
    // The required op failed, so the principal waives it to clear the escalation.
    await w.coordinator.attest(contract.id, attest(contract, w.user, { operationId: "ship", outcome: "waived" }, w.clock.iso()));
    s = await w.coordinator.state(contract.id);
    expect(s.ops.ship!.status).toBe("waived");
    expect(outcome(s).status).toBe("undone"); // money is back and the rest was waived: nothing stands, and that is the verified outcome
  });
});

// ── 14. Concurrency ─────────────────────────────────────────────────────────

describe("concurrency", () => {
  it("parallel recordClaim calls lose nothing and keep the chain intact", async () => {
    const { w, contract } = await approvedWorld();
    const before = (await w.coordinator.state(contract.id)).seq;
    const n = 25;
    await Promise.all(Array.from({ length: n }, (_, i) =>
      w.coordinator.recordClaim(contract.id, "book", { agent: "agent:a", observation: { status: `claim-${i}` } }),
    ));
    const events = await w.coordinator.events(contract.id);
    expect(events).toHaveLength(before + n);
    const seqs = events.map((e) => e.seq);
    expect(new Set(seqs).size).toBe(seqs.length);
    for (let i = 1; i < events.length; i++) expect(events[i]!.prev).toBe(events[i - 1]!.hash);
    const { replay } = await import("../src/index.ts");
    expect(() => replay(events)).not.toThrow();
  });

  it("parallel submits for the same operation produce one attempt, not two", async () => {
    const { w, contract, prov } = await approvedWorld();
    const results = await Promise.all(Array.from({ length: 5 }, () => w.coordinator.submit(contract.id, "book", { agent: "agent:a" })));
    expect(results.filter((r) => r.ok)).toHaveLength(1);
    expect(prov.executions("book")).toHaveLength(1);
    const s = await w.coordinator.state(contract.id);
    expect(s.ops.book!.execute.attempts).toHaveLength(1);
  });
});

// ── 15. Public API fuzz: typed errors only, never silent accepts or crashes ──

describe("public API fuzz", () => {
  it("defineContract rejects garbage with ContractError", () => {
    for (const bad of [{}, { goal: 1 }, null, "x", [], { goal: "g", operations: [] }]) {
      expect(() => defineContract(bad as never)).toThrow(ContractError);
    }
  });

  it("parseContract rejects a contract that is not in normalized form", async () => {
    const { w } = basicWorld();
    const c = contractFor(w, { goal: "g", participants: [{ id: "agent:a", role: "agent" }, { id: "air", role: "provider" }], operations: [{ id: "book", provider: "air", action: "book", executors: ["agent:a"], expect: { success: ["confirmed"] } }] });
    const denormalized = JSON.parse(JSON.stringify(c)) as Record<string, unknown>;
    delete (denormalized.operations as Record<string, unknown>[])[0]!["params"]; // a default defineContract would fill
    expect(() => parseContract(denormalized)).toThrow(ContractError);
    expect(parseContract(JSON.parse(JSON.stringify(c)))).toBeTruthy(); // normalized round-trips
  });

  it("contractProblems catches key reuse across roles (separation of duties)", async () => {
    const { contract } = await approvedWorld();
    const k = generateSigner().publicKey;
    const problems = contractProblems({
      ...contract,
      principal: { id: "user:ana", keys: [k] },
      coordinator: { id: "agentmesh", keys: [k] },
    });
    expect(problems.some((p) => p.includes("one key may hold only one role"))).toBe(true);
  });

  it("checkSubmission on unknown operations and agents returns typed refusals", async () => {
    const { w, contract } = await approvedWorld();
    const s = await w.coordinator.state(contract.id);
    const at = w.clock.iso();
    expect(checkSubmission(s, { operationId: "nope", phase: "execute", agent: "agent:a", at }).ok).toBe(false);
    const r = checkSubmission(s, { operationId: "book", phase: "execute", agent: "agent:ghost", at });
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.kind).toBe("violation");
    // Compensations may only run as the coordinator.
    const c2 = checkSubmission(s, { operationId: "book", phase: "compensate", agent: "agent:a", at });
    expect(c2.ok).toBe(false);
  });

  it("random malformed inputs to pure functions throw typed errors or return typed results", async () => {
    const { replay, renderLog, intentEvents } = await import("../src/index.ts");
    expect(() => replay([])).toThrow(InvariantError);
    expect(() => renderLog([])).toThrow(InvariantError);
    expect(() => intentEvents([])).toThrow(InvariantError);
    expect(verifySigned({ payload: { type: "t" }, signature: { alg: "Ed25519", kid: "x", value: "y" } } as never, [])).toBe(false);
    expect(verifyWebhook("b", "t=1", "s").ok).toBe(false);
    expect(eventHash({ transactionId: "t", seq: 1, at: "x", prev: "y", body: { type: "nonsense" } } as never)).toMatch(/^sha256:/);
  });

  it("discloseIncident and providerPack reject unknown ids with RangeError", async () => {
    const { discloseIncident } = await import("../src/index.ts");
    const { w, contract } = await approvedWorld();
    const events = await w.coordinator.events(contract.id);
    expect(() => discloseIncident(events, "inc-nope", { audience: "public" })).toThrow(RangeError);
    expect(() => providerPack(events, "ghost-provider")).toThrow(RangeError);
  });

  it("derivePhase never verifies on unrecognized statuses, and flags overcharges as disputed", async () => {
    const spec = OperationSchema.parse({
      id: "op", provider: "p", action: "a", executors: ["agent:a"],
      expect: { success: ["ok"], failure: ["no"] },
    });
    const api: ConnectorProfile = { kind: "api", idempotent: true, lookup: false };
    const att = (result: SubmissionResult): Attempt => ({ n: 1, at: "2026-10-12T09:00:00Z", agent: "agent:a", idempotencyKey: "k", generation: 0, connector: api, result, seq: 2 });
    const ev = (status: string, extra: object = {}): EvidenceEntry =>
      ({ source: "provider_record", via: "response", observation: { status, ...extra }, seq: 3, at: "2026-10-12T09:00:00Z", valid: true, proof: true });
    const v = (attempts: Attempt[], evidence: EvidenceEntry[]) => derivePhase({ phase: "execute", spec, expectation: spec.expect, attempts, evidence, expired: false, refs: () => undefined });
    expect(v([att({ outcome: "accepted" })], [ev("weird")]).status).toBe("unknown");
    expect(v([att({ outcome: "accepted" })], [ev("no")]).status).toBe("failed");
    // Charge shown by proof but nothing authorized: disputed, never silently verified.
    expect(v([att({ outcome: "accepted" })], [ev("ok", { debit: money("USD", 5) })]).status).toBe("disputed");
  });
});
