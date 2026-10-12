import { describe, expect, it } from "vitest";
import {
  approveContract, approveStepUp, buildReport, canonicalize, defineContract, eventHash, generateSigner, memoryStore, money, OutcomeCoordinator, renderLog,
  replay, resume, suspend, verifyBundle, type ContractInput, type StoredEvent,
} from "../src/index.ts";
import { sandboxProvider } from "./helpers.ts";

// Continuous verification: random contracts, random provider faults, random concurrent actions, random operator
// interventions. After each run the invariants below must hold against the providers' ground truth, whatever
// happened. A failure names its seed, so `FUZZ_SEED=<n> npm run fuzz` replays it exactly.

const SEEDS = Number(process.env.FUZZ_SEEDS ?? 60);
const ONLY = process.env.FUZZ_SEED ? Number(process.env.FUZZ_SEED) : undefined;

function prng(seed: number) {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

const MODES = ["ok", "ok", "ok", "ok", "reject", "not_executed", "timeout_before", "timeout_after"] as const;
const T0 = Date.parse("2026-10-12T09:00:00.000Z");

async function runSeed(seed: number) {
  const r = prng(seed);
  const int = (n: number) => Math.floor(r() * n);
  const chance = (p: number) => r() < p;
  const pick = <T,>(xs: readonly T[]) => xs[int(xs.length)]!;

  let now = T0;
  const iso = (offset = 0) => new Date(now + offset).toISOString();
  const user = generateSigner(), mesh = generateSigner(), controller = generateSigner();
  const agents = ["agent:a", "agent:b", "agent:c"];
  const nOps = 2 + int(4);
  const signers = Array.from({ length: nOps }, () => generateSigner());
  const useSigner = Array.from({ length: nOps }, () => chance(0.5));

  const providers = Array.from({ length: nOps }, (_, i) => sandboxProvider(`p${i}`, {
    status: "done", pendingStatus: chance(0.25) ? "working" : undefined, idempotent: chance(0.6), lookup: chance(0.6), definitiveLookup: chance(0.8),
    signer: useSigner[i] ? signers[i] : undefined, modes: Array.from({ length: 1 + int(3) }, () => pick(MODES)),
  }));

  const budgetDollars = 100 + int(200);
  const useApproval = chance(0.3);
  const ops: NonNullable<ContractInput["operations"]> = providers.map((p, i) => {
    const spend = chance(0.8) ? money("USD", 10 + int(Math.min(100, budgetDollars - 10))) : undefined;
    const deps = ops_deps(i);
    return {
      id: `op${i}`, provider: p.id, action: "do.it", executors: [pick(agents)], required: chance(0.85), dependsOn: deps, spend,
      deadline: chance(0.3) ? iso((1 + int(5)) * 3_600_000) : undefined, maxAttempts: 1 + int(3),
      expect: { success: ["done"], pending: ["working"] },
    };
  });
  function ops_deps(i: number) { return Array.from({ length: i }, (_, j) => j).filter(() => chance(0.25)).map((j) => `op${j}`); }

  const contract = defineContract({
    createdAt: iso(), expiresAt: iso(7 * 86_400_000), goal: `fuzz ${seed}`,
    principal: { id: "user:u", keys: [user.publicKey] }, coordinator: { id: "agentmesh", keys: [mesh.publicKey] },
    participants: [
      ...agents.map((id) => ({ id, role: "agent" as const, vendor: pick(["v1", "v2", "v3"]) })),
      ...providers.map((p, i) => ({ id: p.id, role: "provider" as const, keys: useSigner[i] ? [signers[i]!.publicKey] : [] })),
      { id: "ctl", role: "controller" as const, keys: [controller.publicKey] },
    ],
    constraints: { budget: money("USD", budgetDollars), approvalAbove: useApproval ? money("USD", 30 + int(40)) : undefined },
    policy: { circuitBreaker: chance(0.3) ? { violations: 2 + int(3), windowSeconds: 600 } : undefined },
    operations: ops,
  });

  const store = memoryStore();
  const coordinator = new OutcomeCoordinator({
    store, signer: mesh, clock: () => new Date(now), staleAfterMs: 5 * 60_000,
    connectors: Object.fromEntries(providers.map((p) => [p.id, p.connector])),
  });
  await coordinator.open(contract);
  await coordinator.approve(contract.id, approveContract(contract, user, iso()));

  const spec = (id: string) => contract.operations.find((o) => o.id === id)!;
  const suspended = new Set<string>();
  let allSuspended = false, revoked = false;
  const steps = 25 + int(25);
  for (let n = 0; n < steps; n++) {
    const opId = `op${int(nOps)}`;
    const submit = () => coordinator.submit(contract.id, opId, {
      agent: chance(0.85) ? spec(opId).executors[0]! : pick(agents),
      amount: chance(0.7) ? undefined : money("USD", 1 + int(150)),
    });
    switch (int(12)) {
      case 0: case 1: case 2: case 3: await submit(); break;
      case 4: await Promise.all(Array.from({ length: 2 + int(3) }, submit)); break;
      case 5: case 6: await coordinator.reconcile(contract.id); break;
      case 7: now += pick([1_000, 60_000, 600_000, 3_600_000]); break;
      case 8: {
        const p = pick(providers);
        const op = `op${providers.indexOf(p)}`;
        p.settle(op);
        const receipt = p.receiptFor(op);
        if (receipt && chance(0.5)) await coordinator.ingestReceipt(receipt);
        break;
      }
      case 9: {
        const agent = pick(agents);
        const state = await coordinator.state(contract.id);
        const held = state.suspended.agents[agent];
        if (held) { await coordinator.resume(contract.id, resume(contract, held.by === "controller" ? controller : user, { agent }, iso())); suspended.delete(agent); }
        else if (!state.suspended.all) { await coordinator.suspend(contract.id, suspend(contract, chance(0.5) ? user : controller, { agent, reason: "fuzz" }, iso())); suspended.add(agent); }
        break;
      }
      case 10: {
        const o = spec(opId);
        await coordinator.stepUp(contract.id, approveStepUp(contract, user, opId, { amount: o.spend }, iso()));
        break;
      }
      case 11: {
        const state = await coordinator.state(contract.id);
        if (chance(0.5) && !state.revoked) {
          if (state.suspended.all) await coordinator.resume(contract.id, resume(contract, state.suspended.all.by === "controller" ? controller : user, {}, iso()));
          else await coordinator.suspend(contract.id, suspend(contract, user, {}, iso()));
        } else if (chance(0.1) && !state.revoked) {
          const { revokeContract } = await import("../src/index.ts");
          await coordinator.revoke(contract.id, revokeContract(contract, user, "fuzz", iso()));
        }
        break;
      }
    }
  }
  // Let everything that can settle settle, then let every deadline pass.
  for (let round = 0; round < 3; round++) {
    for (const agent of agents) await coordinator.run(contract.id, { agent, rounds: 3 });
    for (let i = 0; i < nOps; i++) { providers[i]!.settle(`op${i}`); const rc = providers[i]!.receiptFor(`op${i}`); if (rc && chance(0.5)) await coordinator.ingestReceipt(rc); }
    now += 3_600_000;
  }
  now += 8 * 86_400_000;
  await coordinator.reconcile(contract.id);

  return { contract, providers, coordinator, store, mesh, user, allSuspended, revoked, suspended, nOps, budgetDollars };
}

type Run = Awaited<ReturnType<typeof runSeed>>;

async function check(run: Run, seed: number, rand: () => number) {
  const bad: string[] = [];
  const need = (ok: boolean, what: string) => { if (!ok) bad.push(what); };
  const { coordinator, contract, providers } = run;
  const events = await coordinator.events(contract.id);
  const state = await coordinator.state(contract.id);
  const bundle = await coordinator.exportBundle(contract.id);

  // 1. The log verifies as a whole: every rule held, the checkpoint covers it, the principal approved it.
  const v = verifyBundle(bundle, { coordinatorKeys: [run.mesh.publicKey], principalKeys: [run.user.publicKey] });
  need(v.ok, `bundle failed verification: ${v.problems.join("; ")}`);
  // 2. What the coordinator holds in memory is exactly what replaying the log gives.
  need(canonicalize(state) === canonicalize(replay(events)), "live state differs from replay");
  // 3. The shared budget held against what providers actually did, not what anyone said.
  const debited = providers.flatMap((p) => p.effects).reduce((n, e) => n + (e.debit?.minor ?? 0), 0);
  const limit = (contract.constraints.budget?.minor ?? 0);
  need(debited <= limit, `providers were charged ${debited} against a budget of ${limit}`);
  const report = buildReport(state);
  need(report.budget!.spent.minor + report.budget!.held.minor >= debited, `books show ${report.budget!.spent.minor + report.budget!.held.minor} accounted for but ${debited} was really charged`);
  need(report.budget!.spent.minor + report.budget!.held.minor <= limit, "more accounted for than the budget allows");
  // 4. No duplicate effects; nothing is called verified without a real effect behind it.
  providers.forEach((p, i) => {
    const n = p.executions(`op${i}`).length;
    need(n <= 1, `op${i} was executed ${n} times`);
    if (state.ops[`op${i}`]!.status === "verified") need(n === 1, `op${i} is verified but the provider did nothing`);
  });
  // 5. Nothing was sent while revoked or suspended.
  let revoked = false, all = false;
  const agentHold = new Set<string>();
  for (const e of events) {
    const b = e.body;
    if (b.type === "contract.revoked") revoked = true;
    if (b.type === "contract.suspended") b.suspension.payload.agent === undefined ? (all = true) : agentHold.add(b.suspension.payload.agent);
    if (b.type === "contract.resumed") b.resumption.payload.agent === undefined ? (all = false) : agentHold.delete(b.resumption.payload.agent);
    if (b.type === "operation.submitting") {
      need(!revoked && !all, `event ${e.seq}: submitted while ${revoked ? "revoked" : "suspended"}`);
      if (b.phase === "execute") need(!agentHold.has(b.agent), `event ${e.seq}: ${b.agent} submitted while suspended`);
    }
  }
  // 6. The log reads back as one sentence per entry.
  need(renderLog(events).length === events.length, "renderLog skipped entries");
  // 7. Tampering is always noticed, even when the operator re-signs the checkpoint.
  const tamper = (label: string, evs: StoredEvent[]) => {
    const last = evs.at(-1)!;
    const forged = { ...bundle, events: evs, checkpoint: run.mesh.sign({ type: "agentmesh.checkpoint" as const, transactionId: last.transactionId, seq: last.seq, head: last.hash, at: last.at }) };
    need(!verifyBundle(forged, { coordinatorKeys: [run.mesh.publicKey] }).ok, `${label} went unnoticed`);
  };
  const i = Math.floor(rand() * events.length);
  const shifted = structuredClone(events);
  shifted[i]!.at = new Date(Date.parse(shifted[i]!.at) + 1).toISOString();
  tamper("changing a timestamp", shifted);
  if (events.length > 2) {
    const j = 1 + Math.floor(rand() * (events.length - 2));
    tamper("removing an entry", events.filter((_, k) => k !== j));
    const swapped = structuredClone(events);
    [swapped[j], swapped[j + 1]] = [swapped[j + 1]!, swapped[j]!];
    tamper("reordering entries", swapped);
  }
  if (bad.length) throw new Error(`seed ${seed}: ${bad.join(" | ")}`);
}

describe("invariants under random faults and interventions", () => {
  const seeds = ONLY !== undefined ? [ONLY] : Array.from({ length: SEEDS }, (_, i) => i + 1);

  it(`holds across ${seeds.length} seeded scenarios`, async () => {
    for (const seed of seeds) {
      let run: Run;
      try { run = await runSeed(seed); } catch (err) { throw new Error(`seed ${seed}: the system threw: ${(err as Error).stack}`); }
      await check(run, seed, prng(seed + 1_000_003));
    }
  }, 600_000);

  it("is deterministic: a seed produces the same outcome every time", async () => {
    const outcome = async () => {
      const run = await runSeed(7);
      const state = await run.coordinator.state(run.contract.id);
      return state.order.map((id) => `${id}:${state.ops[id]!.status}`).join(",");
    };
    expect(await outcome()).toBe(await outcome());
  });

  it("includes hand-picked hostile logs: a forged event hash is rejected outright", async () => {
    const run = await runSeed(3);
    const events = await run.coordinator.events(run.contract.id);
    const bad = structuredClone(events);
    bad[2]!.hash = eventHash({ ...bad[2]!, body: { type: "contract.expired" } });
    expect(() => replay(bad)).toThrow();
  });
});
