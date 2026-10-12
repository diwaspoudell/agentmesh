import postgres from "postgres";
import { afterAll, describe, expect, it } from "vitest";
import { money, OutcomeCoordinator, verifyBundle } from "../src/index.ts";
import { postgresStore } from "../src/store/postgres.ts";
import { contractFor, openApproved, sandboxProvider, world } from "./helpers.ts";

// Runs only against a real Postgres: AGENTMESH_TEST_DATABASE_URL=postgres://... npm test
const url = process.env.AGENTMESH_TEST_DATABASE_URL;
const schema = `agentmesh_test_${process.pid}`;

describe.skipIf(!url)("postgres store", () => {
  // Separate connection pools stand in for separate coordinator processes.
  const pools = url ? [postgres(url, { max: 4, onnotice: () => {} }), postgres(url, { max: 4, onnotice: () => {} })] : [];
  afterAll(async () => {
    await pools[0]?.unsafe(`drop schema if exists ${schema} cascade`);
    await Promise.all(pools.map((p) => p.end()));
  });

  it("keeps the shared budget safe across processes and round-trips a verifiable log", async () => {
    const providers = ["airline", "hotel", "cars"].map((id) => sandboxProvider(id, { status: "confirmed" }));
    const connectors = Object.fromEntries(providers.map((p) => [p.id, p.connector]));
    const base = world(connectors);
    const stores = pools.map((sql) => postgresStore(sql, { schema }));
    await stores[0]!.ready();
    const [a, b] = stores.map((store) => new OutcomeCoordinator({ store, signer: base.mesh, connectors, clock: base.clock.now }));
    const w = { ...base, coordinator: a! };
    const c = contractFor(w, {
      goal: "Rebook my trip under $500",
      participants: [{ id: "agent:x", role: "agent" }, ...providers.map((p) => ({ id: p.id, role: "provider" as const }))],
      constraints: { budget: money("USD", 500) },
      operations: [
        { id: "flight", provider: "airline", action: "book", executors: ["agent:x"], spend: money("USD", 300), expect: { success: ["confirmed"] } },
        { id: "hotel", provider: "hotel", action: "book", executors: ["agent:x"], spend: money("USD", 150), expect: { success: ["confirmed"] } },
        { id: "car", provider: "cars", action: "book", executors: ["agent:x"], spend: money("USD", 100), expect: { success: ["confirmed"] } },
      ],
    });
    await openApproved(w, c);
    const results = await Promise.all([
      a!.submit(c.id, "flight", { agent: "agent:x" }), b!.submit(c.id, "hotel", { agent: "agent:x" }), b!.submit(c.id, "car", { agent: "agent:x" }),
      a!.submit(c.id, "car", { agent: "agent:x" }), b!.submit(c.id, "flight", { agent: "agent:x" }),
    ]);
    const spent = providers.flatMap((p) => p.effects).reduce((n, e) => n + (e.debit?.minor ?? 0), 0);
    expect(spent).toBeLessThanOrEqual(50_000);
    expect(providers.every((p) => p.effects.length <= 1)).toBe(true);
    expect(results.filter((r) => r.ok).length).toBe(2);

    const bundle = await b!.exportBundle(c.id);
    expect(verifyBundle(bundle, { coordinatorKeys: [base.mesh.publicKey] }).problems).toEqual([]);
  });
});
