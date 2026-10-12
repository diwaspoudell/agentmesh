import {
  approveContract, defineContract, generateSigner, memoryStore, OutcomeCoordinator, sandboxProvider,
  type ContractInput, type ProviderConnector, type Signer,
} from "../src/index.ts";

export const T0 = Date.parse("2026-10-12T09:00:00.000Z");

/** A controllable clock for deadlines and stale submissions. */
export function testClock(start = T0) {
  let now = start;
  return { now: () => new Date(now), advance: (ms: number) => { now += ms; }, iso: (offsetMs = 0) => new Date(now + offsetMs).toISOString() };
}

export const HOUR = 3_600_000;
export const DAY = 24 * HOUR;

export interface World {
  user: Signer;
  mesh: Signer;
  clock: ReturnType<typeof testClock>;
  store: ReturnType<typeof memoryStore>;
  coordinator: OutcomeCoordinator;
}

export function world(connectors: Record<string, ProviderConnector> = {}, o: { staleAfterMs?: number } = {}): World {
  const user = generateSigner();
  const mesh = generateSigner();
  const clock = testClock();
  const store = memoryStore();
  const coordinator = new OutcomeCoordinator({ store, signer: mesh, connectors, clock: clock.now, staleAfterMs: o.staleAfterMs });
  return { user, mesh, clock, store, coordinator };
}

/** Fills in the principal, coordinator and timestamps for a contract under test. */
export function contractFor(w: World, input: Omit<ContractInput, "principal" | "coordinator" | "expiresAt" | "createdAt"> & { expiresAt?: string }) {
  return defineContract({
    createdAt: w.clock.iso(),
    expiresAt: w.clock.iso(7 * DAY),
    principal: { id: "user:ana", keys: [w.user.publicKey] },
    coordinator: { id: "agentmesh", keys: [w.mesh.publicKey] },
    ...input,
  });
}

export async function openApproved(w: World, contract: ReturnType<typeof defineContract>) {
  await w.coordinator.open(contract);
  return w.coordinator.approve(contract.id, approveContract(contract, w.user, w.clock.iso()));
}

export { sandboxProvider };
