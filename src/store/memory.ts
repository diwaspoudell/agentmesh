import type { StoredEvent } from "../transaction.ts";
import { ConflictError, type EventStore } from "./types.ts";

/** For tests, demos and single-process use. Copies on the way in and out so callers can't mutate the log. */
export function memoryStore(): EventStore & { transactions(): string[] } {
  const logs = new Map<string, StoredEvent[]>();
  return {
    async load(id) {
      await Promise.resolve();
      return structuredClone(logs.get(id) ?? []);
    },
    async append(id, afterSeq, events) {
      await Promise.resolve();
      const log = logs.get(id) ?? [];
      if (log.length !== afterSeq) throw new ConflictError(id);
      logs.set(id, [...log, ...structuredClone(events)]);
    },
    transactions: () => [...logs.keys()],
  };
}
