import type { StoredEvent } from "../transaction.ts";

/** Append-only, per-transaction event logs with optimistic concurrency. */
export interface EventStore {
  load(transactionId: string): Promise<StoredEvent[]>;
  /** Appends `events` only if the log currently ends at `afterSeq`; otherwise throws ConflictError and writes nothing. */
  append(transactionId: string, afterSeq: number, events: StoredEvent[]): Promise<void>;
}

/** Someone else appended first. Reload and decide again. */
export class ConflictError extends Error {
  constructor(transactionId: string) { super(`transaction ${transactionId} changed concurrently`); }
}
