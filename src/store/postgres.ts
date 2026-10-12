import type { Sql } from "postgres";
import type { StoredEvent } from "../transaction.ts";
import { ConflictError, type EventStore } from "./types.ts";

/**
 * Event logs in Postgres. Bodies are stored as the exact JSON text that was hashed (jsonb would normalize it), and
 * the (transaction_id, seq) primary key makes two concurrent appends at the same position impossible: one wins,
 * the other gets ConflictError and re-decides. Tables live in their own schema (default "agentmesh").
 */
export function postgresStore(sql: Sql, o: { schema?: string } = {}): EventStore & { ready(): Promise<void> } {
  const schema = o.schema ?? "agentmesh";
  if (!/^[a-z_][a-z0-9_]{0,62}$/.test(schema)) throw new RangeError(`invalid schema name ${schema}`);
  const table = `${schema}.events`;
  let ready: Promise<void> | undefined;
  const ensure = () => (ready ??= sql.unsafe(`
    create schema if not exists ${schema};
    create table if not exists ${table} (
      transaction_id text not null, seq integer not null, at text not null, prev text not null, hash text not null, body text not null,
      recorded_at timestamptz not null default now(), primary key (transaction_id, seq));
  `).then(() => undefined).catch((e) => { ready = undefined; throw e; }));

  return {
    ready: ensure,
    async load(id) {
      await ensure();
      const rows = await sql.unsafe(`select seq, at, prev, hash, body from ${table} where transaction_id = $1 order by seq`, [id]);
      return rows.map((r) => ({ transactionId: id, seq: r.seq, at: r.at, prev: r.prev, hash: r.hash, body: JSON.parse(r.body) }) as StoredEvent);
    },
    async append(id, afterSeq, events) {
      await ensure();
      try {
        await sql.begin(async (tx) => {
          const [{ n }] = await tx.unsafe(`select count(*)::int as n from ${table} where transaction_id = $1`, [id]) as unknown as [{ n: number }];
          if (n !== afterSeq) throw new ConflictError(id);
          for (const e of events) {
            await tx.unsafe(`insert into ${table} (transaction_id, seq, at, prev, hash, body) values ($1, $2, $3, $4, $5, $6)`,
              [id, e.seq, e.at, e.prev, e.hash, JSON.stringify(e.body)]);
          }
        });
      } catch (err) {
        if (err instanceof ConflictError || (err as { code?: string }).code === "23505") throw new ConflictError(id);
        throw err;
      }
    },
  };
}
