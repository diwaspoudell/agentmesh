import { verifyBundle, type OutcomeBundle } from "./bundle.ts";
import type { PublicKeyJwk, Signed, Signer } from "./keys.ts";
import type { WitnessStatement } from "./statements.ts";

export interface WitnessResult { ok: boolean; problems: string[]; statement?: Signed<WitnessStatement> }

/**
 * An independent witness (an auditor run by someone other than the coordinator's operator). It checks that a bundle is
 * internally valid and extends everything it has witnessed before, then signs what it saw. It never signs a history
 * that conflicts with an earlier one, so an operator can't show different logs to different people without a witness
 * statement contradicting one of them.
 *
 * `seen` is the witness's memory (transaction id → last witnessed position). Pass a Map you persist across restarts.
 */
export function createWitness(
  signer: Signer, o: { coordinatorKeys: readonly PublicKeyJwk[]; seen?: Map<string, { seq: number; head: string }>; clock?: () => Date },
) {
  const seen = o.seen ?? new Map<string, { seq: number; head: string }>();
  return {
    kid: signer.kid,
    publicKey: signer.publicKey,
    seen,
    observe(bundle: OutcomeBundle): WitnessResult {
      const v = verifyBundle(bundle, { coordinatorKeys: o.coordinatorKeys });
      if (!v.ok || !v.state) return { ok: false, problems: v.problems };
      const prev = seen.get(v.state.id);
      if (prev) {
        if (bundle.events.length < prev.seq) return { ok: false, problems: [`log has ${bundle.events.length} entries but ${prev.seq} were already witnessed: it was truncated`] };
        if (bundle.events[prev.seq - 1]!.hash !== prev.head) return { ok: false, problems: [`history was rewritten: entry ${prev.seq} no longer matches what was witnessed`] };
      }
      seen.set(v.state.id, { seq: v.state.seq, head: v.state.head });
      const statement = signer.sign({
        type: "agentmesh.witness-statement" as const, transactionId: v.state.id, seq: v.state.seq, head: v.state.head,
        coordinator: bundle.checkpoint.signature.kid, witnessedAt: (o.clock?.() ?? new Date()).toISOString(),
      });
      return { ok: true, problems: [], statement };
    },
  };
}

/** Attaches witness statements to a bundle. */
export function withWitnessings(bundle: OutcomeBundle, statements: Signed<WitnessStatement>[]): OutcomeBundle {
  return { ...bundle, witnessings: [...(bundle.witnessings ?? []), ...statements] };
}
