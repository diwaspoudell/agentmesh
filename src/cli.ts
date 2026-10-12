#!/usr/bin/env node
import { readFileSync } from "node:fs";
import { verifyBundle, type OutcomeBundle } from "./bundle.ts";
import type { PublicKeyJwk, Signed } from "./keys.ts";
import { renderLog } from "./log.ts";
import { renderReport } from "./report.ts";
import type { Checkpoint } from "./statements.ts";

const USAGE = `agentmesh-verify: re-derive and check a transaction's outcome from its evidence bundle

Usage: agentmesh-verify <bundle.json> --coordinator-key <key> [options]

  --coordinator-key <key>  Trusted coordinator public key (JWK file or JSON). Repeatable. Required.
  --principal-key <key>    Require the contract to have been approved by this key. Repeatable.
  --anchor <file>          A checkpoint you received earlier; the log must still contain that history. Repeatable.
  --witness-key <key>      A trusted independent witness's public key. Repeatable.
  --witnesses <n>          Require statements from at least n distinct trusted witnesses (default 1 when a witness key is given).
  --log                    Print the log as plain sentences.
  --report                 Print the outcome report.
  --json                   Print the result as JSON.

Exit status: 0 verified, 1 verification failed, 2 usage error.`;

const readJson = (arg: string): unknown => {
  const text = arg.trim().startsWith("{") || arg.trim().startsWith("[") ? arg : readFileSync(arg, "utf8");
  return JSON.parse(text);
};
const keys = (arg: string) => [readJson(arg)].flat() as PublicKeyJwk[];

export function run(argv: string[], out: (line: string) => void = console.log): number {
  const flags = new Set(["--log", "--report", "--json"]);
  const valued = new Set(["--coordinator-key", "--principal-key", "--anchor", "--witness-key", "--witnesses"]);
  const file: string[] = [];
  const opts = new Map<string, string[]>();
  const on = new Set<string>();
  try {
    for (let i = 0; i < argv.length; i++) {
      const a = argv[i]!;
      if (flags.has(a)) on.add(a);
      else if (valued.has(a)) {
        const v = argv[++i];
        if (v === undefined) throw new Error(`${a} needs a value`);
        opts.set(a, [...(opts.get(a) ?? []), v]);
      } else if (a === "-h" || a === "--help") { out(USAGE); return 0; }
      else if (a.startsWith("--")) throw new Error(`unknown option ${a}`);
      else file.push(a);
    }
    if (file.length !== 1 || !opts.get("--coordinator-key")) throw new Error("a bundle file and at least one --coordinator-key are required");
    const bundle = readJson(file[0]!) as OutcomeBundle;
    const witnessKeys = (opts.get("--witness-key") ?? []).flatMap(keys);
    const required = opts.get("--witnesses") ? Number(opts.get("--witnesses")![0]) : witnessKeys.length ? 1 : 0;
    if (!Number.isInteger(required) || required < 0) throw new Error("--witnesses must be a whole number");
    const result = verifyBundle(bundle, {
      coordinatorKeys: opts.get("--coordinator-key")!.flatMap(keys),
      principalKeys: opts.get("--principal-key")?.flatMap(keys),
      anchors: (opts.get("--anchor") ?? []).map((f) => readJson(f) as Signed<Checkpoint>),
      witnesses: required > 0 ? { keys: witnessKeys, required } : undefined,
    });
    if (on.has("--json")) {
      out(JSON.stringify({ ok: result.ok, problems: result.problems, outcome: result.report?.status, report: on.has("--report") ? result.report : undefined, log: on.has("--log") && result.state ? renderLog(bundle.events) : undefined }, null, 2));
      return result.ok ? 0 : 1;
    }
    out(result.ok ? "VERIFIED: the log replays under the contract's rules and every trust check passed." : "FAILED:");
    for (const p of result.problems) out(`  - ${p}`);
    if (result.report) out(`Outcome: ${result.report.status.replace(/_/g, " ")} (${result.report.headline})`);
    if (result.witnessed?.length) out(`Witnessed independently by ${result.witnessed.length}.`);
    if (on.has("--log") && result.state) { out(""); renderLog(bundle.events).forEach(out); }
    if (on.has("--report") && result.report) { out(""); out(renderReport(result.report)); }
    return result.ok ? 0 : 1;
  } catch (err) {
    out(`error: ${(err as Error).message}\n\n${USAGE}`);
    return 2;
  }
}

if (process.argv[1] && import.meta.url === new URL(`file://${process.argv[1]}`).href) process.exitCode = run(process.argv.slice(2));
