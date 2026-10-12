import { readFileSync, writeFileSync } from "node:fs";
import { z } from "zod";
import { describe, expect, it } from "vitest";
import { ContractSchema } from "../src/index.ts";

// The portable contract format, for implementations in other languages. Regenerate with: npm run schema
const file = new URL("../schema/outcome-contract.v0.schema.json", import.meta.url);

// The normalized form has every field explicit, so defaults (some of them random) don't belong in it.
const withoutDefaults = (v: unknown): unknown =>
  Array.isArray(v) ? v.map(withoutDefaults)
  : v && typeof v === "object" ? Object.fromEntries(Object.entries(v).filter(([k]) => k !== "default").map(([k, x]) => [k, withoutDefaults(x)]))
  : v;

function generate() {
  const schema = withoutDefaults(z.toJSONSchema(ContractSchema, { io: "output", unrepresentable: "any" })) as Record<string, unknown>;
  return `${JSON.stringify({ ...schema, $id: "urn:agentmesh:schema:outcome-contract:v0", title: "AgentMesh outcome contract (v0, normalized form)" }, null, 2)}\n`;
}

describe("JSON Schema", () => {
  it("is up to date", () => {
    const next = generate();
    if (process.env.UPDATE_SCHEMA) writeFileSync(file, next);
    expect(readFileSync(file, "utf8")).toBe(next);
  });
});
