import { createHash, randomBytes } from "node:crypto";

export type Json = string | number | boolean | null | Json[] | { [key: string]: Json };
export type JsonObject = { [key: string]: Json };

/**
 * Canonical JSON (RFC 8785 style): object keys sorted by UTF-16 code units, no whitespace,
 * ECMAScript number formatting. Two parties hashing the same value always get the same bytes.
 * Undefined object members are dropped (as JSON.stringify does); anything else non-JSON throws.
 */
export function canonicalize(value: unknown): string {
  if (value === null || typeof value === "boolean" || typeof value === "string") return JSON.stringify(value);
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new TypeError("Cannot canonicalize a non-finite number");
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map((v) => {
      if (v === undefined) throw new TypeError("Cannot canonicalize undefined inside an array");
      return canonicalize(v);
    }).join(",")}]`;
  }
  if (typeof value === "object" && isPlainObject(value)) {
    const obj = value as Record<string, unknown>;
    const keys = Object.keys(obj).filter((k) => obj[k] !== undefined).sort();
    return `{${keys.map((k) => `${JSON.stringify(k)}:${canonicalize(obj[k])}`).join(",")}}`;
  }
  throw new TypeError(`Cannot canonicalize a value of type ${typeof value}`);
}

function isPlainObject(v: object) {
  const proto = Object.getPrototypeOf(v);
  return proto === Object.prototype || proto === null;
}

/** "sha256:<hex>" of the canonical form. */
export function digest(value: unknown): string {
  return `sha256:${createHash("sha256").update(canonicalize(value)).digest("hex")}`;
}

/** Deep copy through canonical JSON; also proves the value is plain JSON. */
export function toJson<T>(value: T): T {
  return JSON.parse(canonicalize(value)) as T;
}

/** URL-safe random id or salt. */
export function randomId(prefix = "", bytes = 16) {
  const r = randomBytes(bytes).toString("base64url");
  return prefix ? `${prefix}_${r}` : r;
}

/** Reads a dotted path ("details.effectiveAt", "items.0.sku") from a JSON value. */
export function getPath(value: unknown, path: string): unknown {
  let cur: unknown = value;
  for (const part of path.split(".")) {
    if (cur === null || typeof cur !== "object") return undefined;
    cur = (cur as Record<string, unknown>)[part];
  }
  return cur;
}
