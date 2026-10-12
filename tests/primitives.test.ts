import { describe, expect, it } from "vitest";
import { canonicalize, digest, formatMoney, generateSigner, money, signerFromPrivateKey, verifySigned } from "../src/index.ts";

describe("canonical JSON", () => {
  it("sorts keys, drops undefined members and formats numbers the ECMAScript way", () => {
    expect(canonicalize({ b: 1, a: [true, null, "x"], c: undefined, "é": 1e21, d: 0.1 + 0.2 })).toBe('{"a":[true,null,"x"],"b":1,"d":0.30000000000000004,"é":1e+21}');
    expect(digest({ a: 1, b: 2 })).toBe(digest({ b: 2, a: 1 }));
  });
  it("refuses values with no single JSON form", () => {
    expect(() => canonicalize(Number.NaN)).toThrow();
    expect(() => canonicalize([undefined])).toThrow();
    expect(() => canonicalize(new Date())).toThrow();
    expect(() => canonicalize(new Map())).toThrow();
  });
});

describe("money", () => {
  it("parses exact amounts into minor units without floating point", () => {
    expect(money("USD", "19.99")).toEqual({ currency: "USD", minor: 1999 });
    expect(money("USD", 0.1)).toEqual({ currency: "USD", minor: 10 });
    expect(money("JPY", 500)).toEqual({ currency: "JPY", minor: 500 });
    expect(() => money("USD", "1.005")).toThrow(/precision/);
    expect(() => money("JPY", "1.5")).toThrow(/precision/);
    expect(() => money("usd", 1)).toThrow();
    expect(formatMoney(money("USD", "1234.5"))).toBe("$1,234.50");
  });
});

describe("signatures", () => {
  it("verify only for the right key and the exact payload", () => {
    const k = generateSigner();
    const signed = k.sign({ type: "test", n: 1 });
    expect(verifySigned(signed, [k.publicKey])).toBe(true);
    expect(verifySigned({ ...signed, payload: { type: "test", n: 2 } as typeof signed.payload }, [k.publicKey])).toBe(false);
    expect(verifySigned(signed, [generateSigner().publicKey])).toBe(false);
    // A key whose kid was swapped for the real signer's doesn't pass either.
    const other = generateSigner().publicKey;
    expect(verifySigned(signed, [{ ...other, kid: k.kid }])).toBe(false);
  });
  it("round-trips private keys", () => {
    const k = generateSigner();
    const again = signerFromPrivateKey(k.exportPrivateKey());
    expect(again.kid).toBe(k.kid);
    expect(verifySigned(again.sign({ type: "x" }), [k.publicKey])).toBe(true);
  });
});
