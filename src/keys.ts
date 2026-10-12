import { createHash, createPrivateKey, createPublicKey, generateKeyPairSync, sign, verify, type KeyObject } from "node:crypto";
import { canonicalize } from "./canonical.ts";

/** An Ed25519 public key as a JWK. */
export interface PublicKeyJwk { kty: "OKP"; crv: "Ed25519"; x: string; kid: string }
export interface PrivateKeyJwk extends PublicKeyJwk { d: string }

export interface Signature { alg: "Ed25519"; kid: string; value: string }
/** A JSON payload and a detached signature over its canonical form. Every payload carries a `type` so a signature can't be replayed as a different kind of statement. */
export interface Signed<T extends { type: string }> { payload: T; signature: Signature }

export interface Signer {
  readonly kid: string;
  readonly publicKey: PublicKeyJwk;
  sign<T extends { type: string }>(payload: T): Signed<T>;
  exportPrivateKey(): PrivateKeyJwk;
}

/** RFC 7638 thumbprint, so a key id is derived from the key itself. */
export function keyId(x: string) {
  return createHash("sha256").update(canonicalize({ crv: "Ed25519", kty: "OKP", x })).digest("base64url");
}

function makeSigner(privateKey: KeyObject): Signer {
  const jwk = createPublicKey(privateKey).export({ format: "jwk" }) as { x: string };
  const kid = keyId(jwk.x);
  const publicKey: PublicKeyJwk = { kty: "OKP", crv: "Ed25519", x: jwk.x, kid };
  return {
    kid,
    publicKey,
    sign(payload) {
      const value = sign(null, Buffer.from(canonicalize(payload)), privateKey).toString("base64url");
      return { payload, signature: { alg: "Ed25519", kid, value } };
    },
    exportPrivateKey() {
      const p = privateKey.export({ format: "jwk" }) as { d: string };
      return { ...publicKey, d: p.d };
    },
  };
}

export function generateSigner(): Signer {
  return makeSigner(generateKeyPairSync("ed25519").privateKey);
}

export function signerFromPrivateKey(jwk: PrivateKeyJwk): Signer {
  return makeSigner(createPrivateKey({ key: { kty: "OKP", crv: "Ed25519", x: jwk.x, d: jwk.d }, format: "jwk" }));
}

/** True when the signature is valid under one of `keys` (matched by kid) and the key id matches the key. */
export function verifySigned(signed: Signed<{ type: string }>, keys: readonly PublicKeyJwk[]): boolean {
  const s = signed?.signature;
  if (!s || s.alg !== "Ed25519") return false;
  const key = keys.find((k) => k.kid === s.kid);
  if (!key || keyId(key.x) !== key.kid) return false;
  try {
    const pub = createPublicKey({ key: { kty: "OKP", crv: "Ed25519", x: key.x }, format: "jwk" });
    return verify(null, Buffer.from(canonicalize(signed.payload)), pub, Buffer.from(s.value, "base64url"));
  } catch {
    return false;
  }
}
