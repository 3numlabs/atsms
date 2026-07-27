/**
 * Seed-derived identity (the passkey/PRF flow): a client holding one 32-byte
 * secret — e.g. the WebAuthn PRF extension output — derives this device's
 * long-lived material from it deterministically, so the identity is
 * recoverable from the authenticator alone and the private key never needs to
 * be persisted.
 *
 * Derivation tree (HKDF-SHA256, domain-separated by label):
 *
 *   seed ─┬─ "atsms:seed:identity:v1"    → P-256 identity scalar (the endpoint
 *         │                                cert keypair — long-lived BY DESIGN,
 *         │                                so seed derivation is sound)
 *         └─ "atsms:seed:storage-key:v1" → 32-byte storage master key
 *                                          (encryption-at-rest; reserved until
 *                                          that layer lands)
 *
 * Deliberately NOT derived from the seed: prekeys, protocol signing keys, and
 * all engine state. Those must be destroyable (forward secrecy) — a static
 * seed that could re-derive them would let one seed compromise retroactively
 * recover every past generation. They stay random, persisted in storage.
 */

import { p256 } from "@noble/curves/nist.js";

import { cryptoProvider } from "../crypto-provider.js";

export const SEED_LABEL_IDENTITY = "atsms:seed:identity:v1";
export const SEED_LABEL_STORAGE_KEY = "atsms:seed:storage-key:v1";

/** HKDF-SHA256 over the seed with a domain-separation label (empty salt). */
export async function deriveFromSeed(seed: Uint8Array, label: string, length: number): Promise<Uint8Array> {
  if (seed.length < 16) throw new Error("seed too short — expected ≥16 bytes (PRF outputs are 32)");
  const key = await cryptoProvider.subtle.importKey("raw", seed as BufferSource, "HKDF", false, ["deriveBits"]);
  const bits = await cryptoProvider.subtle.deriveBits(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: new Uint8Array(0),
      info: new TextEncoder().encode(label),
    },
    key,
    length * 8,
  );
  return new Uint8Array(bits);
}

/**
 * The device identity keypair, deterministically from the seed: 48 HKDF bytes
 * reduced mod (n-1) + 1 (uniform, never zero) → P-256 scalar. Returned as a
 * PKCS#8 PEM — feed it to `ATSMSEndpointCertificate.generateWithKey` (same
 * key ⇒ same device fingerprint ⇒ same records/inbox, across recoveries).
 */
export async function deriveIdentityKeyPEM(seed: Uint8Array): Promise<string> {
  const wide = await deriveFromSeed(seed, SEED_LABEL_IDENTITY, 48);
  const n = p256.Point.CURVE().n;
  let acc = 0n;
  for (const b of wide) acc = (acc << 8n) | BigInt(b);
  const scalar = (acc % (n - 1n)) + 1n;
  const d = new Uint8Array(32);
  let v = scalar;
  for (let i = 31; i >= 0; i--) {
    d[i] = Number(v & 0xffn);
    v >>= 8n;
  }

  const pub = p256.getPublicKey(d, false); // 0x04‖X‖Y
  const jwk: JsonWebKey = {
    kty: "EC",
    crv: "P-256",
    d: b64url(d),
    x: b64url(pub.slice(1, 33)),
    y: b64url(pub.slice(33, 65)),
  };
  const key = await cryptoProvider.subtle.importKey("jwk", jwk, { name: "ECDSA", namedCurve: "P-256" }, true, [
    "sign",
  ]);
  const der = new Uint8Array(await cryptoProvider.subtle.exportKey("pkcs8", key));
  return derToPem(der, "PRIVATE KEY");
}

/** The 32-byte storage master key (encryption-at-rest; reserved for that layer). */
export function deriveStorageKey(seed: Uint8Array): Promise<Uint8Array> {
  return deriveFromSeed(seed, SEED_LABEL_STORAGE_KEY, 32);
}

function b64url(bytes: Uint8Array): string {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function derToPem(der: Uint8Array, tag: string): string {
  let bin = "";
  for (const b of der) bin += String.fromCharCode(b);
  const b64 = btoa(bin);
  const lines = b64.match(/.{1,64}/g) ?? [];
  return `-----BEGIN ${tag}-----\n${lines.join("\n")}\n-----END ${tag}-----\n`;
}
