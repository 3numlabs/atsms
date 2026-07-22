/**
 * Byte-faithful port of the `keyhive_crypto` primitives the BeeKEM tree uses
 * (beekem-core §3: BLAKE3 below the PcsKey seam — oracle byte-compatibility).
 *
 * Sources (inkandswitch/keyhive @ 2026-07-09):
 *   keyhive_crypto/src/{separable,domain_separator,share_key,symmetric_key,siv}.rs
 */

import { x25519 } from '@noble/curves/ed25519';
import { blake3 } from '@noble/hashes/blake3';
import { xchacha20poly1305 } from '@noble/ciphers/chacha';
import { concatBytes } from './bytes.js';

/** `/keyhive/` — the keyhive domain separator (domain_separator.rs). */
export const SEPARATOR_STR = '/keyhive/';
export const SEPARATOR: Uint8Array = new TextEncoder().encode(SEPARATOR_STR);

/** `Separable::derive_from_bytes` = blake3::derive_key(SEPARATOR_STR, bytes). */
export function deriveFromBytes(bytes: Uint8Array): Uint8Array {
  return blake3(bytes, { context: SEPARATOR_STR, dkLen: 32 });
}

/** `ShareSecretKey::share_key()` — X25519 public key (clamping inside noble, per RFC 7748). */
export function shareKeyOf(sk: Uint8Array): Uint8Array {
  return x25519.getPublicKey(sk);
}

/** `ShareSecretKey::ratchet_forward()` — one BLAKE3 derive_key step over the raw secret bytes. */
export function ratchetForward(sk: Uint8Array): Uint8Array {
  return deriveFromBytes(sk);
}

/** `ShareSecretKey::ratchet_n_forward(n)`. */
export function ratchetNForward(sk: Uint8Array, n: number): Uint8Array {
  let s = sk;
  for (let i = 0; i < n; i++) s = ratchetForward(s);
  return s;
}

/** `ShareSecretKey::derive_symmetric_key(pk)` = derive_from_bytes(x25519(sk, pk)). */
export function deriveSymmetricKey(sk: Uint8Array, pk: Uint8Array): Uint8Array {
  const shared = x25519.getSharedSecret(sk, pk);
  return deriveFromBytes(shared);
}

/** `Siv::new(key, plaintext, doc_id)` — BLAKE3 XOF-24 over SEPARATOR ‖ docId ‖ key ‖ plaintext. */
export function sivNew(key: Uint8Array, plaintext: Uint8Array, docId: Uint8Array): Uint8Array {
  return blake3(concatBytes(SEPARATOR, docId, key, plaintext), { dkLen: 24 });
}

/** `SymmetricKey::try_encrypt` — XChaCha20-Poly1305, AAD = SEPARATOR; returns ct ‖ tag. */
export function tryEncrypt(key: Uint8Array, nonce24: Uint8Array, plaintext: Uint8Array): Uint8Array {
  return xchacha20poly1305(key, nonce24, SEPARATOR).encrypt(plaintext);
}

/** `SymmetricKey::try_decrypt` — throws on authentication failure. */
export function tryDecrypt(key: Uint8Array, nonce24: Uint8Array, ciphertext: Uint8Array): Uint8Array {
  return xchacha20poly1305(key, nonce24, SEPARATOR).decrypt(ciphertext);
}

/** Injectable randomness (D3 test seam — deterministic tests & the differential oracle). */
export type Csprng = (n: number) => Uint8Array;

export const defaultCsprng: Csprng = (n) => {
  const out = new Uint8Array(n);
  crypto.getRandomValues(out);
  return out;
};

/** `ShareSecretKey::generate` — raw 32 random bytes (x25519 clamping happens at use). */
export function generateShareSecretKey(rng: Csprng): Uint8Array {
  return rng(32);
}
