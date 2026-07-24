/**
 * HPKE Base mode (RFC 9180), suite **DHKEM(X25519, HKDF-SHA256) / HKDF-SHA256 /
 * ChaCha20-Poly1305** — the `sealed-asym` construction (sealed-sender.md §4).
 *
 * Hand-rolled over `@noble` primitives rather than a WebCrypto-based HPKE
 * library, because the v1 client target is React Native (D3), which lacks
 * SubtleCrypto for X25519/HKDF. Structured to mirror RFC 9180 §4.1 (DHKEM),
 * §5.1 (key schedule), §6.1 (single-shot) line-by-line so it is reviewable.
 *
 * Verification status: round-trip + a frozen internal KAT (test-vectors). A
 * cross-check against the official RFC 9180 A.2 known-answer vectors is a
 * Phase-6 external-review deliverable (structure is RFC-faithful; bytes not yet
 * pinned to the RFC).
 */

import { x25519 } from '@noble/curves/ed25519';
import { extract, expand } from '@noble/hashes/hkdf';
import { sha256 } from '@noble/hashes/sha2';
import { chacha20poly1305 } from '@noble/ciphers/chacha';
import { concatBytes } from './bytes.js';
import type { Csprng } from './keyhive.js';

const KEM_ID = 0x0020; // DHKEM(X25519, HKDF-SHA256)
const KDF_ID = 0x0001; // HKDF-SHA256
const AEAD_ID = 0x0003; // ChaCha20Poly1305

const NSECRET = 32; // DHKEM shared-secret length
const NK = 32; // ChaCha20Poly1305 key length
const NN = 12; // ChaCha20Poly1305 nonce length

const ascii = (s: string) => new TextEncoder().encode(s);
const HPKE_V1 = ascii('HPKE-v1');
const EMPTY = new Uint8Array(0);

function i2osp(n: number, len: number): Uint8Array {
  const out = new Uint8Array(len);
  for (let i = len - 1; i >= 0; i--) {
    out[i] = n & 0xff;
    n >>>= 8;
  }
  return out;
}

const KEM_SUITE_ID = concatBytes(ascii('KEM'), i2osp(KEM_ID, 2));
const HPKE_SUITE_ID = concatBytes(ascii('HPKE'), i2osp(KEM_ID, 2), i2osp(KDF_ID, 2), i2osp(AEAD_ID, 2));

/** RFC 9180 §4: LabeledExtract(salt, label, ikm) with a given suite_id. */
function labeledExtract(salt: Uint8Array, suiteId: Uint8Array, label: string, ikm: Uint8Array): Uint8Array {
  return extract(sha256, concatBytes(HPKE_V1, suiteId, ascii(label), ikm), salt);
}

/** RFC 9180 §4: LabeledExpand(prk, label, info, L) with a given suite_id. */
function labeledExpand(
  prk: Uint8Array,
  suiteId: Uint8Array,
  label: string,
  info: Uint8Array,
  len: number,
): Uint8Array {
  return expand(sha256, prk, concatBytes(i2osp(len, 2), HPKE_V1, suiteId, ascii(label), info), len);
}

/** DHKEM ExtractAndExpand (RFC 9180 §4.1). */
function extractAndExpand(dh: Uint8Array, kemContext: Uint8Array): Uint8Array {
  const eaePrk = labeledExtract(EMPTY, KEM_SUITE_ID, 'eae_prk', dh);
  return labeledExpand(eaePrk, KEM_SUITE_ID, 'shared_secret', kemContext, NSECRET);
}

/** DHKEM.Encap(pkR) — returns (shared_secret, enc = ephemeral pubkey). */
function encap(pkR: Uint8Array, rng: Csprng): { sharedSecret: Uint8Array; enc: Uint8Array } {
  const skE = rng(32);
  const pkE = x25519.getPublicKey(skE);
  const dh = x25519.getSharedSecret(skE, pkR); // throws on low-order pkR
  const kemContext = concatBytes(pkE, pkR);
  return { sharedSecret: extractAndExpand(dh, kemContext), enc: pkE };
}

/** DHKEM.Decap(enc, skR). */
function decap(enc: Uint8Array, skR: Uint8Array): Uint8Array {
  const dh = x25519.getSharedSecret(skR, enc);
  const pkR = x25519.getPublicKey(skR);
  const kemContext = concatBytes(enc, pkR);
  return extractAndExpand(dh, kemContext);
}

/** KeySchedule, Base mode (mode = 0x00), single-shot (seq = 0). RFC 9180 §5.1. */
function keySchedule(sharedSecret: Uint8Array, info: Uint8Array): { key: Uint8Array; nonce: Uint8Array } {
  const pskIdHash = labeledExtract(EMPTY, HPKE_SUITE_ID, 'psk_id_hash', EMPTY);
  const infoHash = labeledExtract(EMPTY, HPKE_SUITE_ID, 'info_hash', info);
  const ksContext = concatBytes(new Uint8Array([0x00]), pskIdHash, infoHash); // mode_base = 0
  const secret = labeledExtract(sharedSecret, HPKE_SUITE_ID, 'secret', EMPTY); // psk = ""
  const key = labeledExpand(secret, HPKE_SUITE_ID, 'key', ksContext, NK);
  const baseNonce = labeledExpand(secret, HPKE_SUITE_ID, 'base_nonce', ksContext, NN);
  return { key, nonce: baseNonce }; // seq 0 ⇒ nonce = base_nonce
}

export interface HpkeSealed {
  /** Encapsulated key (X25519 ephemeral public, 32 B). */
  enc: Uint8Array;
  ct: Uint8Array;
}

/** HPKE single-shot SealBase (RFC 9180 §6.1). ChaCha20-Poly1305, 12-byte nonce. */
export function sealBase(pkR: Uint8Array, info: Uint8Array, aad: Uint8Array, pt: Uint8Array, rng: Csprng): HpkeSealed {
  const { sharedSecret, enc } = encap(pkR, rng);
  const { key, nonce } = keySchedule(sharedSecret, info);
  const ct = chacha20poly1305(key, nonce, aad).encrypt(pt);
  return { enc, ct };
}

/** HPKE single-shot OpenBase. Throws on authentication failure. */
export function openBase(
  enc: Uint8Array,
  skR: Uint8Array,
  info: Uint8Array,
  aad: Uint8Array,
  ct: Uint8Array,
): Uint8Array {
  const sharedSecret = decap(enc, skR);
  const { key, nonce } = keySchedule(sharedSecret, info);
  return chacha20poly1305(key, nonce, aad).decrypt(ct);
}
