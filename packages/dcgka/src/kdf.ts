/**
 * Profile-layer KDF (beekem-core §3, KDF split DECIDED 2026-07-22):
 * HKDF-SHA256 above the PcsKey seam, `atsms-beekem:v1:*` labels
 * (wire-format §7). `Expand(ikm, info)` = HKDF-Extract(salt = 32 zero bytes,
 * ikm) then HKDF-Expand(info) — the house definition carried over.
 */

import { hkdf } from '@noble/hashes/hkdf';
import { sha256 } from '@noble/hashes/sha2';
import { concatBytes } from './bytes.js';

const ZERO_SALT = new Uint8Array(32);
const ascii = (s: string) => new TextEncoder().encode(s);

export function expand(ikm: Uint8Array, info: Uint8Array, len = 32): Uint8Array {
  return hkdf(sha256, ikm, ZERO_SALT, info, len);
}

export const LABEL_CHAIN = ascii('atsms-beekem:v1:chain');
export const LABEL_MSGKEY = ascii('atsms-beekem:v1:msgkey');
export const LABEL_NONCE = ascii('atsms-beekem:v1:nonce');
export const LABEL_NEXT = ascii('atsms-beekem:v1:next');

/** chainSeed(e, S) = Expand(PcsKey_e, LABEL_CHAIN ‖ enc(S)). */
export function chainSeed(pcsKey: Uint8Array, encodedMembership: Uint8Array): Uint8Array {
  return expand(pcsKey, concatBytes(LABEL_CHAIN, encodedMembership));
}

export function chainMsgKey(ck: Uint8Array): Uint8Array {
  return expand(ck, LABEL_MSGKEY);
}

export function chainNonce(ck: Uint8Array): Uint8Array {
  return expand(ck, LABEL_NONCE).subarray(0, 12);
}

export function chainNext(ck: Uint8Array): Uint8Array {
  return expand(ck, LABEL_NEXT);
}

/** rootCommit = SHA-256(PcsKey_e) (beekem-core §4.3). */
export function rootCommit(pcsKey: Uint8Array): Uint8Array {
  return sha256(pcsKey);
}
