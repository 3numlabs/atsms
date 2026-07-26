/**
 * Byte-faithful port of beekem/src/keys.rs: NodeKey / ConflictKeys / ShareKeyMap.
 *
 * Keys are raw 32-byte X25519 values (Uint8Array); ordering is lexicographic
 * over the bytes (matching Rust's `ShareKey: Ord`).
 */

import { bytesEqual, bytesToHex, compareBytes } from './bytes.js';
import { deriveSymmetricKey, tryDecrypt } from './keyhive.js';
import type { EncryptedSecret } from './encrypted.js';

/** A node key: one ShareKey, or ≥2 concurrently-merged conflict keys (sorted). */
export type NodeKey =
  | { kind: 'share'; pk: Uint8Array }
  | { kind: 'conflict'; keys: Uint8Array[] }; // invariant: length ≥ 2, sorted lexicographically

export const shareNodeKey = (pk: Uint8Array): NodeKey => ({ kind: 'share', pk });

/** All keys of a NodeKey (Rust `NodeKey::keys()`). */
export function nodeKeyKeys(nk: NodeKey): Uint8Array[] {
  return nk.kind === 'share' ? [nk.pk] : [...nk.keys];
}

export function nodeKeyContains(nk: NodeKey, key: Uint8Array): boolean {
  return nk.kind === 'share'
    ? bytesEqual(nk.pk, key)
    : nk.keys.some((k) => bytesEqual(k, key));
}

function fromSorted(keys: Uint8Array[]): NodeKey {
  if (keys.length === 0) throw new Error('no keys to merge');
  if (keys.length === 1) return { kind: 'share', pk: keys[0]! };
  return { kind: 'conflict', keys };
}

/**
 * Rust `NodeKey::merge(new_key, removed)`:
 * - share key that was removed → replaced by `newKey` outright;
 * - otherwise union of `newKey`'s keys and surviving own keys, sorted
 *   (upstream does not dedup — ported as-is for fidelity).
 */
export function nodeKeyMerge(self: NodeKey, newKey: NodeKey, removed: Uint8Array[]): NodeKey {
  const isRemoved = (k: Uint8Array) => removed.some((r) => bytesEqual(r, k));
  if (self.kind === 'share') {
    if (isRemoved(self.pk)) return newKey.kind === 'share' ? { ...newKey } : { kind: 'conflict', keys: [...newKey.keys] };
    const keys = [...nodeKeyKeys(newKey), self.pk];
    keys.sort(compareBytes);
    return fromSorted(keys);
  }
  const keys = nodeKeyKeys(newKey);
  for (const k of self.keys) if (!isRemoved(k)) keys.push(k);
  keys.sort(compareBytes);
  return fromSorted(keys);
}

/**
 * Rust `ShareKeyMap` — pk → sk store of every path secret this member holds.
 * NOTE (beekem-core §8): unlike upstream, the ATSMS profile requires eviction;
 * `evict()` is the hook (upstream only ever extends).
 */
export class ShareKeyMap {
  private m = new Map<string, { pk: Uint8Array; sk: Uint8Array }>();

  insert(pk: Uint8Array, sk: Uint8Array): void {
    this.m.set(bytesToHex(pk), { pk, sk });
  }

  get(pk: Uint8Array): Uint8Array | undefined {
    return this.m.get(bytesToHex(pk))?.sk;
  }

  containsKey(pk: Uint8Array): boolean {
    return this.m.has(bytesToHex(pk));
  }

  /** Profile-layer eviction hook (beekem-core §8) — NOT part of the upstream API. */
  evict(pk: Uint8Array): void {
    this.m.delete(bytesToHex(pk));
  }

  get size(): number {
    return this.m.size;
  }

  /** All (pk, sk) pairs — for state serialization (the engine's secret material). */
  entries(): Array<{ pk: Uint8Array; sk: Uint8Array }> {
    return [...this.m.values()].map(({ pk, sk }) => ({ pk, sk }));
  }

  extend(other: ShareKeyMap): void {
    for (const { pk, sk } of other.m.values()) this.insert(pk, sk);
  }

  /**
   * Rust `ShareKeyMap::try_decrypt_encryption(encrypter_pk, encrypted)`:
   * sk = self[encrypted.paired_pk]; key = DH(sk, encrypter_pk); open.
   */
  tryDecryptEncryption(encrypterPk: Uint8Array, encrypted: EncryptedSecret): Uint8Array {
    const sk = this.get(encrypted.pairedPk);
    if (sk === undefined) throw new Error('SecretKeyNotFound');
    const key = deriveSymmetricKey(sk, encrypterPk);
    return tryDecrypt(key, encrypted.nonce, encrypted.ciphertext);
  }
}
