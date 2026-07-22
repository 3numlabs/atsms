/** Byte-faithful port of beekem/src/secret_store.rs. */

import { bytesToHex } from './bytes.js';
import { tryEncrypterDecrypt, type EncryptedSecret } from './encrypted.js';
import { nodeKeyContains, type NodeKey, type ShareKeyMap } from './keys.js';

/**
 * Rust `SecretStoreVersion`: one public key for the node, the map of encrypted
 * secrets keyed by tree node index, and the encrypter child's public key.
 */
export interface SecretStoreVersion {
  pk: Uint8Array;
  /** treeIndex → EncryptedSecret (Rust BTreeMap<TreeNodeIndex, _>). */
  sk: Map<number, EncryptedSecret>;
  encrypterPk: Uint8Array;
}

function decryptVersionSecret(
  version: SecretStoreVersion,
  childNodeKey: NodeKey,
  childSks: ShareKeyMap,
  seenIdxs: number[],
): Uint8Array {
  const isEncrypter = nodeKeyContains(childNodeKey, version.encrypterPk);
  if (seenIdxs.length === 0) throw new Error('EncryptedSecretNotFound');
  let lookupIdx = seenIdxs[seenIdxs.length - 1]!;
  if (!version.sk.has(lookupIdx)) {
    let found = false;
    for (let i = seenIdxs.length - 2; i >= 0; i--) {
      if (version.sk.has(seenIdxs[i]!)) {
        lookupIdx = seenIdxs[i]!;
        found = true;
        break;
      }
    }
    if (!found) throw new Error('EncryptedSecretNotFound');
  }
  const encrypted = version.sk.get(lookupIdx);
  if (encrypted === undefined) throw new Error('EncryptedSecretNotFound');

  let decrypted: Uint8Array;
  if (isEncrypter) {
    const secretKey = childSks.get(version.encrypterPk);
    if (secretKey === undefined) throw new Error('SecretKeyNotFound');
    decrypted = tryEncrypterDecrypt(encrypted, secretKey);
  } else {
    decrypted = childSks.tryDecryptEncryption(version.encrypterPk, encrypted);
  }
  if (decrypted.length !== 32) throw new Error('Conversion');
  return decrypted;
}

/** Rust `SecretStore`: ≥1 versions; >1 versions = conflict. */
export class SecretStore {
  constructor(public versions: SecretStoreVersion[]) {
    if (versions.length === 0) throw new Error('SecretStore needs at least one version');
  }

  static new_(pk: Uint8Array, encrypterPk: Uint8Array, sk: Map<number, EncryptedSecret>): SecretStore {
    return new SecretStore([{ pk, sk, encrypterPk }]);
  }

  hasConflict(): boolean {
    return this.versions.length > 1;
  }

  nodeKey(): NodeKey {
    if (this.versions.length === 1) return { kind: 'share', pk: this.versions[0]!.pk };
    const keys = this.versions.map((v) => v.pk);
    if (keys.length === 1) return { kind: 'share', pk: keys[0]! };
    return { kind: 'conflict', keys };
  }

  decryptSecret(childNodeKey: NodeKey, childSks: ShareKeyMap, seenIdxs: number[]): Uint8Array {
    if (this.hasConflict()) throw new Error('UnexpectedKeyConflict');
    return decryptVersionSecret(this.versions[0]!, childNodeKey, childSks, seenIdxs);
  }

  /** Rust `merge(other, removed_keys)`: drop removed versions, then append other's. */
  merge(other: SecretStore, removedKeys: Set<string>): void {
    this.removeKeysFrom(removedKeys);
    this.versions.push(...other.versions.map(cloneVersion));
  }

  private removeKeysFrom(removedKeys: Set<string>): void {
    if (removedKeys.size === 0) return;
    this.versions = this.versions.filter((v) => !removedKeys.has(bytesToHex(v.pk)));
  }

  clone(): SecretStore {
    return new SecretStore(this.versions.map(cloneVersion));
  }
}

function cloneVersion(v: SecretStoreVersion): SecretStoreVersion {
  return { pk: v.pk, encrypterPk: v.encrypterPk, sk: new Map(v.sk) };
}
