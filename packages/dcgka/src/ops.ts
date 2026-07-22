/**
 * Engine-level op model (beekem-core §4). Op IDs are content addresses over
 * the canonical CBOR encoding. [deviation, carried from the DCGKA phase]:
 * once ordering-auth lands, the ID becomes the SignedFrame MessageID
 * (SHA-256(body ‖ sig)) supplied by the host — the engine never mints IDs in
 * production; the hash here serves tests and the pre-frame integration seam.
 */

import { sha256 } from '@noble/hashes/sha2';
import { cborEncode, type CborValue } from './cbor.js';
import { bytesToHex } from './bytes.js';
import type { DeviceID, Membership } from './ids.js';
import type { PathChange } from './tree.js';
import { SecretStore } from './secretstore.js';
import type { EncryptedSecret } from './encrypted.js';
import { nodeKeyKeys, shareNodeKey } from './keys.js';

export type OpPayload =
  | { type: 'create'; initialDevices: Array<{ device: DeviceID; leafPk: Uint8Array }>; initialAdmins: string[] }
  | { type: 'add'; device: DeviceID; leafPk: Uint8Array; leafIndex: number }
  | { type: 'remove'; membership: Membership; removedKeys: Uint8Array[] }
  | { type: 'update'; path: PathChange; rootCommit: Uint8Array }
  | { type: 'grantAdmin'; did: string }
  | { type: 'revokeAdmin'; did: string }
  | { type: 'coverage' };

export interface Op {
  /** Content address (32 bytes). */
  id: Uint8Array;
  /** Author membership (admittedBy zeroed in a create, normalized after hashing). */
  author: Membership;
  /** Causal predecessors — the sender's op heads (ordering-auth §3). */
  deps: Uint8Array[];
  payload: OpPayload;
}

export const OP_TYPE_NUM: Record<OpPayload['type'], number> = {
  create: 1,
  add: 2,
  remove: 3,
  update: 4,
  grantAdmin: 5,
  revokeAdmin: 6,
  coverage: 7,
};

/** PathChange → wire-format §4.1 shape (fresh paths are single-version stores). */
export function encodePathChange(p: PathChange): CborValue {
  const leafPkKeys = nodeKeyKeys(p.leafPk);
  if (leafPkKeys.length !== 1) throw new Error('fresh PathChange leaf must be a single key');
  return [
    p.leafIdx,
    leafPkKeys[0]!,
    p.removedKeys,
    p.path.map(([idx, store]) => {
      if (store.hasConflict()) throw new Error('fresh PathChange stores must be single-version');
      const v = store.versions[0]!;
      return [
        idx,
        v.pk,
        v.encrypterPk,
        [...v.sk.entries()]
          .sort((a, b) => a[0] - b[0])
          .map(([k, e]) => [k, e.pairedPk, e.nonce, e.ciphertext]),
      ];
    }),
  ];
}

export function decodePathChange(leafId: Uint8Array, v: CborValue): PathChange {
  const arr = v as CborValue[];
  const [leafIdx, leafPk, removedKeys, nodes] = arr as [number, Uint8Array, Uint8Array[], CborValue[]];
  return {
    leafId,
    leafIdx,
    leafPk: shareNodeKey(leafPk),
    removedKeys,
    path: nodes.map((n) => {
      const [idx, pk, encrypterPk, secrets] = n as [number, Uint8Array, Uint8Array, CborValue[]];
      const sk = new Map<number, EncryptedSecret>();
      for (const s of secrets) {
        const [k, pairedPk, nonce, ciphertext] = s as [number, Uint8Array, Uint8Array, Uint8Array];
        sk.set(k, { pairedPk, nonce, ciphertext });
      }
      return [idx, SecretStore.new_(pk, encrypterPk, sk)] as [number, SecretStore];
    }),
  };
}

function payloadToCbor(p: OpPayload): CborValue {
  switch (p.type) {
    case 'create':
      return [OP_TYPE_NUM[p.type], [p.initialDevices.map((d) => [[d.device.did, d.device.fingerprint], d.leafPk]), p.initialAdmins]];
    case 'add':
      return [OP_TYPE_NUM[p.type], [[p.device.did, p.device.fingerprint], p.leafPk, p.leafIndex]];
    case 'remove':
      return [OP_TYPE_NUM[p.type], [[[p.membership.device.did, p.membership.device.fingerprint], p.membership.admittedBy], p.removedKeys]];
    case 'update':
      return [OP_TYPE_NUM[p.type], [encodePathChange(p.path), p.rootCommit]];
    case 'grantAdmin':
    case 'revokeAdmin':
      return [OP_TYPE_NUM[p.type], [p.did]];
    case 'coverage':
      return [OP_TYPE_NUM[p.type], []];
  }
}

/** Canonical bytes of an op (sans id); id = SHA-256 over them. */
export function opCanonicalBytes(author: Membership, deps: Uint8Array[], payload: OpPayload): Uint8Array {
  const sortedDeps = [...deps].sort((a, b) => bytesToHex(a).localeCompare(bytesToHex(b)));
  return cborEncode([
    1,
    [[author.device.did, author.device.fingerprint], author.admittedBy],
    sortedDeps,
    payloadToCbor(payload),
  ]);
}

export function makeOp(author: Membership, deps: Uint8Array[], payload: OpPayload): Op {
  const id = sha256(opCanonicalBytes(author, deps, payload));
  return { id, author, deps, payload };
}

export const opKey = (id: Uint8Array): string => bytesToHex(id);
