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
  | {
      type: 'create';
      /** signingPk: the device's initial protocol signing key (ordering-auth §5); ZERO32 when the frame layer is absent (tests). */
      initialDevices: Array<{ device: DeviceID; leafPk: Uint8Array; signingPk?: Uint8Array }>;
      initialAdmins: string[];
      /**
       * What kind of conversation this is, fixed at creation and never
       * inferred from membership (a group that shrinks to two is still a
       * group; a two-person group and the DM with that same person must be
       * distinguishable). `dm` is an AUTHORIZATION statement, not a label:
       * the DGM rejects every membership op on a DM, so no client — hostile
       * or buggy — can grow or shrink someone's direct conversation.
       * Defaults to 'group' when absent.
       */
      kind?: 'dm' | 'group';
      /** Initial shared state (group-state.md §4) — a group born named needs
       *  no application message and no fetch, and a pointer cannot be seeded
       *  here (a message's ConvoId derives from this op's own id). */
      initialState?: Array<{ ns: string; value: Uint8Array }>;
    }
  | { type: 'add'; device: DeviceID; leafPk: Uint8Array; leafIndex: number; signingPk?: Uint8Array }
  | { type: 'remove'; membership: Membership; removedKeys: Uint8Array[] }
  | { type: 'update'; path: PathChange; rootCommit: Uint8Array }
  /**
   * Shared group state (group-state.md): a namespaced register whose contents
   * the engine never interprets. `ns` names it (≤64 bytes, NSID-style by
   * convention), `value` is opaque (≤128 bytes) or null to clear. Admin-only,
   * per-namespace last-writer-wins by causal position. Deliberately opaque so
   * new shared state costs no protocol change.
   */
  | { type: 'setState'; ns: string; value: Uint8Array | null }
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
  setState: 8,
};

/** group-state.md §1 bounds. Over-long values are invalid — ignored, never fatal. */
export const MAX_STATE_NS_BYTES = 64;
export const MAX_STATE_VALUE_BYTES = 128;

/** Is this a well-formed state register write? (§3: bounds are validity.) */
export function stateEntryValid(ns: string, value: Uint8Array | null): boolean {
  return (
    new TextEncoder().encode(ns).length <= MAX_STATE_NS_BYTES &&
    (value === null || value.length <= MAX_STATE_VALUE_BYTES)
  );
}

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

const Z32 = new Uint8Array(32);

export function payloadToCbor(p: OpPayload): CborValue {
  switch (p.type) {
    case 'create':
      return [
        OP_TYPE_NUM[p.type],
        [
          p.initialDevices.map((d) => [[d.device.did, d.device.fingerprint], d.leafPk, d.signingPk ?? Z32]),
          p.initialAdmins,
          p.kind === 'dm' ? 1 : 0,
          (p.initialState ?? []).map((e) => [e.ns, e.value]),
        ],
      ];
    case 'add':
      return [OP_TYPE_NUM[p.type], [[p.device.did, p.device.fingerprint], p.leafPk, p.leafIndex, p.signingPk ?? Z32]];
    case 'remove':
      return [OP_TYPE_NUM[p.type], [[[p.membership.device.did, p.membership.device.fingerprint], p.membership.admittedBy], p.removedKeys]];
    case 'update':
      return [OP_TYPE_NUM[p.type], [encodePathChange(p.path), p.rootCommit]];
    case 'grantAdmin':
    case 'revokeAdmin':
      return [OP_TYPE_NUM[p.type], [p.did]];
    case 'coverage':
      return [OP_TYPE_NUM[p.type], []];
    case 'setState':
      return [OP_TYPE_NUM[p.type], [p.ns, p.value]];
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

/**
 * Host-supplied ID minting (ordering-auth §2: the op ID is the SignedFrame
 * MessageID). The minter sees (author, deps, payload) and returns the 32-byte
 * ID; the frame layer signs the encoded body inside its minter.
 */
export type OpMinter = (author: Membership, deps: Uint8Array[], payload: OpPayload) => Uint8Array;

/** Decode a control payload ([opType, args]) back to an OpPayload. */
export function payloadFromCbor(v: CborValue, authorFingerprint: Uint8Array): OpPayload {
  const [t, args] = v as [number, CborValue];
  const a = args as CborValue[];
  switch (t) {
    case 1: {
      const [devices, admins, kind, state] = a as [
        CborValue[],
        string[],
        number | undefined,
        CborValue[] | undefined,
      ];
      return {
        type: 'create',
        initialDevices: devices.map((d) => {
          const [[did, fp], leafPk, signingPk] = d as [[string, Uint8Array], Uint8Array, Uint8Array];
          return { device: { did, fingerprint: fp }, leafPk, signingPk };
        }),
        initialAdmins: admins,
        kind: kind === 1 ? 'dm' : 'group',
        initialState: (state ?? []).map((e) => {
          const [ns, value] = e as [string, Uint8Array];
          return { ns, value };
        }),
      };
    }
    case 2: {
      const [[did, fp], leafPk, leafIndex, signingPk] = a as [[string, Uint8Array], Uint8Array, number, Uint8Array];
      return { type: 'add', device: { did, fingerprint: fp }, leafPk, leafIndex, signingPk };
    }
    case 3: {
      const [[[did, fp], admittedBy], removedKeys] = a as [[[string, Uint8Array], Uint8Array], Uint8Array[]];
      return {
        type: 'remove',
        membership: { device: { did, fingerprint: fp }, admittedBy },
        removedKeys,
      };
    }
    case 4: {
      const [pathCbor, rc] = a as [CborValue, Uint8Array];
      return { type: 'update', path: decodePathChange(authorFingerprint, pathCbor), rootCommit: rc };
    }
    case 5:
      return { type: 'grantAdmin', did: (a as [string])[0] };
    case 6:
      return { type: 'revokeAdmin', did: (a as [string])[0] };
    case 7:
      return { type: 'coverage' };
    case 8: {
      const [ns, value] = a as [string, Uint8Array | null];
      return { type: 'setState', ns, value };
    }
    default:
      throw new Error(`unknown opType ${t}`);
  }
}
