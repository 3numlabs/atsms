/**
 * SignedFrame codec (wire-format §3, ordering-auth §2): deterministic-CBOR
 * FrameBody embedded as a byte string, Ed25519 signature over those bytes,
 * MessageID = SHA-256(body ‖ sig).
 */

import { ed25519 } from '@noble/curves/ed25519';
import { sha256 } from '@noble/hashes/sha2';
import { cborDecode, cborEncode, type CborValue } from './cbor.js';
import { concatBytes } from './bytes.js';
import type { Membership } from './ids.js';

export const CLS_CONTROL = 1;
export const CLS_WELCOME = 2;
export const CLS_APP = 3;
export const CLS_REPAIR = 4;

export interface FrameBody {
  version: 1;
  groupId: Uint8Array; // zeroed in create (wire-format §2)
  sender: Membership; // admittedBy zeroed in create
  seq: number;
  ctrlSeq: number | null; // null for app/repair
  deps: Uint8Array[];
  cls: number;
  payload: CborValue;
  /** Opaque signed extension bytes — the base wire never parses it (ext.ts). */
  ext: Uint8Array;
}

export interface ParsedFrame {
  body: FrameBody;
  bodyBytes: Uint8Array;
  sig: Uint8Array;
  id: Uint8Array; // MessageID
  raw: Uint8Array; // serialized SignedFrame
}

export function encodeFrameBody(b: FrameBody): Uint8Array {
  return cborEncode([
    b.version,
    b.groupId,
    [[b.sender.device.did, b.sender.device.fingerprint], b.sender.admittedBy],
    b.seq,
    b.ctrlSeq,
    b.deps,
    b.cls,
    b.payload,
    b.ext,
  ]);
}

export function signFrame(bodyBytes: Uint8Array, signingSk: Uint8Array): Uint8Array {
  const sig = ed25519.sign(bodyBytes, signingSk);
  return cborEncode([bodyBytes, sig]);
}

export function verifyFrameSig(bodyBytes: Uint8Array, sig: Uint8Array, pk: Uint8Array): boolean {
  try {
    return ed25519.verify(sig, bodyBytes, pk);
  } catch {
    return false;
  }
}

export function messageIdOf(bodyBytes: Uint8Array, sig: Uint8Array): Uint8Array {
  return sha256(concatBytes(bodyBytes, sig));
}

export function parseFrame(raw: Uint8Array): ParsedFrame {
  const outer = cborDecode(raw) as CborValue[];
  const [bodyBytes, sig] = outer as [Uint8Array, Uint8Array];
  if (!(bodyBytes instanceof Uint8Array) || !(sig instanceof Uint8Array) || sig.length !== 64) {
    throw new Error('frame: malformed SignedFrame');
  }
  const arr = cborDecode(bodyBytes) as CborValue[];
  const [version, groupId, senderArr, seq, ctrlSeq, deps, cls, payload, ext] = arr as [
    number,
    Uint8Array,
    CborValue,
    number,
    number | null,
    Uint8Array[],
    number,
    CborValue,
    Uint8Array,
  ];
  if (version !== 1) throw new Error('frame: unsupported version');
  const [[did, fingerprint], admittedBy] = senderArr as [[string, Uint8Array], Uint8Array];
  return {
    body: {
      version: 1,
      groupId,
      sender: { device: { did, fingerprint }, admittedBy },
      seq,
      ctrlSeq,
      deps,
      cls,
      payload,
      ext,
    },
    bodyBytes,
    sig,
    id: messageIdOf(bodyBytes, sig),
    raw,
  };
}

export function generateSigningKeypair(rng: (n: number) => Uint8Array): {
  sk: Uint8Array;
  pk: Uint8Array;
} {
  const sk = rng(32);
  return { sk, pk: ed25519.getPublicKey(sk) };
}
