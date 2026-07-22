/**
 * Identity-layer handles (dgm.md §2, wire-format §1) and their canonical
 * CBOR encodings: DeviceID = [did, fingerprint]; Membership = [DeviceID, admittedBy].
 */

import { cborEncode } from './cbor.js';
import { bytesEqual, bytesToHex } from './bytes.js';

export interface DeviceID {
  did: string;
  /** SHA-256 of the endpoint-cert SPKI — the tree MemberId (Spike B §3). */
  fingerprint: Uint8Array;
}

export interface Membership {
  device: DeviceID;
  /** MessageID of the admitting op (create/add); zeroes pre-normalization in a create. */
  admittedBy: Uint8Array;
}

export const ZERO32 = new Uint8Array(32);

export function encodeDeviceID(d: DeviceID): Uint8Array {
  return cborEncode([d.did, d.fingerprint]);
}

export function encodeMembership(m: Membership): Uint8Array {
  return cborEncode([[m.device.did, m.device.fingerprint], m.admittedBy]);
}

export function membershipKey(m: Membership): string {
  return `${m.device.did}/${bytesToHex(m.device.fingerprint)}/${bytesToHex(m.admittedBy)}`;
}

export function sameMembership(a: Membership, b: Membership): boolean {
  return (
    a.device.did === b.device.did &&
    bytesEqual(a.device.fingerprint, b.device.fingerprint) &&
    bytesEqual(a.admittedBy, b.admittedBy)
  );
}
