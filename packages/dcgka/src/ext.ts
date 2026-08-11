/**
 * FrameBody `ext` — the signed extension slot (ordering-auth §5, dgm §8, §8.1).
 *
 * On the wire `ext` is an **opaque byte string** (frames.ts): the base codec
 * never parses it, so it contributes **no map / no key-ordering surface** to the
 * signed wire (the DRISL-profile move — the base wire is map-free). The interior
 * is a **fixed positional array** — exactly one encoding per extension set, by
 * construction — decoded only by parties that understand it. Empty extensions
 * encode to a **zero-length** `ext`.
 *
 * Forward-compat: because the frame carries `ext` as raw bytes covered by the
 * signature, a reader that does not understand a newer `ExtBody` version simply
 * does not parse the interior (returns {}) while the bytes stay signed —
 * recovering the "unknown extensions preserved" property without a map.
 *
 *   ExtBody = [ version, digest|null, rotation|null, appHW|null, endpoint|null ]
 */

import { cborDecode, cborEncode, type CborValue } from './cbor.js';

const EXT_VERSION = 1;

export interface FrameExt {
  /** Consistency digest + the sender's valid-op heads it was computed at (dgm §8). */
  digest?: { digest: Uint8Array; heads: Uint8Array[] };
  /** `nextSigningPubKey` — protocol signing-key rotation (ordering-auth §5). */
  rotation?: Uint8Array;
  /** Per-epoch application high-water — highest generation emitted (ordering-auth §8.1). */
  appHW?: Array<{ epochId: Uint8Array; hiGen: number }>;
  /**
   * The device's conversation address (sealed-sender §12): where this device
   * wants its in-conversation envelopes dropped. A self-authored, signed, last-writer-
   * wins advert — the exact shape as `rotation`, a URL instead of a pubkey. v1 is
   * a single `https://…` URL per device (reuse policy); a per-group token is a
   * later device-side policy with no wire change.
   */
  endpoint?: string;
}

function isEmpty(e: FrameExt): boolean {
  return (
    e.digest === undefined &&
    e.rotation === undefined &&
    e.appHW === undefined &&
    e.endpoint === undefined
  );
}

/** Encode to the opaque `ext` bytes (zero-length when there are no extensions). */
export function encodeExt(ext: FrameExt): Uint8Array {
  if (isEmpty(ext)) return new Uint8Array(0);
  const body: CborValue = [
    EXT_VERSION,
    ext.digest === undefined ? null : [ext.digest.digest, ext.digest.heads],
    ext.rotation ?? null,
    ext.appHW === undefined ? null : ext.appHW.map((h) => [h.epochId, h.hiGen]),
    ext.endpoint ?? null,
  ];
  return cborEncode(body);
}

/** Decode the opaque `ext` bytes. Zero-length or an unknown version ⇒ no parsed extensions. */
export function decodeExt(bytes: Uint8Array): FrameExt {
  if (bytes.length === 0) return {};
  const arr = cborDecode(bytes) as CborValue[];
  // Length-tolerant destructure: a shorter (older) array leaves later fields
  // undefined; a longer (newer) one is ignored past what this version reads.
  const [version, digest, rotation, appHW, endpoint] = arr as [
    number,
    CborValue,
    CborValue,
    CborValue,
    CborValue?,
  ];
  if (version !== EXT_VERSION) return {}; // forward-compat: leave a newer layout unparsed
  const out: FrameExt = {};
  if (digest !== null) {
    const [d, heads] = digest as [Uint8Array, Uint8Array[]];
    out.digest = { digest: d, heads };
  }
  if (rotation !== null) out.rotation = rotation as Uint8Array;
  if (appHW !== null) {
    out.appHW = (appHW as CborValue[]).map((h) => {
      const [epochId, hiGen] = h as [Uint8Array, number];
      return { epochId, hiGen };
    });
  }
  if (endpoint !== null && endpoint !== undefined) out.endpoint = endpoint as string;
  return out;
}
