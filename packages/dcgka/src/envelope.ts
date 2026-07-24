/**
 * Sealed-sender envelope layer (sealed-sender.md §3–§5, §11; wire-format §6).
 * This module is the **outermost** cryptographic layer — every transmission
 * crosses the wire as a `SealedEnvelope`. Phase 3 tranche 1: the `sealed-sym`
 * mode (§11) — all in-conversation traffic — plus the shared `SealedPlaintext`
 * padding (§5) and EnvelopeID dedup (§3). `sealed-asym` (HPKE, §4) is a later
 * tranche.
 *
 * Metadata model: the same group message reaches every member, but each fan-out
 * copy carries a **distinct per-recipient tag, nonce, and ciphertext** so an
 * observer cannot correlate the copies into a group graph. The `envKey` itself
 * is per-sender-epoch and shared by all members (a group message is readable by
 * every member — the tag is for unlinkability, not member-to-member secrecy).
 */

import { sha256 } from '@noble/hashes/sha2';
import { xchacha20poly1305 } from '@noble/ciphers/chacha';
import { bytesToHex, concatBytes } from './bytes.js';
import { cborDecode, cborEncode, type CborValue } from './cbor.js';
import { sealBase, openBase } from './hpke.js';
import { expand } from './kdf.js';
import type { Csprng } from './keyhive.js';

// ── constants ────────────────────────────────────────────────────────────────

export const ENV_VERSION = 1;
export const MODE_ASYM = 1;
export const MODE_SYM = 2;

export const CONTENT_FRAME = 1; // body = a SignedFrame (ordering-auth)
export const CONTENT_CMS = 2; // body = CMS SignedData (X509 floor)
export const CONTENT_BLOBREF = 3; // body = blob reference (oversize offload)

export const TAG_LEN = 8; // sealed-sym hint tag width (parameters.md, DECIDED)

/** Padding buckets (parameters.md §5): 1–64 KiB, powers of two. */
export const BUCKETS: number[] = [1, 2, 4, 8, 16, 32, 64].map((k) => k * 1024);
const MAX_BUCKET = BUCKETS[BUCKETS.length - 1]!;

const ascii = (s: string) => new TextEncoder().encode(s);
export const LABEL_SEAL_SYM = ascii('atsms-seal:v1:sym');
export const LABEL_SEAL_HINT = ascii('atsms-seal:v1:hint');
/** HPKE `info` for the asym mode (sealed-sender §4). */
export const SEAL_ASYM_INFO = ascii('atsms-seal:v1');
export const SUITE_X25519 = 1; // asym `suite` id: DHKEM(X25519) (wire-format §6)

/** Signals oversize content that MUST move to blob offload (§5 oversize rule). */
export class OversizeError extends Error {
  constructor(readonly plaintextLen: number) {
    super(`sealed plaintext ${plaintextLen} B exceeds the largest bucket (${MAX_BUCKET} B) — blob offload required`);
    this.name = 'OversizeError';
  }
}

// ── key derivation (§11.2/§11.3) ─────────────────────────────────────────────

/** `envKey(e, S) = Expand(PcsKey_e, "atsms-seal:v1:sym" ‖ enc(S))` — per sender-epoch. */
export function envKeySym(pcsKey: Uint8Array, encSenderMembership: Uint8Array): Uint8Array {
  return expand(pcsKey, concatBytes(LABEL_SEAL_SYM, encSenderMembership));
}

/** `tag = Expand(envKey, "atsms-seal:v1:hint" ‖ enc(recipient))[0..8]` — per recipient. */
export function hintTag(envKey: Uint8Array, encRecipientMembership: Uint8Array): Uint8Array {
  return expand(envKey, concatBytes(LABEL_SEAL_HINT, encRecipientMembership)).subarray(0, TAG_LEN);
}

/** AAD for the sym AEAD: `enc([version, mode, tag])`. */
function symAad(tag: Uint8Array): Uint8Array {
  return cborEncode([ENV_VERSION, MODE_SYM, tag]);
}

// ── padding (§5) ──────────────────────────────────────────────────────────────

function headerSizeForLen(n: number): number {
  return n < 24 ? 1 : n < 256 ? 2 : n < 65536 ? 3 : 5;
}

/**
 * Encode `[contentType, body, pad]` padded so the total is **exactly** the
 * smallest bucket ≥ the unpadded length (strict writer). Throws `OversizeError`
 * if the unpadded plaintext already exceeds the largest bucket.
 */
export function padToBucket(contentType: number, body: Uint8Array): Uint8Array {
  const minimal = cborEncode([contentType, body, new Uint8Array(0)]).length;
  if (minimal > MAX_BUCKET) throw new OversizeError(minimal);
  const bucket = BUCKETS.find((b) => b >= minimal)!;
  // total(p) = C + headerSize(p) + p, where C is everything but the pad's bytes.
  const C = minimal - 1; // minimal used a 1-byte (empty) pad header
  const target = bucket - C; // == headerSize(p) + p
  for (const hs of [1, 2, 3, 5]) {
    const p = target - hs;
    if (p >= 0 && headerSizeForLen(p) === hs) {
      const out = cborEncode([contentType, body, new Uint8Array(p)]);
      if (out.length !== bucket) throw new Error('padding: bucket miss (internal)');
      return out;
    }
  }
  throw new Error('padding: no pad length hits the bucket (internal)');
}

export interface SealedPlaintext {
  contentType: number;
  body: Uint8Array;
}

/** Decode `[contentType, body, pad]`, verifying pad is all zero (§5 covert-channel guard). */
export function decodeSealedPlaintext(bytes: Uint8Array): SealedPlaintext {
  const arr = cborDecode(bytes) as CborValue[];
  if (!Array.isArray(arr) || arr.length !== 3) throw new Error('sealed plaintext: bad shape');
  const [contentType, body, pad] = arr as [number, Uint8Array, Uint8Array];
  if (typeof contentType !== 'number' || !(body instanceof Uint8Array) || !(pad instanceof Uint8Array)) {
    throw new Error('sealed plaintext: bad field types');
  }
  for (let i = 0; i < pad.length; i++) if (pad[i] !== 0) throw new Error('sealed plaintext: nonzero pad');
  return { contentType, body };
}

// ── sym envelope (§11.3) ─────────────────────────────────────────────────────

/** One sealed-sym envelope's bytes = `enc([1, 2, tag, nonce, ct])`. */
export type SymEnvelopeBytes = Uint8Array;

function encodeSymEnvelope(tag: Uint8Array, nonce: Uint8Array, ct: Uint8Array): SymEnvelopeBytes {
  return cborEncode([ENV_VERSION, MODE_SYM, tag, nonce, ct]);
}

/** `EnvelopeID = SHA-256(serialized envelope)` — pre-decryption dedup (§3). */
export function envelopeId(envelope: Uint8Array): Uint8Array {
  return sha256(envelope);
}

/**
 * Seal one group message to a single recipient (§11.3). Fresh 24-byte nonce ⇒
 * distinct ciphertext, even though `envKey` and `body` are shared across the
 * fan-out. Returns the serialized `SymEnvelope`.
 */
export function sealSymTo(
  envKey: Uint8Array,
  encRecipient: Uint8Array,
  contentType: number,
  body: Uint8Array,
  rng: Csprng,
): SymEnvelopeBytes {
  const tag = hintTag(envKey, encRecipient);
  const nonce = rng(24);
  const plaintext = padToBucket(contentType, body);
  const ct = xchacha20poly1305(envKey, nonce, symAad(tag)).encrypt(plaintext);
  return encodeSymEnvelope(tag, nonce, ct);
}

/**
 * Fan out one message to every recipient (sealed-sender §11.3 + the delivery
 * boundary: engine yields (sealed message, recipient list)). Each copy has a
 * distinct tag/nonce/ciphertext; the padded plaintext (hence envelope size) is
 * identical across recipients.
 */
export function sealSymFanout(
  envKey: Uint8Array,
  encRecipients: Uint8Array[],
  contentType: number,
  body: Uint8Array,
  rng: Csprng,
): SymEnvelopeBytes[] {
  return encRecipients.map((r) => sealSymTo(envKey, r, contentType, body, rng));
}

export interface ParsedSymEnvelope {
  tag: Uint8Array;
  nonce: Uint8Array;
  ct: Uint8Array;
}

/** Parse (no decryption) — for tag lookup + EnvelopeID dedup before AEAD (§3). */
export function parseSymEnvelope(envelope: Uint8Array): ParsedSymEnvelope {
  const arr = cborDecode(envelope) as CborValue[];
  const [version, mode, tag, nonce, ct] = arr as [number, number, Uint8Array, Uint8Array, Uint8Array];
  if (version !== ENV_VERSION || mode !== MODE_SYM) throw new Error('not a sealed-sym envelope');
  if (!(tag instanceof Uint8Array) || tag.length !== TAG_LEN) throw new Error('bad tag');
  if (!(nonce instanceof Uint8Array) || nonce.length !== 24) throw new Error('bad nonce');
  if (!(ct instanceof Uint8Array)) throw new Error('bad ct');
  return { tag, nonce, ct };
}

/** Open a sealed-sym envelope with a candidate `envKey` (Poly1305 rejects wrong keys). */
export function openSym(envKey: Uint8Array, envelope: Uint8Array): SealedPlaintext {
  const { tag, nonce, ct } = parseSymEnvelope(envelope);
  const plaintext = xchacha20poly1305(envKey, nonce, symAad(tag)).decrypt(ct);
  return decodeSealedPlaintext(plaintext);
}

// ── sealed-asym envelope (§4, HPKE) ──────────────────────────────────────────

/** AAD for the asym AEAD: binds the cleartext header `enc([version, mode, suite])`. */
function asymAad(suite: number): Uint8Array {
  return cborEncode([ENV_VERSION, MODE_ASYM, suite]);
}

/**
 * Seal to a recipient's X25519 **signed prekey** (bootstrap-class traffic —
 * welcomes, first contact, X509-floor one-shots; sealed-sender §1/§2, D10).
 * HPKE Base to `signedPrekeyPub`, padded plaintext, header bound as AAD.
 */
export function sealAsymTo(
  signedPrekeyPub: Uint8Array,
  contentType: number,
  body: Uint8Array,
  rng: Csprng,
): Uint8Array {
  const plaintext = padToBucket(contentType, body);
  const { enc, ct } = sealBase(signedPrekeyPub, SEAL_ASYM_INFO, asymAad(SUITE_X25519), plaintext, rng);
  return cborEncode([ENV_VERSION, MODE_ASYM, SUITE_X25519, enc, ct]);
}

export interface ParsedAsymEnvelope {
  suite: number;
  enc: Uint8Array;
  ct: Uint8Array;
}

export function parseAsymEnvelope(envelope: Uint8Array): ParsedAsymEnvelope {
  const arr = cborDecode(envelope) as CborValue[];
  const [version, mode, suite, enc, ct] = arr as [number, number, number, Uint8Array, Uint8Array];
  if (version !== ENV_VERSION || mode !== MODE_ASYM) throw new Error('not a sealed-asym envelope');
  if (suite !== SUITE_X25519) throw new Error(`unsupported asym suite ${suite}`);
  if (!(enc instanceof Uint8Array) || enc.length !== 32) throw new Error('bad enc');
  if (!(ct instanceof Uint8Array)) throw new Error('bad ct');
  return { suite, enc, ct };
}

/**
 * Open with a recipient signed-prekey secret. The receiver trial-decrypts
 * across its ≤ 2 live signed-prekey secrets (current + grace, D10) — call once
 * per candidate; a wrong secret throws (AEAD auth failure).
 */
export function openAsym(signedPrekeySecret: Uint8Array, envelope: Uint8Array): SealedPlaintext {
  const { suite, enc, ct } = parseAsymEnvelope(envelope);
  const plaintext = openBase(enc, signedPrekeySecret, SEAL_ASYM_INFO, asymAad(suite), ct);
  return decodeSealedPlaintext(plaintext);
}

// ── receiver tag table (§11.3 lookup, §11.4 maintenance) ─────────────────────

interface TagEntry {
  envKey: Uint8Array;
  /** opaque caller metadata (group, sender, epoch) for routing/telemetry. */
  meta: unknown;
}

/**
 * `tag → (envKey, meta)` lookup (sealed-sender §11.3). A receiver, on deriving
 * an epoch's `PcsKey`, installs — for every sender `S` — the tag under which `S`
 * addresses *this* receiver, mapped to `envKey(e, S)`. Incoming envelopes are
 * routed by exact tag hit; a multi-hit trial-opens each candidate (§11.3), so
 * width is not a safety parameter.
 */
export class TagTable {
  private m = new Map<string, TagEntry[]>();

  /** Install the tag `sender` uses to address `me` in this epoch. */
  install(envKey: Uint8Array, encMe: Uint8Array, meta: unknown): Uint8Array {
    const tag = hintTag(envKey, encMe);
    const k = bytesToHex(tag);
    const entry: TagEntry = { envKey, meta };
    const cur = this.m.get(k);
    if (cur === undefined) this.m.set(k, [entry]);
    else cur.push(entry);
    return tag;
  }

  /** Remove all entries for a superseded epoch's envKey (§11.4 grace eviction). */
  evict(envKey: Uint8Array): void {
    const target = bytesToHex(envKey);
    for (const [k, entries] of this.m) {
      const kept = entries.filter((e) => bytesToHex(e.envKey) !== target);
      if (kept.length === 0) this.m.delete(k);
      else this.m.set(k, kept);
    }
  }

  candidates(tag: Uint8Array): TagEntry[] {
    return this.m.get(bytesToHex(tag)) ?? [];
  }

  /** Route + open an incoming envelope; returns null if no candidate opens it. */
  open(envelope: Uint8Array): { plaintext: SealedPlaintext; meta: unknown } | null {
    const { tag } = parseSymEnvelope(envelope);
    for (const cand of this.candidates(tag)) {
      try {
        return { plaintext: openSym(cand.envKey, envelope), meta: cand.meta };
      } catch {
        /* Poly1305 rejected — try the next multi-hit candidate */
      }
    }
    return null;
  }

  get size(): number {
    return this.m.size;
  }
}
