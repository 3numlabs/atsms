/**
 * v2 message content — decoded (in-memory) types and the part-kind registry
 * (docs/message-format.md §4–§5).
 *
 * The wire form is deterministic CBOR (content.ts); these are the TypeScript
 * views app code works with. Byte fields stay `Uint8Array`; hex conversion is
 * a storage/display concern (ids.ts helpers).
 */

import type { CborMap, CborValue } from "./cbor.js";

/** The content of one message — every field always present (null = absent). */
export interface MessageContent {
  v: 2;
  /** 16 random bytes; feeds the derived message ID (ids.ts). */
  salt: Uint8Array;
  /** 33-byte conversation ID: context byte + 32-byte id (ids.ts). */
  convoId: Uint8Array;
  /** Milliseconds since the Unix epoch, sender clock — display/tiebreak only. */
  createdAt: number;
  /** Message ID of the FIRST version of a message this edits or retracts. */
  replaces: Uint8Array | null;
  /** Thread key; convention: message ID of the thread's first message. */
  topicId: Uint8Array | null;
  /** Message ID being quoted / replied to / reacted to. */
  inReplyTo: Uint8Array | null;
  /** Cooperative disappearing-messages hint. */
  expires: Expiration | null;
  /** Signaling class: never persisted, dropped when stale (§8). */
  ephemeral: boolean;
  /** Plain-text stand-in when no part is understood ("" = none, §5.2). */
  fallback: string;
  /** Registered int keys + private-use string keys (§4). */
  extensions: CborMap;
  /** Typed parts; null = retraction tombstone (only meaningful with replaces). */
  body: Part[] | null;
}

/** `expires`: relative = seconds after the receiver reads it; absolute = epoch seconds. */
export interface Expiration {
  relative: boolean;
  time: number;
}

export type Part = InlinePart | ExternalPart;

/** Inline content: a CBOR map, schema per kind (§5). */
export interface InlinePart {
  kind: number;
  body: Map<string, CborValue>;
}

/** Content stored as an encrypted external blob (§4.1). */
export interface ExternalPart {
  kind: number;
  external: ExternalContent;
}

export interface ExternalContent {
  /** IANA media type of the *plaintext*, e.g. "image/jpeg". */
  contentType: string;
  /** Where the encrypted bytes live. */
  url: string;
  /** Plaintext octets. */
  size: number;
  /** IANA AEAD registry number; ENC_ALG_A128GCM is mandatory to implement. */
  encAlg: number;
  key: Uint8Array;
  nonce: Uint8Array;
  /** IANA named-hash registry number; HASH_ALG_SHA256 is the default. */
  hashAlg: number;
  /** Hash of the *encrypted* bytes at `url`. */
  contentHash: Uint8Array;
  /** Optional string-keyed metadata: filename, description, dims, durationMs, thumb, urlExpires. */
  meta: Map<string, CborValue>;
}

// ── registries (§4/§5) ───────────────────────────────────────────────────────

export const CONTENT_VERSION = 2;

/** Registered extension key: one-shot intended-recipient DIDs (§4). */
export const EXT_RECIPIENTS = 1;

/** IANA AEAD algorithm number for AES-128-GCM (RFC 5116). */
export const ENC_ALG_A128GCM = 1;
/** IANA named-information hash algorithm number for SHA-256. */
export const HASH_ALG_SHA256 = 1;

export const KIND_TEXT = 1;
export const KIND_REACTION = 2;
export const KIND_FILE = 3;
export const KIND_CALL = 4;
export const KIND_CALL_EVENT = 5;
export const KIND_RECEIPT = 6;
export const KIND_TYPING = 7;
export const KIND_PREVIEW = 8;
export const KIND_GROUP_UPDATE = 9;
export const KIND_SMS = 10;
/** Kinds at or above this value are private-use (§5). */
export const KIND_PRIVATE_USE = 1024;

/**
 * How a part is processed (§5): `render` = a transcript bubble; `apply` =
 * mutates conversation/message state, persisted, never a bubble; `signal` =
 * real-time only, sent with `ephemeral: true`, never persisted.
 */
export type PartHandling = "render" | "apply" | "signal";

export const PART_HANDLING: ReadonlyMap<number, PartHandling> = new Map<number, PartHandling>([
  [KIND_TEXT, "render"],
  [KIND_REACTION, "apply"],
  [KIND_FILE, "render"],
  [KIND_CALL, "signal"],
  [KIND_CALL_EVENT, "render"],
  [KIND_RECEIPT, "apply"],
  [KIND_TYPING, "signal"],
  [KIND_PREVIEW, "render"],
  [KIND_GROUP_UPDATE, "apply"],
  [KIND_SMS, "render"],
]);

export function partHandling(kind: number): PartHandling | null {
  return PART_HANDLING.get(kind) ?? null;
}
