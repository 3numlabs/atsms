/**
 * Wire codec for `MessageContent` (docs/message-format.md §4): a fixed-position
 * deterministic-CBOR array. Every field is always present (`null` when absent),
 * so position — not a key — names each field, and the encoding of a given
 * content value is unique (which the derived message ID depends on).
 *
 * Strict reader: wrong version, wrong arity, wrong types, or out-of-profile
 * CBOR all throw. Callers treat a throw as "not a v2 message — drop".
 */

import { cborDecode, cborEncode, type CborMap, type CborValue } from "./cbor.js";
import { CONVO_ID_LENGTH, isConvoId, MESSAGE_ID_LENGTH } from "./ids.js";
import type { Expiration, ExternalContent, MessageContent, Part } from "./types.js";
import { CONTENT_VERSION } from "./types.js";

const TOP_ARITY = 12;
const INLINE_MARKER = 0;
const EXTERNAL_MARKER = 1;
const EXTERNAL_ARITY = 10;

// ── encode ───────────────────────────────────────────────────────────────────

export function encodeContent(content: MessageContent): Uint8Array {
  if (content.v !== CONTENT_VERSION) throw new Error(`content version must be ${CONTENT_VERSION}`);
  if (content.salt.length !== 16) throw new Error("salt must be 16 bytes");
  if (!isConvoId(content.convoId)) throw new Error("convoId must be a 33-byte v2 conversation ID");
  const top: CborValue[] = [
    content.v,
    content.salt,
    content.convoId,
    content.createdAt,
    content.replaces,
    content.topicId,
    content.inReplyTo,
    content.expires === null ? null : [content.expires.relative, content.expires.time],
    content.ephemeral,
    content.fallback,
    content.extensions,
    content.body === null ? null : content.body.map(encodePart),
  ];
  return cborEncode(top);
}

function encodePart(part: Part): CborValue {
  if ("body" in part) return [part.kind, [INLINE_MARKER, part.body]];
  const e = part.external;
  return [
    part.kind,
    [
      EXTERNAL_MARKER,
      e.contentType,
      e.url,
      e.size,
      e.encAlg,
      e.key,
      e.nonce,
      e.hashAlg,
      e.contentHash,
      e.meta,
    ],
  ];
}

// ── decode ───────────────────────────────────────────────────────────────────

export function decodeContent(bytes: Uint8Array): MessageContent {
  const top = cborDecode(bytes);
  if (!Array.isArray(top) || top.length !== TOP_ARITY) throw new Error("content: bad shape");
  const [v, salt, convoId, createdAt, replaces, topicId, inReplyTo, expires, ephemeral, fallback, extensions, body] =
    top;
  if (v !== CONTENT_VERSION) throw new Error("content: unsupported version");
  if (!(salt instanceof Uint8Array) || salt.length !== 16) throw new Error("content: bad salt");
  if (!(convoId instanceof Uint8Array) || convoId.length !== CONVO_ID_LENGTH || !isConvoId(convoId)) {
    throw new Error("content: bad convoId");
  }
  if (typeof createdAt !== "number") throw new Error("content: bad createdAt");
  if (typeof ephemeral !== "boolean") throw new Error("content: bad ephemeral flag");
  if (typeof fallback !== "string") throw new Error("content: bad fallback");
  if (!(extensions instanceof Map)) throw new Error("content: bad extensions");
  return {
    v: CONTENT_VERSION,
    salt,
    convoId,
    createdAt,
    replaces: decodeMessageIdRef(replaces, "replaces"),
    topicId: decodeTopicId(topicId),
    inReplyTo: decodeMessageIdRef(inReplyTo, "inReplyTo"),
    expires: decodeExpiration(expires),
    ephemeral,
    fallback,
    extensions,
    body: body === null ? null : decodeBody(body),
  };
}

function decodeMessageIdRef(v: CborValue, field: string): Uint8Array | null {
  if (v === null) return null;
  if (!(v instanceof Uint8Array) || v.length !== MESSAGE_ID_LENGTH) throw new Error(`content: bad ${field}`);
  return v;
}

function decodeTopicId(v: CborValue): Uint8Array | null {
  if (v === null) return null;
  if (!(v instanceof Uint8Array) || v.length === 0) throw new Error("content: bad topicId");
  return v;
}

function decodeExpiration(v: CborValue): Expiration | null {
  if (v === null) return null;
  if (!Array.isArray(v) || v.length !== 2) throw new Error("content: bad expires");
  const [relative, time] = v;
  if (typeof relative !== "boolean" || typeof time !== "number") throw new Error("content: bad expires");
  return { relative, time };
}

function decodeBody(v: CborValue): Part[] {
  if (!Array.isArray(v)) throw new Error("content: bad body");
  return v.map(decodePart);
}

function decodePart(v: CborValue): Part {
  if (!Array.isArray(v) || v.length !== 2) throw new Error("content: bad part");
  const [kind, inner] = v;
  if (typeof kind !== "number") throw new Error("content: bad part kind");
  if (!Array.isArray(inner) || inner.length < 1) throw new Error("content: bad part content");
  if (inner[0] === INLINE_MARKER) {
    if (inner.length !== 2 || !(inner[1] instanceof Map)) throw new Error("content: bad inline part");
    for (const key of inner[1].keys()) {
      if (typeof key !== "string") throw new Error("content: inline part keys must be strings");
    }
    return { kind, body: inner[1] as Map<string, CborValue> };
  }
  if (inner[0] === EXTERNAL_MARKER) {
    if (inner.length !== EXTERNAL_ARITY) throw new Error("content: bad external part");
    const [, contentType, url, size, encAlg, key, nonce, hashAlg, contentHash, meta] = inner;
    if (
      typeof contentType !== "string" ||
      typeof url !== "string" ||
      typeof size !== "number" ||
      typeof encAlg !== "number" ||
      !(key instanceof Uint8Array) ||
      !(nonce instanceof Uint8Array) ||
      typeof hashAlg !== "number" ||
      !(contentHash instanceof Uint8Array) ||
      !(meta instanceof Map)
    ) {
      throw new Error("content: bad external part fields");
    }
    for (const k of meta.keys()) {
      if (typeof k !== "string") throw new Error("content: external meta keys must be strings");
    }
    const external: ExternalContent = {
      contentType,
      url,
      size,
      encAlg,
      key,
      nonce,
      hashAlg,
      contentHash,
      meta: meta as Map<string, CborValue>,
    };
    return { kind, external };
  }
  throw new Error("content: unknown part cardinality");
}

/** The one-shot recipient DIDs from the registered extension (§4), or null. */
export function recipientsExtension(content: MessageContent, extKey: number): string[] | null {
  const v = content.extensions.get(extKey);
  if (v === undefined) return null;
  if (!Array.isArray(v) || !v.every((d): d is string => typeof d === "string")) {
    throw new Error("content: bad recipients extension");
  }
  return v;
}

export type { CborMap };
