/**
 * Constructors for v2 message content (docs/message-format.md §4–§5) — what
 * app-facing code calls; nobody hand-assembles the CBOR shapes.
 *
 * Salt is a required input (16 bytes from the caller's CSPRNG): the format
 * layer takes no randomness dependency, which keeps encoding deterministic
 * and testable.
 */

import type { CborMap, CborValue } from "./cbor.js";
import type { Expiration, ExternalContent, MessageContent, Part } from "./types.js";
import {
  CONTENT_VERSION,
  KIND_CALL,
  KIND_CALL_EVENT,
  KIND_FILE,
  KIND_GROUP_UPDATE,
  KIND_PREVIEW,
  KIND_REACTION,
  KIND_RECEIPT,
  KIND_SMS,
  KIND_TEXT,
  KIND_TYPING,
} from "./types.js";

export interface CreateContentOptions {
  /** 33-byte v2 conversation ID (ids.ts). */
  convoId: Uint8Array;
  /** 16 fresh random bytes. */
  salt: Uint8Array;
  body: Part[] | null;
  /** Defaults to `Date.now()`. */
  createdAt?: number;
  replaces?: Uint8Array;
  topicId?: Uint8Array;
  inReplyTo?: Uint8Array;
  expires?: Expiration;
  ephemeral?: boolean;
  fallback?: string;
  extensions?: CborMap;
}

export function createContent(opts: CreateContentOptions): MessageContent {
  return {
    v: CONTENT_VERSION,
    salt: opts.salt,
    convoId: opts.convoId,
    createdAt: opts.createdAt ?? Date.now(),
    replaces: opts.replaces ?? null,
    topicId: opts.topicId ?? null,
    inReplyTo: opts.inReplyTo ?? null,
    expires: opts.expires ?? null,
    ephemeral: opts.ephemeral ?? false,
    fallback: opts.fallback ?? "",
    extensions: opts.extensions ?? new Map(),
    body: opts.body,
  };
}

// ── part constructors (§5 registry) ──────────────────────────────────────────

/** AT Protocol-style rich-text facet (mention/link/tag over byte ranges). */
export interface TextFacet {
  byteStart: number;
  byteEnd: number;
  feature: { type: "mention"; did: string } | { type: "link"; uri: string } | { type: "tag"; tag: string };
}

export function textPart(text: string, facets?: TextFacet[]): Part {
  const body = new Map<string, CborValue>([["text", text]]);
  if (facets !== undefined && facets.length > 0) {
    body.set(
      "facets",
      facets.map((f): CborValue => {
        const m = new Map<string, CborValue>([
          ["byteStart", f.byteStart],
          ["byteEnd", f.byteEnd],
          ["type", f.feature.type],
        ]);
        if (f.feature.type === "mention") m.set("did", f.feature.did);
        else if (f.feature.type === "link") m.set("uri", f.feature.uri);
        else m.set("tag", f.feature.tag);
        return m;
      }),
    );
  }
  return { kind: KIND_TEXT, body };
}

/** One emoji; the envelope's `inReplyTo` names the target message (§5). */
export function reactionPart(emoji: string): Part {
  return { kind: KIND_REACTION, body: new Map<string, CborValue>([["emoji", emoji]]) };
}

export function filePart(external: ExternalContent): Part {
  return { kind: KIND_FILE, external };
}

/** Small-file inline form (§5): plaintext ≤ 32 KiB rides in the message itself. */
export const INLINE_FILE_LIMIT = 32 * 1024;

export function inlineFilePart(data: Uint8Array, contentType: string, filename?: string): Part {
  if (data.length > INLINE_FILE_LIMIT) {
    throw new Error(`inline file exceeds ${INLINE_FILE_LIMIT} B — upload as an external blob`);
  }
  const body = new Map<string, CborValue>([
    ["data", data],
    ["contentType", contentType],
  ]);
  if (filename !== undefined) body.set("filename", filename);
  return { kind: KIND_FILE, body };
}

/** Call-control signaling (§5); send with `ephemeral: true`. */
export interface CallSignal {
  callId: string;
  type: "offer" | "answer" | "ice" | "hangup";
  sdp?: string;
  candidate?: { candidate: string; sdpMid: string | null; sdpMLineIndex: number | null };
  mediaTypes?: ("audio" | "video")[];
}

export function callPart(signal: CallSignal): Part {
  const body = new Map<string, CborValue>([
    ["callId", signal.callId],
    ["type", signal.type],
  ]);
  if (signal.sdp !== undefined) body.set("sdp", signal.sdp);
  if (signal.candidate !== undefined) {
    body.set(
      "candidate",
      new Map<string, CborValue>([
        ["candidate", signal.candidate.candidate],
        ["sdpMid", signal.candidate.sdpMid],
        ["sdpMLineIndex", signal.candidate.sdpMLineIndex],
      ]),
    );
  }
  if (signal.mediaTypes !== undefined) body.set("mediaTypes", signal.mediaTypes as CborValue[]);
  return { kind: KIND_CALL, body };
}

/** The durable transcript record of a call (missed/ended/declined). */
export function callEventPart(callId: string, event: "missed" | "ended" | "declined", durationMs?: number): Part {
  const body = new Map<string, CborValue>([
    ["callId", callId],
    ["event", event],
  ]);
  if (durationMs !== undefined) body.set("durationMs", durationMs);
  return { kind: KIND_CALL_EVENT, body };
}

/** Batched delivery/read receipt over message IDs (§5). */
export function receiptPart(status: "delivered" | "read", messageIds: Uint8Array[]): Part {
  return {
    kind: KIND_RECEIPT,
    body: new Map<string, CborValue>([
      ["status", status],
      ["ids", messageIds as CborValue[]],
    ]),
  };
}

export function typingPart(state: "start" | "stop"): Part {
  return { kind: KIND_TYPING, body: new Map<string, CborValue>([["state", state]]) };
}

export function previewPart(url: string, opts?: { title?: string; description?: string }): Part {
  const body = new Map<string, CborValue>([["url", url]]);
  if (opts?.title !== undefined) body.set("title", opts.title);
  if (opts?.description !== undefined) body.set("description", opts.description);
  return { kind: KIND_PREVIEW, body };
}

/** Group metadata over the wire (§5); membership events stay at the DCGKA layer. */
export function groupUpdatePart(update: { title?: string; description?: string }): Part {
  const body = new Map<string, CborValue>();
  if (update.title !== undefined) body.set("title", update.title);
  if (update.description !== undefined) body.set("description", update.description);
  if (body.size === 0) throw new Error("group update needs at least one field");
  return { kind: KIND_GROUP_UPDATE, body };
}

/** Gateway SMS/MMS bridge dialect (§5). */
export function smsPart(text: string, opts?: { from?: string; to?: string }): Part {
  const body = new Map<string, CborValue>([["text", text]]);
  if (opts?.from !== undefined) body.set("from", opts.from);
  if (opts?.to !== undefined) body.set("to", opts.to);
  return { kind: KIND_SMS, body };
}
