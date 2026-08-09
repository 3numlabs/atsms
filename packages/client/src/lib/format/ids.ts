/**
 * Derived identifiers (docs/message-format.md §6, §8).
 *
 * Message IDs are computed, never carried: an ID binds the seal-layer-
 * authenticated sender, the conversation, the exact content bytes, and the
 * per-message salt, so no participant can mint a colliding or forged ID.
 * The construction follows draft-ietf-mimi-content: explicit uint16 length
 * prefixes remove concatenation ambiguity, the salt appears twice (once
 * inside the content bytes, once appended) as a length-extension defense,
 * and the leading byte names the hash so it can be swapped later.
 *
 * Conversation IDs are 33 bytes — one context byte + a 32-byte hash — making
 * the one-shot and conversation spaces structurally disjoint (§8).
 */

import { bytesToHex, concatBytes, hexToBytes } from "@atsms/dcgka";
import { sha256 } from "@noble/hashes/sha2.js";

import type { MessageContent } from "./types.js";

export const MESSAGE_ID_LENGTH = 32;
/** Leading MessageId byte: SHA-256 (IANA named-information registry). */
export const MESSAGE_ID_HASH_SHA256 = 0x01;

export const CONVO_ID_LENGTH = 33;
/** ConvoId context bytes (§8). */
export const CONVO_ONESHOT = 0x01;
export const CONVO_CONVERSATION = 0x02;

const ONESHOT_CONVO_DOMAIN = "atsms/convo/oneshot/v2";

function len16(bytes: Uint8Array): Uint8Array {
  if (bytes.length > 0xffff) throw new Error("length prefix overflow");
  return Uint8Array.of(bytes.length >> 8, bytes.length & 0xff);
}

/**
 * Derive the 32-byte message ID.
 *
 * `senderDid` MUST be the cryptographically authenticated sender (the CMS
 * signer's DID or the DCGKA frame signer's DID) — never a value read from the
 * content. `contentBytes` are the exact deterministic-CBOR bytes that were
 * sealed (encode once, hash what you sent / what you opened).
 */
export function deriveMessageId(senderDid: string, content: MessageContent, contentBytes: Uint8Array): Uint8Array {
  const sender = new TextEncoder().encode(senderDid);
  const digest = sha256(
    concatBytes(len16(sender), sender, len16(content.convoId), content.convoId, contentBytes, content.salt),
  );
  return concatBytes(Uint8Array.of(MESSAGE_ID_HASH_SHA256), digest.subarray(0, MESSAGE_ID_LENGTH - 1));
}

/** Deterministic one-shot conversation ID over the participant set (§8). */
export function oneShotConvoIdV2(participants: string[]): Uint8Array {
  const sorted = [...new Set(participants)].sort();
  const enc = new TextEncoder();
  const pieces: Uint8Array[] = [enc.encode(ONESHOT_CONVO_DOMAIN)];
  for (const did of sorted) {
    const b = enc.encode(did);
    pieces.push(len16(b), b);
  }
  return concatBytes(Uint8Array.of(CONVO_ONESHOT), sha256(concatBytes(...pieces)));
}

/** Wrap a DCGKA GroupID (64-hex) as a conversation ConvoId (§8). */
export function conversationConvoId(groupIdHex: string): Uint8Array {
  const id = hexToBytes(groupIdHex);
  if (id.length !== 32) throw new Error("GroupID must be 32 bytes");
  return concatBytes(Uint8Array.of(CONVO_CONVERSATION), id);
}

export function isConvoId(bytes: Uint8Array): boolean {
  return bytes.length === CONVO_ID_LENGTH && (bytes[0] === CONVO_ONESHOT || bytes[0] === CONVO_CONVERSATION);
}

/** The DCGKA GroupID (hex) inside a conversation ConvoId, or null. */
export function groupIdOfConvoId(convoId: Uint8Array): string | null {
  if (convoId.length !== CONVO_ID_LENGTH || convoId[0] !== CONVO_CONVERSATION) return null;
  return bytesToHex(convoId.subarray(1));
}

// Hex forms — the storage/API currency for both ID spaces.

export function messageIdToHex(id: Uint8Array): string {
  if (id.length !== MESSAGE_ID_LENGTH) throw new Error("message ID must be 32 bytes");
  return bytesToHex(id);
}

export function messageIdFromHex(hex: string): Uint8Array {
  const b = hexToBytes(hex);
  if (b.length !== MESSAGE_ID_LENGTH) throw new Error("message ID must be 32 bytes");
  return b;
}

export function convoIdToHex(id: Uint8Array): string {
  if (!isConvoId(id)) throw new Error("not a v2 conversation ID");
  return bytesToHex(id);
}

export function convoIdFromHex(hex: string): Uint8Array {
  const b = hexToBytes(hex);
  if (!isConvoId(b)) throw new Error("not a v2 conversation ID");
  return b;
}
