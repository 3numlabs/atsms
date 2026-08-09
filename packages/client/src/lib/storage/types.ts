/**
 * ATSMS Storage Types
 *
 * Local message storage over the v2 content format (docs/message-format.md).
 * A stored message row is the authoritative received record: the decoded
 * content plus the identifiers the format derives (never carries) — the
 * message ID and the authenticated sender. `reactions`/`editedAt`/`deleted`
 * are projections maintained by apply-class processing (§5/§6), kept on the
 * row so rendering never has to re-walk the log.
 */

import { Convert } from "pvtsutils";

import { decodeContent, encodeContent, type MessageContent } from "../format/index.js";

export interface LocalMessage {
  /** Hex of the 32-byte derived message ID (format/ids.ts) — the storage key. */
  id: string;
  /** Hex of the 33-byte v2 conversation ID. */
  convoId: string;
  /** The seal-layer-authenticated sender DID (never read from content). */
  senderId: string;
  /** Sender-asserted timestamp (display / fallback ordering). */
  createdAt: Date;
  /** Engine causal position (DCGKA `seq`) — the primary sort key when present. */
  causalOrder?: number;
  /** True if this message started a new conversation. */
  isInvitation: boolean;
  /** The decoded v2 content (adapters persist its deterministic CBOR). */
  content: MessageContent;
  /** Projection: reactions currently applied to this message. */
  reactions?: Reaction[];
  /** Projection: when an accepted edit last replaced this message's content. */
  editedAt?: Date;
  /** Projection: retracted by an accepted tombstone (render a placeholder). */
  deleted?: boolean;
}

export interface LocalConversation {
  id: string; // Conversation ID (hex of the 33-byte v2 ConvoId)
  participantIds: string[]; // All participant DIDs
  createdAt: Date;
  lastMessageAt: Date;
  acceptedAt?: Date; // When user accepted the conversation
  mutedUntil?: Date;
  unreadCount: number;
  lastRev?: string; // Last sync revision
  metadata?: ConversationMetadata;
}

export interface Reaction {
  senderId: string;
  emoji: string;
  createdAt: Date;
  /** Hex ID of the reaction message itself — what a removal's `replaces` names. */
  messageId: string;
}

export interface ConversationMetadata {
  title?: string;
  description?: string;
  /** Fixed at creation: a DM is exactly two people forever; a group stays a
   *  group however much it shrinks. Never inferred from the member count. */
  kind?: "dm" | "group";
  isGroup?: boolean;
  pinnedAt?: Date;
  /** Which encryption path this conversation runs on (atsms-integration §4). */
  protocol?: "dcgka" | "x509";
  /** This device is no longer a member (its removal was processed). Clients
   *  render read-only; cleared automatically if the device is re-admitted. */
  removed?: boolean;
  /** …and it was this device's own choice — `leave()`, not a removal. The UI
   *  tells a different story for each. */
  left?: boolean;
}

export interface ConversationFilter {
  status?: "accepted" | "request" | "all";
  unreadOnly?: boolean;
  participantDid?: string;
}

/**
 * DID information stored in local database
 */
export interface ATSMSDidInfo {
  did: string;
  handle: string;
  certSerial: string;
  isPrimary: boolean; // First DID saved is primary
  createdAt: Date;
  lastUsedAt: Date;
}

// ── content ↔ column serialization (adapters) ───────────────────────────────

/** The deterministic-CBOR content bytes as base64 — the stored column value. */
export function contentToStorage(content: MessageContent): string {
  return Convert.ToBase64(encodeContent(content));
}

export function contentFromStorage(column: string): MessageContent {
  return decodeContent(new Uint8Array(Convert.FromBase64(column)));
}

export function reactionsToStorage(reactions: Reaction[] | undefined): string | null {
  if (reactions === undefined || reactions.length === 0) return null;
  return JSON.stringify(reactions.map((r) => ({ ...r, createdAt: r.createdAt.getTime() })));
}

export function reactionsFromStorage(column: string | null | undefined): Reaction[] | undefined {
  if (column === null || column === undefined) return undefined;
  const raw = JSON.parse(column) as Array<Omit<Reaction, "createdAt"> & { createdAt: number }>;
  return raw.map((r) => ({ ...r, createdAt: new Date(r.createdAt) }));
}
