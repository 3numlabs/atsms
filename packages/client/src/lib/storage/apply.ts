/**
 * Shared inbound ingest for v2 messages (docs/message-format.md §5–§6) — the
 * one place both encryption paths land after decryption + sender
 * authentication. Persists the message row (keyed by the derived ID, so
 * redelivery is idempotent) and maintains the apply-class projections:
 * reactions, edits, retractions, group metadata.
 *
 * Authorization (§5.1): a `replaces` is honored only when the authenticated
 * sender equals the target's authenticated sender. Out-of-order arrivals
 * (an edit/retraction before its target) are stored but not re-applied when
 * the target later arrives — an accepted v1 limitation, noted in the doc.
 */

import {
  KIND_GROUP_UPDATE,
  KIND_REACTION,
  type MessageContent,
  messageIdToHex,
  type Part,
  renderModel,
} from "../format/index.js";
import type { StorageAdapter } from "./interface.js";
import type { LocalMessage, Reaction } from "./types.js";

export interface IngestParams {
  storage: StorageAdapter;
  /** Hex derived message ID (format/ids.ts — computed by the caller from the
   *  authenticated sender + the exact sealed bytes). */
  id: string;
  /** Hex 33-byte v2 ConvoId (must already be verified against the channel). */
  convoId: string;
  /** The seal-layer-authenticated sender DID. */
  senderId: string;
  content: MessageContent;
  /** Local causal position (delivery order) for DCGKA conversations. */
  causalOrder?: number;
  isInvitation?: boolean;
}

/**
 * Persist + apply one non-ephemeral message. Returns the stored row.
 * Callers MUST route `content.ephemeral` messages elsewhere — this function
 * refuses them (nothing ephemeral may reach storage).
 */
export async function ingestMessage(params: IngestParams): Promise<LocalMessage> {
  const { storage, content } = params;
  if (content.ephemeral) throw new Error("ephemeral messages are never persisted");

  const row: LocalMessage = {
    id: params.id,
    convoId: params.convoId,
    senderId: params.senderId,
    createdAt: new Date(content.createdAt),
    causalOrder: params.causalOrder,
    isInvitation: params.isInvitation ?? false,
    content,
  };

  if (content.replaces !== null) {
    await applyReplaces(params, messageIdToHex(content.replaces));
  }
  if (content.inReplyTo !== null) {
    await applyReactions(params, messageIdToHex(content.inReplyTo));
  }
  await applyGroupUpdate(params);

  await storage.saveMessage(row);

  // Keep the conversation record's activity current (sidebar ordering /
  // previews observe conversations, which otherwise only change on
  // lifecycle operations).
  const convo = await storage.getConversation(params.convoId);
  if (convo !== null && row.createdAt.getTime() > convo.lastMessageAt.getTime()) {
    await storage.updateConversation(params.convoId, { lastMessageAt: row.createdAt });
  }

  return row;
}

/** Edit (full replacement body) or retraction (`body: null`) — §5.1/§5.2. */
async function applyReplaces(params: IngestParams, targetId: string): Promise<void> {
  const target = await params.storage.getMessage(targetId);
  if (target === null) return; // out-of-order arrival — row is still stored
  if (target.senderId !== params.senderId) return; // §5.1: same-sender only

  if (params.content.body === null) {
    // Retraction. Retracting a reaction message means removing its projection
    // from the message it reacted to.
    const reactionTarget = reactionTargetOf(target);
    if (reactionTarget !== null) {
      const reacted = await params.storage.getMessage(reactionTarget);
      if (reacted !== null && reacted.reactions !== undefined) {
        await params.storage.updateMessage(reacted.id, {
          reactions: reacted.reactions.filter((r) => r.messageId !== target.id),
        });
      }
    }
    await params.storage.updateMessage(target.id, { deleted: true });
    return;
  }

  // Edit: the target row keeps its identity (and ID); its content becomes the
  // replacement. `replaces` names the FIRST version, so chained edits keep
  // hitting the same row.
  await params.storage.updateMessage(target.id, {
    content: { ...params.content, replaces: target.content.replaces },
    editedAt: new Date(params.content.createdAt),
  });
}

/** Reaction parts target the `inReplyTo` message's projection (§5). */
async function applyReactions(params: IngestParams, targetId: string): Promise<void> {
  const emojis = reactionEmojis(params.content);
  if (emojis.length === 0) return;
  const target = await params.storage.getMessage(targetId);
  if (target === null) return;

  const reactions: Reaction[] = [...(target.reactions ?? [])];
  for (const emoji of emojis) {
    if (reactions.some((r) => r.senderId === params.senderId && r.emoji === emoji)) continue;
    reactions.push({
      senderId: params.senderId,
      emoji,
      createdAt: new Date(params.content.createdAt),
      messageId: params.id,
    });
  }
  await params.storage.updateMessage(target.id, { reactions });
}

/** Group metadata updates land on the conversation record (§5). */
async function applyGroupUpdate(params: IngestParams): Promise<void> {
  for (const part of params.content.body ?? []) {
    if (part.kind !== KIND_GROUP_UPDATE || !("body" in part)) continue;
    const convo = await params.storage.getConversation(params.convoId);
    if (convo === null) return;
    const title = part.body.get("title");
    const description = part.body.get("description");
    await params.storage.updateConversation(params.convoId, {
      metadata: {
        ...convo.metadata,
        ...(typeof title === "string" ? { title } : {}),
        ...(typeof description === "string" ? { description } : {}),
      },
    });
  }
}

/**
 * The transcript view of a message list (client render helper): drops rows
 * that only exist to mutate state — edits/retractions (`replaces` set) and
 * pure apply-class messages like reactions and receipts. Retracted messages
 * stay (rendered as placeholders via `deleted`); §5.2 degradation is the
 * per-message renderModel's job.
 */
export function transcriptMessages(messages: LocalMessage[]): LocalMessage[] {
  return messages.filter((m) => {
    if (m.content.replaces !== null) return false;
    if (m.deleted) return true; // placeholder row
    const model = renderModel(m.content);
    return model.renderParts.length > 0 || model.degraded === "fallback";
  });
}

function reactionTargetOf(message: LocalMessage): string | null {
  if (message.content.inReplyTo === null) return null;
  return reactionEmojis(message.content).length > 0 ? messageIdToHex(message.content.inReplyTo) : null;
}

function reactionEmojis(content: MessageContent): string[] {
  const out: string[] = [];
  for (const part of content.body ?? []) {
    if (part.kind === KIND_REACTION && "body" in part) {
      const emoji = (part as Part & { body: Map<string, unknown> }).body.get("emoji");
      if (typeof emoji === "string") out.push(emoji);
    }
  }
  return out;
}
