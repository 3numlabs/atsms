/**
 * `Conversation` — the app-facing stateful surface (sdk-shape.md Part A). This is
 * what a chat app consumes: it subscribes to `messages$` for **fully-processed**
 * messages (decrypted, verified, ordered, deduped, persisted) and calls `send()`.
 * Crypto is entirely below it, in the `ConversationSession` it wraps.
 *
 * Messages are v2 content (docs/message-format.md): the sealed plaintext is
 * deterministic CBOR, the message ID is derived from the frame-authenticated
 * sender + the exact bytes, and inbound processing routes by handling class —
 * ephemeral signaling to `onSignal`, everything else through the shared
 * `ingestMessage` (projections for reactions/edits/retractions), at which
 * point the store's `observeMessages` stream fires.
 */

import { bytesToHex, type DeviceID, type SessionEvents } from "@atsms/dcgka";
import { Observable } from "rxjs";

import {
  conversationConvoId,
  convoIdToHex,
  createContent,
  decodeContent,
  deriveMessageId,
  encodeContent,
  type Expiration,
  type MessageContent,
  messageIdFromHex,
  messageIdToHex,
  type Part,
  textPart,
} from "../format/index.js";
import { ingestMessage } from "../storage/apply.js";
import type { StorageAdapter } from "../storage/interface.js";
import type { LocalMessage } from "../storage/types.js";
import {
  type ConversationDeps,
  ConversationSession,
  type LocalKeys,
  type MemberDescriptor,
  type Outbound,
} from "./conversation-session.js";

/** Inbound signaling messages are dropped when older than this (format §8). */
const EPHEMERAL_MAX_AGE_MS = 30_000;

export interface ConversationContext extends ConversationDeps {
  /** This device's DID (message sender identity). */
  did: string;
  /** Engine diagnostics (drops, security events) — surfaced, never fatal. */
  onEngineEvent?: (kind: string, detail: string) => void;
  /** Ephemeral (signal-class) messages — call signaling, typing (format §8). */
  onSignal?: (content: MessageContent, senderDid: string) => void;
}

/** What `send()` accepts: plain text, or structured v2 content. */
export interface SendInput {
  text?: string;
  /** Full part list (overrides `text` when both are given). */
  parts?: Part[];
  /** Hex message IDs (the app-facing currency). */
  inReplyTo?: string;
  replaces?: string;
  topicId?: string;
  expires?: Expiration;
  ephemeral?: boolean;
  fallback?: string;
  /** Retraction: `replaces` + `tombstone: true` sends a null body. */
  tombstone?: boolean;
}

export class Conversation {
  private nextCausal: number | null = null;

  private constructor(
    private readonly session: ConversationSession,
    private readonly storage: StorageAdapter,
    private readonly ctx: ConversationContext,
  ) {}

  get groupId(): string {
    return this.session.groupId;
  }

  /** The storage/API conversation ID: hex of the 33-byte v2 ConvoId (format §8). */
  get convoId(): string {
    return convoIdToHex(conversationConvoId(this.groupId));
  }

  /** Fully-processed messages for this conversation, reactively (the app's feed). */
  get messages$(): Observable<LocalMessage[]> {
    return this.storage.observeMessages(this.convoId);
  }

  /** Everyone in the conversation (DIDs, deduped across devices), including self —
   *  derived live from the engine's membership. */
  get members(): string[] {
    return [...new Set(this.session.engine.members().map((m) => m.device.did))];
  }

  /** The member devices (fingerprint hex → DID) — what outbound routing needs. */
  get memberDevices(): Map<string, string> {
    const out = new Map<string, string>();
    for (const m of this.session.engine.members()) out.set(bytesToHex(m.device.fingerprint), m.device.did);
    return out;
  }

  /** A usable epoch exists — `send()` will not throw `NoRootKey`. */
  get hasSendableEpoch(): boolean {
    return this.session.engine.currentEpoch() !== null;
  }

  /** Frames held in the ordering buffer awaiting missing causal ancestors — a
   *  persistent non-zero count is the §8 gap signal (lossy relay). */
  get bufferedFrames(): number {
    return this.session.bufferedFrames;
  }

  /** §8: queue + seal a repair request for the current gaps (empty if none) —
   *  the caller routes the envelopes; members re-serve what they retain. */
  requestRepair(): Promise<Outbound[]> {
    return this.session.requestRepair();
  }

  /**
   * The genesis window: this conversation has never derived any epoch (a
   * bootstrapped joiner awaiting the creator's mandatory first update). Distinct
   * from an established group that is momentarily rootless after a merge — there,
   * live-but-orphaned epochs exist and the client heals immediately
   * (concurrent-update-partition §4.2; §4.1 makes that path converge).
   */
  get awaitingFirstEpoch(): boolean {
    return this.session.engine.currentEpoch() === null && this.session.engine.liveEpochs().length === 0;
  }

  // ── lifecycle ──────────────────────────────────────────────────────────────

  /** Found a conversation. `members` includes this device first (the creator). */
  static async open(
    ctx: ConversationContext,
    params: { keys: LocalKeys; members: MemberDescriptor[]; admins: string[] },
  ): Promise<{ conversation: Conversation; outbound: Outbound[] }> {
    const holder: { convo: Conversation | null } = { convo: null };
    const { conversation: session, outbound } = await ConversationSession.create(ctx, {
      keys: params.keys,
      members: params.members,
      admins: params.admins,
      events: eventsFor(holder, ctx),
    });
    const convo = new Conversation(session, ctx.storage, ctx);
    holder.convo = convo;
    await convo.saveConversationRecord();
    return { conversation: convo, outbound };
  }

  /** Join as a founding member from the conversation's (unsealed) `create` frame. */
  static async bootstrap(
    ctx: ConversationContext,
    params: { keys: LocalKeys; createFrame: Uint8Array },
  ): Promise<Conversation> {
    const holder: { convo: Conversation | null } = { convo: null };
    const session = await ConversationSession.bootstrap(ctx, {
      keys: params.keys,
      createFrame: params.createFrame,
      events: eventsFor(holder, ctx),
    });
    const convo = new Conversation(session, ctx.storage, ctx);
    holder.convo = convo;
    await convo.saveConversationRecord();
    return convo;
  }

  /** Join as an added member from an (unsealed) `welcome` frame. The returned
   *  envelopes carry the mandatory post-join update and MUST be delivered. */
  static async join(
    ctx: ConversationContext,
    params: { keys: LocalKeys; welcomeFrame: Uint8Array },
  ): Promise<{ conversation: Conversation; outbound: Outbound[] }> {
    const holder: { convo: Conversation | null } = { convo: null };
    const { conversation: session, outbound } = await ConversationSession.join(ctx, {
      keys: params.keys,
      welcomeFrame: params.welcomeFrame,
      events: eventsFor(holder, ctx),
    });
    const convo = new Conversation(session, ctx.storage, ctx);
    holder.convo = convo;
    await convo.saveConversationRecord();
    return { conversation: convo, outbound };
  }

  /** Reopen a persisted conversation (engine-state restore). Null if unknown. */
  static async restore(ctx: ConversationContext, groupId: string): Promise<Conversation | null> {
    const holder: { convo: Conversation | null } = { convo: null };
    const session = await ConversationSession.restore(ctx, groupId, eventsFor(holder, ctx));
    if (session === null) return null;
    const convo = new Conversation(session, ctx.storage, ctx);
    holder.convo = convo;
    return convo;
  }

  // ── operations (return sealed envelopes for the transport) ──────────────────

  /**
   * Send a message: `send("hi")`, or structured input — replies, reactions,
   * edits, retractions, signaling (format §4–§5). Non-ephemeral sends are
   * persisted immediately (so they appear in `messages$` right away); deliver
   * the returned envelopes.
   */
  async send(input: string | SendInput): Promise<Outbound[]> {
    const opts = typeof input === "string" ? { text: input } : input;
    const parts = opts.parts ?? (opts.text !== undefined ? [textPart(opts.text)] : null);
    if (parts === null && opts.tombstone !== true) throw new Error("send: no content");

    const content = createContent({
      convoId: conversationConvoId(this.groupId),
      salt: this.ctx.rng(16),
      body: opts.tombstone === true ? null : parts,
      inReplyTo: opts.inReplyTo !== undefined ? messageIdFromHex(opts.inReplyTo) : undefined,
      replaces: opts.replaces !== undefined ? messageIdFromHex(opts.replaces) : undefined,
      topicId: opts.topicId !== undefined ? messageIdFromHex(opts.topicId) : undefined,
      expires: opts.expires,
      ephemeral: opts.ephemeral,
      fallback: opts.fallback,
    });
    const bytes = encodeContent(content);
    const outbound = await this.session.send(bytes);

    if (!content.ephemeral) {
      const id = messageIdToHex(deriveMessageId(this.ctx.did, content, bytes));
      await ingestMessage({
        storage: this.storage,
        id,
        convoId: this.convoId,
        senderId: this.ctx.did,
        content,
        causalOrder: await this.nextCausalOrder(),
      });
    }
    return outbound;
  }

  /** Add a member device (its welcome rides among the returned envelopes). */
  async addMember(member: MemberDescriptor): Promise<Outbound[]> {
    const outbound = await this.session.addMember(member);
    await this.saveConversationRecord();
    return outbound;
  }

  /** Deliver an inbound sealed envelope (a decrypted message lands in
   *  `messages$`); returns any triggered repair envelopes. */
  async deliverEnvelope(envelope: Uint8Array): Promise<Outbound[]> {
    return this.session.deliver(envelope);
  }

  /** Ingest an already-unsealed frame (dispatcher bootstrap path). */
  async ingestFrame(frame: Uint8Array): Promise<Outbound[]> {
    return this.session.ingestFrame(frame);
  }

  /** Rotate keys (post-compromise healing / mandatory post-join update). */
  update(): Promise<Outbound[]> {
    return this.session.update();
  }

  /** Advertise this device's non-welcome delivery endpoint in-band (§12). */
  advertiseEndpoint(url: string): Promise<void> {
    return this.session.advertiseEndpoint(url);
  }

  // ── internals ───────────────────────────────────────────────────────────────

  /**
   * Engine callback sink (public but internal): a peer's app frame was decrypted.
   * Decode → route by class (format §8) → persist via the shared ingest; the
   * store's observable then emits on `messages$`. The frame signature is the
   * authority on the sender; the content self-reports nothing to trust.
   */
  async handleDecrypted(plaintext: Uint8Array, senderDid: string): Promise<void> {
    let content: MessageContent;
    try {
      content = decodeContent(plaintext);
    } catch {
      return; // not v2 content — drop
    }
    // The content must be bound to THIS conversation (defense in depth —
    // integration §5): its convoId is the group's, or it's dropped.
    if (convoIdToHex(content.convoId) !== this.convoId) return;

    if (content.ephemeral) {
      if (Math.abs(Date.now() - content.createdAt) > EPHEMERAL_MAX_AGE_MS) return; // stale signaling
      this.ctx.onSignal?.(content, senderDid);
      return;
    }

    const id = messageIdToHex(deriveMessageId(senderDid, content, plaintext));
    await ingestMessage({
      storage: this.storage,
      id,
      convoId: this.convoId,
      senderId: senderDid,
      content,
      causalOrder: await this.nextCausalOrder(),
    });
  }

  /** Local causal position: the engine delivers in causal order; number arrivals. */
  private async nextCausalOrder(): Promise<number> {
    if (this.nextCausal === null) {
      const recent = await this.storage.getMessages(this.convoId, 1);
      this.nextCausal = (recent[recent.length - 1]?.causalOrder ?? 0) + 1;
    }
    return this.nextCausal++;
  }

  private async saveConversationRecord(): Promise<void> {
    const now = Date.now();
    const existing = await this.storage.getConversation(this.convoId);
    await this.storage.saveConversation({
      id: this.convoId,
      participantIds: this.members,
      createdAt: existing?.createdAt ?? new Date(now),
      lastMessageAt: new Date(now),
      unreadCount: existing?.unreadCount ?? 0,
      metadata: { ...existing?.metadata, protocol: "dcgka" },
    });
  }

}

/** Wire the engine's callbacks to the (not-yet-constructed) Conversation. */
function eventsFor(holder: { convo: Conversation | null }, ctx: ConversationContext): SessionEvents {
  return {
    onAppMessage: (plaintext: Uint8Array, sender: { device: DeviceID }) => {
      void holder.convo?.handleDecrypted(plaintext, sender.device.did);
    },
    onDropped: (reason, id) => ctx.onEngineEvent?.("engine-drop", `${reason} (${hex8(id)})`),
    onSecurityEvent: (kind, detail) => ctx.onEngineEvent?.("engine-security", `${kind}: ${detail}`),
    onDigestMismatch: (frameId) => ctx.onEngineEvent?.("engine-digest-mismatch", frameId),
  };
}

function hex8(id: Uint8Array): string {
  let out = "";
  for (const b of id.slice(0, 4)) out += b.toString(16).padStart(2, "0");
  return out;
}
