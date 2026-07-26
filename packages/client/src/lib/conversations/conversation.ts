/**
 * `Conversation` — the app-facing stateful surface (sdk-shape.md Part A). This is
 * what a chat app consumes: it subscribes to `messages$` for **fully-processed**
 * messages (decrypted, verified, ordered, deduped, persisted) and calls `send()`.
 * Crypto is entirely below it, in the `ConversationSession` it wraps.
 *
 * It owns the receive pipeline: an inbound frame → `ConversationSession.ingest`
 * (decrypt/verify/order) → parse the `ATSMSMessagePayload` → validate → persist as
 * a `LocalMessage`, at which point the store's `observeMessages` stream fires. So
 * `messages$` IS `storage.observeMessages(groupId)` — the app never touches an
 * envelope, a frame, or a key. (Transport is a separate layer; these methods
 * return the frames to deliver.)
 */

import { Observable } from "rxjs";
import type { DeviceID, SessionEvents } from "@atsms/dcgka";

import { createMessagePayload, createTextContent } from "../messages.js";
import type { StorageAdapter } from "../storage/interface.js";
import { payloadToLocalMessage } from "../storage/types.js";
import type { LocalMessage } from "../storage/types.js";
import type { ATSMSMessagePayload } from "../types.js";
import {
  ConversationSession,
  type ConversationDeps,
  type LocalKeys,
  type MemberDescriptor,
} from "./conversation-session.js";

const dec = (b: Uint8Array) => new TextDecoder().decode(b);
const enc = (s: string) => new TextEncoder().encode(s);

export interface ConversationContext extends ConversationDeps {
  /** This device's DID (message sender identity). */
  did: string;
}

export class Conversation {
  private constructor(
    private readonly session: ConversationSession,
    private readonly storage: StorageAdapter,
    private readonly ctx: ConversationContext,
    private readonly participants: string[],
  ) {}

  get groupId(): string {
    return this.session.groupId;
  }

  /** Fully-processed messages for this conversation, reactively (the app's feed). */
  get messages$(): Observable<LocalMessage[]> {
    return this.storage.observeMessages(this.groupId);
  }

  /** Everyone in the conversation (DIDs), including self. */
  get members(): string[] {
    return this.participants;
  }

  // ── lifecycle ──────────────────────────────────────────────────────────────

  /** Found a conversation. `members` includes this device. */
  static async open(
    ctx: ConversationContext,
    params: { keys: LocalKeys; members: MemberDescriptor[]; admins: string[] },
  ): Promise<{ conversation: Conversation; outbound: Uint8Array[] }> {
    const holder: { convo: Conversation | null } = { convo: null };
    const { conversation: session, outbound } = await ConversationSession.create(ctx, {
      keys: params.keys,
      members: params.members,
      admins: params.admins,
      events: eventsFor(holder),
    });
    const participants = params.members.map((m) => m.device.did);
    const convo = new Conversation(session, ctx.storage, ctx, participants);
    holder.convo = convo;
    await convo.saveConversationRecord();
    return { conversation: convo, outbound };
  }

  /** Join as a founding member from the conversation's `create` frame. */
  static async bootstrap(
    ctx: ConversationContext,
    params: { keys: LocalKeys; createFrame: Uint8Array; participants: string[] },
  ): Promise<Conversation> {
    const holder: { convo: Conversation | null } = { convo: null };
    const session = await ConversationSession.bootstrap(ctx, {
      keys: params.keys,
      createFrame: params.createFrame,
      events: eventsFor(holder),
    });
    const convo = new Conversation(session, ctx.storage, ctx, params.participants);
    holder.convo = convo;
    await convo.saveConversationRecord();
    return convo;
  }

  // ── operations ───────────────────────────────────────────────────────────────

  /** Send a text message. Returns the frames to deliver; the sent message is
   *  persisted immediately (so it appears in `messages$` right away). */
  async send(text: string): Promise<Uint8Array[]> {
    const recipients = this.participants.filter((p) => p !== this.ctx.did);
    const payload = createMessagePayload(this.ctx.did, recipients, createTextContent(text), "atsms/text", this.groupId);
    const frames = await this.session.send(enc(JSON.stringify(payload)));
    await this.storage.saveMessage(payloadToLocalMessage(payload));
    return frames;
  }

  /** Ingest an inbound frame (a decrypted message lands in `messages$`). */
  async ingestFrame(frame: Uint8Array): Promise<Uint8Array[]> {
    return this.session.ingest(frame);
  }

  /** Rotate keys (post-compromise healing / mandatory post-join update). */
  update(): Promise<Uint8Array[]> {
    return this.session.update();
  }

  // ── internals ───────────────────────────────────────────────────────────────

  /**
   * Engine callback sink (public but internal): a peer's app frame was decrypted.
   * Parse → validate → persist; the store's observable then emits on `messages$`.
   */
  async handleDecrypted(plaintext: Uint8Array, senderDid: string): Promise<void> {
    let payload: ATSMSMessagePayload;
    try {
      payload = JSON.parse(dec(plaintext)) as ATSMSMessagePayload;
    } catch {
      return; // not a well-formed payload — drop
    }
    // Defense in depth (integration §5): the frame signature is the authority;
    // the payload's self-reported ids must agree with it.
    if (payload.senderId !== senderDid || payload.convoId !== this.groupId) return;
    await this.storage.saveMessage(payloadToLocalMessage(payload)); // dedup by id (INSERT OR REPLACE)
  }

  private async saveConversationRecord(): Promise<void> {
    const now = Date.now();
    await this.storage.saveConversation({
      id: this.groupId,
      participantIds: this.participants,
      createdAt: new Date(now),
      lastMessageAt: new Date(now),
      unreadCount: 0,
      metadata: { protocol: "dcgka" },
    });
  }

}

/** Wire the engine's app-message callback to the (not-yet-constructed) Conversation. */
function eventsFor(holder: { convo: Conversation | null }): SessionEvents {
  return {
    onAppMessage: (plaintext: Uint8Array, sender: { device: DeviceID }) => {
      void holder.convo?.handleDecrypted(plaintext, sender.device.did);
    },
  };
}
