/**
 * `Conversation` — the app-facing stateful surface (sdk-shape.md Part A). This is
 * what a chat app consumes: it subscribes to `messages$` for **fully-processed**
 * messages (decrypted, verified, ordered, deduped, persisted) and calls `send()`.
 * Crypto is entirely below it, in the `ConversationSession` it wraps.
 *
 * It owns the receive pipeline: an inbound sealed envelope → `ConversationSession
 * .deliver` (unseal/decrypt/verify/order) → parse the `ATSMSMessagePayload` →
 * validate → persist as a `LocalMessage`, at which point the store's
 * `observeMessages` stream fires. So `messages$` IS `storage.observeMessages
 * (groupId)` — the app never touches an envelope, a frame, or a key. (Transport
 * is a separate layer; these methods return sealed envelopes to deliver.)
 */

import { bytesToHex, type DeviceID, type SessionEvents } from "@atsms/dcgka";
import { Observable } from "rxjs";

import { createMessagePayload, createTextContent } from "../messages.js";
import type { StorageAdapter } from "../storage/interface.js";
import type { LocalMessage } from "../storage/types.js";
import { payloadToLocalMessage } from "../storage/types.js";
import type { ATSMSMessagePayload } from "../types.js";
import {
  type ConversationDeps,
  ConversationSession,
  type LocalKeys,
  type MemberDescriptor,
  type Outbound,
} from "./conversation-session.js";

const dec = (b: Uint8Array) => new TextDecoder().decode(b);
const enc = (s: string) => new TextEncoder().encode(s);

export interface ConversationContext extends ConversationDeps {
  /** This device's DID (message sender identity). */
  did: string;
  /** Engine diagnostics (drops, security events) — surfaced, never fatal. */
  onEngineEvent?: (kind: string, detail: string) => void;
}

export class Conversation {
  private constructor(
    private readonly session: ConversationSession,
    private readonly storage: StorageAdapter,
    private readonly ctx: ConversationContext,
  ) {}

  get groupId(): string {
    return this.session.groupId;
  }

  /** Fully-processed messages for this conversation, reactively (the app's feed). */
  get messages$(): Observable<LocalMessage[]> {
    return this.storage.observeMessages(this.groupId);
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

  /** Send a text message. The sent message is persisted immediately (so it
   *  appears in `messages$` right away); deliver the returned envelopes. */
  async send(text: string): Promise<Outbound[]> {
    const recipients = this.members.filter((p) => p !== this.ctx.did);
    const payload = createMessagePayload(this.ctx.did, recipients, createTextContent(text), "atsms/text", this.groupId);
    const outbound = await this.session.send(enc(JSON.stringify(payload)));
    await this.storage.saveMessage(payloadToLocalMessage(payload));
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
    const existing = await this.storage.getConversation(this.groupId);
    await this.storage.saveConversation({
      id: this.groupId,
      participantIds: this.members,
      createdAt: existing?.createdAt ?? new Date(now),
      lastMessageAt: new Date(now),
      unreadCount: existing?.unreadCount ?? 0,
      metadata: { protocol: "dcgka" },
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
