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

import { bytesToHex, type DeviceID, type Membership, type SessionEvents } from "@atsms/dcgka";
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
  /** Set when this device left as the LAST member — a purely local act. */
  private locallyLeft = false;

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

  /** Route a sealed envelope's target device to its DID. Current members
   *  first, then devices we have REMOVED — their removal notice is addressed
   *  to them precisely because they are no longer members, so routing must
   *  outlive membership (else the notice is dropped as unroutable). */
  didOfDevice(fingerprintHex: string): string | undefined {
    const member = this.memberDevices.get(fingerprintHex);
    if (member !== undefined) return member;
    for (const gone of this.session.removedMemberships()) {
      if (bytesToHex(gone.device.fingerprint) === fingerprintHex) return gone.device.did;
    }
    return undefined;
  }

  /** What this conversation is — fixed by its create op (a group that shrinks
   *  to two is still a group; a DM is exactly its two people, forever). */
  get kind(): "dm" | "group" {
    return this.session.kind;
  }

  /** Admin DIDs (dgm §4: who may add, remove, and grant admin). */
  get admins(): string[] {
    return [...this.session.engine.admins()];
  }

  /** Am I still a member? False once my own removal is processed — the
   *  removal op is sealed to the device it removes, so this flips without any
   *  polling. A client MUST stop sending (and say so). */
  get amMember(): boolean {
    return this.session.amMember();
  }

  /** Membership history (causal order) derived from the retained op log:
   *  who admitted/removed whom. Frames carry no wall clock, so a UI wanting
   *  timestamps records its own observation time. */
  membershipLog(): Array<{ opId: string; type: "create" | "add" | "remove"; actor: DeviceID; devices: DeviceID[] }> {
    return this.session.membershipLog();
  }

  /** Every membership (device + admission) of one DID — removal currency. */
  membershipsOf(did: string): Membership[] {
    return this.session.engine.members().filter((m: Membership) => m.device.did === did);
  }

  /** A usable epoch exists — `send()` will not throw `NoRootKey`. */
  get hasSendableEpoch(): boolean {
    return this.session.engine.currentEpoch() !== null;
  }

  /** Persistently-unopenable inbound envelopes (C-fallback signal). */
  get unopenableCount(): number {
    return this.session.unopenableCount;
  }

  /** Age (ms) of the last inbound traffic that opened successfully. */
  get sinceHealthyMs(): number {
    return this.session.sinceHealthyMs;
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
    params: { keys: LocalKeys; members: MemberDescriptor[]; admins: string[]; kind?: "dm" | "group" },
  ): Promise<{ conversation: Conversation; outbound: Outbound[] }> {
    const holder: { convo: Conversation | null } = { convo: null };
    const { conversation: session, outbound } = await ConversationSession.create(ctx, {
      keys: params.keys,
      members: params.members,
      admins: params.admins,
      events: eventsFor(holder, ctx),
      ...(params.kind !== undefined ? { kind: params.kind } : {}),
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
    // A last-member departure lives only in the record (no op expresses it),
    // so restore the mark or a reloaded client would look like a member again.
    const record = await ctx.storage.getConversation(convo.convoId);
    if (record?.metadata?.left === true && convo.amMember) convo.locallyLeft = true;
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
    return this.addMembers([member]);
  }

  /** Batched add (add-member-flow §6): every device in ONE round — K adds,
   *  one post-add epoch, K welcomes. */
  async addMembers(members: MemberDescriptor[]): Promise<Outbound[]> {
    if (members.length === 0) return [];
    const outbound = await this.session.addMembers(members);
    await this.saveConversationRecord();
    return outbound;
  }

  /**
   * Members we have never heard a frame from (ordering-auth §8.2). A `create`
   * or `welcome` is never acknowledged, so a lost invitation shows up only as
   * silence — a member everyone's list contains and nobody has heard from. It
   * is not proof of loss: they may be quiet, or may have refused the
   * invitation, and those are indistinguishable by design. Surface it as
   * "invited, not yet joined", never as "delivery failed".
   */
  get pendingMembers(): string[] {
    // A PERSON is present as soon as ANY of their devices has been heard from —
    // people routinely carry a device that is switched off, and "some device of
    // theirs is silent" is close to always true, which would make this useless.
    // So a DID is pending only when every device it has in this conversation is
    // unheard-from. The per-device view is `pendingDevices`.
    const pendingFps = new Set(this.session.pendingMembers.map((m) => bytesToHex(m.device.fingerprint)));
    const tally = new Map<string, { total: number; pending: number }>();
    for (const m of this.session.engine.members()) {
      const t = tally.get(m.device.did) ?? { total: 0, pending: 0 };
      t.total += 1;
      if (pendingFps.has(bytesToHex(m.device.fingerprint))) t.pending += 1;
      tally.set(m.device.did, t);
    }
    return [...tally].filter(([, t]) => t.pending === t.total).map(([did]) => did);
  }

  /** Individual member devices never heard from (fingerprint hex). A device here
   *  whose owner is NOT in `pendingMembers` is a stranded device: its person is
   *  in the conversation on another device, but this one may never have received
   *  its admission material. `reinvite(did)` re-sends to exactly these. */
  get pendingDevices(): string[] {
    return this.session.pendingMembers.map((m) => bytesToHex(m.device.fingerprint));
  }

  /**
   * Re-send a member's admission material — the recovery for a lost `create` or
   * `welcome`, which nothing else repairs (repair belongs to a conversation and
   * they have none). A founding member gets the original create frame back,
   * byte for byte, because its id IS this conversation's id; a later joiner
   * gets a freshly rebuilt welcome pinned to the same add op, which lands them
   * on the group's current state rather than the state at the time of the add.
   * Harmless if they did receive it — duplicates are deduped.
   *
   * Caller-driven on purpose: doing it automatically on silence would point a
   * retry loop at exactly the person who chose not to answer. Bounded attempts
   * and honest wording ("not delivered", never "blocked") belong in the UI.
   */
  async reinvite(did: string): Promise<Outbound[]> {
    const out: Outbound[] = [];
    for (const m of this.session.pendingMembers) {
      if (m.device.did === did) out.push(...(await this.session.reinvite(m.device)));
    }
    return out;
  }

  /** Grant admin to a DID (admin-only) — the succession step a sole admin
   *  must take before it may leave. */
  async grantAdmin(did: string): Promise<Outbound[]> {
    const outbound = await this.session.grantAdmin(did);
    await this.saveConversationRecord();
    return outbound;
  }

  /** Leave this conversation (see ConversationSession.leave). */
  async leave(): Promise<Outbound[]> {
    const outbound = await this.session.leave();
    await this.saveConversationRecord();
    return outbound;
  }

  /** Would leaving now strand the group (sole admin, others remain)? */
  get wouldStrandGroup(): boolean {
    return this.session.wouldStrandGroup();
  }

  /**
   * How this device stopped being a member, or null while it still is.
   * Derived from the op log's actor — no extra wire data: a removal I authored
   * against my own device is a departure, anyone else's is a removal.
   */
  get departure(): "left" | "removed" | null {
    // A last-member departure mints no op — the engine still reports us as a
    // member — so the local mark is the only evidence and comes first.
    if (this.locallyLeft) return "left";
    if (this.amMember) return null;
    const mine = bytesToHex(this.ctx.device.fingerprint);
    let verdict: "left" | "removed" | null = null;
    for (const e of this.membershipLog()) {
      if (e.type !== "remove") continue;
      if (!e.devices.some((d) => bytesToHex(d.fingerprint) === mine)) continue;
      verdict = e.actor.did === this.ctx.did ? "left" : "removed";
    }
    return verdict ?? "removed";
  }

  /** Last-member departure: no op exists (the tree keeps its last member), so
   *  the host records it locally. */
  async markLeftLocally(): Promise<void> {
    this.locallyLeft = true;
    await this.saveConversationRecord();
  }

  /** Batched remove (strong remove, dgm §4 — cross-DID removal needs admin;
   *  the engine enforces it): every membership in ONE round + healing update. */
  async removeMembers(memberships: Membership[]): Promise<Outbound[]> {
    if (memberships.length === 0) return [];
    const outbound = await this.session.removeMembers(memberships);
    await this.saveConversationRecord();
    return outbound;
  }

  /** Deliver an inbound sealed envelope (a decrypted message lands in
   *  `messages$`); returns any triggered repair envelopes. */
  async deliverEnvelope(envelope: Uint8Array): Promise<Outbound[]> {
    return this.withMembershipSync(() => this.session.deliver(envelope));
  }

  /** Ingest an already-unsealed frame (dispatcher bootstrap path). */
  async ingestFrame(frame: Uint8Array): Promise<Outbound[]> {
    return this.withMembershipSync(() => this.session.ingestFrame(frame));
  }

  /**
   * Run an inbound step and reconcile everything membership-derived: the
   * stored roster + `removed` flag (what the UI renders), and the
   * removed-from-conversation transition.
   *
   * Both inbound paths must go through here. Membership ops arrive sym under
   * the parent epoch normally, but ASYM whenever no sealable epoch exists —
   * which is routine right after a batched add, since each joiner's mandatory
   * post-join update makes the epochs concurrent. Wiring this to the sym path
   * alone left removed devices with a stale record and no event.
   */
  private async withMembershipSync(step: () => Promise<Outbound[]>): Promise<Outbound[]> {
    const before = this.members.join(",");
    const wasMember = this.amMember;
    const outbound = await step();
    if (this.members.join(",") !== before || wasMember !== this.amMember) {
      await this.saveConversationRecord();
    }
    if (wasMember && !this.amMember) {
      this.ctx.onEngineEvent?.("removed-from-conversation", this.convoId);
    }
    return outbound;
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
    // Something arrived and opened: whatever else is failing, we are still in
    // this conversation (clears the possibly-removed suspicion).
    this.session.noteHealthy();
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
      // `removed` lets a client render the state without holding the engine
      // (and clears itself if the DID is later re-added and rejoins).
      metadata: {
        ...existing?.metadata,
        protocol: "dcgka",
        kind: this.kind,
        // Two flags, because the UI tells two different stories: `removed` is
        // "you are out", `left` is "and you chose it".
        removed: !this.amMember || this.locallyLeft,
        left: this.departure === "left",
      },
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
