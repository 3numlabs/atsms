/**
 * `ConversationSession` — a frame-log-persisted `@atsms/dcgka` `Session`
 * (sdk-shape.md Part A, the stateful surface). It ties the pure engine to
 * durable storage: every frame the session authors or ingests is appended to the
 * {@link DcgkaSessionStore}, and a conversation is restored by replaying that log
 * (`Session.fromFrames`). Transport is out of scope — methods return the frames
 * to send; who carries them is the delivery layer's job.
 */

import {
  Session,
  ShareKeyMap,
  bytesToHex,
  type Csprng,
  type DeviceID,
  type Membership,
  type SessionEvents,
} from "@atsms/dcgka";

import type { ConversationBootstrap, DcgkaSessionStore } from "./store.js";

/** This device's key material for a conversation. */
export interface LocalMember {
  device: DeviceID;
  signingSk: Uint8Array;
  signingPk: Uint8Array;
  leafPk: Uint8Array; // = the signed prekey (D10)
  leafSk: Uint8Array;
}

/** A member being founded into / added to a conversation. */
export interface MemberDescriptor {
  device: DeviceID;
  leafPk: Uint8Array;
  signingPk: Uint8Array;
}

export interface ConversationDeps {
  store: DcgkaSessionStore;
  rng: Csprng;
}

export class ConversationSession {
  private constructor(
    readonly groupId: string,
    private readonly session: Session,
    private readonly store: DcgkaSessionStore,
  ) {}

  /** The underlying engine — read-only inspection (members, treeHash, epochs). */
  get engine(): Session["engine"] {
    return this.session.engine;
  }

  // ── lifecycle ──────────────────────────────────────────────────────────────

  /** Found a new conversation. `members` includes `me`. Returns the session and
   *  the create frame(s) to deliver (also persisted). */
  static async create(
    deps: ConversationDeps,
    params: { me: LocalMember; members: MemberDescriptor[]; admins: string[]; events?: SessionEvents },
  ): Promise<{ conversation: ConversationSession; outbound: Uint8Array[] }> {
    const sks = shareKeysOf(params.me);
    const session = Session.createGroup(
      params.members,
      params.admins,
      params.me.signingSk,
      sks,
      deps.rng,
      params.events ?? {},
    );
    const groupId = bytesToHex(session.engine.groupId);
    await deps.store.createConversation(bootstrapOf(groupId, params.me));
    const convo = new ConversationSession(groupId, session, deps.store);
    return { conversation: convo, outbound: await convo.drainPersist() };
  }

  /** Join an existing conversation as a founding member from its `create` frame. */
  static async bootstrap(
    deps: ConversationDeps,
    params: { me: LocalMember; createFrame: Uint8Array; events?: SessionEvents },
  ): Promise<ConversationSession> {
    const sks = shareKeysOf(params.me);
    const session = Session.fromFrames(
      [params.createFrame],
      params.me.device,
      params.me.signingSk,
      sks,
      deps.rng,
      params.events ?? {},
    );
    const groupId = bytesToHex(session.engine.groupId);
    await deps.store.createConversation(bootstrapOf(groupId, params.me));
    const convo = new ConversationSession(groupId, session, deps.store);
    await deps.store.appendFrames(groupId, [params.createFrame]);
    return convo;
  }

  /**
   * Restore a conversation from its persisted frame log (replay). Null if unknown.
   *
   * KNOWN LIMITATION: replay reconstructs the tree and every epoch whose secret
   * arrived encrypted in a frame, but NOT a member's own *self-authored* epoch
   * secret (a TreeKEM updater's path secret is encrypted to the others, not into
   * its own frame). Sending after a restart across a self-authored epoch needs the
   * engine's secret material (ShareKeyMap + chain positions) serialized too — a
   * pending `@atsms/dcgka` state-serialization API (atsms-integration §2).
   */
  static async restore(
    deps: ConversationDeps,
    groupId: string,
    events?: SessionEvents,
  ): Promise<ConversationSession | null> {
    const stored = await deps.store.load(groupId);
    if (stored === null) return null;
    const b = stored.bootstrap;
    const sks = new ShareKeyMap();
    sks.insert(b.leafPk, b.leafSk);
    const session = Session.fromFrames(stored.frames, b.device, b.signingSk, sks, deps.rng, events ?? {});
    return new ConversationSession(groupId, session, deps.store);
  }

  // ── operations (return frames to deliver; all persisted) ────────────────────

  /** Send an application payload (the inner-ratchet plaintext of an app frame). */
  async send(plaintext: Uint8Array): Promise<Uint8Array[]> {
    this.session.sendApp(plaintext);
    return this.drainPersist();
  }

  /** Add a device to the conversation. Returns { outbound, welcome } — the welcome
   *  bootstraps the joiner and is delivered point-to-point. */
  async addMember(
    member: MemberDescriptor,
  ): Promise<{ outbound: Uint8Array[]; welcome: Uint8Array }> {
    const { addOpId } = this.session.add(member.device, member.leafPk, member.signingPk);
    const welcome = this.session.buildWelcome(addOpId);
    return { outbound: await this.drainPersist(), welcome };
  }

  /** Remove a member from the conversation. */
  async removeMember(membership: Membership): Promise<Uint8Array[]> {
    this.session.remove(membership);
    return this.drainPersist();
  }

  /** Rotate keys (post-compromise healing / mandatory post-join update). */
  async update(): Promise<Uint8Array[]> {
    this.session.update();
    return this.drainPersist();
  }

  /** Ingest an inbound frame; returns any frames this triggers (repair/coverage). */
  async ingest(raw: Uint8Array): Promise<Uint8Array[]> {
    this.session.ingestFrame(raw);
    await this.store.appendFrames(this.groupId, [raw]);
    return this.drainPersist();
  }

  // ── internals ───────────────────────────────────────────────────────────────

  /** Drain the session outbox, persist the frames, and return them for delivery. */
  private async drainPersist(): Promise<Uint8Array[]> {
    const frames = this.session.takeOutbox();
    if (frames.length > 0) await this.store.appendFrames(this.groupId, frames);
    return frames;
  }
}

function shareKeysOf(me: LocalMember): ShareKeyMap {
  const sks = new ShareKeyMap();
  sks.insert(me.leafPk, me.leafSk);
  return sks;
}

function bootstrapOf(groupId: string, me: LocalMember): ConversationBootstrap {
  return { groupId, device: me.device, signingSk: me.signingSk, leafPk: me.leafPk, leafSk: me.leafSk };
}
