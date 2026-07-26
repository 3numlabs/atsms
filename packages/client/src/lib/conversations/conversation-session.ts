/**
 * `ConversationSession` — a persisted `@atsms/dcgka` `Session` (sdk-shape.md
 * Part A, the stateful surface). State lives in the ONE `StorageAdapter` as a
 * per-conversation engine-state blob (`Session.serialize()`), written after every
 * op and restored verbatim by `Session.restore()`. Transport is out of scope:
 * methods return the frames to send; delivery is a separate layer.
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

import type { StorageAdapter } from "../storage/interface.js";

/** This device's key material for founding/joining a conversation. */
export interface LocalKeys {
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
  storage: StorageAdapter;
  rng: Csprng;
  /** This device's identity — the local member across all conversations. */
  device: DeviceID;
}

export class ConversationSession {
  private constructor(
    readonly groupId: string,
    private readonly session: Session,
    private readonly storage: StorageAdapter,
  ) {}

  /** The underlying engine — read-only inspection (members, treeHash, epochs). */
  get engine(): Session["engine"] {
    return this.session.engine;
  }

  // ── lifecycle ──────────────────────────────────────────────────────────────

  /** Found a new conversation. `members` includes this device. Returns the session
   *  and the create frame(s) to deliver (state is persisted). */
  static async create(
    deps: ConversationDeps,
    params: { keys: LocalKeys; members: MemberDescriptor[]; admins: string[]; events?: SessionEvents },
  ): Promise<{ conversation: ConversationSession; outbound: Uint8Array[] }> {
    const session = Session.createGroup(
      params.members,
      params.admins,
      params.keys.signingSk,
      shareKeysOf(params.keys),
      deps.rng,
      params.events ?? {},
    );
    const convo = new ConversationSession(bytesToHex(session.engine.groupId), session, deps.storage);
    const outbound = session.takeOutbox();
    await convo.persist();
    return { conversation: convo, outbound };
  }

  /** Join an existing conversation as a founding member from its `create` frame. */
  static async bootstrap(
    deps: ConversationDeps,
    params: { keys: LocalKeys; createFrame: Uint8Array; events?: SessionEvents },
  ): Promise<ConversationSession> {
    const session = Session.fromFrames(
      [params.createFrame],
      deps.device,
      params.keys.signingSk,
      shareKeysOf(params.keys),
      deps.rng,
      params.events ?? {},
    );
    const convo = new ConversationSession(bytesToHex(session.engine.groupId), session, deps.storage);
    await convo.persist();
    return convo;
  }

  /** Restore a conversation from its persisted engine-state blob. Null if unknown. */
  static async restore(
    deps: ConversationDeps,
    groupId: string,
    events?: SessionEvents,
  ): Promise<ConversationSession | null> {
    const blob = await deps.storage.loadEngineState(groupId);
    if (blob === null) return null;
    const session = Session.restore(blob, { device: deps.device, rng: deps.rng, events });
    return new ConversationSession(groupId, session, deps.storage);
  }

  /** GroupIDs of all persisted conversations (to reopen on startup). */
  static listIds(deps: ConversationDeps): Promise<string[]> {
    return deps.storage.listEngineStateIds();
  }

  // ── operations (return frames to deliver; state persisted after each) ───────

  /** Send an application payload (the inner-ratchet plaintext of an app frame). */
  async send(plaintext: Uint8Array): Promise<Uint8Array[]> {
    this.session.sendApp(plaintext);
    return this.drain();
  }

  /** Add a device. Returns { outbound, welcome } — the welcome bootstraps the joiner. */
  async addMember(member: MemberDescriptor): Promise<{ outbound: Uint8Array[]; welcome: Uint8Array }> {
    const { addOpId } = this.session.add(member.device, member.leafPk, member.signingPk);
    const welcome = this.session.buildWelcome(addOpId);
    return { outbound: await this.drain(), welcome };
  }

  /** Remove a member. */
  async removeMember(membership: Membership): Promise<Uint8Array[]> {
    this.session.remove(membership);
    return this.drain();
  }

  /** Rotate keys (post-compromise healing / mandatory post-join update). */
  async update(): Promise<Uint8Array[]> {
    this.session.update();
    return this.drain();
  }

  /** Ingest an inbound frame; returns any frames this triggers (repair/coverage). */
  async ingest(raw: Uint8Array): Promise<Uint8Array[]> {
    this.session.ingestFrame(raw);
    return this.drain();
  }

  /** Forget the conversation (key deletion — FS depends on the store honoring it). */
  async forget(): Promise<void> {
    await this.storage.deleteEngineState(this.groupId);
  }

  // ── internals ───────────────────────────────────────────────────────────────

  private async drain(): Promise<Uint8Array[]> {
    const frames = this.session.takeOutbox();
    await this.persist();
    return frames;
  }

  /** Full engine-state snapshot → the one store (encrypted at rest by that layer). */
  private async persist(): Promise<void> {
    await this.storage.saveEngineState(this.groupId, this.session.serialize());
  }
}

function shareKeysOf(keys: LocalKeys): ShareKeyMap {
  const sks = new ShareKeyMap();
  sks.insert(keys.leafPk, keys.leafSk);
  return sks;
}
