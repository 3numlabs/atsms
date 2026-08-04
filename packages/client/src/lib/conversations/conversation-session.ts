/**
 * `ConversationSession` — a persisted, **sealed** `@atsms/dcgka` `Session`
 * (sdk-shape.md Part A, the stateful surface). Two layers in one wrapper:
 *
 * - persistence: state lives in the ONE `StorageAdapter` as a per-conversation
 *   engine-state blob (`Session.serialize()`), written after every op and
 *   restored verbatim by `Session.restore()`;
 * - sealing: a `SealLayer` wraps the session, so every op returns per-recipient
 *   `SealedEnvelope`s (`Outbound`: `{ to, url, envelope }`) and inbound traffic
 *   arrives as envelopes via `deliver()`. The whole protocol crosses the wire
 *   as opaque, uncorrelatable blobs (sealed-sender §1).
 *
 * Transport stays out of scope: methods return the envelopes to deliver; who
 * carries them (worker POST /inbox, SMTP fallback) is the transport layer's job.
 */

import {
  bytesToHex,
  cborDecode,
  CLS_CONTROL,
  CLS_WELCOME,
  type Csprng,
  type DeviceID,
  type Membership,
  type Outbound,
  parseFrame,
  payloadFromCbor,
  SealLayer,
  Session,
  type SessionEvents,
  ShareKeyMap,
} from "@atsms/dcgka";

import type { StorageAdapter } from "../storage/interface.js";

export type { Outbound };

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
  /** This device's live signed-prekey secrets (current + grace, D4) — what the
   *  seal layer trial-opens inbound `sealed-asym` envelopes with. */
  prekeySecrets: Uint8Array[];
  /** Seal-layer diagnostics (e.g. persistently-unopenable envelopes,
   *  concurrent-update-partition §4.3). Surfaced, never fatal. */
  onEvent?: (kind: string, detail: string) => void;
}

export class ConversationSession {
  /** Count of persistently-unopenable inbound envelopes (C-fallback signal). */
  private unopenable = 0;
  /** When inbound traffic last opened successfully. A member that is quietly
   *  out of the group stops opening ANYTHING; a healthy member with some
   *  unopenable junk keeps working. Only the difference distinguishes them. */
  private lastHealthyAt = Date.now();

  private constructor(
    readonly groupId: string,
    private readonly session: Session,
    private readonly seal: SealLayer,
    private readonly storage: StorageAdapter,
  ) {}

  /** The underlying engine — read-only inspection (members, treeHash, epochs). */
  get engine(): Session["engine"] {
    return this.session.engine;
  }

  // ── lifecycle ──────────────────────────────────────────────────────────────

  /** Found a new conversation. `members` includes this device **first** (the
   *  creator). Returns the session and the sealed create envelope(s) to deliver. */
  static async create(
    deps: ConversationDeps,
    params: {
      keys: LocalKeys;
      members: MemberDescriptor[];
      admins: string[];
      events?: SessionEvents;
      kind?: "dm" | "group";
    },
  ): Promise<{ conversation: ConversationSession; outbound: Outbound[] }> {
    const session = Session.createGroup(
      params.members,
      params.admins,
      params.keys.signingSk,
      shareKeysOf(params.keys),
      deps.rng,
      params.events ?? {},
      params.kind ?? "group",
    );
    const convo = ConversationSession.wrap(session, deps);
    const outbound = await convo.drain();
    return { conversation: convo, outbound };
  }

  /** Join an existing conversation as a founding member from its `create` frame
   *  (the dispatcher has already unsealed the bootstrap envelope). */
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
    const convo = ConversationSession.wrap(session, deps);
    await convo.persist();
    return convo;
  }

  /** Join as an added member from an (unsealed) `welcome` frame. Performs the
   *  mandatory post-join `update` (the healing rule, ordering-auth A4) — the
   *  returned envelopes carry it and MUST be delivered. */
  static async join(
    deps: ConversationDeps,
    params: { keys: LocalKeys; welcomeFrame: Uint8Array; events?: SessionEvents },
  ): Promise<{ conversation: ConversationSession; outbound: Outbound[] }> {
    const session = Session.fromWelcome(
      params.welcomeFrame,
      deps.device,
      params.keys.signingSk,
      shareKeysOf(params.keys),
      deps.rng,
      params.events ?? {},
    );
    const convo = ConversationSession.wrap(session, deps);
    session.update(); // mandatory post-join healing
    const outbound = await convo.drain();
    return { conversation: convo, outbound };
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
    return ConversationSession.wrap(session, deps);
  }

  /** GroupIDs of all persisted conversations (to reopen on startup). */
  static listIds(deps: ConversationDeps): Promise<string[]> {
    return deps.storage.listEngineStateIds();
  }

  // ── operations (return sealed envelopes to deliver; state persisted after) ──

  /** Send an application payload (the inner-ratchet plaintext of an app frame). */
  async send(plaintext: Uint8Array): Promise<Outbound[]> {
    this.session.sendApp(plaintext);
    return this.drain();
  }

  /** Add a device. The joiner's welcome is among the returned envelopes (asym,
   *  routed via the joiner's public inbox — its `url` is null). */
  async addMember(member: MemberDescriptor): Promise<Outbound[]> {
    return this.addMembers([member]);
  }

  /**
   * Batched add (add-member-flow §6): K adds, then ONE update, then K
   * welcomes — a single sealed round instead of K add→update→welcome rounds
   * (which minted K epochs and dominated live /add latency; the recorded
   * span was rounds=4, deliver 7.1 s of an 8.3 s op).
   *
   * The §4b invariant generalizes: the post-add epoch is established AFTER
   * every add (its path secrets cover all the new leaves) and BEFORE any
   * welcome, so each welcome's op log carries all K adds plus the
   * epoch-establishing update — every joiner derives the epoch on replay
   * instead of racing a heal, and existing members walk ONE epoch step.
   * Mirrors the genesis "born with an epoch" orchestration.
   */
  async addMembers(members: MemberDescriptor[]): Promise<Outbound[]> {
    if (members.length === 0) return [];
    const addOpIds = members.map((m) => this.session.add(m.device, m.leafPk, m.signingPk).addOpId);
    this.session.update();
    for (const addOpId of addOpIds) this.session.buildWelcome(addOpId);
    return this.drain();
  }

  /** Remove a member (single device). */
  async removeMember(membership: Membership): Promise<Outbound[]> {
    return this.removeMembers([membership]);
  }

  /**
   * Batched remove (mirrors addMembers): K removes, then ONE healing update,
   * one sealed round. Each remove blanks the root (strong remove — no secret
   * survives a resolution change), so the remover establishes the post-remove
   * epoch immediately; its path secrets exclude every removed leaf, which IS
   * the strong-remove guarantee. The removed devices receive nothing (the
   * seal pass fans to post-op membership) — they simply stop being able to
   * decrypt. A removal notification for the removed device's UX is a later,
   * deliberate feature, not an accident to reintroduce here.
   */
  async removeMembers(memberships: Membership[]): Promise<Outbound[]> {
    if (memberships.length === 0) return [];
    for (const m of memberships) this.session.remove(m);
    this.session.update();
    return this.drain();
  }

  /** Grant admin to a DID (admin-only, dgm §4). */
  async grantAdmin(did: string): Promise<Outbound[]> {
    this.session.grantAdmin(did);
    return this.drain();
  }

  /** Leave: remove every device of my DID, mine last, no healing update (the
   *  leaver cannot mint an epoch that excludes it — remaining members heal
   *  lazily on their next send). Throws LastAdmin / LastMember / AlreadyLeft. */
  async leave(): Promise<Outbound[]> {
    this.session.leave();
    return this.drain();
  }

  /** Would leaving now strand the group (I am the sole admin, others remain)? */
  wouldStrandGroup(): boolean {
    return this.session.wouldStrandGroup();
  }

  /** Rotate keys (post-compromise healing / mandatory post-join update). */
  async update(): Promise<Outbound[]> {
    this.session.update();
    return this.drain();
  }

  /** Deliver an inbound sealed envelope; returns any envelopes this triggers
   *  (repair traffic). Unopenable envelopes are buffered briefly by the seal
   *  layer (epoch not yet derived) or dropped. */
  async deliver(envelope: Uint8Array): Promise<Outbound[]> {
    this.seal.deliver(envelope);
    return this.drain();
  }

  /** Ingest an already-unsealed frame (dispatcher bootstrap path). */
  async ingestFrame(frame: Uint8Array): Promise<Outbound[]> {
    this.session.ingestFrame(frame);
    return this.drain();
  }

  /** Advertise this device's non-welcome delivery endpoint in-band
   *  (sealed-sender §12) — the transport's ingress URL. */
  async advertiseEndpoint(url: string): Promise<void> {
    this.session.setEndpoint(url);
    await this.persist();
  }

  /** Persistently-unopenable inbound envelopes seen by the seal layer — the
   *  C-fallback signal (nothing opening may mean we were removed and missed
   *  the notice). */
  get unopenableCount(): number {
    return this.unopenable;
  }

  /** Age (ms) of the last successfully-opened inbound traffic. */
  get sinceHealthyMs(): number {
    return Date.now() - this.lastHealthyAt;
  }

  /** Inbound traffic opened and processed — the conversation is working. */
  noteHealthy(): void {
    this.lastHealthyAt = Date.now();
    this.unopenable = 0;
  }

  /** What this conversation is — fixed by its create op, never counted. */
  get kind(): "dm" | "group" {
    return this.session.kind;
  }

  /** Am I still a member in my own view (see Session.amMember). */
  amMember(): boolean {
    return this.session.amMember();
  }

  /** Memberships we removed and still hold the removal op for (routing +
   *  identification of a device that has not learned yet). */
  removedMemberships(): Membership[] {
    return this.session.removedMemberships();
  }

  /** Membership history from the retained op log (causal order). */
  membershipLog(): ReturnType<Session["membershipLog"]> {
    return this.session.membershipLog();
  }

  /** Frames buffered awaiting missing causal ancestors (§8 gap signal). */
  get bufferedFrames(): number {
    return this.session.bufferedCount();
  }

  /** §8 repair trigger: queue a request for the current ordering gaps and seal
   *  it for delivery (deps are empty, so it seals asym to member prekeys —
   *  deliverable even mid-divergence). Empty when there is nothing to repair. */
  async requestRepair(): Promise<Outbound[]> {
    if (!this.session.requestRepair()) return [];
    return this.drain();
  }

  /** Forget the conversation (key deletion — FS depends on the store honoring it). */
  async forget(): Promise<void> {
    await this.storage.deleteEngineState(this.groupId);
  }

  // ── internals ───────────────────────────────────────────────────────────────

  private static wrap(session: Session, deps: ConversationDeps): ConversationSession {
    const holder: { convo: ConversationSession | null } = { convo: null };
    const seal = new SealLayer(session, deps.prekeySecrets, deps.rng, (kind, detail) => {
      if (kind === "unopenable-envelope" && holder.convo !== null) holder.convo.unopenable += 1;
      deps.onEvent?.(kind, detail);
    });
    const convo = new ConversationSession(bytesToHex(session.engine.groupId), session, seal, deps.storage);
    holder.convo = convo;
    return convo;
  }

  private async drain(): Promise<Outbound[]> {
    const out = this.seal.drainSealed();
    await this.persist();
    return out;
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

// ── admission-key selection (bootstrap/join helpers for the dispatcher) ───────

/**
 * Find the admission material a `create` or `welcome` frame pins for `device`,
 * and match it against the device's live key rings: the declared `leafPk`
 * against the signed-prekey secrets, the declared `signingPk` against the
 * initial-signing keypairs (identity-devices §4.2 — the admitting op may have
 * resolved either live bundle generation). Returns the exact `LocalKeys` the
 * session must boot with, or null if this frame does not admit `device` / the
 * pinned generation is no longer held.
 */
export function admissionKeysFor(
  frame: Uint8Array,
  device: DeviceID,
  prekeySecrets: Uint8Array[],
  signingKeys: Array<{ sk: Uint8Array; pk: Uint8Array }>,
  derivePublic: (prekeySk: Uint8Array) => Uint8Array,
): LocalKeys | null {
  const admission = admissionOf(frame, device);
  if (admission === null) return null;
  const leafSk = prekeySecrets.find((sk) => bytesToHex(derivePublic(sk)) === bytesToHex(admission.leafPk));
  const signing = signingKeys.find((k) => bytesToHex(k.pk) === bytesToHex(admission.signingPk));
  if (leafSk === undefined || signing === undefined) return null;
  return { signingSk: signing.sk, signingPk: signing.pk, leafPk: admission.leafPk, leafSk };
}

/** The `{ leafPk, signingPk }` a create/add/welcome frame declares for `device`, or null. */
function admissionOf(
  raw: Uint8Array,
  device: DeviceID,
): { leafPk: Uint8Array; signingPk: Uint8Array } | null {
  const frame = parseFrame(raw);
  if (frame.body.cls === CLS_WELCOME) {
    // A welcome wraps the retained frame log; the admitting add is inside it.
    // Welcome body = cbor([checkpoint, frames, deliveryMap, profile]) (A4).
    //
    // Use the add op the welcome NAMES, not the first one that mentions this
    // device: a re-added device appears twice in the log (its original add and
    // the new one), and the earlier admission pins key material a device that
    // has since re-keyed no longer holds — the welcome would be dropped and
    // the re-add would silently do nothing (live 2026-08-03).
    const [addOpId, bodyBytes] = frame.body.payload as [Uint8Array, Uint8Array];
    const frames = (cborDecode(bodyBytes) as [unknown, Uint8Array[], unknown, number])[1];
    const wanted = bytesToHex(addOpId);
    for (const inner of frames) {
      if (bytesToHex(parseFrame(inner).id) !== wanted) continue;
      return admissionOf(inner, device);
    }
    // The named op is missing (older sender, or a pruned log): fall back to the
    // LAST admission for this device — the most recent one is the live pin.
    let latest: { leafPk: Uint8Array; signingPk: Uint8Array } | null = null;
    for (const inner of frames) {
      const found = admissionOf(inner, device);
      if (found !== null) latest = found;
    }
    return latest;
  }
  if (frame.body.cls !== CLS_CONTROL) return null;
  const payload = payloadFromCbor(frame.body.payload, frame.body.sender.device.fingerprint);
  const fp = bytesToHex(device.fingerprint);
  if (payload.type === "create") {
    const mine = payload.initialDevices.find((d) => bytesToHex(d.device.fingerprint) === fp);
    if (mine !== undefined && mine.signingPk !== undefined) {
      return { leafPk: mine.leafPk, signingPk: mine.signingPk };
    }
  } else if (payload.type === "add") {
    if (bytesToHex(payload.device.fingerprint) === fp && payload.signingPk !== undefined) {
      return { leafPk: payload.leafPk, signingPk: payload.signingPk };
    }
  }
  return null;
}
