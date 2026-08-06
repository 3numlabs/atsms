/**
 * Ordering & authentication session (ordering-auth.md v0.2): wraps the Engine
 * with signed frames, signing-key rotation (A1/§5), control-plane FIFO (A2),
 * causal readiness + bounded buffering (A3/§4), welcome-first (A4/§4.2),
 * MessageID dedup (A5/§6), membership gating via the DGM filter (A6), and
 * end-to-end repair (§8). Frame MessageIDs ARE the engine's op IDs (the
 * minter seam — ordering-auth §2).
 *
 * Timers (T_REPAIR, T_COVER, staleness) are the host's: the session exposes
 * data (`buildRepairRequest`, `takeOutbox`), it never schedules.
 */

import { bytesEqual, bytesToHex } from './bytes.js';
import { cborDecode, cborEncode, type CborValue } from './cbor.js';
import { decodeExt, encodeExt, type FrameExt } from './ext.js';
import { Engine, type AppMessage } from './engine.js';
import {
  CLS_APP,
  CLS_CONTROL,
  CLS_REPAIR,
  CLS_WELCOME,
  encodeFrameBody,
  generateSigningKeypair,
  messageIdOf,
  parseFrame,
  signFrame,
  verifyFrameSig,
  type ParsedFrame,
} from './frames.js';
import { ZERO32, membershipKey, type DeviceID, type Membership } from './ids.js';
import type { Csprng } from './keyhive.js';
import { ShareKeyMap } from './keys.js';
import {
  OP_TYPE_NUM,
  payloadFromCbor,
  payloadToCbor,
  type Op,
  type OpPayload,
} from './ops.js';

export const MAX_BUFFERED_PER_SENDER = 200;
export const MAX_BUFFERED_TOTAL = 2000;

interface RetainedMeta {
  raw: Uint8Array;
  senderKey: string;
  seq: number;
  ctrlSeq: number | null;
}

interface SenderState {
  lastSeq: number; // highest processed seq (-1 initially)
  lastCtrlSeq: number; // highest processed ctrlSeq (-1 initially)
  /** rotation table: sorted by fromSeq ascending; pruned to the live tail. */
  keys: Array<{ fromSeq: number; pk: Uint8Array }>;
}

export interface SessionEvents {
  onAppMessage?: (plaintext: Uint8Array, sender: Membership) => void;
  /** Sound security events only (bad-signature, root-commit-mismatch). */
  onSecurityEvent?: (kind: string, detail: string) => void;
  /**
   * Soft consistency-digest disagreement (dgm §8) — informational, NOT proof of
   * equivocation (can be transient mid-reconciliation). A confirmed detector is
   * deferred; sound defenses are rootCommit + signatures.
   */
  onDigestMismatch?: (frameId: string) => void;
  onDropped?: (reason: string, id: Uint8Array) => void;
}

export class Session {
  readonly engine: Engine;
  private groupIdHex: string;
  private signing: { sk: Uint8Array; pk: Uint8Array };
  private seq = 0;
  private ctrlSeq = 0;
  private senders = new Map<string, SenderState>();
  private processed = new Set<string>();
  private retained = new Map<string, RetainedMeta>();
  private retainedOrder: string[] = [];
  private buffer = new Map<string, ParsedFrame[]>();
  private bufferedTotal = 0;
  private outbox: Uint8Array[] = [];
  private pendingLocal: { raw: Uint8Array; idHex: string; meta: RetainedMeta } | null = null;
  /** Op id that established my current protocol signing key (ordering-auth §5). */
  private myKeyOpId: Uint8Array;
  /** In-band non-welcome delivery endpoint advert (sealed-sender §12). */
  private myEndpoint: string | null = null;
  private endpointDirty = false;
  /** device fingerprint hex → last-writer-wins {url, seq} learned from peers' ext. */
  private peerEndpoints = new Map<string, { url: string; seq: number }>();
  /** device fingerprint hex → app frames dropped from that non-member, driving
   *  the removal re-notice cadence (a device that keeps talking never got it). */
  private nonMemberDrops = new Map<string, number>();
  /** Membership keys we have ever processed a frame from (§8.2). A member we
   *  have never heard from may simply be quiet — but it is also the only shape
   *  a lost `create`/`welcome` takes, since neither is acknowledged. Rebuilt on
   *  restore, because restoring replays the retained log through `processFrame`. */
  private heardFrom = new Set<string>();

  private constructor(
    engine: Engine,
    signing: { sk: Uint8Array; pk: Uint8Array },
    private rng: Csprng,
    private events: SessionEvents,
    counters: { seq: number; ctrlSeq: number },
  ) {
    this.engine = engine;
    this.signing = signing;
    this.groupIdHex = bytesToHex(engine.groupId);
    this.seq = counters.seq;
    this.ctrlSeq = counters.ctrlSeq;
    this.myKeyOpId = engine.groupId; // initial key announced in the create; superseded on first rotation
  }

  // ── construction ──────────────────────────────────────────────────────────

  /** Found a group. Every founding device's initial signing pk rides in the create payload. */
  static createGroup(
    devices: Array<{ device: DeviceID; leafPk: Uint8Array; signingPk: Uint8Array }>,
    initialAdmins: string[],
    mySigningSk: Uint8Array,
    sks: ShareKeyMap,
    rng: Csprng,
    events: SessionEvents = {},
    kind: 'dm' | 'group' = 'group',
  ): Session {
    const holder: { s: Session | null } = { s: null };
    const boot = {
      signing: { sk: mySigningSk, pk: devices[0]!.signingPk },
      seq: 0,
      ctrlSeq: 0,
      frames: [] as Array<{ raw: Uint8Array; idHex: string; meta: RetainedMeta }>,
    };
    const minter = (author: Membership, deps: Uint8Array[], payload: OpPayload): Uint8Array => {
      const s = holder.s;
      if (s !== null) return s.mintControl(author, deps, payload);
      // Bootstrap mint (the create op, before the Session object exists).
      return mintControlRaw(boot, ZERO32, author, deps, payload, rng, boot.frames);
    };
    const engine = Engine.create(devices, initialAdmins, sks, rng, minter, kind);
    const session = new Session(engine, boot.signing, rng, events, {
      seq: boot.seq,
      ctrlSeq: boot.ctrlSeq,
    });
    holder.s = session;
    for (const f of boot.frames) session.commitLocal(f);
    return session;
  }

  /** Bootstrap from a frame log beginning with the create frame (founding members). */
  static fromFrames(
    frames: Uint8Array[],
    myDevice: DeviceID,
    mySigningSk: Uint8Array,
    sks: ShareKeyMap,
    rng: Csprng,
    events: SessionEvents = {},
  ): Session {
    const [createRaw, ...rest] = frames;
    if (createRaw === undefined) throw new Error('empty frame log');
    const create = parseFrame(createRaw);
    if (create.body.cls !== CLS_CONTROL) throw new Error('first frame must be the create');
    const payload = payloadFromCbor(create.body.payload, create.body.sender.device.fingerprint);
    if (payload.type !== 'create') throw new Error('first frame must be the create');
    // Verify the create against the creator's declared initial signing key.
    const creator = payload.initialDevices[0]!;
    if (!verifyFrameSig(create.bodyBytes, create.sig, creator.signingPk ?? ZERO32)) {
      throw new Error('create frame signature invalid');
    }
    const createOp: Op = {
      id: create.id,
      author: create.body.sender,
      deps: create.body.deps,
      payload,
    };
    const holder: { s: Session | null } = { s: null };
    const minter = (author: Membership, deps: Uint8Array[], p: OpPayload): Uint8Array => {
      if (holder.s === null) throw new Error('minter used before session ready');
      return holder.s.mintControl(author, deps, p);
    };
    const engine = Engine.fromOpLog([createOp], myDevice, sks, rng, minter);
    const mySigningPk =
      payload.initialDevices.find((d) => bytesEqual(d.device.fingerprint, myDevice.fingerprint))
        ?.signingPk ?? generateSigningKeypair(rng).pk;
    const session = new Session(engine, { sk: mySigningSk, pk: mySigningPk }, rng, events, {
      seq: 0,
      ctrlSeq: 0,
    });
    holder.s = session;
    session.learnFromControl(create, payload);
    session.markProcessed(create);
    for (const raw of rest) session.ingestFrame(raw);
    return session;
  }

  /** Joiner path (A4): process the welcome's frame log, then the caller MUST update (healing rule). */
  static fromWelcome(
    welcomeRaw: Uint8Array,
    myDevice: DeviceID,
    mySigningSk: Uint8Array,
    sks: ShareKeyMap,
    rng: Csprng,
    events: SessionEvents = {},
  ): Session {
    const welcome = parseFrame(welcomeRaw);
    if (welcome.body.cls !== CLS_WELCOME) throw new Error('not a welcome frame');
    const [addOpId, bodyBytes] = welcome.body.payload as [Uint8Array, Uint8Array];
    const decoded = cborDecodeWelcomeBody(bodyBytes);
    const session = Session.fromFrames(decoded.frames, myDevice, mySigningSk, sks, rng, events);
    // The admitting add op must be present and DGM-valid.
    if (!session.engine.isValidOp(addOpId)) throw new Error('welcome: admitting add op invalid or missing');
    // Verify the welcome frame itself against the adder's (post-log) key table.
    const st = session.senders.get(membershipKey(welcome.body.sender));
    const pk = st === undefined ? null : keyForSeq(st, welcome.body.seq);
    if (pk === null || !verifyFrameSig(welcome.bodyBytes, welcome.sig, pk)) {
      throw new Error('welcome frame signature invalid');
    }
    session.engine.settle();
    return session;
  }

  /** Build the welcome for a just-added device (call right after `add()`). */
  buildWelcome(addOpId: Uint8Array): Uint8Array {
    // ONLY control frames: the joiner rebuilds group state from the op log.
    // Previously this shipped the entire retained log — including app frames
    // it cannot decrypt and, fatally, previous WELCOME frames, each of which
    // embeds the log as it stood. Welcomes nesting welcomes made the body
    // grow multiplicatively: a second add round on a 3-device DID produced a
    // 104 KB plaintext and blew the 64 KiB seal bucket, so re-adding anyone
    // failed outright (live, 2026-08-03).
    const frames: Uint8Array[] = [];
    for (const k of this.retainedOrder) {
      const meta = this.retained.get(k);
      if (meta === undefined) continue;
      if (parseFrame(meta.raw).body.cls !== CLS_CONTROL) continue;
      frames.push(meta.raw);
    }
    const welcomeBody = cborEncode([null, frames, [], 1]); // [checkpoint, ops, deliveryMap, profile]
    // ctrlSeq null: the welcome is point-to-point (sealed asym to the joiner
    // only — existing members never receive it), so it must not occupy a slot
    // in this sender's broadcast ctrlSeq contiguity chain. A numbered welcome
    // leaves a permanent gap at every existing member: `ready()` buffers all
    // subsequent control frames forever (live add-flow partition, 2026-08-02).
    // Like CLS_APP/CLS_REPAIR it still consumes `seq` (order-exempt lane), and
    // the joiner verifies it by seq via keyForSeq — no contiguity needed.
    return this.buildFrame(CLS_WELCOME, null, [addOpId], [addOpId, welcomeBody], new Uint8Array(0));
  }

  // ── state serialization (host persistence, atsms-integration §2) ────────────
  //
  // The complete durable state, so a restart restores verbatim (no lossy replay):
  // the frame log rebuilds the public state (tree/ops/dgm/receiver chains/signing-
  // key table), and the *secret + counter* state a replay cannot reconstruct is
  // carried explicitly — the ShareKeyMap (self-authored path secrets), each
  // epoch's SenderChain position (a reset one would reuse nonces), and my
  // authoring counters. The signing key + rng + events are injected on restore.

  /** Serialize the session to an opaque blob (the host persists it, encrypted). */
  serialize(): Uint8Array {
    const snapshot: CborValue = [
      1, // version
      this.retainedOrder.map((k) => this.retained.get(k)!.raw),
      this.engine.sks.entries().map((e) => [e.pk, e.sk]),
      this.engine.exportSenderChains().map((c) => [c.epochId, c.ck, c.generation]),
      this.engine.currentEpoch(), // hex string | null
      this.seq,
      this.ctrlSeq,
      this.myEndpoint,
      // The PROTOCOL signing key rotates on every control op (§5) — the current
      // secret + the op that announced it are state, not derivable from the log.
      this.signing.sk,
      this.signing.pk,
      this.myKeyOpId,
    ];
    return cborEncode(snapshot);
  }

  /** Restore a session from `serialize()` output. `rng`/`events` are injected
   *  (behavior, not persisted state); `device` identifies the local member. */
  static restore(
    bytes: Uint8Array,
    ctx: { device: DeviceID; rng: Csprng; events?: SessionEvents },
  ): Session {
    const arr = cborDecode(bytes) as CborValue[];
    const version = arr[0] as number;
    if (version !== 1) throw new Error(`unknown session snapshot version ${version}`);
    const frames = arr[1] as Uint8Array[];
    const sksEntries = arr[2] as Array<[Uint8Array, Uint8Array]>;
    const senderChains = arr[3] as Array<[string, Uint8Array, number]>;
    const currentEpochId = arr[4] as string | null;
    const seq = arr[5] as number;
    const ctrlSeq = arr[6] as number;
    const myEndpoint = arr[7] as string | null;
    const signingSk = arr[8] as Uint8Array;
    const signingPk = arr[9] as Uint8Array;
    const myKeyOpId = arr[10] as Uint8Array;

    const sks = new ShareKeyMap();
    for (const [pk, sk] of sksEntries) sks.insert(pk, sk);

    // Rebuild the public state from the log with the FULL secret material, so even
    // self-authored epochs derive. (fromFrames sets the signing key to the create's
    // initial one; override with the current, rotated key below.)
    const session = Session.fromFrames(frames, ctx.device, signingSk, sks, ctx.rng, ctx.events ?? {});

    session.signing = { sk: signingSk, pk: signingPk };
    session.myKeyOpId = myKeyOpId;
    session.engine.importSenderChains(
      senderChains.map(([epochId, ck, generation]) => ({ epochId, ck, generation })),
    );
    session.engine.setCurrentEpoch(currentEpochId);
    session.seq = seq;
    session.ctrlSeq = ctrlSeq;
    session.myEndpoint = myEndpoint;
    return session;
  }

  // ── local operations (returned bytes are also queued on the outbox) ───────

  update(): Uint8Array {
    this.engine.buildUpdate();
    return this.finalizeLocal();
  }

  add(device: DeviceID, leafPk: Uint8Array, signingPk: Uint8Array): { frame: Uint8Array; addOpId: Uint8Array } {
    const op = this.engine.buildAdd(device, leafPk, signingPk);
    return { frame: this.finalizeLocal(), addOpId: op.id };
  }

  remove(membership: Membership): Uint8Array {
    this.engine.buildRemove(membership);
    return this.finalizeLocal();
  }

  /** Grant admin to a DID (admin-only, dgm §4) — the succession step a sole
   *  admin must take before it is allowed to leave. */
  grantAdmin(did: string): Uint8Array {
    this.engine.buildGrantAdmin(did);
    return this.finalizeLocal();
  }

  /** True iff I am the only admin DID and someone else is still here — the
   *  state in which leaving would freeze the group (nobody could ever add or
   *  remove again), so `leave()` refuses. */
  wouldStrandGroup(): boolean {
    const me = this.engine.me.device.did;
    const others = new Set(
      this.engine.members().filter((m) => m.device.did !== me).map((m) => m.device.did),
    );
    if (others.size === 0) return false; // last one out — nothing to strand
    const admins = this.engine.admins();
    return admins.has(me) && [...admins].every((a) => a === me);
  }

  /**
   * Leave: remove every device of MY DID, my authoring device LAST.
   *
   * Order is load-bearing. An op authored by an already-removed member is
   * invalid (dgm SR1), so my own removal must be the last op I ever author
   * here. Same-DID removal needs no admin (dgm §4 gates cross-DID only), so
   * leaving is always available — except to a sole admin with others still in
   * the group, who must appoint a successor first or the group freezes.
   *
   * There is deliberately NO healing update: the post-leave epoch must exclude
   * me, so minting it is structurally not my job. The remaining members heal
   * lazily — the next one to send hits the rootless state and updates, which
   * is exactly the existing self-heal path. A silent group stays unhealed and
   * loses nothing, because nothing is being encrypted in it.
   */
  leave(): Uint8Array[] {
    if (!this.amMember()) throw new Error('AlreadyLeft: not a member of this conversation');
    if (this.kind === 'dm') {
      // Signal semantics: you do not leave a direct conversation, you delete
      // it. Checked before the admin rules, which have nothing to say here.
      throw new Error('DirectConversation: a DM cannot be left — delete it locally instead');
    }
    if (this.engine.members().length === 1) {
      // The tree keeps at least one member (tree.ts RemoveLastMember), and
      // rightly: an empty group has no one to notify and nothing to heal.
      // Leaving as the last member is therefore a purely LOCAL act — the host
      // marks it left and may forget the state; no ops are produced.
      throw new Error('LastMember: nothing to leave — forget the conversation instead');
    }
    if (this.wouldStrandGroup()) {
      throw new Error(
        'LastAdmin: appoint another admin before leaving (grantAdmin) — otherwise nobody could add or remove members',
      );
    }
    const me = this.engine.me;
    const mine = this.engine.members().filter((m) => m.device.did === me.device.did);
    const others = mine.filter((m) => !bytesEqual(m.device.fingerprint, me.device.fingerprint));
    const self = mine.filter((m) => bytesEqual(m.device.fingerprint, me.device.fingerprint));
    return [...others, ...self].map((m) => this.remove(m));
  }

  coverage(): Uint8Array {
    this.engine.buildCoverage();
    return this.finalizeLocal();
  }

  sendApp(plaintext: Uint8Array): Uint8Array {
    const msg = this.engine.sendApp(plaintext);
    const payload: CborValue = [msg.generation, msg.ct];
    // Depend on the epoch anchor AND the op that established my signing key, so
    // a receiver never verifies this frame before it knows my current key
    // (ordering-auth §5 — app frames are FIFO-exempt but key-continuity is not).
    const deps = [msg.epochId];
    if (!bytesEqual(this.myKeyOpId, msg.epochId)) deps.push(this.myKeyOpId);
    return this.buildFrame(CLS_APP, null, deps, payload, new Uint8Array(0));
  }

  takeOutbox(): Uint8Array[] {
    const out = this.outbox;
    this.outbox = [];
    return out;
  }

  // ── ingestion ─────────────────────────────────────────────────────────────

  ingestFrame(raw: Uint8Array): void {
    const frame = parseFrame(raw);
    // Repair requests are unauthenticated, idempotent service requests (§8, D5
    // anonymous-ingress spirit): serve from retained frames, never buffer/track.
    if (frame.body.cls === CLS_REPAIR) {
      for (const resend of this.serveRepair(raw)) this.outbox.push(resend);
      return;
    }
    const idHex = bytesToHex(frame.id);
    if (this.processed.has(idHex)) return; // A5 dedup
    if (frame.body.cls !== CLS_CONTROL || !isCreatePayload(frame.body.payload)) {
      if (bytesToHex(frame.body.groupId) !== this.groupIdHex) {
        this.events.onDropped?.('wrong-group', frame.id);
        return;
      }
    }
    if (this.ready(frame)) {
      this.processFrame(frame);
      this.drain();
    } else {
      this.bufferFrame(frame);
    }
  }

  /**
   * Self-healing removal notice: a device still sending app frames at us has
   * not processed its own removal (its notice was lost, or it was offline past
   * mailbox retention). Re-queue the removal op — the seal pass addresses it to
   * the removed device as well as the members, and A5 dedup makes the members'
   * copies free. Cadence, not a timer (the session never schedules): the first
   * drop, then every eighth — enough to converge, bounded under a flood.
   */
  private renotifyRemoved(device: DeviceID): void {
    const fp = bytesToHex(device.fingerprint);
    const n = (this.nonMemberDrops.get(fp) ?? 0) + 1;
    this.nonMemberDrops.set(fp, n);
    if (n !== 1 && n % 8 !== 0) return;
    const raw = this.removeFrameFor(device);
    if (raw !== null) this.outbox.push(raw);
  }

  /** Memberships we have removed and still hold the removal op for — the seal
   *  layer keeps identification-only receive tags for these so a device that
   *  never got its notice can be recognized (and re-notified) without its
   *  content ever being accepted. Bounded by frame retention. */
  removedMemberships(): Membership[] {
    const out: Membership[] = [];
    for (const idHex of this.retainedOrder) {
      const meta = this.retained.get(idHex);
      if (meta === undefined) continue;
      const frame = parseFrame(meta.raw);
      if (frame.body.cls !== CLS_CONTROL) continue;
      try {
        const payload = payloadFromCbor(frame.body.payload, frame.body.sender.device.fingerprint);
        if (payload.type === 'remove' && !this.engine.isMemberDevice(payload.membership.device)) {
          out.push(payload.membership);
        }
      } catch {
        /* not a decodable control payload — skip */
      }
    }
    return out;
  }

  /** Re-queue the removal op for a device still talking to us (§ self-heal).
   *  Public for the seal layer, which recognizes such traffic by its
   *  identification-only tags. */
  renotifyRemovedDevice(device: DeviceID): void {
    this.renotifyRemoved(device);
  }

  /** The retained removal frame that removed `device`, if we still hold it. */
  private removeFrameFor(device: DeviceID): Uint8Array | null {
    for (const idHex of this.retainedOrder) {
      const meta = this.retained.get(idHex);
      if (meta === undefined) continue;
      const frame = parseFrame(meta.raw);
      if (frame.body.cls !== CLS_CONTROL) continue;
      try {
        const payload = payloadFromCbor(frame.body.payload, frame.body.sender.device.fingerprint);
        if (
          payload.type === 'remove' &&
          payload.membership.device.did === device.did &&
          bytesEqual(payload.membership.device.fingerprint, device.fingerprint)
        ) {
          return meta.raw;
        }
      } catch {
        /* not a decodable control payload — skip */
      }
    }
    return null;
  }

  /** What this conversation is — fixed by its create op (see OpPayload.kind). */
  get kind(): 'dm' | 'group' {
    return this.engine.kind;
  }

  /** Am I still a member in my own view? False once I process my own removal
   *  (the removal op is sealed to me — sealed-sender: the removed device is a
   *  recipient of the frame that removes it). A client MUST stop sending. */
  amMember(): boolean {
    return this.engine.isMemberDevice(this.engine.me.device);
  }

  /**
   * Membership history in causal order, derived from the retained frame log —
   * who admitted/removed whom. Frames carry no wall clock (deliberate), so the
   * order is causal, not temporal; a UI wanting timestamps must record its own
   * observation time. Bounded by retention (covered-by-all / 30 d).
   */
  membershipLog(): Array<{
    opId: string;
    type: 'create' | 'add' | 'remove';
    actor: DeviceID;
    devices: DeviceID[];
  }> {
    const out: Array<{ opId: string; type: 'create' | 'add' | 'remove'; actor: DeviceID; devices: DeviceID[] }> = [];
    for (const idHex of this.retainedOrder) {
      const meta = this.retained.get(idHex);
      if (meta === undefined) continue;
      const frame = parseFrame(meta.raw);
      if (frame.body.cls !== CLS_CONTROL) continue;
      let payload: OpPayload;
      try {
        payload = payloadFromCbor(frame.body.payload, frame.body.sender.device.fingerprint);
      } catch {
        continue;
      }
      const actor = frame.body.sender.device;
      if (payload.type === 'create') {
        out.push({ opId: idHex, type: 'create', actor, devices: payload.initialDevices.map((d) => d.device) });
      } else if (payload.type === 'add') {
        out.push({ opId: idHex, type: 'add', actor, devices: [payload.device] });
      } else if (payload.type === 'remove') {
        out.push({ opId: idHex, type: 'remove', actor, devices: [payload.membership.device] });
      }
    }
    return out;
  }

  /**
   * §8.2: members admitted in our view that we have never processed a frame
   * from. Neither a `create` nor a `welcome` is acknowledged — by design, since
   * security properties attach to processing, not to acks — so silence is the
   * ONLY shape a lost invitation takes. It is not proof: a member may simply be
   * quiet, or may have refused the invitation, and those are deliberately
   * indistinguishable. Treat it as the input to a human decision, never as an
   * automatic trigger.
   */
  pendingMembers(): Membership[] {
    const meKey = membershipKey(this.engine.me);
    return this.engine
      .members()
      .filter((m) => membershipKey(m) !== meKey && !this.heardFrom.has(membershipKey(m)));
  }

  /** The retained `create` frame — the group's genesis, byte-identical for the
   *  lifetime of the group (its id IS the group id, so a resend must never be a
   *  rebuild). Null only if we joined by welcome and it fell out of retention. */
  createFrame(): Uint8Array | null {
    for (const idHex of this.retainedOrder) {
      const meta = this.retained.get(idHex);
      if (meta === undefined) continue;
      const frame = parseFrame(meta.raw);
      if (frame.body.cls === CLS_CONTROL && isCreatePayload(frame.body.payload)) return meta.raw;
    }
    return null;
  }

  /**
   * §8.2: re-send a member's admission material — the answer to a lost `create`
   * or `welcome`, which no other mechanism recovers (repair belongs to a
   * conversation, and the recipient has none).
   *
   * The two differ, and the difference is forced by what the material IS:
   * - a **founding** member is admitted by the `create` itself, whose id is the
   *   group id, so we re-send that exact frame — authoring a second one would
   *   found a second group;
   * - a **later** joiner gets a freshly built welcome pinned to the SAME add op
   *   that admitted it (`admittedBy`), because a welcome is a state snapshot
   *   with no dependents: rebuilding costs nothing and hands them the group as
   *   it stands now rather than as it stood at the add.
   *
   * Any member can do this, not only the original adder: a welcome body is just
   * the retained control frames, the joiner's entitlement comes from the add op
   * it opens with its own prekey secret, and the joiner verifies the welcome
   * against the rebuilder's key history carried in that same log.
   *
   * Queues on the outbox for the host's normal seal/route pass. Returns false if
   * the device is not a current member, or if the material is unavailable (a
   * create that fell out of retention). Idempotent at the receiver: a member
   * that already holds this material dedups it (A5).
   *
   * NOT recovery for a device whose prekey has rotated past its grace window —
   * the add op pinned its leaf key to the prekey of the day, so it can no longer
   * derive its leaf secret whatever we seal to. That case needs a fresh add.
   *
   * Returns the queued frame (so the seal layer can address it) or null.
   */
  reinvite(device: DeviceID): Uint8Array | null {
    const member = this.engine
      .members()
      .find(
        (m) => m.device.did === device.did && bytesEqual(m.device.fingerprint, device.fingerprint),
      );
    if (member === undefined) return null;
    if (!bytesEqual(member.admittedBy, this.engine.groupId)) {
      return this.buildWelcome(member.admittedBy); // authors + queues it
    }
    const raw = this.createFrame();
    if (raw === null) return null;
    this.outbox.push(raw); // the original frame, re-queued verbatim
    return raw;
  }

  /** §8: repair request covering current gaps (unresolved deps + ctrlSeq holes). */
  buildRepairRequest(): Uint8Array | null {
    const missingIds: Uint8Array[] = [];
    const ranges: CborValue[] = [];
    for (const [senderKey, frames] of this.buffer) {
      const st = this.senders.get(senderKey);
      for (const f of frames) {
        for (const dep of f.body.deps) {
          if (!this.processed.has(bytesToHex(dep))) missingIds.push(dep);
        }
        if (f.body.ctrlSeq !== null && st !== undefined && f.body.ctrlSeq > st.lastCtrlSeq + 1) {
          ranges.push([
            [[f.body.sender.device.did, f.body.sender.device.fingerprint], f.body.sender.admittedBy],
            st.lastCtrlSeq + 1,
            f.body.ctrlSeq - 1,
          ]);
        }
      }
    }
    if (missingIds.length === 0 && ranges.length === 0) return null;
    const payload: CborValue = [missingIds.length > 0 ? 2 : 1, ranges, missingIds];
    // Repair requests do not consume a seq or enter our processed/outbox state —
    // they are transient, unauthenticated queries (served via ingestFrame above).
    const body = encodeFrameBody({
      version: 1,
      groupId: this.engine.groupId,
      sender: this.engine.me,
      seq: this.seq,
      ctrlSeq: null,
      deps: [],
      cls: CLS_REPAIR,
      payload,
      ext: new Uint8Array(0),
    });
    return signFrame(body, this.signing.sk);
  }

  /**
   * §8 trigger surface: build the repair request for current gaps and queue it
   * on the outbox so the host's normal seal/route pass delivers it (the session
   * computes repair data but never schedules — the HOST decides when, per
   * `T_REPAIR`). Returns false when there is nothing to repair. Responses are
   * served automatically by `ingestFrame` (CLS_REPAIR) on whichever member
   * receives the request, and A5 dedup makes duplicate serves harmless.
   */
  requestRepair(): boolean {
    const req = this.buildRepairRequest();
    if (req === null) return false;
    this.outbox.push(req);
    return true;
  }

  /** §8: serve a repair request from retained frames (responses are re-deliveries). */
  serveRepair(requestRaw: Uint8Array): Uint8Array[] {
    const req = parseFrame(requestRaw);
    if (req.body.cls !== CLS_REPAIR) throw new Error('not a repair frame');
    const [, ranges, ids] = req.body.payload as [number, CborValue[], Uint8Array[]];
    const out: Uint8Array[] = [];
    const seen = new Set<string>();
    const emit = (idHex: string, raw: Uint8Array) => {
      if (!seen.has(idHex)) {
        seen.add(idHex);
        out.push(raw);
      }
    };
    for (const id of ids) {
      const idHex = bytesToHex(id);
      const meta = this.retained.get(idHex);
      if (meta !== undefined) emit(idHex, meta.raw);
    }
    // ctrlSeq-gap ranges: the missing frame is not a dep of the buffered frame,
    // so it can only be recovered by (sender, ctrlSeq) match — the ID is unknown
    // to the requester precisely because the frame is missing.
    for (const r of ranges) {
      const [senderCbor, from, to] = r as [CborValue, number, number];
      const [[did, fp], admittedBy] = senderCbor as [[string, Uint8Array], Uint8Array];
      const key = membershipKey({ device: { did, fingerprint: fp }, admittedBy });
      for (const [idHex, meta] of this.retained) {
        if (meta.senderKey === key && meta.ctrlSeq !== null && meta.ctrlSeq >= from && meta.ctrlSeq <= to) {
          emit(idHex, meta.raw);
        }
      }
    }
    return out;
  }

  bufferedCount(): number {
    return this.bufferedTotal;
  }

  /** The session's current causal frontier (head op ids as hex) — dgm §8. */
  headSet(): Set<string> {
    return new Set(this.engine.headsList().map(bytesToHex));
  }

  /**
   * Advertise the current frontier so peers can reconcile (head reconciliation,
   * dgm §8). A coverage frame's deps ARE the frontier, so a peer missing any of
   * our ops buffers it and repairs; the carried digest catches divergence. This
   * is just `coverage()` named for intent.
   */
  advertiseHeads(): Uint8Array {
    return this.coverage();
  }

  // ── internals ─────────────────────────────────────────────────────────────

  /**
   * Bootstrap zeroing (wire-format §2): a create frame's sender carries
   * admittedBy = 0³² at signing time; processors normalize it to the frame's
   * MessageID for all tracking.
   */
  private senderOf(frame: ParsedFrame): Membership {
    const s = frame.body.sender;
    if (
      frame.body.cls === CLS_CONTROL &&
      isCreatePayload(frame.body.payload) &&
      bytesEqual(s.admittedBy, ZERO32)
    ) {
      return { device: s.device, admittedBy: frame.id };
    }
    return s;
  }

  private ready(frame: ParsedFrame): boolean {
    for (const dep of frame.body.deps) {
      if (!this.processed.has(bytesToHex(dep))) return false;
    }
    if (frame.body.ctrlSeq !== null) {
      const st = this.senders.get(membershipKey(this.senderOf(frame)));
      const last = st?.lastCtrlSeq ?? -1;
      if (frame.body.ctrlSeq !== last + 1) return false;
    }
    return true;
  }

  private processFrame(frame: ParsedFrame): void {
    const senderKey = membershipKey(this.senderOf(frame));
    const st = this.senders.get(senderKey);
    // A1: verify under the sender's key for this seq. Unknown sender → the
    // admitting op hasn't processed; treat as not-ready (buffered upstream).
    if (st === undefined) {
      this.bufferFrame(frame);
      return;
    }
    const pk = keyForSeq(st, frame.body.seq);
    if (pk === null || !verifyFrameSig(frame.bodyBytes, frame.sig, pk)) {
      this.events.onSecurityEvent?.('bad-signature', bytesToHex(frame.id));
      this.events.onDropped?.('bad-signature', frame.id);
      return; // dropped, never buffered (ordering-auth §5)
    }
    // Replay is caught by the MessageID processed-set (A5, checked at ingest);
    // `seq` is NOT a contiguity gate for app/repair frames (they share the
    // per-sender counter but are order-exempt — ordering-auth §4.1), so a lower
    // seq here is legitimate out-of-order delivery, not a replay.

    const idHex = bytesToHex(frame.id);
    try {
      if (frame.body.cls === CLS_CONTROL) {
        const payload = payloadFromCbor(frame.body.payload, frame.body.sender.device.fingerprint);
        // §8 equivocation check: if the sender advertises exactly our current
        // frontier, we have the same op set and our digests MUST agree.
        // (Computed pre-ingest, against our current heads.)
        // Consistency-digest handling (dgm.md §8). The advertised [digest, heads]
        // is carried for equivocation detection, but a raw same-frontier digest
        // comparison is only sound at mutual quiescence — mid-async, two peers
        // can transiently present the same head-set while one is still
        // reconciling, and the trees converge moments later (verified: such
        // mismatches always resolve). So a single mismatch is a *soft* signal,
        // surfaced but not treated as proof. Sound equivocation defenses remain
        // active: rootCommit (key-material, beekem-core §4.3) and frame
        // signatures. A confirmed detector (persistent disagreement at a stable
        // covered-by-all frontier) is deferred — see notes.
        const digestExt = decodeExt(frame.body.ext).digest;
        if (digestExt !== undefined) {
          const { digest: advDigest, heads: advHeads } = digestExt;
          const mine = new Set(this.engine.headsList().map(bytesToHex));
          const adv = new Set(advHeads.map(bytesToHex));
          if (mine.size === adv.size && [...adv].every((h) => mine.has(h))) {
            this.engine.settle();
            if (!bytesEqual(advDigest, this.engine.validDigest())) {
              this.events.onDigestMismatch?.(bytesToHex(frame.id));
            }
          }
        }
        const op: Op = { id: frame.id, author: frame.body.sender, deps: frame.body.deps, payload };
        this.engine.ingest(op);
        this.learnFromControl(frame, payload);
      } else if (frame.body.cls === CLS_APP) {
        // A6 membership gating (ordering-auth §1): application content from a
        // device that is not a current member IN OUR VIEW is never accepted.
        // This is the receive half of strong remove — a removed member never
        // learns it was removed (the remove is not sealed to it) and keeps
        // sending; those frames must not enter the conversation, whatever
        // epoch they were sealed under and whichever envelopes we can still
        // open. Not a security event: a member sending concurrently with its
        // own removal, or a view that has not yet processed an add, are both
        // normal — the drop IS the enforcement. (Before this gate the frame
        // usually died at decryption instead, which is why the REMOVER — with
        // a live epoch and a stale tag table — could still accept it.)
        if (!this.engine.isMemberDevice(frame.body.sender.device)) {
          this.events.onDropped?.('app-from-non-member', frame.id);
          this.renotifyRemoved(frame.body.sender.device);
          return;
        }
        const [generation, ct] = frame.body.payload as [number, Uint8Array];
        const msg: AppMessage = {
          epochId: frame.body.deps[0] ?? new Uint8Array(32),
          sender: frame.body.sender,
          generation,
          ct,
        };
        try {
          const pt = this.engine.receiveApp(msg);
          this.events.onAppMessage?.(pt, frame.body.sender);
        } catch {
          // Undecryptable for us: an epoch we never derived / were not entitled
          // to / have evicted, or a message beyond the skipped-key window
          // (ordering-auth §4.2, beekem-core §8). Silent drop — but we still fall
          // through to retain the bytes so we can serve them to repair.
          this.events.onDropped?.('app-undecryptable', frame.id);
        }
      }
      // CLS_WELCOME received by an existing member: not addressed to us — record only.
      // CLS_REPAIR is intercepted in ingestFrame and never reaches here.
    } catch (e) {
      if (e instanceof Error && e.message.startsWith('RootCommitMismatch')) {
        this.events.onSecurityEvent?.('root-commit-mismatch', bytesToHex(frame.id));
        this.events.onDropped?.('root-commit-mismatch', frame.id);
        return; // rejected — do not mark processed (a corrected op may follow)
      }
      throw e;
    }

    this.heardFrom.add(senderKey);
    st.lastSeq = Math.max(st.lastSeq, frame.body.seq);
    if (frame.body.ctrlSeq !== null) st.lastCtrlSeq = frame.body.ctrlSeq;
    this.applyRotation(frame, st);
    this.applyEndpoint(frame);
    this.processed.add(idHex);
    this.retain(idHex, {
      raw: frame.raw,
      senderKey,
      seq: frame.body.seq,
      ctrlSeq: frame.body.ctrlSeq,
    });
  }

  private drain(): void {
    let progressed = true;
    while (progressed) {
      progressed = false;
      for (const [senderKey, frames] of [...this.buffer]) {
        const still: ParsedFrame[] = [];
        for (const f of frames) {
          if (this.processed.has(bytesToHex(f.id))) {
            this.bufferedTotal -= 1;
            continue;
          }
          if (this.ready(f)) {
            this.bufferedTotal -= 1;
            this.processFrame(f);
            progressed = true;
          } else {
            still.push(f);
          }
        }
        if (still.length === 0) this.buffer.delete(senderKey);
        else this.buffer.set(senderKey, still);
      }
    }
  }

  private bufferFrame(frame: ParsedFrame): void {
    const senderKey = membershipKey(this.senderOf(frame));
    const q = this.buffer.get(senderKey) ?? [];
    if (q.some((f) => bytesEqual(f.id, frame.id))) return;
    if (q.length >= MAX_BUFFERED_PER_SENDER || this.bufferedTotal >= MAX_BUFFERED_TOTAL) {
      // §4.4: drop newest from the largest queue, surface for repair.
      this.events.onDropped?.('buffer-overflow', frame.id);
      return;
    }
    q.push(frame);
    this.buffer.set(senderKey, q);
    this.bufferedTotal += 1;
  }

  /** Learn initial signing keys and rotations from a processed control frame. */
  private learnFromControl(frame: ParsedFrame, payload: OpPayload): void {
    if (payload.type === 'create') {
      for (const d of payload.initialDevices) {
        const m: Membership = { device: d.device, admittedBy: frame.id };
        this.ensureSender(m).keys.push({ fromSeq: 0, pk: d.signingPk ?? ZERO32 });
      }
    } else if (payload.type === 'add') {
      const m: Membership = { device: payload.device, admittedBy: frame.id };
      this.ensureSender(m).keys.push({ fromSeq: 0, pk: payload.signingPk ?? ZERO32 });
    }
  }

  private applyRotation(frame: ParsedFrame, st: SenderState): void {
    if (frame.body.cls !== CLS_CONTROL) return;
    const opType = (frame.body.payload as CborValue[])[0];
    if (
      opType === OP_TYPE_NUM.create ||
      opType === OP_TYPE_NUM.update ||
      opType === OP_TYPE_NUM.remove
    ) {
      const next = decodeExt(frame.body.ext).rotation;
      if (next instanceof Uint8Array && next.length === 32) {
        // Keep the full rotation history: verifying a repaired old frame
        // (ordering-auth §8) requires the key that was effective at its seq.
        // Bounded by the sender's lifetime rotation count; pruning is only safe
        // behind a checkpoint that also drops the frames those keys verify.
        if (!st.keys.some((k) => k.fromSeq === frame.body.seq + 1)) {
          st.keys.push({ fromSeq: frame.body.seq + 1, pk: next });
          st.keys.sort((a, b) => a.fromSeq - b.fromSeq);
        }
      }
    }
  }

  /** Learn a peer's non-welcome delivery endpoint from a processed frame's ext
   *  (sealed-sender §12), last-writer-wins by the author's own seq. */
  private applyEndpoint(frame: ParsedFrame): void {
    const url = decodeExt(frame.body.ext).endpoint;
    if (typeof url !== 'string') return;
    const fp = bytesToHex(frame.body.sender.device.fingerprint);
    const cur = this.peerEndpoints.get(fp);
    if (cur === undefined || frame.body.seq > cur.seq) {
      this.peerEndpoints.set(fp, { url, seq: frame.body.seq });
    }
  }

  /**
   * Advertise where this device wants its non-welcome envelopes delivered
   * (sealed-sender §12). Rides the next authored control frame's signed `ext`
   * (the joiner's healing update is the natural first carrier) and re-adverts on
   * coverage. v1 is a single https URL per device; a per-group token is a later
   * device-side policy with no wire change.
   */
  setEndpoint(url: string): void {
    if (this.myEndpoint === url) return;
    this.myEndpoint = url;
    this.endpointDirty = true;
  }

  /** The delivery endpoint learned in-band for a device, or null if not yet seen. */
  endpointOf(fingerprint: Uint8Array): string | null {
    return this.peerEndpoints.get(bytesToHex(fingerprint))?.url ?? null;
  }

  private ensureSender(m: Membership): SenderState {
    const k = membershipKey(m);
    let st = this.senders.get(k);
    if (st === undefined) {
      st = { lastSeq: -1, lastCtrlSeq: -1, keys: [] };
      this.senders.set(k, st);
    }
    return st;
  }

  private markProcessed(frame: ParsedFrame): void {
    const senderKey = membershipKey(this.senderOf(frame));
    const st = this.ensureSender(this.senderOf(frame));
    this.heardFrom.add(senderKey);
    st.lastSeq = Math.max(st.lastSeq, frame.body.seq);
    if (frame.body.ctrlSeq !== null) st.lastCtrlSeq = Math.max(st.lastCtrlSeq, frame.body.ctrlSeq);
    this.applyRotation(frame, st);
    this.applyEndpoint(frame);
    this.processed.add(bytesToHex(frame.id));
    // A welcome is point-to-point admission material — no peer ever repairs it
    // and no joiner needs another joiner's — so it stays out of the retained
    // log (which is also what a welcome body is built from).
    if (frame.body.cls === CLS_WELCOME) return;
    this.retain(bytesToHex(frame.id), {
      raw: frame.raw,
      senderKey,
      seq: frame.body.seq,
      ctrlSeq: frame.body.ctrlSeq,
    });
  }

  private retain(idHex: string, meta: RetainedMeta): void {
    if (!this.retained.has(idHex)) {
      this.retained.set(idHex, meta);
      this.retainedOrder.push(idHex);
    }
  }

  /** Engine minter: build+sign the control frame; its MessageID becomes the op id. */
  private mintControl(author: Membership, deps: Uint8Array[], payload: OpPayload): Uint8Array {
    const rotate =
      payload.type === 'create' || payload.type === 'update' || payload.type === 'remove';
    const extObj: FrameExt = {};
    let next: { sk: Uint8Array; pk: Uint8Array } | null = null;
    if (rotate) {
      next = generateSigningKeypair(this.rng);
      extObj.rotation = next.pk;
    }
    // Coverage frames carry the consistency digest + the sender's frontier
    // (dgm.md §8). The deps of a coverage frame ARE that frontier, so a receiver
    // missing any advertised head buffers this frame and repairs it — that is
    // the head-reconciliation path. The digest lets a same-frontier receiver
    // detect divergence (§8 equivocation check).
    if (payload.type === 'coverage') {
      extObj.digest = { digest: this.engine.validDigest(), heads: this.engine.headsList() };
    }
    // In-band delivery-endpoint advert (sealed-sender §12): stamp on change, and
    // opportunistically re-advert on coverage so a late/offline joiner reconverges
    // on everyone's address the same way coverage reconciles heads.
    if (this.myEndpoint !== null && (this.endpointDirty || payload.type === 'coverage')) {
      extObj.endpoint = this.myEndpoint;
      this.endpointDirty = false;
    }
    const ext = encodeExt(extObj);
    const body = encodeFrameBody({
      version: 1,
      groupId: payload.type === 'create' ? ZERO32 : this.engine.groupId,
      sender: author,
      seq: this.seq,
      ctrlSeq: this.ctrlSeq,
      deps,
      cls: CLS_CONTROL,
      payload: payloadToCbor(payload),
      ext,
    });
    const raw = signFrame(body, this.signing.sk);
    const parsed = parseFrame(raw);
    this.pendingLocal = {
      raw,
      idHex: bytesToHex(parsed.id),
      meta: { raw, senderKey: membershipKey(author), seq: this.seq, ctrlSeq: this.ctrlSeq },
    };
    this.seq += 1;
    this.ctrlSeq += 1;
    if (next !== null) {
      this.signing = next;
      this.myKeyOpId = parsed.id; // this op announced the key I now sign under
    }
    return parsed.id;
  }

  private commitLocal(f: { raw: Uint8Array; idHex: string; meta: RetainedMeta }): void {
    this.processed.add(f.idHex);
    this.retain(f.idHex, f.meta);
    const st = this.ensureSender(this.engine.me);
    this.heardFrom.add(membershipKey(this.engine.me));
    st.lastSeq = Math.max(st.lastSeq, f.meta.seq);
    if (f.meta.ctrlSeq !== null) st.lastCtrlSeq = Math.max(st.lastCtrlSeq, f.meta.ctrlSeq);
    const parsed = parseFrame(f.raw);
    if (parsed.body.cls === CLS_CONTROL) {
      const payload = payloadFromCbor(parsed.body.payload, parsed.body.sender.device.fingerprint);
      this.learnFromControl(parsed, payload);
      this.applyRotation(parsed, st);
    }
    this.outbox.push(f.raw);
  }

  private finalizeLocal(): Uint8Array {
    const f = this.pendingLocal;
    if (f === null) throw new Error('no pending local frame');
    this.pendingLocal = null;
    this.commitLocal(f);
    return f.raw;
  }

  private nextCtrlSeq(): number {
    const c = this.ctrlSeq;
    this.ctrlSeq += 1;
    return c;
  }

  private buildFrame(
    cls: number,
    ctrlSeq: number | null,
    deps: Uint8Array[],
    payload: CborValue,
    ext: Uint8Array,
  ): Uint8Array {
    const body = encodeFrameBody({
      version: 1,
      groupId: this.engine.groupId,
      sender: this.engine.me,
      seq: this.seq,
      ctrlSeq,
      deps,
      cls,
      payload,
      ext,
    });
    this.seq += 1;
    const raw = signFrame(body, this.signing.sk);
    const parsed = parseFrame(raw);
    this.markProcessed(parsed);
    this.outbox.push(raw);
    return raw;
  }
}

// ── module helpers ───────────────────────────────────────────────────────────

function keyForSeq(st: SenderState, seq: number): Uint8Array | null {
  let found: Uint8Array | null = null;
  for (const k of st.keys) {
    if (k.fromSeq <= seq) found = k.pk;
  }
  return found;
}

function isCreatePayload(payload: CborValue): boolean {
  return Array.isArray(payload) && payload[0] === OP_TYPE_NUM.create;
}

function cborDecodeWelcomeBody(bytes: Uint8Array): { frames: Uint8Array[] } {
  const [checkpoint, frames] = cborDecode(bytes) as [CborValue, Uint8Array[]];
  if (checkpoint !== null) throw new Error('checkpoint welcomes not yet supported');
  return { frames };
}

/** Bootstrap mint for the create op (used before the Session object exists). */
function mintControlRaw(
  boot: {
    signing: { sk: Uint8Array; pk: Uint8Array };
    seq: number;
    ctrlSeq: number;
    frames: Array<{ raw: Uint8Array; idHex: string; meta: RetainedMeta }>;
  },
  groupId: Uint8Array,
  author: Membership,
  deps: Uint8Array[],
  payload: OpPayload,
  rng: Csprng,
  sink: Array<{ raw: Uint8Array; idHex: string; meta: RetainedMeta }>,
): Uint8Array {
  const next = generateSigningKeypair(rng);
  const ext = encodeExt({ rotation: next.pk });
  const body = encodeFrameBody({
    version: 1,
    groupId,
    sender: author,
    seq: boot.seq,
    ctrlSeq: boot.ctrlSeq,
    deps,
    cls: CLS_CONTROL,
    payload: payloadToCbor(payload),
    ext,
  });
  const raw = signFrame(body, boot.signing.sk);
  const id = messageIdOf(body, cborDecodeSig(raw));
  sink.push({
    raw,
    idHex: bytesToHex(id),
    meta: { raw, senderKey: membershipKey(author), seq: boot.seq, ctrlSeq: boot.ctrlSeq },
  });
  boot.seq += 1;
  boot.ctrlSeq += 1;
  boot.signing = next;
  return id;
}

function cborDecodeSig(raw: Uint8Array): Uint8Array {
  return parseFrame(raw).sig;
}
