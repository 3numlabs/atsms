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
import { cborDecode, cborEncode, type CborMap, type CborValue } from './cbor.js';
import { Engine, type AppMessage } from './engine.js';
import {
  CLS_APP,
  CLS_CONTROL,
  CLS_REPAIR,
  CLS_WELCOME,
  EXT_DIGEST,
  EXT_NEXT_SIGNING_KEY,
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
import type { ShareKeyMap } from './keys.js';
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
    const engine = Engine.create(devices, initialAdmins, sks, rng, minter);
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
    const frames = this.retainedOrder.map((k) => this.retained.get(k)!.raw);
    const welcomeBody = cborEncode([null, frames, [], 1]); // [checkpoint, ops, deliveryMap, profile]
    return this.buildFrame(CLS_WELCOME, this.nextCtrlSeq(), [addOpId], [addOpId, welcomeBody], new Map());
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
    return this.buildFrame(CLS_APP, null, deps, payload, new Map());
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
      ext: new Map(),
    });
    return signFrame(body, this.signing.sk);
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
        const digestExt = frame.body.ext.get(EXT_DIGEST);
        if (Array.isArray(digestExt)) {
          const [advDigest, advHeads] = digestExt as [Uint8Array, Uint8Array[]];
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

    st.lastSeq = Math.max(st.lastSeq, frame.body.seq);
    if (frame.body.ctrlSeq !== null) st.lastCtrlSeq = frame.body.ctrlSeq;
    this.applyRotation(frame, st);
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
      const next = frame.body.ext.get(EXT_NEXT_SIGNING_KEY);
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
    st.lastSeq = Math.max(st.lastSeq, frame.body.seq);
    if (frame.body.ctrlSeq !== null) st.lastCtrlSeq = Math.max(st.lastCtrlSeq, frame.body.ctrlSeq);
    this.applyRotation(frame, st);
    this.processed.add(bytesToHex(frame.id));
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
    const ext: CborMap = new Map();
    let next: { sk: Uint8Array; pk: Uint8Array } | null = null;
    if (rotate) {
      next = generateSigningKeypair(this.rng);
      ext.set(EXT_NEXT_SIGNING_KEY, next.pk);
    }
    // Coverage frames carry the consistency digest + the sender's frontier
    // (dgm.md §8). The deps of a coverage frame ARE that frontier, so a receiver
    // missing any advertised head buffers this frame and repairs it — that is
    // the head-reconciliation path. The digest lets a same-frontier receiver
    // detect divergence (§8 equivocation check).
    if (payload.type === 'coverage') {
      ext.set(EXT_DIGEST, [this.engine.validDigest(), this.engine.headsList()]);
    }
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
    ext: CborMap,
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
  const ext: CborMap = new Map();
  const next = generateSigningKeypair(rng);
  ext.set(EXT_NEXT_SIGNING_KEY, next.pk);
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
