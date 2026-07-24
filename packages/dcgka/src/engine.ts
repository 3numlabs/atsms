/**
 * The BeeKEM engine (beekem-core §2/§4–§8): op graph + epochs + merge/replay
 * with the DGM validity filter (PR-1..3), the PcsKey seam, rootCommit,
 * per-sender chains, coverage tracking, epoch eviction, and checkpoints.
 *
 * Concurrency handling ports `cgka.rs::merge_concurrent_operation` /
 * `apply_epochs` / `replay`; the DGM filter and everything above the PcsKey
 * seam are ATSMS profile (explicit oracle-allowlist deviations).
 *
 * The engine is transport-free: ops in, ops/events out. Signatures and frame
 * readiness are ordering-auth's job (next tranche) — ops arriving here are
 * assumed authenticated and causally ready (deps ingested first).
 */

import { sha256 } from '@noble/hashes/sha2';
import { bytesEqual, bytesToHex, concatBytes, hexToBytes } from './bytes.js';
import { cborEncode } from './cbor.js';
import { ReceiverChain, SenderChain, openApp, sealApp } from './chains.js';
import { evaluate, normalizeCreateAuthor, type DgmSeed, type DgmView } from './dgm.js';
import { encodeMembership, membershipKey, type DeviceID, type Membership } from './ids.js';
import { chainSeed, rootCommit } from './kdf.js';
import { generateShareSecretKey, shareKeyOf, type Csprng } from './keyhive.js';
import { envKeySym } from './envelope.js';
import { ShareKeyMap, shareNodeKey } from './keys.js';
import { makeOp, opKey, type Op, type OpMinter, type OpPayload } from './ops.js';
import { SecretStore } from './secretstore.js';
import { BeeKem, type PathChange } from './tree.js';

export interface AppMessage {
  epochId: Uint8Array;
  sender: Membership;
  generation: number;
  ct: Uint8Array;
}

interface Epoch {
  pcsKey: Uint8Array;
  send: SenderChain | null;
  recv: Map<string, ReceiverChain>;
  closed: boolean;
}

interface Checkpoint {
  tree: BeeKem;
  seed: DgmSeed;
  /** Ops inside the checkpoint (pruned); membership ops are re-seeded via `seed`. */
  covered: Set<string>;
}

export class Engine {
  readonly groupId: Uint8Array;
  /** This device's own Membership — admittedBy is set from the resolved view
   *  (createId for founding members, the add-op id for joiners). */
  me: Membership;
  readonly sks: ShareKeyMap;
  private tree: BeeKem;
  private ops = new Map<string, Op>();
  private anc = new Map<string, Set<string>>();
  private heads = new Set<string>();
  private pendingStructural = false;
  private dgm: DgmView;
  private epochs = new Map<string, Epoch>();
  private currentEpochId: string | null = null;
  /** membershipKey → op ids authored (coverage frontier source). */
  private authored = new Map<string, Set<string>>();
  private checkpoint: Checkpoint | null = null;
  private skippedBudget = { used: 0 };
  private createOp: Op;

  private minter: OpMinter | null;

  private constructor(
    createOp: Op,
    myDevice: DeviceID,
    sks: ShareKeyMap,
    private rng: Csprng,
    minter: OpMinter | null = null,
  ) {
    this.minter = minter;
    if (createOp.payload.type !== 'create') throw new Error('first op must be create');
    this.createOp = createOp;
    this.groupId = createOp.id;
    this.me = { device: myDevice, admittedBy: createOp.id };
    this.sks = sks;
    const p = createOp.payload;
    const first = p.initialDevices[0];
    if (first === undefined) throw new Error('create needs at least one device');
    this.tree = new BeeKem(this.groupId, first.device.fingerprint, first.leafPk);
    for (const d of p.initialDevices.slice(1)) {
      this.tree.pushLeaf(d.device.fingerprint, shareNodeKey(d.leafPk));
    }
    this.recordOp(normalizeCreateAuthor(createOp));
    this.dgm = this.evaluateDgm();
  }

  /** Found a group: builds the create op and the creator's engine. */
  static create(
    devices: Array<{ device: DeviceID; leafPk: Uint8Array; signingPk?: Uint8Array }>,
    initialAdmins: string[],
    creatorSks: ShareKeyMap,
    rng: Csprng,
    minter: OpMinter | null = null,
  ): Engine {
    const creator = devices[0];
    if (creator === undefined) throw new Error('create needs at least one device');
    const author: Membership = { device: creator.device, admittedBy: new Uint8Array(32) };
    const payload: OpPayload = { type: 'create', initialDevices: devices, initialAdmins };
    const op =
      minter !== null
        ? { id: minter(author, [], payload), author, deps: [], payload }
        : makeOp(author, [], payload);
    return new Engine(op, creator.device, creatorSks, rng, minter);
  }

  /** Reconstruct from an op log (test/join-by-full-history path; the welcome flow wraps this). */
  static fromOpLog(
    log: Op[],
    myDevice: DeviceID,
    sks: ShareKeyMap,
    rng: Csprng,
    minter: OpMinter | null = null,
  ): Engine {
    const [createOp, ...rest] = log;
    if (createOp === undefined) throw new Error('empty op log');
    const e = new Engine(createOp, myDevice, sks, rng, minter);
    for (const op of rest) e.ingest(op);
    e.refreshMe();
    return e;
  }

  /**
   * Re-derive `me.admittedBy` from the current membership view: a joiner's
   * Membership is keyed by the add op that admitted it, not the create op the
   * engine bootstrapped from. Call after ingesting a joiner's admitting add.
   */
  refreshMe(): void {
    const fp = this.me.device.fingerprint;
    for (const m of this.dgm.members.values()) {
      if (bytesEqual(m.device.fingerprint, fp)) {
        this.me = m;
        return;
      }
    }
  }

  private mint(payload: OpPayload): Op {
    const deps = this.headsArr();
    if (this.minter !== null) {
      return { id: this.minter(this.me, deps, payload), author: this.me, deps, payload };
    }
    return makeOp(this.me, deps, payload);
  }

  // ── op ingestion (cgka.rs::merge_concurrent_operation) ───────────────────

  ingest(op: Op): boolean {
    const k = opKey(op.id);
    if (this.ops.has(k)) return false;
    for (const dep of op.deps) {
      if (!this.ops.has(bytesToHex(dep)) && !(this.checkpoint?.covered.has(bytesToHex(dep)) ?? false)) {
        throw new Error('OutOfOrderOperation');
      }
    }
    const depSet = new Set(op.deps.map(bytesToHex));
    const isConcurrent = ![...this.heads].every((h) => depSet.has(h));
    const isMembership = op.payload.type === 'add' || op.payload.type === 'remove';

    if (isConcurrent) {
      if (this.pendingStructural || isMembership) {
        this.pendingStructural = true;
        this.recordOp(op);
        this.dgm = this.evaluateDgm();
      } else {
        this.recordOp(op);
        this.dgm = this.evaluateDgm();
        this.applyOp(op);
      }
    } else {
      if (this.shouldReplay()) this.replay();
      this.recordOp(op);
      this.dgm = this.evaluateDgm();
      this.applyOp(op);
    }
    // A joiner's own admitting add resolves its Membership (admittedBy = add id).
    if (op.payload.type === 'add' && bytesEqual(op.payload.device.fingerprint, this.me.device.fingerprint)) {
      this.refreshMe();
    }
    return true;
  }

  /** Force pending concurrency to resolve (upstream does this lazily before local ops). */
  settle(): void {
    if (this.shouldReplay()) this.replay();
  }

  private shouldReplay(): boolean {
    return this.heads.size > 0 && (this.pendingStructural || this.heads.size > 1);
  }

  // ── local op builders (broadcast the returned op) ─────────────────────────

  buildAdd(device: DeviceID, leafPk: Uint8Array, signingPk?: Uint8Array): Op {
    this.settle();
    if (device.did !== this.me.device.did && !this.dgm.admins.has(this.me.device.did)) {
      throw new Error('Unauthorized: cross-DID add requires admin (dgm.md §4)');
    }
    if (this.tree.containsId(device.fingerprint)) throw new Error('already a member');
    const leafIndex = this.tree.pushLeaf(device.fingerprint, shareNodeKey(leafPk));
    const op = this.mint({ type: 'add', device, leafPk, leafIndex, signingPk });
    this.recordOp(op);
    this.dgm = this.evaluateDgm();
    this.currentEpochId = null; // path blanked
    return op;
  }

  buildRemove(membership: Membership): Op {
    this.settle();
    if (
      membership.device.did !== this.me.device.did &&
      !this.dgm.admins.has(this.me.device.did)
    ) {
      throw new Error('Unauthorized: cross-DID remove requires admin (dgm.md §4)');
    }
    const [, removedKeys] = this.tree.removeId(membership.device.fingerprint);
    const op = this.mint({ type: 'remove', membership, removedKeys });
    this.recordOp(op);
    this.dgm = this.evaluateDgm();
    this.currentEpochId = null;
    return op;
  }

  /** PCS update (beekem-core §10's update-first rule is the caller's trigger). */
  buildUpdate(): Op {
    this.settle();
    const newSk = generateShareSecretKey(this.rng);
    const newPk = shareKeyOf(newSk);
    this.sks.insert(newPk, newSk);
    const [root, path] = this.tree.encryptPath(
      this.me.device.fingerprint,
      newPk,
      this.sks,
      this.rng,
    );
    const op = this.mint({ type: 'update', path, rootCommit: rootCommit(root) });
    this.recordOp(op);
    this.dgm = this.evaluateDgm();
    this.registerEpoch(op.id, root);
    return op;
  }

  buildCoverage(): Op {
    // Settle first so the advertised consistency digest reflects the canonical
    // (replayed) tree, not a transient pending-concurrency state (dgm §8).
    this.settle();
    const op = this.mint({ type: 'coverage' });
    this.recordOp(op);
    return op;
  }

  buildGrantAdmin(did: string): Op {
    if (!this.dgm.admins.has(this.me.device.did)) {
      throw new Error('Unauthorized: grantAdmin requires admin (dgm.md §4)');
    }
    const op = this.mint({ type: 'grantAdmin', did });
    this.recordOp(op);
    this.dgm = this.evaluateDgm();
    return op;
  }

  // ── application messages (per-sender chains, §7) ──────────────────────────

  sendApp(plaintext: Uint8Array): AppMessage {
    if (this.currentEpochId === null) throw new Error('NoRootKey: update before sending');
    const epoch = this.epochs.get(this.currentEpochId)!;
    if (epoch.send === null) {
      epoch.send = new SenderChain(chainSeed(epoch.pcsKey, encodeMembership(this.me)));
    }
    const { generation, msgKey, nonce } = epoch.send.next();
    const ad = this.appAd(this.me, generation);
    const ct = sealApp(msgKey, nonce, ad, plaintext);
    return { epochId: hexToId(this.currentEpochId), sender: this.me, generation, ct };
  }

  receiveApp(msg: AppMessage): Uint8Array {
    const ek = bytesToHex(msg.epochId);
    const epoch = this.epochs.get(ek);
    if (epoch === undefined || epoch.closed) throw new Error('EpochClosed');
    const sk = membershipKey(msg.sender);
    let chain = epoch.recv.get(sk);
    if (chain === undefined) {
      chain = new ReceiverChain(chainSeed(epoch.pcsKey, encodeMembership(msg.sender)), this.skippedBudget);
      epoch.recv.set(sk, chain);
    }
    const { msgKey, nonce } = chain.keyFor(msg.generation);
    return openApp(msgKey, nonce, this.appAd(msg.sender, msg.generation), msg.ct);
  }

  private appAd(sender: Membership, generation: number): Uint8Array {
    return cborEncode([this.groupId, [[sender.device.did, sender.device.fingerprint], sender.admittedBy], generation]);
  }

  // ── coverage, eviction, checkpoints (§5/§6/§8) ────────────────────────────

  /** Op X is covered by member M iff M authored an op with X in its causal past. */
  covered(opId: string, member: Membership): boolean {
    const authored = this.authored.get(membershipKey(member));
    if (authored === undefined) return false;
    if (authored.has(opId)) return true;
    for (const a of authored) {
      if (this.anc.get(a)?.has(opId) ?? false) return true;
    }
    return false;
  }

  coveredByAll(opId: string): boolean {
    for (const m of this.dgm.members.values()) {
      if (!this.covered(opId, m)) return false;
    }
    return this.dgm.members.size > 0;
  }

  /** Evict a closed epoch's keys (FS bound — T_EPOCH_GRACE is the host's clock). */
  closeEpoch(epochId: string): void {
    const e = this.epochs.get(epochId);
    if (e === undefined) return;
    e.pcsKey = new Uint8Array(32); // best-effort overwrite
    e.recv.clear();
    e.send = null;
    e.closed = true;
  }

  /** Live (non-evicted) epoch ids — the seal layer derives envKeys for these (sealed-sender §11.4). */
  liveEpochs(): string[] {
    return [...this.epochs].filter(([, e]) => !e.closed).map(([id]) => id);
  }

  /**
   * The epoch a frame with these `deps` MUST be sealed under (sealed-sender
   * §11.4): the latest **established** epoch among the frame's causal ancestors.
   * For an `app` frame this is the current epoch; for an epoch-*advancing*
   * control op (`update`) the op is not its own ancestor, so this resolves to the
   * **parent** epoch — receivers hold it, and derive the new one by processing
   * this frame. Null when no epoch precedes the frame (the first update after
   * `create`, which rides `sealed-asym`). Deterministic on concurrent frontiers.
   */
  sealEpochFor(deps: Uint8Array[]): string | null {
    const reach = new Set<string>();
    for (const dep of deps) {
      const dk = bytesToHex(dep);
      reach.add(dk);
      for (const x of this.anc.get(dk) ?? []) reach.add(x);
    }
    const epochOps = [...reach].filter((k) => {
      const e = this.epochs.get(k);
      return e !== undefined && !e.closed;
    });
    // Keep the maximal epoch-op(s): not an ancestor of any other reachable epoch.
    const maximal = epochOps.filter(
      (k) => !epochOps.some((o) => o !== k && (this.anc.get(o)?.has(k) ?? false)),
    );
    maximal.sort();
    return maximal[0] ?? null;
  }

  /**
   * `envKey(epoch, S) = Expand(PcsKey_epoch, "atsms-seal:v1:sym" ‖ enc(S))` — the
   * sealed-sym key for sender `S` in `epoch` (sealed-sender §11.2). Null if the
   * epoch is unknown or evicted. Every member can derive every member's envKey.
   */
  epochEnvKey(epochId: string, encSender: Uint8Array): Uint8Array | null {
    const e = this.epochs.get(epochId);
    if (e === undefined || e.closed) return null;
    return envKeySym(e.pcsKey, encSender);
  }

  /** Close every epoch that is covered-by-all and superseded (beekem-core §8). */
  gcEpochs(): string[] {
    const closed: string[] = [];
    for (const [id, e] of this.epochs) {
      if (e.closed || id === this.currentEpochId) continue;
      if (this.coveredByAll(id)) {
        this.closeEpoch(id);
        closed.push(id);
      }
    }
    return closed;
  }

  /**
   * Advance the checkpoint to the covered-by-all frontier and prune behind it
   * (§6; safety = the frontier lemma, Spike B §6).
   */
  advanceCheckpoint(): boolean {
    const covered = new Set<string>();
    for (const [k] of this.ops) if (this.coveredByAll(k)) covered.add(k);
    if (covered.size === 0) return false;
    // Tree/DGM state over the covered prefix only (causally closed by construction).
    const subset = [...covered].map((k) => this.ops.get(k)!);
    const view = evaluate(subset, this.checkpoint?.seed);
    const tree = this.rebuildTree(subset, view, this.checkpoint ?? null);
    const prevCovered = this.checkpoint?.covered ?? new Set<string>();
    for (const k of covered) prevCovered.add(k);
    this.checkpoint = {
      tree,
      seed: { members: [...view.members.values()], admins: [...view.admins] },
      covered: prevCovered,
    };
    // Prune: drop covered ops that are not heads (heads stay as dep anchors).
    for (const k of covered) {
      if (!this.heads.has(k)) {
        this.ops.delete(k);
        this.anc.delete(k);
      }
    }
    return true;
  }

  // ── state inspection ──────────────────────────────────────────────────────

  /** The group's create op (bootstrap for other replicas until welcomes land). */
  bootstrapOp(): Op {
    return this.createOp;
  }

  hasRootKey(): boolean {
    return this.tree.hasRootKey();
  }

  currentEpoch(): string | null {
    return this.currentEpochId;
  }

  members(): Membership[] {
    return [...this.dgm.members.values()];
  }

  admins(): Set<string> {
    return new Set(this.dgm.admins);
  }

  isValidOp(opId: Uint8Array): boolean {
    return this.dgm.valid.has(bytesToHex(opId));
  }

  treeHash(): string {
    return bytesToHex(sha256(this.tree.publicStateBytes()));
  }

  opCount(): number {
    return this.ops.size;
  }

  /** The current causal frontier — op ids no processed op depends on (dgm §8). */
  headsList(): Uint8Array[] {
    return [...this.heads].map(hexToBytes);
  }

  /**
   * Consistency digest (dgm.md §8, narrowed by D11 — no secret inputs):
   * `H(groupId ‖ sorted valid-op ids ‖ H(tree public state))`. Two members
   * with the same head-set have the same op set (deterministic ancestor
   * closure) and therefore the same digest; a mismatch at equal heads is a
   * divergence (bug or equivocation).
   */
  validDigest(): Uint8Array {
    const parts: Uint8Array[] = [this.groupId];
    for (const idHex of [...this.dgm.valid].sort()) parts.push(hexToBytes(idHex));
    parts.push(this.canonicalTreeHashBytes());
    return sha256(concatBytes(...parts));
  }

  /**
   * Tree hash of the CANONICAL (deterministically replayed) tree — a pure
   * function of the op set + DGM view + checkpoint, independent of the live
   * incremental application order. The digest must use this so two members with
   * the same op set always agree, even if one's live tree is a transient
   * pending state. Non-mutating (rebuildTree returns a fresh tree).
   */
  private canonicalTreeHashBytes(): Uint8Array {
    const savedEpoch = this.lastEpochCandidate;
    const tree = this.rebuildTree([...this.ops.values()], this.dgm, this.checkpoint);
    this.lastEpochCandidate = savedEpoch;
    return sha256(tree.publicStateBytes());
  }

  // ── internals ─────────────────────────────────────────────────────────────

  private headsArr(): Uint8Array[] {
    return [...this.heads].map(hexToId);
  }

  private recordOp(op: Op): void {
    const k = opKey(op.id);
    this.ops.set(k, op);
    const a = new Set<string>();
    for (const dep of op.deps) {
      const dk = bytesToHex(dep);
      a.add(dk);
      for (const x of this.anc.get(dk) ?? []) a.add(x);
      this.heads.delete(dk);
    }
    this.anc.set(k, a);
    this.heads.add(k);
    const mk = membershipKey(op.author);
    if (!this.authored.has(mk)) this.authored.set(mk, new Set());
    this.authored.get(mk)!.add(k);
  }

  private evaluateDgm(): DgmView {
    return evaluate([...this.ops.values()], this.checkpoint?.seed);
  }

  /** Apply one DGM-valid op to the live tree (copy-on-success for updates). */
  private applyOp(op: Op): void {
    const k = opKey(op.id);
    if (!this.dgm.valid.has(k)) return; // invalid ops stay causal history only (PR-1)
    const p = op.payload;
    if (p.type === 'add') {
      if (!this.tree.containsId(p.device.fingerprint)) {
        this.tree.pushLeaf(p.device.fingerprint, shareNodeKey(p.leafPk));
      }
      this.currentEpochId = null;
    } else if (p.type === 'remove') {
      if (this.tree.containsId(p.membership.device.fingerprint)) {
        this.tree.removeId(p.membership.device.fingerprint);
      }
      this.currentEpochId = null;
    } else if (p.type === 'update') {
      const cloned = this.tree.clone();
      cloned.applyPath(clonePathChange(p.path));
      if (cloned.hasRootKey() && this.amMember()) {
        // §4.3: verify rootCommit at derivation time. A merge applied around
        // pending structural changes can leave a root the local member cannot
        // yet derive (e.g. we were added concurrently — replay's cleanup will
        // re-blank); that defers derivation, it is not equivocation.
        let root: Uint8Array | null = null;
        try {
          root = cloned.decryptTreeSecret(this.me.device.fingerprint, this.sks);
        } catch {
          root = null;
        }
        if (root !== null && !bytesEqual(rootCommit(root), p.rootCommit)) {
          // beekem-core §4.3: reject, no state change, surface.
          this.ops.delete(k);
          this.anc.delete(k);
          this.authored.get(membershipKey(op.author))?.delete(k);
          this.rebuildHeads();
          this.dgm = this.evaluateDgm();
          throw new Error('RootCommitMismatch: seed equivocation rejected');
        }
        this.tree = cloned;
        if (root !== null) {
          this.registerEpoch(op.id, root);
        } else {
          this.currentEpochId = null; // derivable later (settle/replay/next epoch)
        }
      } else {
        this.tree = cloned;
        if (!cloned.hasRootKey()) this.currentEpochId = null;
      }
    }
    // grant/revoke/coverage: DGM/coverage only.
  }

  /** Full replay from checkpoint/scratch (cgka.rs::replay + apply_epochs, DGM-filtered). */
  private replay(): void {
    const all = [...this.ops.values()];
    this.dgm = this.evaluateDgm();
    this.tree = this.rebuildTree(all, this.dgm, this.checkpoint);
    this.pendingStructural = false;
    // Re-derive the current epoch if a root survived replay (deferred on failure).
    this.currentEpochId = null;
    if (this.tree.hasRootKey() && this.lastEpochCandidate !== null && this.amMember()) {
      try {
        const root = this.tree.decryptTreeSecret(this.me.device.fingerprint, this.sks);
        const candidateOp = this.ops.get(this.lastEpochCandidate);
        if (candidateOp !== undefined && candidateOp.payload.type === 'update') {
          if (!bytesEqual(rootCommit(root), candidateOp.payload.rootCommit)) {
            throw new Error('RootCommitMismatch: seed equivocation rejected');
          }
        }
        this.registerEpoch(hexToId(this.lastEpochCandidate), root);
      } catch (e) {
        if (e instanceof Error && e.message.startsWith('RootCommitMismatch')) throw e;
        // Not derivable for us yet — defer.
      }
    }
  }

  private lastEpochCandidate: string | null = null;

  private rebuildTree(ops: Op[], view: DgmView, checkpoint: Checkpoint | null): BeeKem {
    // Depth-layered epochs (topsort.rs semantics: same layer ⇒ mutually concurrent).
    const depth = new Map<string, number>();
    const d = (id: string): number => {
      const c = depth.get(id);
      if (c !== undefined) return c;
      const op = this.ops.get(id);
      let dd = 0;
      if (op !== undefined) {
        for (const dep of op.deps) dd = Math.max(dd, d(bytesToHex(dep)) + 1);
      }
      depth.set(id, dd);
      return dd;
    };
    const inSet = new Set(ops.map((o) => opKey(o.id)));
    const layers = new Map<number, Op[]>();
    for (const op of ops) {
      const dd = d(opKey(op.id));
      if (!layers.has(dd)) layers.set(dd, []);
      layers.get(dd)!.push(op);
    }
    let tree: BeeKem;
    if (checkpoint !== null) {
      tree = checkpoint.tree.clone();
    } else {
      const create = ops.find((o) => o.payload.type === 'create');
      if (create === undefined || create.payload.type !== 'create') {
        throw new Error('replay without create or checkpoint');
      }
      const first = create.payload.initialDevices[0]!;
      tree = new BeeKem(this.groupId, first.device.fingerprint, first.leafPk);
      for (const dev of create.payload.initialDevices.slice(1)) {
        tree.pushLeaf(dev.device.fingerprint, shareNodeKey(dev.leafPk));
      }
    }
    this.lastEpochCandidate = null;
    const isCgka = (o: Op) =>
      o.payload.type === 'create' ||
      o.payload.type === 'add' ||
      o.payload.type === 'remove' ||
      o.payload.type === 'update';
    const sorted = [...layers.keys()].sort((a, b) => a - b);
    for (const layer of sorted) {
      // Only CGKA ops enter the tree-application epochs (upstream's graph holds
      // nothing else); coverage/grant/revoke are DAG-only.
      const epochOps = layers
        .get(layer)!
        .filter((o) => isCgka(o) && inSet.has(opKey(o.id)) && view.valid.has(opKey(o.id)))
        .sort((a, b) => (opKey(a.id) < opKey(b.id) ? -1 : 1));
      const hasMembership = epochOps.some(
        (o) => o.payload.type === 'add' || o.payload.type === 'remove',
      );
      const addedIds = new Set<string>();
      const removedIds: Array<[Uint8Array, number]> = [];
      for (const op of epochOps) {
        const p = op.payload;
        if (p.type === 'create') continue; // handled at tree construction
        if (p.type === 'add') {
          if (!tree.containsId(p.device.fingerprint)) {
            tree.pushLeaf(p.device.fingerprint, shareNodeKey(p.leafPk));
          }
          addedIds.add(bytesToHex(p.device.fingerprint));
          this.lastEpochCandidate = null;
        } else if (p.type === 'remove') {
          if (tree.containsId(p.membership.device.fingerprint)) {
            const [idx] = tree.removeId(p.membership.device.fingerprint);
            removedIds.push([p.membership.device.fingerprint, idx]);
          }
          this.lastEpochCandidate = null;
        } else if (p.type === 'update') {
          tree.applyPath(clonePathChange(p.path));
          if (tree.hasRootKey()) this.lastEpochCandidate = opKey(op.id);
        }
      }
      if (hasMembership && epochOps.length > 1) {
        tree.sortLeavesAndBlankPathsForConcurrentMembershipChanges(addedIds, removedIds);
        this.lastEpochCandidate = null;
      }
    }
    return tree;
  }

  private registerEpoch(opId: Uint8Array, root: Uint8Array): void {
    const k = bytesToHex(opId);
    if (!this.epochs.has(k)) {
      this.epochs.set(k, { pcsKey: root, send: null, recv: new Map(), closed: false });
    }
    this.currentEpochId = k;
  }

  private amMember(): boolean {
    return this.tree.containsId(this.me.device.fingerprint);
  }

  private rebuildHeads(): void {
    this.heads = new Set(this.ops.keys());
    for (const op of this.ops.values()) {
      for (const dep of op.deps) this.heads.delete(bytesToHex(dep));
    }
  }
}

function clonePathChange(p: PathChange): PathChange {
  return {
    leafId: p.leafId,
    leafIdx: p.leafIdx,
    leafPk: p.leafPk.kind === 'share' ? { kind: 'share', pk: p.leafPk.pk } : { kind: 'conflict', keys: [...p.leafPk.keys] },
    removedKeys: [...p.removedKeys],
    path: p.path.map(([i, s]) => [i, s.clone()] as [number, SecretStore]),
  };
}

const hexToId = hexToBytes;
