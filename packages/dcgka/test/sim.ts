/**
 * Deterministic simulation harness (implementation-plan Phase 2 quality gate):
 * N in-memory Sessions over a lossy / reordering / duplicating / partitioning
 * fake mailbox, driven by a seeded PRNG. Asserts (in the driving test):
 *   - live members converge to an identical tree hash + member set,
 *   - end-to-end app delivery after a settling update,
 *   - buffers stay bounded,
 *   - no unhandled errors across fuzzed schedules.
 *
 * Everything is seeded (harness scheduling + per-client key material), so any
 * failure reproduces from its seed alone.
 */

import { blake3 } from '@noble/hashes/blake3';
import { Session } from '../src/ordering.js';
import { generateSigningKeypair, parseFrame, CLS_WELCOME, CLS_REPAIR } from '../src/frames.js';
import { generateShareSecretKey, shareKeyOf, type Csprng } from '../src/keyhive.js';
import { ShareKeyMap } from '../src/keys.js';
import { bytesToHex } from '../src/bytes.js';
import type { DeviceID, Membership } from '../src/ids.js';

/** mulberry32 — small deterministic PRNG for scheduling choices. */
function mulberry32(seed: number): () => number {
  let s = seed >>> 0;
  return () => {
    s = (s + 0x6d2b79f5) | 0;
    let t = Math.imul(s ^ (s >>> 15), 1 | s);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

function labelRng(label: string): Csprng {
  let ctr = 0;
  return (n) => blake3(new TextEncoder().encode(`${label}:${ctr++}`), { dkLen: n });
}

interface PoolDevice {
  device: DeviceID;
  leafSk: Uint8Array;
  leafPk: Uint8Array;
  signingSk: Uint8Array;
  signingPk: Uint8Array;
  rng: Csprng;
}

function poolDevice(name: string): PoolDevice {
  const rng = labelRng(name);
  const leafSk = generateShareSecretKey(rng);
  const kp = generateSigningKeypair(rng);
  return {
    device: { did: `did:${name}`, fingerprint: blake3(new TextEncoder().encode(`fp:${name}`), { dkLen: 32 }) },
    leafSk,
    leafPk: shareKeyOf(leafSk),
    signingSk: kp.sk,
    signingPk: kp.pk,
    rng,
  };
}

interface Client {
  idx: number;
  pd: PoolDevice;
  session: Session;
  online: boolean;
  removed: boolean;
  received: string[]; // decrypted app plaintexts
}

interface Wire {
  to: number;
  raw: Uint8Array;
  cls: number; // parsed once at enqueue (avoids re-parsing in the delivery hot path)
}

export interface SimStats {
  seed: number;
  steps: number;
  adds: number;
  removes: number;
  updates: number;
  apps: number;
  drops: number;
  dups: number;
  maxBuffered: number;
  finalMembers: number;
}

export interface SimOptions {
  founding: number; // initial member count
  poolSize: number; // total devices available (founding + addable)
  steps: number;
  lossProb: number;
  dupProb: number;
  offlineProb: number;
  maxGroup: number;
}

/**
 * Run one simulation. Returns stats; throws (with the seed) on any invariant
 * violation the harness itself can detect. Convergence assertions are returned
 * for the caller to `expect`, keyed so failures name the seed.
 */
export function runSim(seed: number, opt: SimOptions): {
  stats: SimStats;
  liveHashes: Map<number, string>;
  liveMembers: Map<number, number>;
  appDelivered: { expected: number; got: number };
} {
  const rnd = mulberry32(seed);
  const pick = <T>(arr: T[]): T => arr[Math.floor(rnd() * arr.length)]!;
  const chance = (p: number) => rnd() < p;

  const pool = Array.from({ length: opt.poolSize }, (_, i) => poolDevice(`c${seed}_${i}`));
  const clients: Client[] = [];
  const wire: Wire[] = [];
  const stats: SimStats = {
    seed,
    steps: 0,
    adds: 0,
    removes: 0,
    updates: 0,
    apps: 0,
    drops: 0,
    dups: 0,
    maxBuffered: 0,
    finalMembers: 0,
  };

  const mkEvents = (rec: string[]) => ({
    onAppMessage: (pt: Uint8Array) => rec.push(new TextDecoder().decode(pt)),
    onSecurityEvent: (kind: string, detail: string) => {
      // Security events are expected only for genuinely bad inputs; the harness
      // never injects those, so any occurrence is a real defect.
      throw new Error(`unexpected security event: ${kind} ${detail} (seed ${seed})`);
    },
    onDropped: () => {},
  });

  // ── founding ────────────────────────────────────────────────────────────
  const foundingDevs = pool.slice(0, opt.founding);
  const alice = foundingDevs[0]!;
  const aliceRec: string[] = [];
  const aliceSession = Session.createGroup(
    foundingDevs.map((d) => ({ device: d.device, leafPk: d.leafPk, signingPk: d.signingPk })),
    [alice.device.did],
    alice.signingSk,
    seedSks(alice),
    alice.rng,
    mkEvents(aliceRec),
  );
  const createFrames = aliceSession.takeOutbox();
  clients.push({ idx: 0, pd: alice, session: aliceSession, online: true, removed: false, received: aliceRec });
  for (let i = 1; i < opt.founding; i++) {
    const pd = foundingDevs[i]!;
    const rec: string[] = [];
    const s = Session.fromFrames(createFrames, pd.device, pd.signingSk, seedSks(pd), pd.rng, mkEvents(rec));
    s.takeOutbox();
    clients.push({ idx: i, pd, session: s, online: true, removed: false, received: rec });
  }
  let nextPool = opt.founding;

  const live = () => clients.filter((c) => !c.removed);
  const onlineLive = () => live().filter((c) => c.online);

  const pump = (c: Client): void => {
    for (const raw of c.session.takeOutbox()) enqueueBroadcast(c.idx, raw);
  };

  function enqueueBroadcast(fromIdx: number, raw: Uint8Array): void {
    enqueueFrom(fromIdx, raw);
  }

  /** Broadcast a frame to every live peer (welcomes are point-to-point — dropped). */
  function enqueueFrom(fromIdx: number, raw: Uint8Array): void {
    const cls = parseFrame(raw).body.cls;
    if (cls === CLS_WELCOME) return;
    for (const c of clients) {
      if (c.idx === fromIdx || c.removed) continue;
      wire.push({ to: c.idx, raw, cls });
    }
  }

  /** True while any frame remains that could still be delivered to someone. */
  function deliverablePending(): boolean {
    return wire.some((w) => (clients[w.to]!.removed ? w.cls === CLS_REPAIR : true));
  }

  function deliverOne(reliable: boolean): void {
    // Purge frames that can never be delivered (non-repair frames whose target
    // was removed after enqueue) so reliable delivery always makes progress.
    for (let i = wire.length - 1; i >= 0; i--) {
      const w = wire[i]!;
      if (clients[w.to]!.removed && w.cls !== CLS_REPAIR) wire.splice(i, 1);
    }
    // Removed clients still serve repair requests (they retain the frames they
    // authored/processed — every op is retained by its author forever), but
    // receive no other traffic.
    const deliverable = wire
      .map((w, i) => ({ w, i }))
      .filter(({ w }) => {
        const t = clients[w.to]!;
        if (t.removed) return w.cls === CLS_REPAIR;
        return t.online || reliable;
      });
    if (deliverable.length === 0) return;
    const chosen = deliverable[Math.floor(rnd() * deliverable.length)]!;
    const { w } = chosen;
    // Loss.
    if (!reliable && chance(opt.lossProb)) {
      wire.splice(chosen.i, 1);
      stats.drops += 1;
      return;
    }
    // Duplication: leave in the wire.
    const dup = !reliable && chance(opt.dupProb);
    if (!dup) wire.splice(chosen.i, 1);
    else stats.dups += 1;
    const target = clients[w.to]!;
    target.session.ingestFrame(w.raw);
    stats.maxBuffered = Math.max(stats.maxBuffered, target.session.bufferedCount());
    // Drain outputs (repair responses); removed servers broadcast to live peers.
    for (const raw of target.session.takeOutbox()) enqueueFrom(target.idx, raw);
  }

  // ── fuzz loop ─────────────────────────────────────────────────────────────
  for (let step = 0; step < opt.steps; step++) {
    stats.steps += 1;
    const roll = rnd();
    if (roll < 0.45) {
      // deliver
      deliverOne(false);
    } else if (roll < 0.6) {
      // update (any online live client)
      const actors = onlineLive();
      if (actors.length > 0) {
        const c = pick(actors);
        try {
          c.session.update();
          stats.updates += 1;
          pump(c);
        } catch {
          /* update-before-settle edge; skip */
        }
      }
    } else if (roll < 0.72) {
      // coverage
      const actors = onlineLive();
      if (actors.length > 0) {
        const c = pick(actors);
        c.session.coverage();
        pump(c);
      }
    } else if (roll < 0.85) {
      // app (needs a live epoch)
      const actors = onlineLive().filter((c) => c.session.engine.currentEpoch() !== null);
      if (actors.length > 0) {
        const c = pick(actors);
        c.session.sendApp(new TextEncoder().encode(`app-${c.idx}-${step}`));
        stats.apps += 1;
        pump(c);
      }
    } else if (roll < 0.9) {
      // add (alice only, if pool + capacity remain)
      if (nextPool < opt.poolSize && live().length < opt.maxGroup && !clients[0]!.removed) {
        const pd = pool[nextPool]!;
        nextPool += 1;
        try {
          const { frame, addOpId } = clients[0]!.session.add(pd.device, pd.leafPk, pd.signingPk);
          const welcome = clients[0]!.session.buildWelcome(addOpId);
          // Bootstrap the joiner from the welcome; then it heals immediately.
          const rec: string[] = [];
          const joiner = Session.fromWelcome(welcome, pd.device, pd.signingSk, seedSks(pd), pd.rng, mkEvents(rec));
          joiner.takeOutbox();
          const jc: Client = { idx: clients.length, pd, session: joiner, online: true, removed: false, received: rec };
          clients.push(jc);
          stats.adds += 1;
          // Broadcast the add to existing members; deliver the welcome frame nowhere.
          void frame;
          pump(clients[0]!);
          // Mandatory post-join self-update (healing rule, beekem-core §6).
          joiner.update();
          pump(jc);
        } catch {
          /* add raced a pending structural change; skip */
        }
      }
    } else if (roll < 0.94) {
      // remove (alice removes a random other live member; never the last two)
      const targets = live().filter((c) => c.idx !== 0);
      if (targets.length > 0 && live().length > 2 && !clients[0]!.removed) {
        const victim = pick(targets);
        const m = clients[0]!.session.engine
          .members()
          .find((mm: Membership) => bytesToHex(mm.device.fingerprint) === bytesToHex(victim.pd.device.fingerprint));
        if (m !== undefined) {
          try {
            clients[0]!.session.remove(m);
            victim.removed = true;
            stats.removes += 1;
            pump(clients[0]!);
          } catch {
            /* remove raced; skip */
          }
        }
      }
    } else {
      // toggle online/offline (never alice — she stays reachable)
      const togglers = clients.filter((c) => c.idx !== 0 && !c.removed);
      if (togglers.length > 0) {
        const c = pick(togglers);
        c.online = chance(opt.offlineProb) ? false : !c.online;
      }
    }
  }

  // ── settle: everyone online, reliable delivery + repair to quiescence ──────
  for (const c of clients) c.online = true;
  settle(clients, wire, deliverReliable, seed);

  function deliverReliable(): boolean {
    let delivered = false;
    let guard = 0;
    while (deliverablePending()) {
      const before = wire.length;
      deliverOne(true);
      delivered = true;
      if (wire.length >= before && ++guard > 200000) throw new Error(`deliver loop stalled (seed ${seed})`);
    }
    return delivered;
  }

  for (const c of live()) c.session.engine.settle();

  // ── finalize: alice updates to a clean root, then broadcasts one app ───────
  clients[0]!.session.update();
  pump(clients[0]!);
  settle(clients, wire, deliverReliable, seed);
  for (const c of live()) c.session.engine.settle();

  const marker = `FINAL-${seed}`;
  clients[0]!.session.sendApp(new TextEncoder().encode(marker));
  pump(clients[0]!);
  settle(clients, wire, deliverReliable, seed);

  // ── collect convergence data ───────────────────────────────────────────────
  const liveHashes = new Map<number, string>();
  const liveMembers = new Map<number, number>();
  for (const c of live()) {
    liveHashes.set(c.idx, c.session.engine.treeHash());
    liveMembers.set(c.idx, c.session.engine.members().length);
  }
  stats.finalMembers = live().length;
  const nonAliceLive = live().filter((c) => c.idx !== 0);
  const appDelivered = {
    expected: nonAliceLive.length,
    got: nonAliceLive.filter((c) => c.received.includes(marker)).length,
  };

  return { stats, liveHashes, liveMembers, appDelivered };
}

function seedSks(pd: PoolDevice): ShareKeyMap {
  const sks = new ShareKeyMap();
  sks.insert(pd.leafPk, pd.leafSk);
  return sks;
}

/**
 * Reach a converged state using the protocol's OWN head-reconciliation
 * mechanism (dgm §8), not a harness cheat: every live member reliably delivers
 * what it has and then **advertises its frontier** (a coverage frame whose deps
 * are its heads). A peer missing any advertised op buffers the advertisement
 * and recovers the gap via end-to-end repair (ordering-auth §8). Iterating this
 * drives all live members to one op set → one head-set → one tree.
 *
 * The lossy/reorder/dup/partition faults belong to the fuzz phase; settle runs
 * reliably so it exercises reconciliation, not the transport.
 */
function settle(clients: Client[], wire: Wire[], _deliverAll: () => boolean, seed: number): void {
  const live = () => clients.filter((c) => !c.removed);
  const deliverToLive = (raw: Uint8Array): void => {
    if (parseFrame(raw).body.cls === CLS_WELCOME) return;
    for (const c of live()) c.session.ingestFrame(raw);
  };
  // Broadcast every client's pending outbox to all live members until stable.
  const drainOutboxes = (): void => {
    for (let guard = 0; guard < 10000; guard++) {
      let any = false;
      for (const c of clients) {
        for (const raw of c.session.takeOutbox()) {
          any = true;
          deliverToLive(raw);
        }
      }
      if (!any) return;
    }
    throw new Error(`drainOutboxes runaway (seed ${seed})`);
  };
  // End-to-end repair: each buffering client asks every peer (removed peers
  // still retain and serve) until its buffer drains.
  const repairDrain = (): void => {
    for (let round = 0; round < 200; round++) {
      const stuck = live().filter((c) => c.session.bufferedCount() > 0);
      if (stuck.length === 0) return;
      let progressed = false;
      for (const c of stuck) {
        const before = c.session.bufferedCount();
        const req = c.session.buildRepairRequest();
        if (req === null) continue;
        for (const server of clients) {
          if (server.idx === c.idx) continue;
          for (const resp of server.session.serveRepair(req)) c.session.ingestFrame(resp);
        }
        if (c.session.bufferedCount() < before) progressed = true;
      }
      if (!progressed) return;
    }
  };

  // Deliver whatever is still on the wire reliably, then drain + repair.
  for (const w of wire) if (!clients[w.to]!.removed) clients[w.to]!.session.ingestFrame(w.raw);
  wire.length = 0;
  drainOutboxes();
  repairDrain();

  const converged = (): boolean => {
    const sets = live().map((c) => [...c.session.headSet()].sort().join(','));
    return new Set(sets).size <= 1 && live().every((c) => c.session.bufferedCount() === 0);
  };

  const CAP = 40;
  for (let round = 0; round < CAP && !converged(); round++) {
    for (const c of live()) c.session.advertiseHeads(); // coverage frame = frontier advert
    drainOutboxes(); // deliver adverts; missing-dep receivers buffer
    repairDrain(); // recover the gaps the adverts exposed
    drainOutboxes(); // propagate anything repair unblocked
  }
  if (!converged()) {
    const stuck = live().filter((c) => c.session.bufferedCount() > 0).length;
    const sets = new Set(live().map((c) => [...c.session.headSet()].sort().join(',')));
    throw new Error(
      `settle did not converge (seed ${seed}): ${stuck} buffering, ${sets.size} distinct head-sets`,
    );
  }
}
