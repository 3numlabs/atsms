/**
 * Engine integration (beekem-core §4–§10): multi-replica convergence, DGM
 * filter, rootCommit, chains/FS, coverage/eviction, checkpoints.
 */

import { blake3 } from '@noble/hashes/blake3';
import { describe, expect, it } from 'vitest';
import { Engine } from '../src/engine.js';
import { generateShareSecretKey, shareKeyOf, type Csprng } from '../src/keyhive.js';
import { ShareKeyMap } from '../src/keys.js';
import type { DeviceID } from '../src/ids.js';
import { makeOp } from '../src/ops.js';

function testRng(label: string): Csprng {
  let ctr = 0;
  return (n) => blake3(new TextEncoder().encode(`${label}:${ctr++}`), { dkLen: n });
}

interface Party {
  device: DeviceID;
  sks: ShareKeyMap;
  leafPk: Uint8Array;
  rng: Csprng;
}

function party(u: string, d = 0): Party {
  const rng = testRng(`${u}-${d}`);
  const sk = generateShareSecretKey(rng);
  const leafPk = shareKeyOf(sk);
  const sks = new ShareKeyMap();
  sks.insert(leafPk, sk);
  return {
    device: { did: `did:${u}`, fingerprint: blake3(new TextEncoder().encode(`${u}/${d}`), { dkLen: 32 }) },
    sks,
    leafPk,
    rng,
  };
}

/** Found a 3-party group; returns engines for alice (admin), bob, carol. */
function found(): { a: Engine; b: Engine; c: Engine; parties: Party[] } {
  const pa = party('alice');
  const pb = party('bob');
  const pc = party('carol');
  const devices = [
    { device: pa.device, leafPk: pa.leafPk },
    { device: pb.device, leafPk: pb.leafPk },
    { device: pc.device, leafPk: pc.leafPk },
  ];
  const a = Engine.create(devices, ['did:alice'], pa.sks, pa.rng);
  const log = [a.bootstrapOp()];
  const b = Engine.fromOpLog(log, pb.device, pb.sks, pb.rng);
  const c = Engine.fromOpLog(log, pc.device, pc.sks, pc.rng);
  return { a, b, c, parties: [pa, pb, pc] };
}

const text = (s: string) => new TextEncoder().encode(s);

describe('Engine', () => {
  it('founding + first update: shared epoch, app messages round-trip', () => {
    const { a, b, c } = found();
    expect(a.hasRootKey()).toBe(false);
    const u = a.buildUpdate();
    b.ingest(u);
    c.ingest(u);
    expect(a.treeHash()).toBe(b.treeHash());
    expect(b.treeHash()).toBe(c.treeHash());
    expect(a.currentEpoch()).toBe(b.currentEpoch());
    const msg = a.sendApp(text('hello group'));
    expect(new TextDecoder().decode(b.receiveApp(msg))).toBe('hello group');
    expect(new TextDecoder().decode(c.receiveApp(msg))).toBe('hello group');
    // Cross-direction in the same epoch.
    const msgB = b.sendApp(text('hi back'));
    expect(new TextDecoder().decode(a.receiveApp(msgB))).toBe('hi back');
  });

  it('concurrent add ∥ update: replicas converge after settle, joiner included next epoch', () => {
    const { a, b, c } = found();
    const u0 = a.buildUpdate();
    b.ingest(u0);
    c.ingest(u0);
    // Concurrently: alice adds dave; bob updates.
    const pd = party('dave');
    const addOp = a.buildAdd(pd.device, pd.leafPk);
    const uB = b.buildUpdate();
    a.ingest(uB);
    b.ingest(addOp);
    c.ingest(addOp);
    c.ingest(uB);
    a.settle();
    b.settle();
    c.settle();
    expect(a.treeHash()).toBe(b.treeHash());
    expect(b.treeHash()).toBe(c.treeHash());
    // Dave joins from the log; a fresh update readmits everyone incl. dave.
    const d = Engine.fromOpLog([a.bootstrapOp(), u0, addOp, uB], pd.device, pd.sks, pd.rng);
    d.settle();
    expect(d.treeHash()).toBe(a.treeHash());
    const uC = c.buildUpdate();
    for (const e of [a, b, d]) e.ingest(uC);
    const msg = c.sendApp(text('welcome dave'));
    expect(new TextDecoder().decode(d.receiveApp(msg))).toBe('welcome dave');
    expect(new TextDecoder().decode(a.receiveApp(msg))).toBe('welcome dave');
  });

  it('remove excludes the target from the next epoch (update-first rule)', () => {
    const { a, b, c } = found();
    const u0 = a.buildUpdate();
    b.ingest(u0);
    c.ingest(u0);
    const carolMembership = a.members().find((m) => m.device.did === 'did:carol')!;
    const rm = a.buildRemove(carolMembership);
    b.ingest(rm);
    expect(a.hasRootKey()).toBe(false); // blanked — must update before sending
    expect(() => a.sendApp(text('x'))).toThrow(/NoRootKey/);
    const u1 = b.buildUpdate();
    a.ingest(u1);
    const msg = a.sendApp(text('post-removal'));
    expect(new TextDecoder().decode(b.receiveApp(msg))).toBe('post-removal');
    expect(a.members().some((m) => m.device.did === 'did:carol')).toBe(false);
  });

  it('DGM filter: an unauthorized add is causal history but never touches the tree', () => {
    const { a, b, c } = found();
    const u0 = a.buildUpdate();
    b.ingest(u0);
    c.ingest(u0);
    // Bob (not admin) can't build a cross-DID add locally…
    const pe = party('eve');
    expect(() => b.buildAdd(pe.device, pe.leafPk)).toThrow(/Unauthorized/);
    // …and a hand-crafted one is filtered on ingest (op recorded, tree unchanged).
    const bobMembership = b.members().find((m) => m.device.did === 'did:bob')!;
    const forged = makeOp(bobMembership, [u0.id], {
      type: 'add',
      device: pe.device,
      leafPk: pe.leafPk,
      leafIndex: 3,
    });
    const before = a.treeHash();
    a.ingest(forged);
    a.settle();
    expect(a.isValidOp(forged.id)).toBe(false);
    expect(a.treeHash()).toBe(before);
    expect(a.members().some((m) => m.device.did === 'did:eve')).toBe(false);
  });

  it('rootCommit mismatch: op rejected with no state change (beekem-core §4.3)', () => {
    const { a, b } = found();
    const u0 = a.buildUpdate();
    b.ingest(u0);
    const u1 = b.buildUpdate();
    const tampered = {
      ...u1,
      payload: {
        ...(u1.payload as Extract<typeof u1.payload, { type: 'update' }>),
        rootCommit: blake3(new Uint8Array(1), { dkLen: 32 }),
      },
    };
    const before = a.treeHash();
    expect(() => a.ingest(tampered)).toThrow(/RootCommitMismatch/);
    expect(a.treeHash()).toBe(before);
    expect(a.opCount()).toBe(2); // create + u0 only
    // The untampered op still ingests cleanly afterwards.
    a.ingest(u1);
    expect(a.treeHash()).toBe(b.treeHash());
  });

  it('chains: out-of-order delivery, single-use skipped keys', () => {
    const { a, b } = found();
    const u0 = a.buildUpdate();
    b.ingest(u0);
    const m0 = a.sendApp(text('zero'));
    const m1 = a.sendApp(text('one'));
    const m2 = a.sendApp(text('two'));
    expect(new TextDecoder().decode(b.receiveApp(m2))).toBe('two'); // skips 0,1
    expect(new TextDecoder().decode(b.receiveApp(m0))).toBe('zero');
    expect(() => b.receiveApp(m0)).toThrow(/SecretReuse/); // single-use
    expect(new TextDecoder().decode(b.receiveApp(m1))).toBe('one');
  });

  it('FS: a closed epoch is undecryptable-by-design', () => {
    const { a, b, c } = found();
    const u0 = a.buildUpdate();
    b.ingest(u0);
    c.ingest(u0);
    const e1 = a.currentEpoch()!;
    const late = a.sendApp(text('late message'));
    // Move to a fresh epoch, then evict e1 on the receiver.
    const u1 = b.buildUpdate();
    a.ingest(u1);
    c.ingest(u1);
    c.closeEpoch(e1);
    expect(() => c.receiveApp(late)).toThrow(/EpochClosed/);
    // A replica that has not evicted (within grace) still decrypts.
    expect(new TextDecoder().decode(b.receiveApp(late))).toBe('late message');
  });

  it('coverage: gcEpochs closes superseded epochs once covered-by-all', () => {
    const { a, b, c } = found();
    const u0 = a.buildUpdate();
    b.ingest(u0);
    c.ingest(u0);
    const e1 = a.currentEpoch()!;
    const u1 = b.buildUpdate(); // covers u0 for bob
    a.ingest(u1);
    c.ingest(u1);
    expect(a.coveredByAll(e1)).toBe(false); // carol hasn't spoken since u0
    const cov = c.buildCoverage();
    a.ingest(cov);
    b.ingest(cov);
    // alice covers via her next op:
    const covA = a.buildCoverage();
    b.ingest(covA);
    c.ingest(covA);
    expect(a.coveredByAll(e1)).toBe(true);
    expect(a.gcEpochs()).toContain(e1);
  });

  it('three-way concurrency (add ∥ remove ∥ update) converges across delivery orders', () => {
    const { a, b, c } = found();
    const u0 = a.buildUpdate();
    b.ingest(u0);
    c.ingest(u0);
    // Concurrently: alice adds dave, alice's co-replica... use three distinct authors:
    // alice removes carol, bob updates, carol adds her second device (same-DID — SR1 will kill it).
    const carolMembership = a.members().find((m) => m.device.did === 'did:carol')!;
    const rm = a.buildRemove(carolMembership);
    const uB = b.buildUpdate();
    const pc2 = party('carol', 1);
    const selfAdd = c.buildAdd(pc2.device, pc2.leafPk); // same-DID add, concurrent with rm
    // Deliver in different orders per replica.
    a.ingest(uB);
    a.ingest(selfAdd);
    b.ingest(selfAdd);
    b.ingest(rm);
    c.ingest(rm);
    c.ingest(uB);
    a.settle();
    b.settle();
    c.settle();
    expect(a.treeHash()).toBe(b.treeHash());
    expect(b.treeHash()).toBe(c.treeHash());
    // SR1: carol out, and her concurrent same-DID add cascaded away.
    const dids = new Set(a.members().map((m) => m.device.did));
    expect(dids).toEqual(new Set(['did:alice', 'did:bob']));
    expect(a.isValidOp(selfAdd.id)).toBe(false);
    // Fresh epoch: survivors converse.
    const u2 = a.buildUpdate();
    b.ingest(u2);
    const msg = b.sendApp(text('survivors'));
    expect(new TextDecoder().decode(a.receiveApp(msg))).toBe('survivors');
  });

  it('checkpoint: prune behind covered-by-all frontier; state matches full-history replica', () => {
    const { a, b, c } = found();
    const u0 = a.buildUpdate();
    b.ingest(u0);
    c.ingest(u0);
    const covB = b.buildCoverage();
    const covC = c.buildCoverage();
    for (const [e, ops] of [
      [a, [covB, covC]],
      [b, [covC]],
      [c, [covB]],
    ] as const) {
      for (const op of ops) e.ingest(op);
    }
    const covA = a.buildCoverage();
    b.ingest(covA);
    c.ingest(covA);
    const before = a.opCount();
    expect(a.advanceCheckpoint()).toBe(true);
    expect(a.opCount()).toBeLessThan(before);
    // Continue after the checkpoint: b updates; a (pruned) and c (full) converge.
    const u1 = b.buildUpdate();
    a.ingest(u1);
    c.ingest(u1);
    a.settle();
    c.settle();
    expect(a.treeHash()).toBe(c.treeHash());
    const msg = b.sendApp(text('post-checkpoint'));
    expect(new TextDecoder().decode(a.receiveApp(msg))).toBe('post-checkpoint');
  });
});
