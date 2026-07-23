/**
 * Ordering-auth session (ordering-auth.md v0.2): signed frames end-to-end —
 * A1 auth + §5 rotation, A2 FIFO buffering, A5 dedup, welcome flow (A4),
 * §8 repair. Replicas exchange nothing but serialized frame bytes.
 */

import { blake3 } from '@noble/hashes/blake3';
import { describe, expect, it } from 'vitest';
import { Session } from '../src/ordering.js';
import { encodeFrameBody, generateSigningKeypair, parseFrame, signFrame } from '../src/frames.js';
import { generateShareSecretKey, shareKeyOf, type Csprng } from '../src/keyhive.js';
import { ShareKeyMap } from '../src/keys.js';
import type { DeviceID } from '../src/ids.js';

function testRng(label: string): Csprng {
  let ctr = 0;
  return (n) => blake3(new TextEncoder().encode(`${label}:${ctr++}`), { dkLen: n });
}

interface P {
  device: DeviceID;
  sks: ShareKeyMap;
  leafPk: Uint8Array;
  rng: Csprng;
  signingSk: Uint8Array;
  signingPk: Uint8Array;
}

function partyOf(u: string): P {
  const rng = testRng(u);
  const sk = generateShareSecretKey(rng);
  const leafPk = shareKeyOf(sk);
  const sks = new ShareKeyMap();
  sks.insert(leafPk, sk);
  const kp = generateSigningKeypair(rng);
  return {
    device: { did: `did:${u}`, fingerprint: blake3(new TextEncoder().encode(`fp:${u}`), { dkLen: 32 }) },
    sks,
    leafPk,
    rng,
    signingSk: kp.sk,
    signingPk: kp.pk,
  };
}

function foundSessions(): { sa: Session; sb: Session; sc: Session; ps: P[]; createFrames: Uint8Array[] } {
  const pa = partyOf('alice');
  const pb = partyOf('bob');
  const pc = partyOf('carol');
  const devices = [
    { device: pa.device, leafPk: pa.leafPk, signingPk: pa.signingPk },
    { device: pb.device, leafPk: pb.leafPk, signingPk: pb.signingPk },
    { device: pc.device, leafPk: pc.leafPk, signingPk: pc.signingPk },
  ];
  const sa = Session.createGroup(devices, ['did:alice'], pa.signingSk, pa.sks, pa.rng);
  const createFrames = sa.takeOutbox();
  const sb = Session.fromFrames(createFrames, pb.device, pb.signingSk, pb.sks, pb.rng);
  const sc = Session.fromFrames(createFrames, pc.device, pc.signingSk, pc.sks, pc.rng);
  sb.takeOutbox();
  sc.takeOutbox();
  return { sa, sb, sc, ps: [pa, pb, pc], createFrames };
}

const text = (s: string) => new TextEncoder().encode(s);

describe('ordering-auth Session', () => {
  it('frame-only end-to-end: create → update → app both directions', () => {
    const { sa, sb, sc } = foundSessions();
    const u0 = sa.update();
    sb.ingestFrame(u0);
    sc.ingestFrame(u0);
    expect(sa.engine.treeHash()).toBe(sb.engine.treeHash());
    expect(sb.engine.treeHash()).toBe(sc.engine.treeHash());

    const got: string[] = [];
    // app: a → b, c
    const appFrame = sa.sendApp(text('over frames'));
    let pt = '';
    const sb2 = sb as unknown as { events: { onAppMessage?: (p: Uint8Array) => void } };
    sb2.events.onAppMessage = (p: Uint8Array) => {
      pt = new TextDecoder().decode(p);
    };
    sb.ingestFrame(appFrame);
    expect(pt).toBe('over frames');
    // app: b → a (rotated keys in play: update rotated alice's signing key)
    const back = sb.sendApp(text('reply'));
    const sa2 = sa as unknown as { events: { onAppMessage?: (p: Uint8Array) => void } };
    sa2.events.onAppMessage = (p: Uint8Array) => got.push(new TextDecoder().decode(p));
    sa.ingestFrame(back);
    expect(got).toEqual(['reply']);
  });

  it('A2/A3: out-of-order control frames buffer and drain in order', () => {
    const { sa, sb } = foundSessions();
    const f1 = sa.update();
    const f2 = sa.coverage(); // ctrlSeq consecutive after the update
    // Deliver in reverse: f2 must buffer (ctrlSeq gap + missing dep), then drain.
    sb.ingestFrame(f2);
    expect(sb.bufferedCount()).toBe(1);
    sb.ingestFrame(f1);
    expect(sb.bufferedCount()).toBe(0);
    expect(sb.engine.treeHash()).toBe(sa.engine.treeHash());
  });

  it('A5: duplicate frames are no-ops; tampered signatures are dropped, not buffered', () => {
    const { sa, sb } = foundSessions();
    const f1 = sa.update();
    sb.ingestFrame(f1);
    const hashAfter = sb.engine.treeHash();
    sb.ingestFrame(f1); // dup
    expect(sb.engine.treeHash()).toBe(hashAfter);

    // Tamper: re-sign alice's next frame under a wrong key.
    const f2 = sa.coverage();
    const parsed = parseFrame(f2);
    const wrongKp = generateSigningKeypair(testRng('mallory'));
    const forged = signFrame(parsed.bodyBytes, wrongKp.sk);
    const dropped: string[] = [];
    const sbAny = sb as unknown as { events: { onDropped?: (r: string) => void } };
    sbAny.events.onDropped = (r: string) => dropped.push(r);
    sb.ingestFrame(forged);
    expect(dropped).toContain('bad-signature');
    expect(sb.bufferedCount()).toBe(0);
    // The genuine frame still lands.
    sb.ingestFrame(f2);
    expect(sb.engine.treeHash()).toBe(sa.engine.treeHash());
  });

  it('§5 rotation: pre-rotation key cannot sign post-rotation seqs', () => {
    const { sa, sb, ps } = foundSessions();
    const u0 = sa.update(); // alice rotates: frames after u0 use the new key
    sb.ingestFrame(u0);
    // Forge a frame at a higher seq signed with alice's ORIGINAL key.
    const parsed = parseFrame(u0);
    const forgedBody = { ...parsed.body, seq: parsed.body.seq + 5, ctrlSeq: parsed.body.ctrlSeq! + 1 };
    const bodyBytes = encodeFrameBody(forgedBody);
    const forged = signFrame(bodyBytes, ps[0]!.signingSk); // original founding key
    const dropped: string[] = [];
    const sbAny = sb as unknown as { events: { onDropped?: (r: string) => void } };
    sbAny.events.onDropped = (r: string) => dropped.push(r);
    sb.ingestFrame(forged);
    expect(dropped).toContain('bad-signature');
  });

  it('A4 welcome: joiner boots from the welcome, heals, and converses', () => {
    const { sa, sb, sc } = foundSessions();
    const u0 = sa.update();
    sb.ingestFrame(u0);
    sc.ingestFrame(u0);
    const pd = partyOf('dave');
    const { frame: addFrame, addOpId } = sa.add(pd.device, pd.leafPk, pd.signingPk);
    sb.ingestFrame(addFrame);
    sc.ingestFrame(addFrame);
    const welcome = sa.buildWelcome(addOpId);
    const sd = Session.fromWelcome(welcome, pd.device, pd.signingSk, pd.sks, pd.rng);
    sd.takeOutbox();
    expect(sd.engine.treeHash()).toBe(sa.engine.treeHash());
    // Healing rule: dave updates immediately (mandatory post-join self-update).
    const uD = sd.update();
    for (const s of [sa, sb, sc]) s.ingestFrame(uD);
    expect(sa.engine.treeHash()).toBe(sd.engine.treeHash());
    // Dave speaks; everyone hears.
    const msg = sd.sendApp(text('hi, I am new'));
    let heard = '';
    const scAny = sc as unknown as { events: { onAppMessage?: (p: Uint8Array) => void } };
    scAny.events.onAppMessage = (p: Uint8Array) => {
      heard = new TextDecoder().decode(p);
    };
    sc.ingestFrame(msg);
    expect(heard).toBe('hi, I am new');
  });

  it('§8 repair: gap detected, request served from retained frames, drained', () => {
    const { sa, sb } = foundSessions();
    const f1 = sa.update();
    const f2 = sa.coverage();
    sb.ingestFrame(f2); // f1 missing → buffered
    expect(sb.bufferedCount()).toBe(1);
    const req = sb.buildRepairRequest();
    expect(req).not.toBeNull();
    const resent = sa.serveRepair(req!);
    expect(resent.length).toBeGreaterThan(0);
    for (const r of resent) sb.ingestFrame(r);
    expect(sb.bufferedCount()).toBe(0);
    expect(sb.engine.treeHash()).toBe(sa.engine.treeHash());
  });

  it('concurrent membership over frames converges (three-way, mixed delivery)', () => {
    const { sa, sb, sc } = foundSessions();
    const u0 = sa.update();
    sb.ingestFrame(u0);
    sc.ingestFrame(u0);
    const carolMembership = sa.engine.members().find((m) => m.device.did === 'did:carol')!;
    const rm = sa.remove(carolMembership);
    const uB = sb.update();
    sa.ingestFrame(uB);
    sb.ingestFrame(rm);
    sc.ingestFrame(rm);
    sc.ingestFrame(uB);
    sa.engine.settle();
    sb.engine.settle();
    expect(sa.engine.treeHash()).toBe(sb.engine.treeHash());
    const u2 = sa.update();
    sb.ingestFrame(u2);
    const msg = sb.sendApp(text('after the storm'));
    let heard = '';
    const saAny = sa as unknown as { events: { onAppMessage?: (p: Uint8Array) => void } };
    saAny.events.onAppMessage = (p: Uint8Array) => {
      heard = new TextDecoder().decode(p);
    };
    sa.ingestFrame(msg);
    expect(heard).toBe('after the storm');
  });
});
