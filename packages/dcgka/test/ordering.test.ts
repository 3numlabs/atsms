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

  it('§8 trigger surface: requestRepair queues on the outbox; served via ingest', () => {
    const { sa, sb } = foundSessions();
    sa.update();
    sb.ingestFrame(sa.coverage()); // the update is missing → buffered
    expect(sb.requestRepair()).toBe(true);
    const [reqFrame, ...rest] = sb.takeOutbox();
    expect(rest.length).toBe(0);
    sa.ingestFrame(reqFrame!); // the serving side answers from inside ingest
    for (const resp of sa.takeOutbox()) sb.ingestFrame(resp);
    expect(sb.bufferedCount()).toBe(0);
    expect(sb.engine.treeHash()).toBe(sa.engine.treeHash());
    expect(sb.requestRepair()).toBe(false); // nothing left to repair
  });

  it('head reconciliation: a member missing ops recovers them from a frontier advert (dgm §8)', () => {
    const { sa, sb, sc } = foundSessions();
    // Alice and Carol advance; Bob is partitioned and misses everything.
    const u0 = sa.update();
    sc.ingestFrame(u0);
    const cov = sc.coverage();
    sa.ingestFrame(cov);
    const u1 = sa.update();
    sc.ingestFrame(u1);
    // Bob is behind and, crucially, has NOTHING buffered — he cannot know what
    // he's missing until someone advertises their frontier.
    expect(sb.bufferedCount()).toBe(0);
    expect([...sb.headSet()].sort()).not.toEqual([...sa.headSet()].sort());

    // Alice advertises her frontier (coverage frame; deps = her heads). Bob
    // receives it, cannot process it (missing deps), and buffers it.
    const advert = sa.advertiseHeads();
    sb.ingestFrame(advert);
    expect(sb.bufferedCount()).toBeGreaterThan(0);

    // Bob repairs the exposed gap end-to-end; Alice serves the missing frames.
    let guard = 0;
    while (sb.bufferedCount() > 0 && guard++ < 20) {
      const req = sb.buildRepairRequest();
      expect(req).not.toBeNull();
      for (const resp of sa.serveRepair(req!)) sb.ingestFrame(resp);
    }
    // Bob now shares Alice's op set → identical frontier and tree.
    expect([...sb.headSet()].sort()).toEqual([...sa.headSet()].sort());
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

  it('a welcome must not leave a ctrlSeq gap for existing members (add → update → welcome ×2)', () => {
    // Live-failure regression: the welcome is point-to-point (only the joiner
    // ever receives it), so it must not occupy a slot in the sender's broadcast
    // ctrlSeq contiguity chain — otherwise every existing member buffers the
    // NEXT control frame forever, waiting for a frame that will never arrive.
    const { sa, sb } = foundSessions();
    const u0 = sa.update();
    sb.ingestFrame(u0);

    // Alice runs the live addMember orchestration twice (add → update →
    // welcome), exactly as ConversationSession.addMember does — one call per
    // joining device. Bob receives everything EXCEPT the welcomes.
    for (const name of ['dave', 'erin']) {
      const pj = partyOf(name);
      const { frame: addFrame, addOpId } = sa.add(pj.device, pj.leafPk, pj.signingPk);
      const postAddUpdate = sa.update(); // §4b: adder establishes the post-add epoch
      sa.buildWelcome(addOpId); // sealed asym to the joiner only — Bob never sees it
      sb.ingestFrame(addFrame);
      sb.ingestFrame(postAddUpdate);
    }

    // Nothing may be stranded in Bob's ordering buffer, and the trees agree.
    expect(sb.bufferedCount()).toBe(0);
    expect(sb.engine.treeHash()).toBe(sa.engine.treeHash());

    // And Alice's next message still reaches Bob.
    let heard = '';
    const sbAny = sb as unknown as { events: { onAppMessage?: (p: Uint8Array) => void } };
    sbAny.events.onAppMessage = (p: Uint8Array) => {
      heard = new TextDecoder().decode(p);
    };
    sb.ingestFrame(sa.sendApp(text('still with us, bob?')));
    expect(heard).toBe('still with us, bob?');
  });

  it('leave: removes my own devices last, and the remaining members heal lazily', () => {
    const { sa, sb, sc } = foundSessions();
    const u0 = sa.update();
    sb.ingestFrame(u0);
    sc.ingestFrame(u0);

    // Bob leaves. Same-DID removal needs no admin, so a non-admin can always go.
    expect(sb.amMember()).toBe(true);
    const frames = sb.leave();
    expect(frames.length).toBe(1); // one device for bob in this harness
    for (const f of frames) {
      sa.ingestFrame(f);
      sc.ingestFrame(f);
    }
    expect(sb.amMember(), 'the leaver is out in its own view').toBe(false);
    expect(sa.engine.members().some((m) => m.device.did === 'did:bob')).toBe(false);
    expect(sc.engine.members().some((m) => m.device.did === 'did:bob')).toBe(false);

    // No healing update came from the leaver: the group is rootless until a
    // REMAINING member speaks, and that member's self-heal re-keys it.
    expect(() => sa.sendApp(text('after bob left'))).toThrow(/NoRootKey/);
    const heal = sa.update();
    sc.ingestFrame(heal);
    let heard = '';
    const scAny = sc as unknown as { events: { onAppMessage?: (p: Uint8Array) => void } };
    scAny.events.onAppMessage = (p: Uint8Array) => {
      heard = new TextDecoder().decode(p);
    };
    sc.ingestFrame(sa.sendApp(text('after bob left')));
    expect(heard).toBe('after bob left');
    expect(sa.engine.treeHash()).toBe(sc.engine.treeHash());
  });

  it('leave: a sole admin must appoint a successor first (refuse, then allow)', () => {
    const { sa, sb, sc } = foundSessions(); // alice is the only admin
    const u0 = sa.update();
    sb.ingestFrame(u0);
    sc.ingestFrame(u0);

    // Leaving now would freeze the group — nobody could ever add or remove.
    expect(sa.wouldStrandGroup()).toBe(true);
    expect(() => sa.leave()).toThrow(/LastAdmin/);

    // Appoint Bob, then leaving is allowed.
    const grant = sa.grantAdmin('did:bob');
    sb.ingestFrame(grant);
    sc.ingestFrame(grant);
    expect(sa.wouldStrandGroup()).toBe(false);
    for (const f of sa.leave()) {
      sb.ingestFrame(f);
      sc.ingestFrame(f);
    }
    expect(sa.amMember()).toBe(false);
    expect(sb.engine.admins().has('did:bob'), 'the successor can still run the group').toBe(true);
    expect(sb.engine.members().some((m) => m.device.did === 'did:alice')).toBe(false);
  });

  it('leave: the last member has nothing to leave (local act, not an op)', () => {
    const { sa } = foundSessions();
    sa.update();
    for (const did of ['did:bob', 'did:carol']) {
      const m = sa.engine.members().find((x) => x.device.did === did)!;
      sa.remove(m);
    }
    // No successor needed — but also nobody to tell and nothing to heal, and
    // the tree keeps its last member. The host handles this locally.
    expect(sa.wouldStrandGroup(), 'nobody left to strand').toBe(false);
    expect(() => sa.leave()).toThrow(/LastMember/);
    expect(sa.amMember()).toBe(true);
  });
});
