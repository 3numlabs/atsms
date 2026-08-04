/**
 * Sealed-sender delivery integration: the whole protocol running over
 * SealedEnvelopes end-to-end (create/first-update = asym, in-conversation = sym,
 * welcome = asym), never raw frames on the wire.
 */

import { blake3 } from '@noble/hashes/blake3';
import { x25519 } from '@noble/curves/ed25519';
import { describe, expect, it } from 'vitest';
import { Session } from '../src/ordering.js';
import { SealLayer, type Outbound } from '../src/seal-layer.js';
import { CLS_WELCOME, generateSigningKeypair, parseFrame } from '../src/frames.js';
import { type Csprng } from '../src/keyhive.js';
import { ShareKeyMap } from '../src/keys.js';
import { MODE_ASYM, MODE_SYM, envelopeMode } from '../src/envelope.js';
import type { DeviceID } from '../src/ids.js';

function rngOf(label: string): Csprng {
  let c = 0;
  return (n) => blake3(new TextEncoder().encode(`${label}:${c++}`), { dkLen: n });
}

interface Party {
  device: DeviceID;
  leafSk: Uint8Array; // = signed prekey secret (D10: leaf key IS the signed prekey)
  leafPk: Uint8Array;
  signingSk: Uint8Array;
  signingPk: Uint8Array;
  rng: Csprng;
  sks: ShareKeyMap;
}

function party(u: string): Party {
  const rng = rngOf(u);
  const leafSk = rng(32);
  const leafPk = x25519.getPublicKey(leafSk); // prekey = X25519(leafSk); also the BeeKEM leaf pk
  const kp = generateSigningKeypair(rng);
  const sks = new ShareKeyMap();
  sks.insert(leafPk, leafSk);
  return {
    device: { did: `did:${u}`, fingerprint: blake3(new TextEncoder().encode(`fp:${u}`), { dkLen: 32 }) },
    leafSk,
    leafPk,
    signingSk: kp.sk,
    signingPk: kp.pk,
    rng,
    sks,
  };
}

const text = (s: string) => new TextEncoder().encode(s);

/** A trivial in-memory transport: fingerprint hex → its inbox of envelopes. */
class Wire {
  inbox = new Map<string, Uint8Array[]>();
  send(out: Outbound[]): void {
    for (const o of out) {
      if (!this.inbox.has(o.to)) this.inbox.set(o.to, []);
      this.inbox.get(o.to)!.push(o.envelope);
    }
  }
  take(fp: string): Uint8Array[] {
    const q = this.inbox.get(fp) ?? [];
    this.inbox.set(fp, []);
    return q;
  }
}

describe('SealLayer end-to-end (sealed transport)', () => {
  it('founds, first-updates, converses, and adds a member — all over sealed envelopes', () => {
    const wire = new Wire();
    const pa = party('alice');
    const pb = party('bob');
    const pc = party('carol');
    const fpOf = (p: Party) => blakeHex(p.device.fingerprint);

    // Alice founds a 3-party group.
    const aliceSession = Session.createGroup(
      [pa, pb, pc].map((p) => ({ device: p.device, leafPk: p.leafPk, signingPk: p.signingPk })),
      [pa.device.did],
      pa.signingSk,
      pa.sks,
      pa.rng,
    );
    const alice = new SealLayer(aliceSession, [pa.leafSk], pa.rng);
    // The create frame is sealed ASYM to bob & carol's prekeys.
    const createOut = alice.drainSealed();
    expect(createOut.length).toBe(2);
    for (const o of createOut) expect(envelopeMode(o.envelope)).toBe(MODE_ASYM);
    wire.send(createOut);

    // Bob & Carol bootstrap by unsealing the asym create, then wrap in a SealLayer.
    const bootstrap = (p: Party): SealLayer => {
      const env = wire.take(fpOf(p))[0]!;
      const createFrame = SealLayer.openBootstrap(env, [p.leafSk]);
      const s = Session.fromFrames([createFrame], p.device, p.signingSk, p.sks, p.rng);
      return new SealLayer(s, [p.leafSk], p.rng);
    };
    const bob = bootstrap(pb);
    const carol = bootstrap(pc);

    const rec: Record<string, string[]> = { alice: [], bob: [], carol: [], dave: [] };
    const sink = (who: string) => (p: Uint8Array) => (rec[who] ??= []).push(new TextDecoder().decode(p));
    (aliceSession as unknown as { events: { onAppMessage?: (p: Uint8Array) => void } }).events.onAppMessage =
      sink('alice');
    (bob.session as unknown as { events: { onAppMessage?: (p: Uint8Array) => void } }).events.onAppMessage =
      sink('bob');
    (carol.session as unknown as { events: { onAppMessage?: (p: Uint8Array) => void } }).events.onAppMessage =
      sink('carol');

    const layers: Record<string, SealLayer> = { [fpOf(pa)]: alice, [fpOf(pb)]: bob, [fpOf(pc)]: carol };
    const pump = (l: SealLayer): void => wire.send(l.drainSealed());
    const deliverAll = (): void => {
      for (let i = 0; i < 8; i++) {
        for (const [fp, l] of Object.entries(layers)) {
          for (const env of wire.take(fp)) l.deliver(env);
          pump(l);
        }
      }
    };

    // Control frames (the update) ride ASYM to prekeys — an epoch-advancing op
    // can't be sealed under the epoch it creates.
    aliceSession.update();
    const upOut = alice.drainSealed();
    for (const o of upOut) expect(envelopeMode(o.envelope), 'control update is asym').toBe(MODE_ASYM);
    wire.send(upOut);
    deliverAll();

    // Everyone converged on the same tree.
    expect(bob.session.engine.treeHash()).toBe(aliceSession.engine.treeHash());
    expect(carol.session.engine.treeHash()).toBe(aliceSession.engine.treeHash());

    // Now in-conversation app traffic rides SYM.
    const appEnv = aliceSession.sendApp(text('hello over the seal'));
    void appEnv;
    const appOut = alice.drainSealed();
    for (const o of appOut) expect(envelopeMode(o.envelope), 'app frame is sym').toBe(MODE_SYM);
    wire.send(appOut);
    deliverAll();
    expect(rec.bob).toContain('hello over the seal');
    expect(rec.carol).toContain('hello over the seal');

    // Add Dave: add frame rides SYM to members under the parent epoch; welcome
    // rides ASYM to Dave's prekey.
    const pd = party('dave');
    const { addOpId } = aliceSession.add(pd.device, pd.leafPk, pd.signingPk);
    aliceSession.buildWelcome(addOpId);
    const addOut = alice.drainSealed();
    const daveFp = blakeHex(pd.device.fingerprint);
    // Dave gets a sym add-copy (he can't open it — no parent epoch) plus the asym
    // welcome; the welcome is the asym one that unseals to a CLS_WELCOME frame.
    const welcomeEnv = addOut
      .filter((o) => o.to === daveFp && envelopeMode(o.envelope) === MODE_ASYM)
      .find((o) => parseFrame(SealLayer.openBootstrap(o.envelope, [pd.leafSk])).body.cls === CLS_WELCOME);
    expect(welcomeEnv, 'welcome addressed to dave').toBeDefined();
    expect(envelopeMode(welcomeEnv!.envelope), 'welcome is asym').toBe(MODE_ASYM);
    wire.send(addOut);
    deliverAll();

    // Dave bootstraps from the asym welcome, heals, and joins the conversation.
    const daveFrame = SealLayer.openBootstrap(welcomeEnv!.envelope, [pd.leafSk]);
    const daveSession = Session.fromWelcome(daveFrame, pd.device, pd.signingSk, pd.sks, pd.rng);
    const dave = new SealLayer(daveSession, [pd.leafSk], pd.rng);
    layers[blakeHex(pd.device.fingerprint)] = dave;
    (daveSession as unknown as { events: { onAppMessage?: (p: Uint8Array) => void } }).events.onAppMessage =
      sink('dave');
    daveSession.update(); // mandatory healing update
    pump(dave);
    deliverAll();

    expect(dave.session.engine.treeHash()).toBe(aliceSession.engine.treeHash());

    // Bob speaks; Dave (now a member) hears it — sym, post-join.
    bob.session.sendApp(text('welcome dave'));
    pump(bob);
    deliverAll();
    expect(rec.dave).toContain('welcome dave');
  });
});

describe('SealLayer in-band delivery-endpoint advertisement (§12)', () => {
  it('learns peers’ endpoints from signed ext and routes non-welcome envelopes to them', () => {
    const wire = new Wire();
    const pa = party('ep-alice');
    const pb = party('ep-bob');
    const fpA = blakeHex(pa.device.fingerprint);
    const fpB = blakeHex(pb.device.fingerprint);
    const urlA = 'https://relay.example/alice-inbox';
    const urlB = 'https://relay.example/bob-inbox';

    const aliceSession = Session.createGroup(
      [pa, pb].map((p) => ({ device: p.device, leafPk: p.leafPk, signingPk: p.signingPk })),
      [pa.device.did],
      pa.signingSk,
      pa.sks,
      pa.rng,
    );
    const alice = new SealLayer(aliceSession, [pa.leafSk], pa.rng);
    wire.send(alice.drainSealed()); // create (asym) to bob

    const createFrame = SealLayer.openBootstrap(wire.take(fpB)[0]!, [pb.leafSk]);
    const bobSession = Session.fromFrames([createFrame], pb.device, pb.signingSk, pb.sks, pb.rng);
    const bob = new SealLayer(bobSession, [pb.leafSk], pb.rng);

    // Each device advertises where it wants its non-welcome envelopes delivered.
    aliceSession.setEndpoint(urlA);
    bobSession.setEndpoint(urlB);

    const layers: Record<string, SealLayer> = { [fpA]: alice, [fpB]: bob };
    const deliverAll = (): void => {
      for (let i = 0; i < 6; i++) {
        for (const [fp, l] of Object.entries(layers)) {
          for (const env of wire.take(fp)) l.deliver(env);
          wire.send(l.drainSealed());
        }
      }
    };

    // The adverts ride each device's next authored control frame. Sequential (not
    // concurrent) updates keep the epoch's root derivable: alice establishes
    // epoch 1, bob converges then establishes epoch 2 on top.
    aliceSession.update();
    wire.send(alice.drainSealed());
    deliverAll();
    bobSession.update();
    wire.send(bob.drainSealed());
    deliverAll();

    // Each side learned the other's endpoint in-band.
    expect(bobSession.endpointOf(pa.device.fingerprint)).toBe(urlA);
    expect(aliceSession.endpointOf(pb.device.fingerprint)).toBe(urlB);

    // A non-welcome (app) envelope is routed to the recipient's advertised URL.
    aliceSession.sendApp(text('routed by endpoint'));
    const appOut = alice.drainSealed();
    const toBob = appOut.find((o) => o.to === fpB);
    expect(toBob, 'app envelope addressed to bob').toBeDefined();
    expect(toBob!.url).toBe(urlB);
  });

  it('a REMOVED member cannot inject: no one accepts its post-removal traffic (strong remove)', () => {
    // Live failure 2026-08-03: after A removed C, C sent a message — the REMOVER
    // still displayed it (stale receive tag table + no membership gate on app
    // frames), while the third member correctly saw nothing. Strong remove must
    // hold on the RECEIVE path too, symmetrically.
    const wire = new Wire();
    const pa = party('alice');
    const pb = party('bob');
    const pc = party('carol');
    const fpOf = (p: Party) => blakeHex(p.device.fingerprint);

    const aliceSession = Session.createGroup(
      [pa, pb, pc].map((p) => ({ device: p.device, leafPk: p.leafPk, signingPk: p.signingPk })),
      [pa.device.did],
      pa.signingSk,
      pa.sks,
      pa.rng,
    );
    const alice = new SealLayer(aliceSession, [pa.leafSk], pa.rng);
    wire.send(alice.drainSealed());
    const bootstrap = (p: Party): SealLayer => {
      const env = wire.take(fpOf(p))[0]!;
      const s2 = Session.fromFrames([SealLayer.openBootstrap(env, [p.leafSk])], p.device, p.signingSk, p.sks, p.rng);
      return new SealLayer(s2, [p.leafSk], p.rng);
    };
    const bob = bootstrap(pb);
    const carol = bootstrap(pc);

    const rec: Record<string, string[]> = { alice: [], bob: [], carol: [] };
    const sink = (who: string) => (p: Uint8Array) => rec[who]!.push(new TextDecoder().decode(p));
    for (const [who, l] of [['alice', alice], ['bob', bob], ['carol', carol]] as const) {
      (l.session as unknown as { events: { onAppMessage?: (p: Uint8Array) => void } }).events.onAppMessage =
        sink(who);
    }
    const layers: Record<string, SealLayer> = { [fpOf(pa)]: alice, [fpOf(pb)]: bob, [fpOf(pc)]: carol };
    const deliverAll = (): void => {
      for (let i = 0; i < 8; i++) {
        for (const [fp, l] of Object.entries(layers)) {
          for (const env of wire.take(fp)) l.deliver(env);
          wire.send(l.drainSealed());
        }
      }
    };

    aliceSession.update();
    wire.send(alice.drainSealed());
    deliverAll();
    aliceSession.sendApp(text('everyone is here'));
    wire.send(alice.drainSealed());
    deliverAll();
    expect(rec.carol).toContain('everyone is here');

    // Carol speaks too — so every member's RECEIVE tag table holds an entry
    // for (current epoch, carol). This is the live precondition: the remover
    // has been conversing with the member it is about to remove.
    carol.session.sendApp(text('carol here'));
    wire.send(carol.drainSealed());
    deliverAll();
    expect(rec.alice).toContain('carol here');
    expect(rec.bob).toContain('carol here');

    // Alice removes Carol (+ the healing update, as the client batches it).
    const carolMembership = aliceSession.engine.members().find((m) => m.device.did === 'did:carol')!;
    aliceSession.remove(carolMembership);
    aliceSession.update();
    wire.send(alice.drainSealed());
    deliverAll();
    expect(aliceSession.engine.members().some((m) => m.device.did === 'did:carol')).toBe(false);
    expect(bob.session.engine.members().some((m) => m.device.did === 'did:carol')).toBe(false);

    // The removal op IS sealed to the device it removes (always-notify), so
    // Carol knows immediately — and can no longer send: her root was blanked
    // by her own removal and the post-remove epoch is not hers to derive.
    expect(carol.session.amMember(), 'the removed device learns it was removed').toBe(false);
    expect(aliceSession.amMember()).toBe(true);
    expect(bob.session.amMember()).toBe(true);
    expect(() => carol.session.sendApp(text('hey again'))).toThrow(/NoRootKey/);

    // Membership history is derivable from the retained log for a UI to render.
    const log = aliceSession.membershipLog();
    expect(log[0]!.type).toBe('create');
    expect(log.some((e) => e.type === 'remove' && e.devices[0]!.did === 'did:carol')).toBe(true);

    // And the group keeps working between the remaining members.
    aliceSession.sendApp(text('carry on'));
    wire.send(alice.drainSealed());
    deliverAll();
    expect(rec.bob).toContain('carry on');
  });

  it('a LOST removal notice self-heals: the first injected frame triggers a re-notice', () => {
    // A+C: the removal notice is best-effort (one envelope; the device may be
    // offline past mailbox retention). A device that keeps sending has plainly
    // not processed it — so members re-queue the removal op on the dropped
    // frame, and the removed device converges without any timer.
    const wire = new Wire();
    const pa = party('alice');
    const pb = party('bob');
    const pc = party('carol');
    const fpOf = (p: Party) => blakeHex(p.device.fingerprint);

    const aliceSession = Session.createGroup(
      [pa, pb, pc].map((p) => ({ device: p.device, leafPk: p.leafPk, signingPk: p.signingPk })),
      [pa.device.did],
      pa.signingSk,
      pa.sks,
      pa.rng,
    );
    const alice = new SealLayer(aliceSession, [pa.leafSk], pa.rng);
    wire.send(alice.drainSealed());
    const bootstrap = (p: Party): SealLayer => {
      const env = wire.take(fpOf(p))[0]!;
      const s2 = Session.fromFrames([SealLayer.openBootstrap(env, [p.leafSk])], p.device, p.signingSk, p.sks, p.rng);
      return new SealLayer(s2, [p.leafSk], p.rng);
    };
    const bob = bootstrap(pb);
    const carol = bootstrap(pc);
    const rec: Record<string, string[]> = { alice: [], bob: [], carol: [] };
    for (const [who, l] of [['alice', alice], ['bob', bob], ['carol', carol]] as const) {
      (l.session as unknown as { events: { onAppMessage?: (p: Uint8Array) => void } }).events.onAppMessage =
        (p: Uint8Array) => rec[who]!.push(new TextDecoder().decode(p));
    }
    const layers: Record<string, SealLayer> = { [fpOf(pa)]: alice, [fpOf(pb)]: bob, [fpOf(pc)]: carol };
    const deliverAll = (): void => {
      for (let i = 0; i < 8; i++) {
        for (const [fp, l] of Object.entries(layers)) {
          for (const env of wire.take(fp)) l.deliver(env);
          wire.send(l.drainSealed());
        }
      }
    };

    aliceSession.update();
    wire.send(alice.drainSealed());
    deliverAll();
    carol.session.sendApp(text('carol here'));
    wire.send(carol.drainSealed());
    deliverAll();
    expect(rec.alice).toContain('carol here');

    // Alice removes Carol — but Carol's copy of the notice is LOST in transit.
    const carolMembership = aliceSession.engine.members().find((m) => m.device.did === 'did:carol')!;
    aliceSession.remove(carolMembership);
    aliceSession.update();
    wire.send(alice.drainSealed().filter((o) => o.to !== fpOf(pc)));
    deliverAll();
    expect(carol.session.amMember(), 'notice lost — Carol still believes she is in').toBe(true);

    // Carol speaks into the void. Nobody accepts it — and the drop re-queues
    // the removal op, which the seal pass addresses to her.
    carol.session.sendApp(text('hey again'));
    wire.send(carol.drainSealed());
    deliverAll();
    expect(rec.alice).not.toContain('hey again');
    expect(rec.bob).not.toContain('hey again');
    expect(carol.session.amMember(), 'the re-notice reached her').toBe(false);
    expect(() => carol.session.sendApp(text('anyone?'))).toThrow(/NoRootKey/);
  });
});

function blakeHex(b: Uint8Array): string {
  let s = '';
  for (const x of b) s += x.toString(16).padStart(2, '0');
  return s;
}

