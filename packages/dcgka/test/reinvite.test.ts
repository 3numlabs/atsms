/**
 * §8.2 first-contact recovery: a `create` or `welcome` that never arrives is
 * the one loss no other mechanism repairs — repair belongs to a conversation,
 * and the party that missed its invitation has none. Neither message is
 * acknowledged (security attaches to processing, not to acks), so the only
 * evidence is silence: a member we have never processed a frame from.
 *
 * These tests drop the invitation on the floor, assert the group is left with a
 * member that is present in everyone's view and entirely absent in fact, then
 * re-invite and watch them join.
 */

import { blake3 } from '@noble/hashes/blake3';
import { x25519 } from '@noble/curves/ed25519';
import { describe, expect, it } from 'vitest';
import { MODE_ASYM, envelopeMode } from '../src/envelope.js';
import { CLS_WELCOME, generateSigningKeypair, parseFrame } from '../src/frames.js';
import type { DeviceID } from '../src/ids.js';
import { type Csprng } from '../src/keyhive.js';
import { ShareKeyMap } from '../src/keys.js';
import { Session } from '../src/ordering.js';
import { SealLayer, type Outbound } from '../src/seal-layer.js';

const rngOf = (label: string): Csprng => {
  let c = 0;
  return (n) => blake3(new TextEncoder().encode(`${label}:${c++}`), { dkLen: n });
};

interface Party {
  device: DeviceID;
  leafSk: Uint8Array;
  leafPk: Uint8Array;
  signingSk: Uint8Array;
  signingPk: Uint8Array;
  rng: Csprng;
  sks: ShareKeyMap;
}

function party(u: string): Party {
  const rng = rngOf(u);
  const leafSk = rng(32);
  const leafPk = x25519.getPublicKey(leafSk);
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

const fpHex = (p: Party) => Buffer.from(p.device.fingerprint).toString('hex');
const text = (s: string) => new TextEncoder().encode(s);

/** Open an asym envelope addressed to `p` and say what class of frame it holds. */
function bootstrapClass(env: Uint8Array, p: Party): number | null {
  try {
    return parseFrame(SealLayer.openBootstrap(env, [p.leafSk])).body.cls;
  } catch {
    return null;
  }
}

describe('§8.2 re-invitation', () => {
  it('rebuilds a lost welcome — and the joiner lands on the CURRENT state', () => {
    const [pa, pb, pc] = [party('alice'), party('bob'), party('carol')];
    const alice = Session.createGroup(
      [
        { device: pa.device, leafPk: pa.leafPk, signingPk: pa.signingPk },
        { device: pb.device, leafPk: pb.leafPk, signingPk: pb.signingPk },
      ],
      [pa.device.did],
      pa.signingSk,
      pa.sks,
      pa.rng,
    );
    const aliceSeal = new SealLayer(alice, [pa.leafSk], pa.rng);
    const bob = Session.fromFrames(alice.takeOutbox(), pb.device, pb.signingSk, pb.sks, pb.rng);
    aliceSeal.drainSealed();
    alice.ingestFrame(bob.update());
    bob.takeOutbox();

    // Carol is added — and her welcome is lost in transit.
    const { frame: addFrame, addOpId } = alice.add(pc.device, pc.leafPk, pc.signingPk);
    bob.ingestFrame(addFrame);
    alice.buildWelcome(addOpId);
    aliceSeal.drainSealed(); // the welcome goes nowhere: this is the loss

    // Everyone else believes Carol is a member. Nobody has heard from her.
    expect(alice.engine.isMemberDevice(pc.device)).toBe(true);
    expect(alice.pendingMembers().map((m) => m.device.did)).toEqual(['did:carol']);
    expect(bob.pendingMembers().map((m) => m.device.did)).toEqual(['did:carol']);

    // The group moves on without her — this is what a rebuild must catch up.
    alice.ingestFrame(bob.update());
    bob.ingestFrame(alice.update());
    aliceSeal.drainSealed();

    // Re-invite: Alice rebuilds the welcome, pinned to the same admission.
    expect(aliceSeal.reinvite(pc.device)).toBe(true);
    const out = aliceSeal.drainSealed();
    const forCarol = out.filter((o) => o.to === fpHex(pc));
    expect(forCarol.length, 'addressed to Carol alone').toBe(out.length);
    expect(envelopeMode(forCarol[0]!.envelope)).toBe(MODE_ASYM);
    expect(bootstrapClass(forCarol[0]!.envelope, pc)).toBe(CLS_WELCOME);

    // Carol boots from it and is at the group's CURRENT state, not the state as
    // it stood when she was added — a rebuild re-snapshots.
    const carol = Session.fromWelcome(
      SealLayer.openBootstrap(forCarol[0]!.envelope, [pc.leafSk]),
      pc.device,
      pc.signingSk,
      pc.sks,
      pc.rng,
    );
    carol.takeOutbox();
    expect(carol.engine.treeHash()).toBe(alice.engine.treeHash());

    // She heals and speaks; everyone hears her, and she is no longer pending.
    const heal = carol.update();
    alice.ingestFrame(heal);
    bob.ingestFrame(heal);
    let heard = '';
    (bob as unknown as { events: { onAppMessage?: (p: Uint8Array) => void } }).events.onAppMessage = (p) => {
      heard = new TextDecoder().decode(p);
    };
    bob.ingestFrame(carol.sendApp(text('I got there in the end')));
    expect(heard).toBe('I got there in the end');
    expect(alice.pendingMembers()).toEqual([]);
    expect(bob.pendingMembers()).toEqual([]);
  });

  it('re-sends the identical create frame for a founding member', () => {
    const [pa, pb] = [party('alice2'), party('bob2')];
    const alice = Session.createGroup(
      [
        { device: pa.device, leafPk: pa.leafPk, signingPk: pa.signingPk },
        { device: pb.device, leafPk: pb.leafPk, signingPk: pb.signingPk },
      ],
      [pa.device.did],
      pa.signingSk,
      pa.sks,
      pa.rng,
    );
    const aliceSeal = new SealLayer(alice, [pa.leafSk], pa.rng);
    const created = alice.takeOutbox()[0]!; // what Bob should have received
    aliceSeal.drainSealed();
    expect(alice.pendingMembers().map((m) => m.device.did)).toEqual(['did:bob2']);

    // Alice moves on alone, then re-invites Bob.
    alice.update();
    aliceSeal.drainSealed();
    expect(aliceSeal.reinvite(pb.device)).toBe(true);
    const out = aliceSeal.drainSealed();
    expect(out.length, 'addressed to Bob alone, not fanned to the group').toBe(1);
    expect(out[0]!.to).toBe(fpHex(pb));

    // Byte-identical to the original: the create frame's id IS the group id, so
    // a re-invitation must never author a second one (that founds a second group).
    const resent = SealLayer.openBootstrap(out[0]!.envelope, [pb.leafSk]);
    expect(Buffer.from(resent).equals(Buffer.from(created))).toBe(true);

    const bob = Session.fromFrames([resent], pb.device, pb.signingSk, pb.sks, pb.rng);
    expect(bob.engine.groupId).toEqual(alice.engine.groupId);
    // Bob is at genesis and repairs forward by the ordinary path (§8).
    alice.ingestFrame(bob.update());
    expect(alice.pendingMembers()).toEqual([]);
  });

  it('will not re-invite a device that is not a member', () => {
    const [pa, pb, pz] = [party('alice3'), party('bob3'), party('mallory')];
    const alice = Session.createGroup(
      [
        { device: pa.device, leafPk: pa.leafPk, signingPk: pa.signingPk },
        { device: pb.device, leafPk: pb.leafPk, signingPk: pb.signingPk },
      ],
      [pa.device.did],
      pa.signingSk,
      pa.sks,
      pa.rng,
    );
    const seal = new SealLayer(alice, [pa.leafSk], pa.rng);
    alice.takeOutbox();
    seal.drainSealed();
    expect(seal.reinvite(pz.device)).toBe(false);
    expect(seal.drainSealed()).toEqual([]);
  });

  it('a removed member is not pending — and cannot be re-invited', () => {
    const [pa, pb] = [party('alice4'), party('bob4')];
    const alice = Session.createGroup(
      [
        { device: pa.device, leafPk: pa.leafPk, signingPk: pa.signingPk },
        { device: pb.device, leafPk: pb.leafPk, signingPk: pb.signingPk },
      ],
      [pa.device.did],
      pa.signingSk,
      pa.sks,
      pa.rng,
    );
    const seal = new SealLayer(alice, [pa.leafSk], pa.rng);
    alice.takeOutbox();
    seal.drainSealed();
    expect(alice.pendingMembers().map((m) => m.device.did)).toEqual(['did:bob4']);

    alice.remove({ device: pb.device, admittedBy: alice.engine.groupId });
    seal.drainSealed();
    expect(alice.pendingMembers(), 'a removed member is gone, not pending').toEqual([]);
    expect(seal.reinvite(pb.device)).toBe(false);
  });
});
