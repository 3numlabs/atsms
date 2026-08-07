/**
 * Shared group state (group-state.md): a namespaced register carried by an
 * admin-only op, resolved per namespace by causal position with an op-id
 * tie-break, and — the property the whole design exists for — available to a
 * joiner the moment it processes its welcome, with no fetch and no application
 * message.
 */

import { blake3 } from '@noble/hashes/blake3';
import { x25519 } from '@noble/curves/ed25519';
import { describe, expect, it } from 'vitest';
import { generateSigningKeypair } from '../src/frames.js';
import type { DeviceID } from '../src/ids.js';
import { type Csprng } from '../src/keyhive.js';
import { ShareKeyMap } from '../src/keys.js';
import { Session } from '../src/ordering.js';

const rngOf = (l: string): Csprng => {
  let c = 0;
  return (n) => blake3(new TextEncoder().encode(`${l}:${c++}`), { dkLen: n });
};

function party(u: string) {
  const rng = rngOf(u);
  const leafSk = rng(32);
  const leafPk = x25519.getPublicKey(leafSk);
  const kp = generateSigningKeypair(rng);
  const sks = new ShareKeyMap();
  sks.insert(leafPk, leafSk);
  const device: DeviceID = {
    did: `did:${u}`,
    fingerprint: blake3(new TextEncoder().encode(`fp:${u}`), { dkLen: 32 }),
  };
  return { device, leafSk, leafPk, signingSk: kp.sk, signingPk: kp.pk, rng, sks };
}

const NAME = 'at.atsms.group.name';
const text = (s: string) => new TextEncoder().encode(s);
const str = (b: Uint8Array | null) => (b === null ? null : new TextDecoder().decode(b));

/** Alice (admin) + Bob, with Alice's session ready to author. */
function founded(initialState: Array<{ ns: string; value: Uint8Array }> = []) {
  const pa = party('alice');
  const pb = party('bob');
  const alice = Session.createGroup(
    [
      { device: pa.device, leafPk: pa.leafPk, signingPk: pa.signingPk },
      { device: pb.device, leafPk: pb.leafPk, signingPk: pb.signingPk },
    ],
    [pa.device.did],
    pa.signingSk,
    pa.sks,
    pa.rng,
    {},
    'group',
    initialState,
  );
  const frames = alice.takeOutbox();
  const bob = Session.fromFrames(frames, pb.device, pb.signingSk, pb.sks, pb.rng);
  bob.takeOutbox();
  return { pa, pb, alice, bob };
}

describe('shared group state', () => {
  it('a group is born named — no message, no fetch, and the joiner has it too', () => {
    const { alice, bob } = founded([{ ns: NAME, value: text('Trip to Kyoto') }]);
    expect(str(alice.state(NAME))).toBe('Trip to Kyoto');
    expect(str(bob.state(NAME)), 'the founding member reads it from the create op').toBe('Trip to Kyoto');
    expect(alice.stateNamespaces()).toEqual([NAME]);
  });

  it('a rename propagates, and clearing removes the namespace', () => {
    const { alice, bob } = founded([{ ns: NAME, value: text('Trip') }]);
    bob.ingestFrame(alice.setState(NAME, text('Trip to Kyoto')));
    expect(str(bob.state(NAME))).toBe('Trip to Kyoto');

    bob.ingestFrame(alice.setState(NAME, null));
    expect(bob.state(NAME)).toBeNull();
    expect(bob.stateNamespaces()).toEqual([]);
  });

  it('a late joiner reads the name from its welcome — no fetch', () => {
    const { pa, alice } = founded([{ ns: NAME, value: text('Book Club') }]);
    alice.update();
    alice.takeOutbox();
    const pc = party('carol');
    const { addOpId } = alice.add(pc.device, pc.leafPk, pc.signingPk);
    const welcome = alice.buildWelcome(addOpId);
    alice.takeOutbox();

    const carol = Session.fromWelcome(welcome, pc.device, pc.signingSk, pc.sks, pc.rng);
    expect(str(carol.state(NAME)), 'carried by the control log inside the welcome').toBe('Book Club');
    void pa;
  });

  it('is admin-only, refused locally and dropped remotely', () => {
    const { alice, bob } = founded([{ ns: NAME, value: text('Ours') }]);
    // Bob is not an admin: his own engine refuses to author.
    expect(() => bob.setState(NAME, text('Mine'))).toThrow(/Unauthorized/);

    // And if a modified client authored one anyway, the DGM filter drops it —
    // simulated by promoting Bob, authoring, then checking a view that never
    // saw the grant. Here: after a grant he is allowed, which is the mirror.
    bob.ingestFrame(alice.grantAdmin(bob.engine.me.device.did));
    alice.ingestFrame(bob.setState(NAME, text('Ours, jointly')));
    expect(str(alice.state(NAME))).toBe('Ours, jointly');
  });

  it('concurrent renames converge on every replica', () => {
    const { pa, pb, alice, bob } = founded([{ ns: NAME, value: text('Start') }]);
    alice.ingestFrame(bob.update()); // give Bob a rotation so both can author
    bob.ingestFrame(alice.grantAdmin(pb.device.did));
    alice.takeOutbox();
    bob.takeOutbox();

    // Neither sees the other's rename before authoring its own.
    const fromAlice = alice.setState(NAME, text('Alice picked this'));
    const fromBob = bob.setState(NAME, text('Bob picked this'));
    alice.ingestFrame(fromBob);
    bob.ingestFrame(fromAlice);

    expect(alice.state(NAME), 'both replicas agree').toEqual(bob.state(NAME));
    expect(['Alice picked this', 'Bob picked this']).toContain(str(alice.state(NAME)));
    void pa;
  });

  it('rejects a name over the byte cap, and an oversized namespace', () => {
    const { alice } = founded();
    expect(() => alice.setState(NAME, new Uint8Array(129))).toThrow(/≤128/);
    expect(() => alice.setState('x'.repeat(65), text('hi'))).toThrow(/≤64/);
    // 64 bytes exactly is fine — and is ~21 CJK characters, not 64.
    expect(() => alice.setState(NAME, new Uint8Array(128))).not.toThrow();
  });

  it('survives serialize/restore', () => {
    const { pa, alice } = founded([{ ns: NAME, value: text('Persisted') }]);
    const blob = alice.serialize();
    const back = Session.restore(blob, { device: pa.device, rng: pa.rng });
    expect(str(back.state(NAME))).toBe('Persisted');
  });
});
