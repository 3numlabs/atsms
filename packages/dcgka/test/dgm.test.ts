/** Strong-remove DGM vectors (dgm.md §9.2, Spike B §9). */

import { blake3 } from '@noble/hashes/blake3';
import { describe, expect, it } from 'vitest';
import { evaluate } from '../src/dgm.js';
import { ZERO32, membershipKey, type DeviceID, type Membership } from '../src/ids.js';
import { makeOp, type Op } from '../src/ops.js';
import { bytesToHex } from '../src/bytes.js';

const fp = (s: string) => blake3(new TextEncoder().encode(s), { dkLen: 32 });
const dev = (u: string, d: number): DeviceID => ({ did: `did:${u}`, fingerprint: fp(`${u}-${d}`) });
const pk = (s: string) => fp(`pk-${s}`);

const A0 = dev('alice', 0);
const B0 = dev('bob', 0);
const B1 = dev('bob', 1);
const C0 = dev('carol', 0);
const D0 = dev('dave', 0);

function createOp(devices: DeviceID[], admins: string[]): Op {
  return makeOp({ device: devices[0]!, admittedBy: ZERO32 }, [], {
    type: 'create',
    initialDevices: devices.map((d, i) => ({ device: d, leafPk: pk(`init${i}`) })),
    initialAdmins: admins,
  });
}

const memberOf = (create: Op, d: DeviceID): Membership => ({ device: d, admittedBy: create.id });
const add = (author: Membership, deps: Op[], d: DeviceID): Op =>
  makeOp(author, deps.map((o) => o.id), { type: 'add', device: d, leafPk: pk(d.did), leafIndex: 0 });
const remove = (author: Membership, deps: Op[], target: Membership): Op =>
  makeOp(author, deps.map((o) => o.id), { type: 'remove', membership: target, removedKeys: [] });

const memberDids = (view: ReturnType<typeof evaluate>) =>
  new Set([...view.members.values()].map((m) => m.device.did));

describe('DGM strong remove (SR1–SR5)', () => {
  it('create establishes members and admins; unauthorized cross-DID add is invalid', () => {
    const c = createOp([A0, B0], ['did:alice']);
    const bob = memberOf(c, B0);
    const badAdd = add(bob, [c], C0); // bob is not admin
    const view = evaluate([c, badAdd]);
    expect(view.valid.has(bytesToHex(badAdd.id))).toBe(false);
    expect(memberDids(view)).toEqual(new Set(['did:alice', 'did:bob']));
  });

  it('admin add works; SR2: add concurrent with remove-of-adder cascades', () => {
    const c = createOp([A0, B0], ['did:alice', 'did:bob']);
    const alice = memberOf(c, A0);
    const bob = memberOf(c, B0);
    const goodAdd = add(alice, [c], C0); // sequential — valid
    const v1 = evaluate([c, goodAdd]);
    expect(memberDids(v1)).toContain('did:carol');

    // Concurrent: alice adds dave; bob removes alice.
    const x = add(alice, [c, goodAdd], D0);
    const r = remove(bob, [c, goodAdd], alice);
    const carol: Membership = { device: C0, admittedBy: goodAdd.id };
    const daveOp = add({ device: D0, admittedBy: x.id }, [x], dev('eve', 0)); // dave (cascaded) adds eve
    const view = evaluate([c, goodAdd, x, r, daveOp]);
    expect(memberDids(view)).toEqual(new Set(['did:bob', 'did:carol']));
    expect(view.valid.has(bytesToHex(x.id))).toBe(false); // SR1
    expect(view.valid.has(bytesToHex(daveOp.id))).toBe(false); // SR2 cascade
    void carol;
  });

  it('SR3: mutual admin removes — both out', () => {
    const c = createOp([A0, B0], ['did:alice', 'did:bob']);
    const alice = memberOf(c, A0);
    const bob = memberOf(c, B0);
    const r1 = remove(alice, [c], bob);
    const r2 = remove(bob, [c], alice);
    const view = evaluate([c, r1, r2]);
    expect(memberDids(view)).toEqual(new Set());
    expect(view.admins.size).toBe(0);
  });

  it('SR1 on removes: A removes B ∥ B removes C — C survives, B out', () => {
    const c = createOp([A0, B0, C0], ['did:alice', 'did:bob']);
    const alice = memberOf(c, A0);
    const bob = memberOf(c, B0);
    const carol = memberOf(c, C0);
    const rAB = remove(alice, [c], bob);
    const rBC = remove(bob, [c], carol);
    const view = evaluate([c, rAB, rBC]);
    expect(memberDids(view)).toEqual(new Set(['did:alice', 'did:carol']));
    expect(view.valid.has(bytesToHex(rBC.id))).toBe(false);
  });

  it('remove cycle of three: mutual destruction — all out', () => {
    const c = createOp([A0, B0, C0], ['did:alice', 'did:bob', 'did:carol']);
    const alice = memberOf(c, A0);
    const bob = memberOf(c, B0);
    const carol = memberOf(c, C0);
    const view = evaluate([
      c,
      remove(alice, [c], bob),
      remove(bob, [c], carol),
      remove(carol, [c], alice),
    ]);
    expect(memberDids(view)).toEqual(new Set());
  });

  it('SR5: self-leave lands despite a concurrent remove of the leaver', () => {
    const c = createOp([A0, B0], ['did:alice']);
    const alice = memberOf(c, A0);
    const bob = memberOf(c, B0);
    const r = remove(alice, [c], bob);
    const leave = remove(bob, [c], bob); // self-leave
    const view = evaluate([c, r, leave]);
    expect(view.valid.has(bytesToHex(leave.id))).toBe(true);
    expect(view.valid.has(bytesToHex(r.id))).toBe(true);
    expect(memberDids(view)).toEqual(new Set(['did:alice']));
  });

  it('same-DID device add is open to any member device, but dies under SR1', () => {
    const c = createOp([A0, B0], ['did:alice']);
    const alice = memberOf(c, A0);
    const bob = memberOf(c, B0);
    // Sequential same-DID add: valid without admin.
    const selfAdd = add(bob, [c], B1);
    expect(evaluate([c, selfAdd]).members.size).toBe(3);
    // Concurrent with a remove of the adder: invalid (SR1).
    const r = remove(alice, [c], bob);
    const view = evaluate([c, selfAdd, r]);
    expect(view.valid.has(bytesToHex(selfAdd.id))).toBe(false);
    expect(memberDids(view)).toEqual(new Set(['did:alice']));
  });

  it('re-add after remove yields a fresh Membership', () => {
    const c = createOp([A0, B0], ['did:alice']);
    const alice = memberOf(c, A0);
    const bob = memberOf(c, B0);
    const r = remove(alice, [c], bob);
    const readd = add(alice, [c, r], B0);
    const view = evaluate([c, r, readd]);
    const bobMemberships = [...view.members.values()].filter((m) => m.device.did === 'did:bob');
    expect(bobMemberships.length).toBe(1);
    expect(membershipKey(bobMemberships[0]!)).not.toBe(membershipKey(bob));
    expect(bytesToHex(bobMemberships[0]!.admittedBy)).toBe(
      bytesToHex(readd.id),
    );
  });

  it('last-admin revoke is invalid; grantAdmin needs a member grantee', () => {
    const c = createOp([A0, B0], ['did:alice']);
    const alice = memberOf(c, A0);
    const selfRevoke = makeOp(alice, [c.id], { type: 'revokeAdmin', did: 'did:alice' });
    const badGrant = makeOp(alice, [c.id], { type: 'grantAdmin', did: 'did:nobody' });
    const view = evaluate([c, selfRevoke, badGrant]);
    expect(view.valid.has(bytesToHex(selfRevoke.id))).toBe(false);
    expect(view.valid.has(bytesToHex(badGrant.id))).toBe(false);
    expect(view.admins).toEqual(new Set(['did:alice']));
  });

  it('P1/P5: evaluation is independent of input order', () => {
    const c = createOp([A0, B0, C0], ['did:alice', 'did:bob']);
    const alice = memberOf(c, A0);
    const bob = memberOf(c, B0);
    const ops = [
      c,
      add(alice, [c], D0),
      remove(bob, [c], alice),
      remove(alice, [c], bob),
      add(bob, [c], dev('frank', 0)),
    ];
    const base = evaluate(ops);
    for (let i = 0; i < 5; i++) {
      const shuffled = [...ops].sort(() => (fp(`shuffle-${i}`)[i % 32]! % 2 === 0 ? -1 : 1));
      const v = evaluate(shuffled);
      expect(memberDids(v)).toEqual(memberDids(base));
      expect(v.valid).toEqual(base.valid);
    }
  });
});
