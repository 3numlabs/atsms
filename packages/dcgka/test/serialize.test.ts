/**
 * Session state serialization (atsms-integration §2): serialize → restart →
 * restore must be verbatim. The load-bearing property is sender-chain continuity:
 * a receiver must still decrypt messages sent AFTER the author's restart, which
 * fails if the sender chain reset (generation/nonce reuse).
 */

import { blake3 } from '@noble/hashes/blake3';
import { x25519 } from '@noble/curves/ed25519';
import { describe, expect, it } from 'vitest';
import { Session } from '../src/ordering.js';
import { generateSigningKeypair } from '../src/frames.js';
import { ShareKeyMap } from '../src/keys.js';
import type { Csprng } from '../src/keyhive.js';

function rngOf(label: string): Csprng {
  let c = 0;
  return (n) => blake3(new TextEncoder().encode(`${label}:${c++}`), { dkLen: n });
}

function party(u: string) {
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

const text = (s: string) => new TextEncoder().encode(s);
const dec = (b: Uint8Array) => new TextDecoder().decode(b);

describe('Session.serialize / restore', () => {
  it('restores verbatim and continues the sender chain (no nonce reuse after restart)', () => {
    const pa = party('alice');
    const pb = party('bob');
    const bobRecv: string[] = [];

    const alice = Session.createGroup(
      [pa, pb].map((p) => ({ device: p.device, leafPk: p.leafPk, signingPk: p.signingPk })),
      [pa.device.did],
      pa.signingSk,
      pa.sks,
      pa.rng,
    );
    const createFrame = alice.takeOutbox()[0]!;
    const bob = Session.fromFrames([createFrame], pb.device, pb.signingSk, pb.sks, pb.rng, {
      onAppMessage: (pt) => bobRecv.push(dec(pt)),
    });

    // Alice establishes the epoch (self-authored) and sends two app messages.
    alice.update();
    for (const f of alice.takeOutbox()) bob.ingestFrame(f);
    alice.sendApp(text('m0'));
    alice.sendApp(text('m1'));
    for (const f of alice.takeOutbox()) bob.ingestFrame(f);
    expect(bobRecv).toEqual(['m0', 'm1']);

    const hashBefore = alice.engine.treeHash();
    const epochBefore = alice.engine.currentEpoch();

    // ── serialize, then "restart" Alice from the blob alone ──
    const blob = alice.serialize();
    const alice2 = Session.restore(blob, { device: pa.device, rng: pa.rng });

    // Public state restored (this worked with plain replay too)...
    expect(alice2.engine.treeHash()).toBe(hashBefore);
    expect(alice2.engine.currentEpoch()).toBe(epochBefore);

    // ...and — the point — she can still SEND: the self-authored epoch secret was
    // preserved (sks), and the sender chain continues at generation 2.
    alice2.sendApp(text('m2'));
    for (const f of alice2.takeOutbox()) bob.ingestFrame(f);
    expect(bobRecv).toEqual(['m0', 'm1', 'm2']); // bob decrypted m2 ⇒ no generation reuse
  });

  it('restore is idempotent-ish: a restored session re-serializes to an equivalent state', () => {
    const pa = party('a2');
    const pb = party('b2');
    const alice = Session.createGroup(
      [pa, pb].map((p) => ({ device: p.device, leafPk: p.leafPk, signingPk: p.signingPk })),
      [pa.device.did],
      pa.signingSk,
      pa.sks,
      pa.rng,
    );
    alice.takeOutbox();
    alice.update();
    alice.takeOutbox();
    alice.sendApp(text('x'));
    alice.takeOutbox();

    const alice2 = Session.restore(alice.serialize(), { device: pa.device, rng: pa.rng });
    // Same tree, same current epoch — and it can keep operating.
    expect(alice2.engine.treeHash()).toBe(alice.engine.treeHash());
    expect(alice2.engine.currentEpoch()).toBe(alice.engine.currentEpoch());
    alice2.update();
    expect(alice2.takeOutbox().length).toBeGreaterThan(0);
  });
});
