/**
 * Sealed-sym envelope (sealed-sender §5/§11, wire-format §6): padding buckets,
 * per-recipient fan-out unlinkability, tag routing, EnvelopeID dedup.
 */

import { blake3 } from '@noble/hashes/blake3';
import { describe, expect, it } from 'vitest';
import {
  BUCKETS,
  CONTENT_FRAME,
  OversizeError,
  TAG_LEN,
  TagTable,
  decodeSealedPlaintext,
  envKeySym,
  envelopeId,
  hintTag,
  openSym,
  padToBucket,
  parseSymEnvelope,
  sealSymFanout,
  sealSymTo,
} from '../src/envelope.js';
import { bytesToHex } from '../src/bytes.js';
import { encodeMembership, type Membership } from '../src/ids.js';
import type { Csprng } from '../src/keyhive.js';

function rngOf(label: string): Csprng {
  let c = 0;
  return (n) => blake3(new TextEncoder().encode(`${label}:${c++}`), { dkLen: n });
}
const member = (u: string): Membership => ({
  device: { did: `did:${u}`, fingerprint: blake3(new TextEncoder().encode(`fp:${u}`), { dkLen: 32 }) },
  admittedBy: blake3(new TextEncoder().encode(`adm:${u}`), { dkLen: 32 }),
});
const bytes = (n: number, fill: number) => new Uint8Array(n).fill(fill);

describe('padding (§5)', () => {
  it('pads to an exact bucket for a range of body sizes', () => {
    for (const len of [0, 1, 100, 300, 1000, 1024, 1500, 4096, 40000, 65000]) {
      const out = padToBucket(CONTENT_FRAME, bytes(len, 0xab));
      expect(BUCKETS, `len ${len} → ${out.length}`).toContain(out.length);
      const smallest = BUCKETS.find((b) => b >= out.length)!;
      // must be the SMALLEST bucket that fits the unpadded content
      expect(out.length).toBe(smallest);
      const { contentType, body } = decodeSealedPlaintext(out);
      expect(contentType).toBe(CONTENT_FRAME);
      expect(bytesToHex(body)).toBe(bytesToHex(bytes(len, 0xab)));
    }
  });

  it('all buckets are distinct sizes and cover 1..64 KiB', () => {
    expect(BUCKETS).toEqual([1024, 2048, 4096, 8192, 16384, 32768, 65536]);
  });

  it('oversize content throws (blob-offload signal)', () => {
    expect(() => padToBucket(CONTENT_FRAME, bytes(70000, 1))).toThrow(OversizeError);
  });

  it('nonzero pad is rejected (covert-channel guard)', () => {
    const good = padToBucket(CONTENT_FRAME, bytes(10, 1));
    const tampered = good.slice();
    tampered[tampered.length - 1] = 0xff; // last byte is pad
    expect(() => decodeSealedPlaintext(tampered)).toThrow(/nonzero pad/);
  });
});

describe('sealed-sym seal/open (§11.3)', () => {
  const pcs = bytes(32, 0x11);
  const alice = member('alice');
  const bob = member('bob');
  const encAlice = encodeMembership(alice);
  const encBob = encodeMembership(bob);

  it('round-trips a frame body', () => {
    const envKey = envKeySym(pcs, encAlice);
    const body = new TextEncoder().encode('hello group');
    const env = sealSymTo(envKey, encBob, CONTENT_FRAME, body, rngOf('n'));
    const { contentType, body: got } = openSym(envKey, env);
    expect(contentType).toBe(CONTENT_FRAME);
    expect(new TextDecoder().decode(got)).toBe('hello group');
  });

  it('an outsider (wrong envKey) cannot open', () => {
    const envKey = envKeySym(pcs, encAlice);
    const env = sealSymTo(envKey, encBob, CONTENT_FRAME, bytes(20, 7), rngOf('n'));
    expect(() => openSym(bytes(32, 0x99), env)).toThrow();
  });

  it('tag is a per-recipient PRF (8 B), pseudorandom across recipients', () => {
    const envKey = envKeySym(pcs, encAlice);
    const tagB = hintTag(envKey, encBob);
    const tagC = hintTag(envKey, encodeMembership(member('carol')));
    expect(tagB.length).toBe(TAG_LEN);
    expect(bytesToHex(tagB)).not.toBe(bytesToHex(tagC));
  });
});

describe('fan-out unlinkability (§11.3 normative)', () => {
  const pcs = bytes(32, 0x22);
  const sender = member('sender');
  const recipients = ['r0', 'r1', 'r2', 'r3'].map(member);
  const encRecipients = recipients.map(encodeMembership);

  it('each copy has a distinct tag, nonce, and ciphertext; identical size', () => {
    const envKey = envKeySym(pcs, encodeMembership(sender));
    const body = new TextEncoder().encode('one group message');
    const envs = sealSymFanout(envKey, encRecipients, CONTENT_FRAME, body, rngOf('fan'));
    const tags = new Set<string>();
    const nonces = new Set<string>();
    const cts = new Set<string>();
    const sizes = new Set<number>();
    for (const e of envs) {
      const p = parseSymEnvelope(e);
      tags.add(bytesToHex(p.tag));
      nonces.add(bytesToHex(p.nonce));
      cts.add(bytesToHex(p.ct));
      sizes.add(e.length);
    }
    expect(tags.size, 'distinct tags').toBe(envs.length);
    expect(nonces.size, 'distinct nonces').toBe(envs.length);
    expect(cts.size, 'distinct ciphertexts').toBe(envs.length);
    expect(sizes.size, 'identical envelope size').toBe(1); // no size leak across mailboxes
  });

  it('members share envKey → any member opens any copy to the same plaintext (group message)', () => {
    // The per-recipient tag is unlinkability, NOT member-to-member secrecy.
    const envKey = envKeySym(pcs, encodeMembership(sender));
    const envs = sealSymFanout(envKey, encRecipients, CONTENT_FRAME, new TextEncoder().encode('gm'), rngOf('f2'));
    for (const e of envs) {
      expect(new TextDecoder().decode(openSym(envKey, e).body)).toBe('gm');
    }
  });

  it('EnvelopeIDs are distinct per copy (no cross-mailbox linkage)', () => {
    const envKey = envKeySym(pcs, encodeMembership(sender));
    const envs = sealSymFanout(envKey, encRecipients, CONTENT_FRAME, bytes(50, 3), rngOf('f3'));
    const ids = new Set(envs.map((e) => bytesToHex(envelopeId(e))));
    expect(ids.size).toBe(envs.length);
  });
});

describe('TagTable routing (§11.3 lookup)', () => {
  it('routes an incoming envelope to the right sender-epoch envKey', () => {
    const pcs = bytes(32, 0x33);
    const me = member('me');
    const encMe = encodeMembership(me);
    const alice = member('alice');
    const bob = member('bob');
    // Receiver installs the tags alice/bob use to address me this epoch.
    const table = new TagTable();
    const envKeyAlice = envKeySym(pcs, encodeMembership(alice));
    const envKeyBob = envKeySym(pcs, encodeMembership(bob));
    table.install(envKeyAlice, encMe, { sender: 'alice' });
    table.install(envKeyBob, encMe, { sender: 'bob' });

    // Alice seals a message to me.
    const env = sealSymTo(envKeyAlice, encMe, CONTENT_FRAME, new TextEncoder().encode('hi from alice'), rngOf('t'));
    const opened = table.open(env);
    expect(opened).not.toBeNull();
    expect((opened!.meta as { sender: string }).sender).toBe('alice');
    expect(new TextDecoder().decode(opened!.plaintext.body)).toBe('hi from alice');
  });

  it('an envelope for an uninstalled tag does not route (returns null)', () => {
    const pcs = bytes(32, 0x44);
    const table = new TagTable();
    const stranger = envKeySym(pcs, encodeMembership(member('stranger')));
    const env = sealSymTo(stranger, encodeMembership(member('me')), CONTENT_FRAME, bytes(5, 1), rngOf('t2'));
    expect(table.open(env)).toBeNull();
  });

  it('evict removes a superseded epoch envKey', () => {
    const pcs = bytes(32, 0x55);
    const me = encodeMembership(member('me'));
    const table = new TagTable();
    const envKey = envKeySym(pcs, encodeMembership(member('s')));
    table.install(envKey, me, {});
    expect(table.size).toBe(1);
    table.evict(envKey);
    expect(table.size).toBe(0);
  });
});
