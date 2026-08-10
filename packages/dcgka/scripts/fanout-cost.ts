/**
 * Sender-side fan-out cost, measured rather than estimated.
 *
 * Without a group relay the sender pays for the whole group: the engine seals
 * one envelope per recipient device, and the sender uploads all of them. This
 * script builds real groups at a range of sizes, authors a real application
 * message and a real re-key, seals the resulting frames the way the transport
 * would, and adds up the bytes that go on the wire.
 *
 * It exists because those numbers are quoted publicly. A table nobody can
 * regenerate is an assertion; this makes it a measurement.
 *
 *   bun run scripts/fanout-cost.ts            # the published sizes
 *   bun run scripts/fanout-cost.ts 3 7 12     # any sizes you like
 *   bun run scripts/fanout-cost.ts --markdown # the table, ready to paste
 *
 * What is counted: the serialized sealed envelope, one per recipient device,
 * as handed to the transport. Not counted: HTTP or SMTP framing, TLS, and the
 * recipient's own copy — a sender does not seal to itself.
 *
 * Two re-key columns, because the cost depends on the shape of the tree. A
 * healed tree is one where members have updated through their own paths. A
 * fresh or recently churned tree still has blank nodes, and an update has to
 * re-key around them, so the frame is larger. Both are real states; the second
 * is what you get immediately after creating a group or after a burst of
 * membership changes, and it heals as members update.
 */

import { blake3 } from '@noble/hashes/blake3';
import { x25519 } from '@noble/curves/ed25519';
import { CONTENT_FRAME, sealSymTo } from '../src/envelope.js';
import { generateSigningKeypair } from '../src/frames.js';
import type { DeviceID } from '../src/ids.js';
import type { Csprng } from '../src/keyhive.js';
import { ShareKeyMap } from '../src/keys.js';
import { Session } from '../src/ordering.js';

/** Deterministic RNG, so a run is reproducible and two runs can be compared. */
const rngOf = (label: string): Csprng => {
  let counter = 0;
  return (n) => blake3(new TextEncoder().encode(`${label}:${counter++}`), { dkLen: n });
};

function party(name: string) {
  const rng = rngOf(name);
  const leafSk = rng(32);
  const leafPk = x25519.getPublicKey(leafSk);
  const kp = generateSigningKeypair(rng);
  const sks = new ShareKeyMap();
  sks.insert(leafPk, leafSk);
  const device: DeviceID = {
    did: `did:example:${name}`,
    fingerprint: blake3(new TextEncoder().encode(`fp:${name}`), { dkLen: 32 }),
  };
  return { device, leafPk, signingSk: kp.sk, signingPk: kp.pk, rng, sks };
}

/**
 * Seal `frame` to every recipient and return the total wire bytes. The
 * recipient keys only have to be distinct — the hint tag is derived per
 * recipient, and the envelope size does not depend on which key it is.
 */
function fanoutBytes(frame: Uint8Array, recipients: number, rng: Csprng): number {
  const envKey = rng(32);
  let total = 0;
  for (let i = 0; i < recipients; i++) {
    const recipientKey = x25519.getPublicKey(rng(32));
    total += sealSymTo(envKey, recipientKey, CONTENT_FRAME, frame, rng).length;
  }
  return total;
}

interface Row {
  devices: number;
  message: number;
  rekeyHealed: number | null;
  rekeyBlank: number;
}

function measure(devices: number): Row {
  const parties = Array.from({ length: devices }, (_, i) => party(`d${i}`));
  const author = parties[0]!;
  const rng = rngOf(`fanout:${devices}`);
  const recipients = devices - 1; // a sender does not seal to itself

  const session = Session.createGroup(
    parties.map((p) => ({ device: p.device, leafPk: p.leafPk, signingPk: p.signingPk })),
    [author.device.did],
    author.signingSk,
    author.sks,
    author.rng,
  );
  session.takeOutbox(); // discard the create frames; we are measuring steady state

  // The creator's mandatory first update (concurrent-update-partition §4.2).
  // It runs against the tree as created — blank nodes everywhere — so it is
  // also the honest measurement of a re-key on an unhealed tree.
  session.update();
  const rekeyBlank = session
    .takeOutbox()
    .reduce((sum, f) => sum + fanoutBytes(f, recipients, rng), 0);

  // One application message. The body is one word: padding puts anything up to
  // the first bucket boundary at the same size, which is the point of padding.
  session.sendApp(new TextEncoder().encode('ok'));
  const message = session
    .takeOutbox()
    .reduce((sum, f) => sum + fanoutBytes(f, recipients, rng), 0);

  // A re-key against a healed tree. Every member updates once through its own
  // path first, which fills the blanks; then measure the author's next update.
  let rekeyHealed: number | null = null;
  const HEAL_LIMIT = Number(process.env.HEAL_LIMIT ?? 50);
  try {
    if (devices > HEAL_LIMIT) throw new Error('skipped: healing is O(n^2) deliveries');
    const healed = Session.createGroup(
      parties.map((p) => ({ device: p.device, leafPk: p.leafPk, signingPk: p.signingPk })),
      [author.device.did],
      author.signingSk,
      author.sks,
      author.rng,
    );
    const createFrames = healed.takeOutbox();
    const mirrors = parties.slice(1).map((p) => {
      const s = Session.fromFrames(createFrames, p.device, p.signingSk, p.sks, p.rng);
      s.takeOutbox();
      return { party: p, session: s };
    });
    // Heal SEQUENTIALLY. Concurrent updates do not fill blanks — BeeKEM merges
    // them with conflict keys, which is the whole point of it, but it leaves
    // the tree no healthier. One update at a time, delivered to everyone before
    // the next, is what actually fills the blanked regions.
    const all = [{ session: healed }, ...mirrors];
    const broadcast = (from: { session: Session }) => {
      const frames = from.session.takeOutbox();
      for (const other of all) {
        if (other === from) continue;
        for (const f of frames) other.session.ingestFrame(f);
      }
    };
    healed.update();
    broadcast({ session: healed });
    for (const m of mirrors) {
      m.session.update();
      broadcast(m);
    }
    for (const other of all) other.session.takeOutbox(); // drain echoes

    healed.update();
    rekeyHealed = healed.takeOutbox().reduce((sum, f) => sum + fanoutBytes(f, recipients, rng), 0);
  } catch {
    // Not measured rather than not possible: healing needs every member to
    // update and every update delivered to everyone, which is O(n^2) and slow
    // above ~50 devices. Raise HEAL_LIMIT to measure it anyway.
    rekeyHealed = null;
  }

  return { devices, message, rekeyHealed, rekeyBlank };
}

/** KiB up to a mebibyte, then MiB — binary units throughout, which is the
 *  trap the hand-written version of this table fell into (dividing KiB by 1000
 *  and labelling the result MiB). */
const kib = (n: number | null): string => {
  if (n === null) return '—';
  const k = n / 1024;
  return k >= 1024 ? `${(k / 1024).toFixed(1)} MiB` : `${k.toFixed(1)} KiB`;
};

const args = process.argv.slice(2);
const markdown = args.includes('--markdown');
const sizes = args.filter((a) => !a.startsWith('--')).map(Number).filter((n) => n >= 2);
const targets = sizes.length > 0 ? sizes : [5, 10, 25, 50, 100, 150];

const rows = targets.map(measure);

if (markdown) {
  console.log('| Devices | One message | Re-key, healed tree | Re-key, fresh or recently churned |');
  console.log('|---|---|---|---|');
  for (const r of rows) {
    console.log(`| ${r.devices} | ${kib(r.message)} | ${kib(r.rekeyHealed)} | ${kib(r.rekeyBlank)} |`);
  }
} else {
  console.log('Sender-side fan-out, total bytes uploaded for one operation.');
  console.log('Sealed envelopes only — no HTTP, SMTP or TLS framing.\n');
  console.log('devices   one message   re-key (healed)   re-key (blank)   per-device');
  for (const r of rows) {
    const per = r.message / (r.devices - 1);
    console.log(
      `${String(r.devices).padStart(7)}   ${kib(r.message).padStart(11)}   ` +
        `${kib(r.rekeyHealed).padStart(15)}   ${kib(r.rekeyBlank).padStart(14)}   ` +
        `${(per / 1024).toFixed(3)} KiB`,
    );
  }
  console.log(
    '\nMessages scale linearly: one padded envelope per recipient device.' +
      '\nRe-keys grow with the group, because the update payload itself grows' +
      '\nand then goes to every device anyway.',
  );
}
