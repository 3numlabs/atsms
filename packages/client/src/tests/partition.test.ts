/**
 * Concurrent-update partition — regression suite (atsms-dcgka
 * spec/concurrent-update-partition.md §6). Exercises the REAL sealed path
 * (`deliverEnvelope` → seal layer → `sealEpochFor`), which is where the bug
 * lived. Before the §4.1 fix, the genesis race left creator and joiners on
 * disjoint private epochs and no message crossed; these assert convergence.
 */

import { bytesToHex, type Csprng, envelopeMode, generateSigningKeypair, MODE_ASYM, MODE_SYM, SealLayer } from "@atsms/dcgka";
import { x25519 } from "@noble/curves/ed25519";
import { Database } from "bun:sqlite";
import { describe, expect, test } from "bun:test";

import { Conversation, type LocalKeys, type MemberDescriptor, type Outbound } from "../lib/conversations/index.js";
import { textOf } from "../lib/format/index.js";
import { SQLiteAdapter } from "../lib/storage/sqlite-adapter.js";

class Wrap {
  private db = new Database(":memory:");
  exec(s: string): void {
    this.db.exec(s);
  }
  prepare(s: string) {
    const st = this.db.prepare(s);
    return {
      run: (...p: unknown[]) => st.run(...(p as never[])),
      get: (...p: unknown[]) => st.get(...(p as never[])),
      all: (...p: unknown[]) => st.all(...(p as never[])),
    };
  }
  transaction<T>(fn: () => T): T {
    return this.db.transaction(fn)();
  }
}
const newStore = () => new SQLiteAdapter(new Wrap() as never);
const rngOf = (seed: number): Csprng => {
  let s = seed >>> 0;
  return (n: number) => {
    const o = new Uint8Array(n);
    for (let i = 0; i < n; i++) {
      s = (s * 1664525 + 1013904223) >>> 0;
      o[i] = (s >>> 24) & 0xff;
    }
    return o;
  };
};
const hex = (b: Uint8Array) => bytesToHex(b);

function party(seed: number, did: string, events?: string[]) {
  const rng = rngOf(seed);
  const leafSk = rng(32);
  const kp = generateSigningKeypair(rng);
  const device = { did, fingerprint: rng(32) };
  const keys: LocalKeys = { signingSk: kp.sk, signingPk: kp.pk, leafPk: x25519.getPublicKey(leafSk), leafSk };
  const descriptor: MemberDescriptor = { device, leafPk: keys.leafPk, signingPk: keys.signingPk };
  const ctx = {
    storage: newStore(),
    rng,
    device,
    did,
    prekeySecrets: [leafSk],
    onEvent: events === undefined ? undefined : (kind: string, detail: string) => events.push(`${kind}: ${detail}`),
  };
  return { did, keys, descriptor, ctx, fp: hex(device.fingerprint) };
}

/** Deliver each sealed envelope to its addressee, chasing repair traffic. */
async function pipe(out: Outbound[], convos: Map<string, Conversation>): Promise<void> {
  for (const o of out) {
    const t = convos.get(o.to);
    if (t !== undefined) await pipe(await t.deliverEnvelope(o.envelope), convos);
  }
}

const texts = async (p: ReturnType<typeof party>, c: Conversation) =>
  (await p.ctx.storage.getMessages(c.convoId)).map((m) => textOf(m.content));

/** Found the group and bootstrap every joiner from the sealed create — WITHOUT
 *  delivering the creator's first update (the caller drives the update race). */
async function foundConcurrent(creator: ReturnType<typeof party>, joiners: ReturnType<typeof party>[]) {
  const { conversation: cv, outbound } = await Conversation.open(creator.ctx, {
    keys: creator.keys,
    members: [creator.descriptor, ...joiners.map((j) => j.descriptor)],
    admins: [creator.did],
  });
  const convos = new Map<string, Conversation>([[creator.fp, cv]]);
  const joined: Conversation[] = [];
  for (const j of joiners) {
    const createFrame = SealLayer.openBootstrap(outbound.find((o) => o.to === j.fp)!.envelope, [j.keys.leafSk]);
    const c = await Conversation.bootstrap(j.ctx, { keys: j.keys, createFrame });
    convos.set(j.fp, c);
    joined.push(c);
  }
  return { cv, joined, convos };
}

describe("concurrent-update partition (§6 regression)", () => {
  test("genesis race: creator + joiner update concurrently → converges bidirectionally", async () => {
    const a = party(31, "did:plc:a");
    const b = party(32, "did:plc:b");
    const { cv, joined, convos } = await foundConcurrent(a, b === undefined ? [] : [b]);
    const cb = joined[0]!;

    // Both update concurrently (neither has seen the other's) — the genesis race.
    const updA = await cv.update();
    const updB = await cb.update();
    await pipe(updA, convos);
    await pipe(updB, convos);
    // Both are now rootless with disjoint private epochs (the pre-fix partition).
    expect(cv.hasSendableEpoch).toBe(false);
    expect(cb.hasSendableEpoch).toBe(false);

    // A heals (a fresh update). With §4.1 it seals asym to prekeys → reaches B.
    await pipe(await cv.update(), convos);
    await pipe(await cv.send("from-a"), convos);
    await pipe(await cb.send("from-b"), convos);

    expect(await texts(b, cb)).toContain("from-a");
    expect(await texts(a, cv)).toContain("from-b");
  });

  test("N-way: creator + 3 joiners all self-heal concurrently → one epoch, full mesh", async () => {
    const creator = party(41, "did:plc:creator");
    const j = [party(42, "did:plc:p"), party(43, "did:plc:p"), party(44, "did:plc:p")];
    const { cv, joined, convos } = await foundConcurrent(creator, j);

    // Everyone updates concurrently off the create — maximal genesis contention.
    const updates = [await cv.update(), ...(await Promise.all(joined.map((c) => c.update())))];
    for (const u of updates) await pipe(u, convos);

    // A single healer breaks the tie; §4.1 carries it asym to all.
    await pipe(await cv.update(), convos);

    await pipe(await cv.send("hello-all"), convos);
    for (const [i, c] of joined.entries()) {
      expect(await texts(j[i]!, c)).toContain("hello-all");
      await pipe(await c.send(`reply-${i}`), convos);
    }
    // Every reply reached the creator → full mesh on one converged epoch.
    const seen = await texts(creator, cv);
    for (let i = 0; i < joined.length; i++) expect(seen).toContain(`reply-${i}`);
    // All members agree on the same current epoch.
    const epoch = (cv as unknown as { session: { engine: { currentEpoch(): string | null } } }).session.engine.currentEpoch();
    expect(epoch).not.toBeNull();
    for (const c of joined) {
      expect((c as unknown as { session: { engine: { currentEpoch(): string | null } } }).session.engine.currentEpoch()).toBe(epoch);
    }
  });

  test("no regression: healthy linear traffic still seals sealed-sym (not asym)", async () => {
    const a = party(51, "did:plc:a");
    const b = party(52, "did:plc:b");
    const { cv, joined, convos } = await foundConcurrent(a, [b]);
    const cb = joined[0]!;
    // Linear genesis: deliver the creator's update before anyone else acts.
    await pipe(await cv.update(), convos);
    expect(cv.hasSendableEpoch).toBe(true);

    // An app send in the established epoch must ride sealed-sym to the peer.
    const out = await cv.send("linear");
    expect(out.length).toBeGreaterThan(0);
    for (const o of out) expect(envelopeMode(o.envelope)).toBe(MODE_SYM);
    await pipe(out, convos);
    expect(await texts(b, cb)).toContain("linear");
  });

  test("orphaned epoch still DECRYPTS pre-merge traffic delivered late", async () => {
    const a = party(61, "did:plc:a");
    const b = party(62, "did:plc:b");
    const { cv, joined, convos } = await foundConcurrent(a, [b]);
    const cb = joined[0]!;
    // Establish a shared epoch E0.
    await pipe(await cv.update(), convos);

    // A sends under E0 but we HOLD the envelope (don't deliver to B yet).
    const straggler = await cv.send("under-e0");
    expect(straggler.every((o) => envelopeMode(o.envelope) === MODE_SYM)).toBe(true);

    // Now a concurrent-update merge orphans E0 as the current epoch on B…
    await pipe(await cv.update(), convos); // A → E1 (B derives it too, linear so far)
    const updB = await cb.update(); // B updates concurrently with A's next…
    const updA2 = await cv.update();
    await pipe(updB, convos);
    await pipe(updA2, convos);

    // …but the held straggler, sealed under E0, must still open on B (E0 stays
    // decryptable though it is no longer sealable, §4.1).
    await pipe(straggler, convos);
    expect(await texts(b, cb)).toContain("under-e0");
  });

  test("persistently-unopenable sym traffic is reported, not silently dropped (§4.3)", async () => {
    // Foreign sym traffic from a group B is not in: B can never derive its tag,
    // so each envelope buffers and, after the retry threshold, must surface
    // `unopenable-envelope` (instead of the old silent buffer-forever).
    const events: string[] = [];
    // Source group A+pA (two members → app sends produce real sym envelopes).
    const a = party(71, "did:plc:a");
    const pa = party(72, "did:plc:pa");
    const { cv: ga, convos: gaConvos } = await foundConcurrent(a, [pa]);
    await pipe(await ga.update(), gaConvos); // establish a shared epoch
    expect(ga.hasSendableEpoch).toBe(true);

    // B's own established group (its onEvent sink is what we assert on).
    const b = party(73, "did:plc:b", events);
    const pb = party(74, "did:plc:pb");
    const { cv: cb, convos: cbConvos } = await foundConcurrent(b, [pb]);
    await pipe(await cb.update(), cbConvos);

    // Feed B's conversation distinct foreign sym envelopes; each deliver pumps
    // one refresh, so the earliest buffered ones cross the report threshold.
    for (let i = 0; i < 12; i++) {
      const out = await ga.send(`m${i}`);
      const sym = out.find((o) => envelopeMode(o.envelope) === MODE_SYM);
      if (sym !== undefined) await cb.deliverEnvelope(sym.envelope);
    }
    expect(events.some((e) => e.startsWith("unopenable-envelope"))).toBe(true);
  });
});
