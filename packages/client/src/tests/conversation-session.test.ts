/**
 * ConversationSession over the unified StorageAdapter, sealed: every op yields
 * per-recipient SealedEnvelopes, inbound traffic is delivered as envelopes, and
 * a session persists its engine state (Session.serialize()) and is restored
 * verbatim — including the ability to keep sending after a restart
 * (sdk-shape.md Part A; sealed-sender §1).
 */

import { bytesToHex, type Csprng,generateSigningKeypair, SealLayer } from "@atsms/dcgka";
import { x25519 } from "@noble/curves/ed25519";
import { Database } from "bun:sqlite";
import { describe, expect, test } from "bun:test";

import {
  ConversationSession,
  type LocalKeys,
  type MemberDescriptor,
  type Outbound,
} from "../lib/conversations/index.js";
import { SQLiteAdapter } from "../lib/storage/sqlite-adapter.js";

const enc = (s: string) => new TextEncoder().encode(s);
const dec = (b: Uint8Array) => new TextDecoder().decode(b);

/** In-memory SQLite wrapper matching the SQLiteDatabase interface (BLOB-capable). */
class BunSQLiteWrapper {
  private db = new Database(":memory:");
  exec(sql: string): void {
    this.db.exec(sql);
  }
  prepare(sql: string) {
    const stmt = this.db.prepare(sql);
    return {
      run: (...p: unknown[]) => stmt.run(...(p as never[])),
      get: (...p: unknown[]) => stmt.get(...(p as never[])),
      all: (...p: unknown[]) => stmt.all(...(p as never[])),
    };
  }
  transaction<T>(fn: () => T): T {
    return this.db.transaction(fn)();
  }
  close(): void {
    this.db.close();
  }
}

const newStore = () => new SQLiteAdapter(new BunSQLiteWrapper() as never);

/** Deterministic (non-crypto) byte source — fine for generating test key material. */
function rngOf(seed: number): Csprng {
  let s = seed >>> 0;
  return (n: number) => {
    const out = new Uint8Array(n);
    for (let i = 0; i < n; i++) {
      s = (s * 1664525 + 1013904223) >>> 0;
      out[i] = (s >>> 24) & 0xff;
    }
    return out;
  };
}

function party(seed: number, did: string) {
  const rng = rngOf(seed);
  const leafSk = rng(32);
  const kp = generateSigningKeypair(rng);
  const device = { did, fingerprint: rng(32) };
  const keys: LocalKeys = { signingSk: kp.sk, signingPk: kp.pk, leafPk: x25519.getPublicKey(leafSk), leafSk };
  const descriptor: MemberDescriptor = { device, leafPk: keys.leafPk, signingPk: keys.signingPk };
  const deps = { storage: newStore(), rng, device, prekeySecrets: [leafSk] };
  return { did, device, keys, descriptor, deps, fp: bytesToHex(device.fingerprint) };
}

/** Deliver each envelope to its addressee (by fingerprint), chasing repair traffic. */
async function pipe(outbound: Outbound[], sessions: Map<string, ConversationSession>): Promise<void> {
  for (const o of outbound) {
    const target = sessions.get(o.to);
    if (target !== undefined) await pipe(await target.deliver(o.envelope), sessions);
  }
}

describe("ConversationSession (sealed, unified storage)", () => {
  test("survives a restart and can still send (engine-state serialize/restore)", async () => {
    const alice = party(1, "did:plc:alice");
    const bob = party(2, "did:plc:bob");

    const { conversation, outbound } = await ConversationSession.create(alice.deps, {
      keys: alice.keys,
      members: [alice.descriptor, bob.descriptor],
      admins: [alice.did],
    });

    // The create leaves as a sealed-asym envelope addressed to Bob; the
    // dispatcher unseals bootstrap-class envelopes with the prekey secrets.
    const toBob = outbound.filter((o) => o.to === bob.fp);
    expect(toBob).toHaveLength(1);
    const createFrame = SealLayer.openBootstrap(toBob[0]!.envelope, [bob.keys.leafSk]);

    const bobRecv: string[] = [];
    const bob0 = await ConversationSession.bootstrap(bob.deps, {
      keys: bob.keys,
      createFrame,
      events: { onAppMessage: (pt) => bobRecv.push(dec(pt)) },
    });

    const wires = new Map([[bob.fp, bob0]]);
    await pipe(await conversation.update(), wires);
    await pipe(await conversation.send(enc("m0")), wires);
    expect(bobRecv).toEqual(["m0"]);

    const hashBefore = conversation.engine.treeHash();

    // Restart Alice — nothing in memory, only the persisted engine-state blob.
    const alice2 = await ConversationSession.restore(alice.deps, conversation.groupId);
    expect(alice2).not.toBeNull();
    expect(alice2!.engine.treeHash()).toBe(hashBefore);

    // She can still SEND across a self-authored epoch, and Bob decrypts it (the
    // sender chain continued — no generation reuse; a fresh SealLayer reseals).
    await pipe(await alice2!.send(enc("m1")), wires);
    expect(bobRecv).toEqual(["m0", "m1"]);
  });

  test("an added member joins from the sealed welcome and converses (mandatory heal)", async () => {
    const alice = party(5, "did:plc:alice5");
    const bob = party(6, "did:plc:bob6");
    const carol = party(7, "did:plc:carol7");

    const { conversation: a, outbound } = await ConversationSession.create(alice.deps, {
      keys: alice.keys,
      members: [alice.descriptor, bob.descriptor],
      admins: [alice.did],
    });
    const b = await ConversationSession.bootstrap(bob.deps, {
      keys: bob.keys,
      createFrame: SealLayer.openBootstrap(outbound.find((o) => o.to === bob.fp)!.envelope, [bob.keys.leafSk]),
    });
    const wires = new Map([
      [alice.fp, a],
      [bob.fp, b],
    ]);
    await pipe(await a.update(), wires);

    // Alice adds Carol; the welcome is among the sealed envelopes, asym to Carol.
    const addOut = await a.addMember(carol.descriptor);
    const toCarol = addOut.filter((o) => o.to === carol.fp);
    expect(toCarol.length).toBeGreaterThan(0);
    await pipe(addOut, wires); // Bob processes the add

    // Carol trial-opens her envelopes; exactly one unseals to her welcome.
    let welcomeFrame: Uint8Array | null = null;
    for (const o of toCarol) {
      try {
        welcomeFrame = SealLayer.openBootstrap(o.envelope, [carol.keys.leafSk]);
        break;
      } catch {
        /* the sym add-copy she can't open yet */
      }
    }
    expect(welcomeFrame).not.toBeNull();

    const carolRecv: string[] = [];
    const { conversation: c, outbound: healOut } = await ConversationSession.join(carol.deps, {
      keys: carol.keys,
      welcomeFrame: welcomeFrame!,
      events: { onAppMessage: (pt) => carolRecv.push(dec(pt)) },
    });
    wires.set(carol.fp, c);
    await pipe(healOut, wires); // the mandatory post-join update reaches Alice + Bob

    await pipe(await a.send(enc("hi carol")), wires);
    expect(carolRecv).toEqual(["hi carol"]);

    // And Carol can speak — everyone converges on her post-heal epoch.
    await pipe(await c.send(enc("hi all")), wires);
    expect(a.engine.treeHash()).toBe(c.engine.treeHash());
    expect(b.engine.treeHash()).toBe(c.engine.treeHash());
  });

  test("restore returns null for an unknown conversation", async () => {
    const p = party(9, "did:plc:x");
    expect(await ConversationSession.restore(p.deps, "deadbeef")).toBeNull();
  });

  test("listIds enumerates persisted conversations", async () => {
    const alice = party(3, "did:plc:alice3");
    const bob = party(4, "did:plc:bob4");
    const { conversation } = await ConversationSession.create(alice.deps, {
      keys: alice.keys,
      members: [alice.descriptor, bob.descriptor],
      admins: [alice.did],
    });
    expect(await ConversationSession.listIds(alice.deps)).toEqual([conversation.groupId]);

    await conversation.forget();
    expect(await ConversationSession.listIds(alice.deps)).toEqual([]);
    expect(await ConversationSession.restore(alice.deps, conversation.groupId)).toBeNull();
  });
});
