/**
 * ConversationSession over the unified StorageAdapter: a DCGKA session persists
 * its engine state (Session.serialize()) and is restored verbatim — including the
 * ability to keep sending after a restart (sdk-shape.md Part A).
 */

import { Database } from "bun:sqlite";
import { x25519 } from "@noble/curves/ed25519";
import { generateSigningKeypair, type Csprng } from "@atsms/dcgka";
import { describe, expect, test } from "bun:test";

import { SQLiteAdapter } from "../lib/storage/sqlite-adapter.js";
import {
  ConversationSession,
  type LocalKeys,
  type MemberDescriptor,
} from "../lib/conversations/index.js";

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
  return { did, device, keys, descriptor, rng };
}

describe("ConversationSession over unified storage", () => {
  test("survives a restart and can still send (engine-state serialize/restore)", async () => {
    const alice = party(1, "did:plc:alice");
    const bob = party(2, "did:plc:bob");
    const aDeps = { storage: newStore(), rng: alice.rng, device: alice.device };
    const bDeps = { storage: newStore(), rng: bob.rng, device: bob.device };

    const { conversation, outbound } = await ConversationSession.create(aDeps, {
      keys: alice.keys,
      members: [alice.descriptor, bob.descriptor],
      admins: [alice.did],
    });

    const bobRecv: string[] = [];
    const bob0 = await ConversationSession.bootstrap(bDeps, {
      keys: bob.keys,
      createFrame: outbound[0]!,
      events: { onAppMessage: (pt) => bobRecv.push(dec(pt)) },
    });

    for (const f of await conversation.update()) await bob0.ingest(f);
    for (const f of await conversation.send(enc("m0"))) await bob0.ingest(f);
    expect(bobRecv).toEqual(["m0"]);

    const hashBefore = conversation.engine.treeHash();

    // Restart Alice — nothing in memory, only the persisted engine-state blob.
    const alice2 = await ConversationSession.restore(aDeps, conversation.groupId);
    expect(alice2).not.toBeNull();
    expect(alice2!.engine.treeHash()).toBe(hashBefore);

    // She can still SEND across a self-authored epoch, and Bob decrypts it (the
    // sender chain continued — no generation reuse).
    for (const f of await alice2!.send(enc("m1"))) await bob0.ingest(f);
    expect(bobRecv).toEqual(["m0", "m1"]);
  });

  test("restore returns null for an unknown conversation", async () => {
    const deps = { storage: newStore(), rng: rngOf(9), device: party(9, "did:plc:x").device };
    expect(await ConversationSession.restore(deps, "deadbeef")).toBeNull();
  });

  test("listIds enumerates persisted conversations", async () => {
    const alice = party(3, "did:plc:alice3");
    const bob = party(4, "did:plc:bob4");
    const deps = { storage: newStore(), rng: alice.rng, device: alice.device };
    const { conversation } = await ConversationSession.create(deps, {
      keys: alice.keys,
      members: [alice.descriptor, bob.descriptor],
      admins: [alice.did],
    });
    expect(await ConversationSession.listIds(deps)).toEqual([conversation.groupId]);

    await conversation.forget();
    expect(await ConversationSession.listIds(deps)).toEqual([]);
    expect(await ConversationSession.restore(deps, conversation.groupId)).toBeNull();
  });
});
