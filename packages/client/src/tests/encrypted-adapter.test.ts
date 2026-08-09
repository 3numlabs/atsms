/**
 * EncryptedStorageAdapter — envelope (KEK/DEK) encryption-at-rest for the
 * engine/device state blobs, over a real SQLite adapter.
 */

import { bytesToHex, type Csprng,generateSigningKeypair, SealLayer } from "@atsms/dcgka";
import { x25519 } from "@noble/curves/ed25519";
import { Database } from "bun:sqlite";
import { describe, expect, test } from "bun:test";

import { Conversation, ConversationSession, type LocalKeys, type MemberDescriptor } from "../lib/conversations/index.js";
import { textOf } from "../lib/format/index.js";
import { EncryptedStorageAdapter } from "../lib/storage/encrypted-adapter.js";
import type { StorageAdapter } from "../lib/storage/interface.js";
import { SQLiteAdapter } from "../lib/storage/sqlite-adapter.js";

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

const kek = (fill: number) => new Uint8Array(32).fill(fill);
const bytes = (n: number) => crypto.getRandomValues(new Uint8Array(n));

describe("EncryptedStorageAdapter (envelope encryption-at-rest)", () => {
  test("engine + device state round-trip through the encrypting adapter", async () => {
    const inner = new SQLiteAdapter(new BunSQLiteWrapper() as never);
    const enc = await EncryptedStorageAdapter.wrap(inner, kek(1));

    const engine = bytes(300);
    const ring = bytes(96);
    await enc.saveEngineState("g1", engine);
    await enc.saveDeviceState("prekey-ring", ring);

    expect(Array.from((await enc.loadEngineState("g1"))!)).toEqual(Array.from(engine));
    expect(Array.from((await enc.loadDeviceState("prekey-ring"))!)).toEqual(Array.from(ring));
    expect(await enc.loadEngineState("missing")).toBeNull();
    expect(await enc.listEngineStateIds()).toEqual(["g1"]);
  });

  test("blobs are actually ciphertext at rest (the inner store never sees plaintext)", async () => {
    const inner = new SQLiteAdapter(new BunSQLiteWrapper() as never);
    const enc = await EncryptedStorageAdapter.wrap(inner, kek(2));
    const engine = new TextEncoder().encode("SECRET-RATCHET-STATE-0123456789");
    await enc.saveEngineState("g1", engine);

    const raw = (await inner.loadEngineState("g1"))!;
    expect(raw).not.toBeNull();
    // Longer than plaintext (nonce + tag), and does not contain the plaintext.
    expect(raw.length).toBeGreaterThan(engine.length);
    expect(new TextDecoder().decode(raw)).not.toContain("SECRET-RATCHET-STATE");
  });

  test("reopening with the same KEK reuses the keyslot and decrypts existing data", async () => {
    const wrapper = new BunSQLiteWrapper();
    const inner = new SQLiteAdapter(wrapper as never);
    const enc1 = await EncryptedStorageAdapter.wrap(inner, kek(3));
    const engine = bytes(200);
    await enc1.saveEngineState("g1", engine);

    // Second wrap over the SAME inner store + SAME KEK = a fresh "app launch".
    const enc2 = await EncryptedStorageAdapter.wrap(inner, kek(3));
    expect(Array.from((await enc2.loadEngineState("g1"))!)).toEqual(Array.from(engine));
  });

  test("a wrong KEK cannot unwrap the keyslot", async () => {
    const inner = new SQLiteAdapter(new BunSQLiteWrapper() as never);
    await EncryptedStorageAdapter.wrap(inner, kek(4)); // establishes the keyslot
    await expect(EncryptedStorageAdapter.wrap(inner, kek(5))).rejects.toThrow(/wrong device master key/);
  });

  test("the reserved keyslot key is not writable through the public surface", async () => {
    const inner = new SQLiteAdapter(new BunSQLiteWrapper() as never);
    const enc = await EncryptedStorageAdapter.wrap(inner, kek(6));
    await expect(enc.saveDeviceState("__atsms_dek_keyslot_v1__", bytes(32))).rejects.toThrow(/reserved/);
  });

  test("non-blob operations pass through unencrypted", async () => {
    const inner = new SQLiteAdapter(new BunSQLiteWrapper() as never);
    const enc = await EncryptedStorageAdapter.wrap(inner, kek(7));
    await enc.saveConversation({
      id: "c1",
      participantIds: ["did:plc:a", "did:plc:b"],
      createdAt: new Date(),
      lastMessageAt: new Date(),
      unreadCount: 0,
      metadata: { protocol: "dcgka" },
    });
    expect((await enc.getConversation("c1"))?.participantIds).toEqual(["did:plc:a", "did:plc:b"]);
    // Passed straight to the inner store (not the encrypting path).
    expect((await inner.getConversation("c1"))?.id).toBe("c1");
  });

  test("a full sealed conversation survives a restart over encrypted stores", async () => {
    const rngOf = (seed: number): Csprng => {
      let s = seed >>> 0;
      return (n: number) => {
        const out = new Uint8Array(n);
        for (let i = 0; i < n; i++) {
          s = (s * 1664525 + 1013904223) >>> 0;
          out[i] = (s >>> 24) & 0xff;
        }
        return out;
      };
    };
    const party = async (seed: number, did: string, wrapper: BunSQLiteWrapper) => {
      const rng = rngOf(seed);
      const leafSk = rng(32);
      const kp = generateSigningKeypair(rng);
      const device = { did, fingerprint: rng(32) };
      const keys: LocalKeys = { signingSk: kp.sk, signingPk: kp.pk, leafPk: x25519.getPublicKey(leafSk), leafSk };
      const descriptor: MemberDescriptor = { device, leafPk: keys.leafPk, signingPk: keys.signingPk };
      const storage: StorageAdapter = await EncryptedStorageAdapter.wrap(
        new SQLiteAdapter(wrapper as never),
        kek(seed),
      );
      const ctx = { storage, rng, device, did, prekeySecrets: [leafSk] };
      return { did, keys, descriptor, ctx, fp: bytesToHex(device.fingerprint), rng, device, leafSk };
    };

    const aliceDb = new BunSQLiteWrapper();
    const alice = await party(11, "did:plc:enc-alice", aliceDb);
    const bob = await party(12, "did:plc:enc-bob", new BunSQLiteWrapper());

    const { conversation: a, outbound } = await Conversation.open(alice.ctx, {
      keys: alice.keys,
      members: [alice.descriptor, bob.descriptor],
      admins: [alice.did],
    });
    const createFrame = SealLayer.openBootstrap(outbound.find((o) => o.to === bob.fp)!.envelope, [bob.leafSk]);
    const b = await Conversation.bootstrap(bob.ctx, { keys: bob.keys, createFrame });
    const wires = new Map([
      [alice.fp, a],
      [bob.fp, b],
    ]);
    const pipe = async (out: Awaited<ReturnType<typeof a.send>>): Promise<void> => {
      for (const o of out) {
        const t = wires.get(o.to);
        if (t !== undefined) await pipe(await t.deliverEnvelope(o.envelope));
      }
    };
    await pipe(await a.update());
    await pipe(await a.send("encrypted at rest"));
    expect((await bob.ctx.storage.getMessages(b.convoId)).map((m) => textOf(m.content))).toContain(
      "encrypted at rest",
    );

    // "Restart" Alice: a fresh encrypted adapter over her same DB + KEK restores
    // the engine state and she can still send (the encrypted serialize/restore path).
    const aliceStorage2 = await EncryptedStorageAdapter.wrap(new SQLiteAdapter(aliceDb as never), kek(11));
    const a2 = await ConversationSession.restore(
      { storage: aliceStorage2, rng: alice.rng, device: alice.device, prekeySecrets: [alice.leafSk] },
      a.groupId,
    );
    expect(a2).not.toBeNull();
    // engine_state was saved encrypted, then loaded + decrypted + restored.
    expect(a2!.engine.members().length).toBe(2);
  });
});
