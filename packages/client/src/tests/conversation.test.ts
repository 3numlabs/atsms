/**
 * Conversation (app-facing): a peer's send lands as a fully-processed message in
 * the recipient's messages$ / store — decrypted, verified, persisted — with the
 * app touching no crypto (sdk-shape.md Part A). Frames are piped directly here;
 * transport is a separate layer.
 */

import { Database } from "bun:sqlite";
import { x25519 } from "@noble/curves/ed25519";
import { generateSigningKeypair, type Csprng } from "@atsms/dcgka";
import { describe, expect, test } from "bun:test";

import { SQLiteAdapter } from "../lib/storage/sqlite-adapter.js";
import { parseTextContent } from "../lib/messages.js";
import type { LocalMessage } from "../lib/storage/types.js";
import { Conversation, type LocalKeys, type MemberDescriptor } from "../lib/conversations/index.js";

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
  const ctx = { storage: newStore(), rng, device, did };
  return { did, device, keys, descriptor, ctx };
}

const texts = (msgs: LocalMessage[]) => msgs.map((m) => parseTextContent(m.content).text);

describe("Conversation (app-facing message pipeline)", () => {
  test("a peer's send arrives as a fully-processed message; the app sees no crypto", async () => {
    const alice = party(1, "did:plc:alice");
    const bob = party(2, "did:plc:bob");

    const { conversation: a, outbound } = await Conversation.open(alice.ctx, {
      keys: alice.keys,
      members: [alice.descriptor, bob.descriptor],
      admins: [alice.did],
    });
    const b = await Conversation.bootstrap(bob.ctx, {
      keys: bob.keys,
      createFrame: outbound[0]!,
      participants: [alice.did, bob.did],
    });

    // (transport would carry these; here we pipe frames directly)
    for (const f of await a.update()) await b.ingestFrame(f);
    for (const f of await a.send("hello bob")) await b.ingestFrame(f);

    // Bob's store now holds the fully-processed message.
    expect(texts(await bob.ctx.storage.getMessages(b.groupId))).toContain("hello bob");
    // Alice's own sent message is persisted immediately too.
    expect(texts(await alice.ctx.storage.getMessages(a.groupId))).toContain("hello bob");

    // Bidirectional: Bob replies, Alice receives it processed.
    for (const f of await b.send("hi alice")) await a.ingestFrame(f);
    expect(texts(await alice.ctx.storage.getMessages(a.groupId))).toEqual(
      expect.arrayContaining(["hello bob", "hi alice"]),
    );
  });

  test("messages$ emits the processed message reactively", async () => {
    const alice = party(3, "did:plc:alice3");
    const bob = party(4, "did:plc:bob4");
    const { conversation: a, outbound } = await Conversation.open(alice.ctx, {
      keys: alice.keys,
      members: [alice.descriptor, bob.descriptor],
      admins: [alice.did],
    });
    const b = await Conversation.bootstrap(bob.ctx, {
      keys: bob.keys,
      createFrame: outbound[0]!,
      participants: [alice.did, bob.did],
    });
    for (const f of await a.update()) await b.ingestFrame(f);

    const seen: string[][] = [];
    const sub = b.messages$.subscribe((msgs) => seen.push(texts(msgs)));

    for (const f of await a.send("reactive")) await b.ingestFrame(f);
    await new Promise((r) => setTimeout(r, 10)); // let the observable flush

    expect(seen.at(-1)).toContain("reactive");
    sub.unsubscribe();
  });

  test("a payload whose self-reported sender/convo disagrees with the frame is dropped", async () => {
    // The frame signature is authority; a lying payload never reaches the store.
    const alice = party(5, "did:plc:alice5");
    const bob = party(6, "did:plc:bob6");
    const { conversation: a, outbound } = await Conversation.open(alice.ctx, {
      keys: alice.keys,
      members: [alice.descriptor, bob.descriptor],
      admins: [alice.did],
    });
    const b = await Conversation.bootstrap(bob.ctx, {
      keys: bob.keys,
      createFrame: outbound[0]!,
      participants: [alice.did, bob.did],
    });
    for (const f of await a.update()) await b.ingestFrame(f);

    // Forge a payload claiming a different sender via handleDecrypted directly.
    await b.handleDecrypted(new TextEncoder().encode(JSON.stringify({
      version: "1.0", contentType: "atsms/text", id: "x", content: '{"text":"forged"}',
      senderId: "did:plc:evil", recipientIds: [], convoId: b.groupId, createdAt: new Date().toISOString(),
    })), "did:plc:alice5");
    expect(texts(await bob.ctx.storage.getMessages(b.groupId))).not.toContain("forged");
  });
});
