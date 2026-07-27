/**
 * Conversation (app-facing): a peer's send lands as a fully-processed message in
 * the recipient's messages$ / store — unsealed, decrypted, verified, persisted —
 * with the app touching no crypto (sdk-shape.md Part A). Sealed envelopes are
 * piped directly here; transport is a separate layer.
 */

import { bytesToHex, type Csprng,generateSigningKeypair, SealLayer } from "@atsms/dcgka";
import { x25519 } from "@noble/curves/ed25519";
import { Database } from "bun:sqlite";
import { describe, expect, test } from "bun:test";

import {
  Conversation,
  type LocalKeys,
  type MemberDescriptor,
  type Outbound,
} from "../lib/conversations/index.js";
import { parseTextContent } from "../lib/messages.js";
import { SQLiteAdapter } from "../lib/storage/sqlite-adapter.js";
import type { LocalMessage } from "../lib/storage/types.js";

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
  const ctx = { storage: newStore(), rng, device, did, prekeySecrets: [leafSk] };
  return { did, device, keys, descriptor, ctx, fp: bytesToHex(device.fingerprint) };
}

/** Deliver each envelope to its addressee (by fingerprint), chasing repair traffic. */
async function pipe(outbound: Outbound[], convos: Map<string, Conversation>): Promise<void> {
  for (const o of outbound) {
    const target = convos.get(o.to);
    if (target !== undefined) await pipe(await target.deliverEnvelope(o.envelope), convos);
  }
}

const texts = (msgs: LocalMessage[]) => msgs.map((m) => parseTextContent(m.content).text);

/** Found an Alice↔Bob conversation, bootstrapping Bob from the sealed create. */
async function founded(a: ReturnType<typeof party>, b: ReturnType<typeof party>) {
  const { conversation: convoA, outbound } = await Conversation.open(a.ctx, {
    keys: a.keys,
    members: [a.descriptor, b.descriptor],
    admins: [a.did],
  });
  const createFrame = SealLayer.openBootstrap(outbound.find((o) => o.to === b.fp)!.envelope, [b.keys.leafSk]);
  const convoB = await Conversation.bootstrap(b.ctx, { keys: b.keys, createFrame });
  const wires = new Map([
    [a.fp, convoA],
    [b.fp, convoB],
  ]);
  await pipe(await convoA.update(), wires);
  return { convoA, convoB, wires };
}

describe("Conversation (app-facing message pipeline)", () => {
  test("a peer's send arrives as a fully-processed message; the app sees no crypto", async () => {
    const alice = party(1, "did:plc:alice");
    const bob = party(2, "did:plc:bob");
    const { convoA, convoB, wires } = await founded(alice, bob);

    await pipe(await convoA.send("hello bob"), wires);

    // Bob's store now holds the fully-processed message.
    expect(texts(await bob.ctx.storage.getMessages(convoB.groupId))).toContain("hello bob");
    // Alice's own sent message is persisted immediately too.
    expect(texts(await alice.ctx.storage.getMessages(convoA.groupId))).toContain("hello bob");

    // Bidirectional: Bob replies, Alice receives it processed.
    await pipe(await convoB.send("hi alice"), wires);
    expect(texts(await alice.ctx.storage.getMessages(convoA.groupId))).toEqual(
      expect.arrayContaining(["hello bob", "hi alice"]),
    );

    // Membership is derived from the engine (DIDs, deduped).
    expect(new Set(convoB.members)).toEqual(new Set([alice.did, bob.did]));
  });

  test("messages$ emits the processed message reactively", async () => {
    const alice = party(3, "did:plc:alice3");
    const bob = party(4, "did:plc:bob4");
    const { convoA, convoB, wires } = await founded(alice, bob);

    const seen: string[][] = [];
    const sub = convoB.messages$.subscribe((msgs) => seen.push(texts(msgs)));

    await pipe(await convoA.send("reactive"), wires);
    await new Promise((r) => setTimeout(r, 10)); // let the observable flush

    expect(seen.at(-1)).toContain("reactive");
    sub.unsubscribe();
  });

  test("a payload whose self-reported sender/convo disagrees with the frame is dropped", async () => {
    // The frame signature is authority; a lying payload never reaches the store.
    const alice = party(5, "did:plc:alice5");
    const bob = party(6, "did:plc:bob6");
    const { convoB } = await founded(alice, bob);

    // Forge a payload claiming a different sender via handleDecrypted directly.
    await convoB.handleDecrypted(new TextEncoder().encode(JSON.stringify({
      version: "1.0", contentType: "atsms/text", id: "x", content: '{"text":"forged"}',
      senderId: "did:plc:evil", recipientIds: [], convoId: convoB.groupId, createdAt: new Date().toISOString(),
    })), "did:plc:alice5");
    expect(texts(await bob.ctx.storage.getMessages(convoB.groupId))).not.toContain("forged");
  });
});
