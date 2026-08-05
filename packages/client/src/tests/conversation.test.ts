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
import {
  callPart,
  createContent,
  encodeContent,
  KIND_CALL,
  type MessageContent,
  messageIdToHex,
  oneShotConvoIdV2,
  reactionPart,
  textOf,
  textPart,
} from "../lib/format/index.js";
import { transcriptMessages } from "../lib/storage/apply.js";
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

const texts = (msgs: LocalMessage[]) => msgs.map((m) => textOf(m.content));

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
    expect(texts(await bob.ctx.storage.getMessages(convoB.convoId))).toContain("hello bob");
    // Alice's own sent message is persisted immediately too.
    expect(texts(await alice.ctx.storage.getMessages(convoA.convoId))).toContain("hello bob");

    // Bidirectional: Bob replies, Alice receives it processed.
    await pipe(await convoB.send("hi alice"), wires);
    expect(texts(await alice.ctx.storage.getMessages(convoA.convoId))).toEqual(
      expect.arrayContaining(["hello bob", "hi alice"]),
    );

    // Membership is derived from the engine (DIDs, deduped).
    expect(new Set(convoB.members)).toEqual(new Set([alice.did, bob.did]));
  });

  test("messages$ emits the processed message reactively", async () => {
    const alice = party(3, "did:plc:alice3");
    const bob = party(4, "did:plc:bob4");
    const { convoA, convoB, wires } = await founded(alice, bob);

    const seen: Array<Array<string | null>> = [];
    const sub = convoB.messages$.subscribe((msgs) => seen.push(texts(msgs)));

    await pipe(await convoA.send("reactive"), wires);
    await new Promise((r) => setTimeout(r, 10)); // let the observable flush

    expect(seen.at(-1)).toContain("reactive");
    sub.unsubscribe();
  });

  test("reply, reaction (+ removal), edit, and retraction project onto the transcript", async () => {
    const alice = party(11, "did:plc:alice11");
    const bob = party(12, "did:plc:bob12");
    const { convoA, convoB, wires } = await founded(alice, bob);

    // Alice: a message; Bob: a reply + a reaction to it.
    await pipe(await convoA.send("original"), wires);
    const original = (await bob.ctx.storage.getMessages(convoB.convoId)).find(
      (m) => textOf(m.content) === "original",
    )!;
    await pipe(await convoB.send({ text: "a reply", inReplyTo: original.id }), wires);
    await pipe(await convoB.send({ parts: [reactionPart("👍")], inReplyTo: original.id }), wires);

    // Both stores agree: the original carries Bob's reaction, the reply links back.
    for (const [store, convoId] of [
      [alice.ctx.storage, convoA.convoId],
      [bob.ctx.storage, convoB.convoId],
    ] as const) {
      const msgs = await store.getMessages(convoId);
      const orig = msgs.find((m) => m.id === original.id)!;
      expect(orig.reactions?.map((r) => r.emoji)).toEqual(["👍"]);
      const reply = msgs.find((m) => textOf(m.content) === "a reply")!;
      expect(messageIdToHex(reply.content.inReplyTo!)).toBe(original.id);
    }

    // Removal: retract the reaction message → the projection empties.
    const reactionRow = (await bob.ctx.storage.getMessages(convoB.convoId)).find(
      (m) => m.content.inReplyTo !== null && m.reactions === undefined && textOf(m.content) === null,
    )!;
    await pipe(await convoB.send({ replaces: reactionRow.id, tombstone: true }), wires);
    expect((await alice.ctx.storage.getMessage(original.id))!.reactions ?? []).toEqual([]);

    // Edit: Alice replaces her original; both sides show the new text + marker.
    await pipe(await convoA.send({ text: "original (edited)", replaces: original.id }), wires);
    const editedAtBob = (await bob.ctx.storage.getMessage(original.id))!;
    expect(textOf(editedAtBob.content)).toBe("original (edited)");
    expect(editedAtBob.editedAt).toBeDefined();

    // A same-id edit from the WRONG sender is ignored (§5.1 authorization).
    await pipe(await convoB.send({ text: "hijacked", replaces: original.id }), wires);
    expect(textOf((await alice.ctx.storage.getMessage(original.id))!.content)).toBe("original (edited)");

    // Retraction: Alice deletes it; transcript shows a placeholder, not the text.
    await pipe(await convoA.send({ replaces: original.id, tombstone: true }), wires);
    const gone = (await bob.ctx.storage.getMessage(original.id))!;
    expect(gone.deleted).toBe(true);
    const transcript = transcriptMessages(await bob.ctx.storage.getMessages(convoB.convoId));
    expect(transcript.map((m) => m.id)).toContain(original.id); // placeholder row survives
    expect(transcript.some((m) => textOf(m.content) === "a reply")).toBe(true);
    expect(transcript.some((m) => m.content.replaces !== null)).toBe(false); // edit/retract rows hidden
  });

  test("ephemeral signaling reaches onSignal and never touches storage", async () => {
    const alice = party(13, "did:plc:alice13");
    const bob = party(14, "did:plc:bob14");
    const signals: string[] = [];
    (bob.ctx as { onSignal?: (c: MessageContent, s: string) => void }).onSignal = (c, sender) => {
      const call = c.body?.find((part) => part.kind === KIND_CALL);
      if (call !== undefined && "body" in call) signals.push(`${sender}:${String(call.body.get("type"))}`);
    };
    const { convoA, convoB, wires } = await founded(alice, bob);

    await pipe(
      await convoA.send({ parts: [callPart({ callId: "c1", type: "offer", sdp: "v=0" })], ephemeral: true }),
      wires,
    );
    expect(signals).toEqual(["did:plc:alice13:offer"]);
    // Nothing persisted on either side — the replay-bug class is structurally gone.
    expect(await texts(await alice.ctx.storage.getMessages(convoA.convoId))).toEqual([]);
    expect(await texts(await bob.ctx.storage.getMessages(convoB.convoId))).toEqual([]);
  });

  test("content bound to a different conversation is dropped", async () => {
    // The frame signature is authority on the sender; the content's convoId
    // must still bind to THIS conversation (defense in depth, format §4).
    const alice = party(5, "did:plc:alice5");
    const bob = party(6, "did:plc:bob6");
    const { convoB } = await founded(alice, bob);

    const stray = createContent({
      convoId: oneShotConvoIdV2(["did:plc:alice5", "did:plc:evil"]),
      salt: new Uint8Array(16),
      body: [textPart("forged")],
    });
    await convoB.handleDecrypted(encodeContent(stray), "did:plc:alice5");
    expect(texts(await bob.ctx.storage.getMessages(convoB.convoId))).not.toContain("forged");
  });
});
