/**
 * IndexedDBAdapter verification (fake-indexeddb): the browser storage layer
 * exercised through everything the ATSMS client needs — messages,
 * conversations (incl. participant-set lookup), engine-state and device-state
 * blobs, observers — plus a full sealed conversation end-to-end over
 * IndexedDB-backed parties. (The old test file was `.skip` and had never run.)
 */

import "fake-indexeddb/auto";

import { type Csprng,generateSigningKeypair, SealLayer } from "@atsms/dcgka";
import { x25519 } from "@noble/curves/ed25519";
import { describe, expect, test } from "bun:test";

import { Conversation, type LocalKeys, type MemberDescriptor, type Outbound } from "../lib/conversations/index.js";
import { parseTextContent } from "../lib/messages.js";
import { IndexedDBAdapter } from "../lib/storage/indexeddb-adapter.js";
import type { LocalMessage } from "../lib/storage/types.js";

let dbCounter = 0;
const newStore = () => new IndexedDBAdapter(`atsms-test-${++dbCounter}`);

let clock = Date.now();
const msg = (id: string, convoId: string): LocalMessage => ({
  id,
  convoId,
  senderId: "did:plc:a",
  recipientIds: ["did:plc:b"],
  content: JSON.stringify({ text: `text-${id}` }),
  contentType: "atsms/text",
  createdAt: new Date(++clock), // distinct timestamps — createdAt orders the feed
  isInvitation: false,
});

describe("IndexedDBAdapter (browser storage layer)", () => {
  test("messages: save/get/getMessages/delete + observer emission", async () => {
    const store = newStore();
    const seen: number[] = [];
    const sub = store.observeMessages("c1").subscribe((msgs) => seen.push(msgs.length));

    await store.saveMessage(msg("m1", "c1"));
    await store.saveMessage(msg("m2", "c1"));
    await store.saveMessage(msg("m3", "other"));

    expect((await store.getMessage("m1"))?.id).toBe("m1");
    expect((await store.getMessages("c1")).map((m) => m.id)).toEqual(["m1", "m2"]);
    await store.deleteMessage("m2");
    expect((await store.getMessages("c1")).map((m) => m.id)).toEqual(["m1"]);
    await new Promise((r) => setTimeout(r, 5));
    expect(seen.at(-1)).toBe(1);
    sub.unsubscribe();
  });

  test("conversations: save/get/find-by-participants/update", async () => {
    const store = newStore();
    await store.saveConversation({
      id: "convo-1",
      participantIds: ["did:plc:a", "did:plc:b"],
      createdAt: new Date(),
      lastMessageAt: new Date(),
      unreadCount: 0,
      metadata: { protocol: "dcgka" },
    });
    expect((await store.getConversation("convo-1"))?.metadata).toEqual({ protocol: "dcgka" });
    const found = await store.findConversationByParticipants(["did:plc:b", "did:plc:a"]);
    expect(found?.id).toBe("convo-1");
    expect(await store.findConversationByParticipants(["did:plc:a", "did:plc:x"])).toBeNull();
  });

  test("engine-state + device-state blobs round-trip verbatim", async () => {
    const store = newStore();
    const blob = crypto.getRandomValues(new Uint8Array(512));
    await store.saveEngineState("group-1", blob);
    expect(Array.from((await store.loadEngineState("group-1"))!)).toEqual(Array.from(blob));
    expect(await store.listEngineStateIds()).toEqual(["group-1"]);
    await store.deleteEngineState("group-1");
    expect(await store.loadEngineState("group-1")).toBeNull();

    const ring = crypto.getRandomValues(new Uint8Array(128));
    await store.saveDeviceState("prekey-ring", ring);
    expect(Array.from((await store.loadDeviceState("prekey-ring"))!)).toEqual(Array.from(ring));
    await store.deleteDeviceState("prekey-ring");
    expect(await store.loadDeviceState("prekey-ring")).toBeNull();
  });

  test("observers emit CURRENT data on subscribe (page-reload contract)", async () => {
    // A freshly-loaded page subscribes to a store that already has data — it
    // must hear about it without waiting for the next write.
    const store = newStore();
    await store.saveConversation({
      id: "warm-1",
      participantIds: ["did:plc:a", "did:plc:b"],
      createdAt: new Date(),
      lastMessageAt: new Date(),
      unreadCount: 0,
      metadata: { protocol: "dcgka" },
    });
    await store.saveMessage(msg("wm1", "warm-1"));

    const convoLists: number[] = [];
    const msgLists: number[] = [];
    const s1 = store.observeConversations().subscribe((c) => convoLists.push(c.length));
    const s2 = store.observeMessages("warm-1").subscribe((m) => msgLists.push(m.length));
    await new Promise((r) => setTimeout(r, 10));
    expect(convoLists.at(0)).toBe(1); // initial emission, not silence
    expect(msgLists.at(0)).toBe(1);

    await store.saveMessage(msg("wm2", "warm-1"));
    await new Promise((r) => setTimeout(r, 10));
    expect(msgLists.at(-1)).toBe(2); // and live updates still flow
    s1.unsubscribe();
    s2.unsubscribe();
  });

  test("a full sealed conversation runs over IndexedDB-backed parties", async () => {
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
    const party = (seed: number, did: string) => {
      const rng = rngOf(seed);
      const leafSk = rng(32);
      const kp = generateSigningKeypair(rng);
      const device = { did, fingerprint: rng(32) };
      const keys: LocalKeys = { signingSk: kp.sk, signingPk: kp.pk, leafPk: x25519.getPublicKey(leafSk), leafSk };
      const descriptor: MemberDescriptor = { device, leafPk: keys.leafPk, signingPk: keys.signingPk };
      const ctx = { storage: newStore(), rng, device, did, prekeySecrets: [leafSk] };
      return { did, keys, descriptor, ctx, fp: Buffer.from(device.fingerprint).toString("hex") };
    };
    const pipe = async (outbound: Outbound[], convos: Map<string, Conversation>): Promise<void> => {
      for (const o of outbound) {
        const target = convos.get(o.to);
        if (target !== undefined) await pipe(await target.deliverEnvelope(o.envelope), convos);
      }
    };

    const alice = party(21, "did:plc:idb-alice");
    const bob = party(22, "did:plc:idb-bob");
    const { conversation: a, outbound } = await Conversation.open(alice.ctx, {
      keys: alice.keys,
      members: [alice.descriptor, bob.descriptor],
      admins: [alice.did],
    });
    const createFrame = SealLayer.openBootstrap(outbound.find((o) => o.to === bob.fp)!.envelope, [bob.keys.leafSk]);
    const b = await Conversation.bootstrap(bob.ctx, { keys: bob.keys, createFrame });
    const wires = new Map([
      [alice.fp, a],
      [bob.fp, b],
    ]);
    await pipe(await a.update(), wires);
    await pipe(await a.send("hello over indexeddb"), wires);
    await pipe(await b.send("works both ways"), wires);

    const bobTexts = (await bob.ctx.storage.getMessages(b.groupId)).map((m) => parseTextContent(m.content).text);
    const aliceTexts = (await alice.ctx.storage.getMessages(a.groupId)).map((m) => parseTextContent(m.content).text);
    expect(bobTexts).toContain("hello over indexeddb");
    expect(aliceTexts).toEqual(expect.arrayContaining(["hello over indexeddb", "works both ways"]));

    // Restart from the persisted engine state alone (the browser-refresh path).
    const a2 = await Conversation.restore(alice.ctx, a.groupId);
    expect(a2).not.toBeNull();
    wires.set(alice.fp, a2!);
    await pipe(await a2!.send("after refresh"), wires);
    expect((await bob.ctx.storage.getMessages(b.groupId)).map((m) => parseTextContent(m.content).text)).toContain(
      "after refresh",
    );
  });
});
