/**
 * ConversationSession: a frame-log-persisted DCGKA session survives a restart
 * (restore by replay) and converges across members (sdk-shape.md Part A).
 */

import { x25519 } from "@noble/curves/ed25519";
import { generateSigningKeypair, type Csprng } from "@atsms/dcgka";
import { describe, expect, test } from "bun:test";

import {
  ConversationSession,
  InMemoryDcgkaSessionStore,
  type LocalMember,
  type MemberDescriptor,
} from "../lib/conversations/index.js";

const enc = (s: string) => new TextEncoder().encode(s);
const dec = (b: Uint8Array) => new TextDecoder().decode(b);

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

function party(seed: number, did: string): { me: LocalMember; rng: Csprng } {
  const rng = rngOf(seed);
  const leafSk = rng(32);
  const kp = generateSigningKeypair(rng);
  return {
    rng,
    me: {
      device: { did, fingerprint: rng(32) },
      signingSk: kp.sk,
      signingPk: kp.pk,
      leafPk: x25519.getPublicKey(leafSk),
      leafSk,
    },
  };
}

const desc = (me: LocalMember): MemberDescriptor => ({
  device: me.device,
  leafPk: me.leafPk,
  signingPk: me.signingPk,
});

describe("ConversationSession persistence", () => {
  test("restore replays the frame log to the same tree state", async () => {
    const store = new InMemoryDcgkaSessionStore();
    const alice = party(1, "did:plc:alice");
    const bob = party(2, "did:plc:bob");

    const { conversation } = await ConversationSession.create(
      { store, rng: alice.rng },
      { me: alice.me, members: [desc(alice.me), desc(bob.me)], admins: [alice.me.device.did] },
    );
    await conversation.update(); // establish the first epoch
    await conversation.send(enc("hello"));
    const groupId = conversation.groupId;
    const hashBefore = conversation.engine.treeHash();

    // "Restart" — a fresh process rebuilds only from the persisted log.
    const restored = await ConversationSession.restore({ store, rng: alice.rng }, groupId);
    expect(restored).not.toBeNull();
    expect(restored!.engine.treeHash()).toBe(hashBefore);
  });

  // KNOWN GAP → needs a dcgka enhancement. Frame-log replay reconstructs the tree
  // (above) and any epoch whose secret arrived encrypted in a frame (the two-party
  // test below), but NOT a member's *self-authored* epoch secret: a TreeKEM
  // updater's own path secret is encrypted to the others, never into its own
  // frame. So after a restart the author can't send until it re-derives — the
  // engine's secret material (ShareKeyMap + sender-chain positions) must be
  // serialized alongside the frames (atsms-integration §2 "serializable state").
  test.todo("restore reconstructs self-authored epoch secrets (needs engine state serialization)");

  test("restore returns null for an unknown conversation", async () => {
    const restored = await ConversationSession.restore(
      { store: new InMemoryDcgkaSessionStore(), rng: rngOf(9) },
      "deadbeef",
    );
    expect(restored).toBeNull();
  });

  test("two members converge; ingested frames persist and survive a restart", async () => {
    const alice = party(1, "did:plc:alice");
    const bob = party(2, "did:plc:bob");
    const aStore = new InMemoryDcgkaSessionStore();
    const bStore = new InMemoryDcgkaSessionStore();

    const { conversation: a, outbound: createOut } = await ConversationSession.create(
      { store: aStore, rng: alice.rng },
      { me: alice.me, members: [desc(alice.me), desc(bob.me)], admins: [alice.me.device.did] },
    );

    const received: string[] = [];
    const b = await ConversationSession.bootstrap(
      { store: bStore, rng: bob.rng },
      { me: bob.me, createFrame: createOut[0]!, events: { onAppMessage: (pt) => received.push(dec(pt)) } },
    );

    for (const f of await a.update()) await b.ingest(f);
    for (const f of await a.send(enc("hi bob"))) await b.ingest(f);

    expect(received).toContain("hi bob");
    expect(b.engine.treeHash()).toBe(a.engine.treeHash());

    // Bob restarts — the ingested frames were persisted, so replay converges.
    const bRestored = await ConversationSession.restore({ store: bStore, rng: bob.rng }, b.groupId);
    expect(bRestored!.engine.treeHash()).toBe(a.engine.treeHash());
  });
});
