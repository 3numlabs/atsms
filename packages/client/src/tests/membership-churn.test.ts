/**
 * Membership churn: the scenario suite for add / remove / re-add over the real
 * client stack (DID-routed delivery, multi-device DIDs, batched ops).
 *
 * Every live membership bug so far — the welcome ctrlSeq gap, strong remove at
 * the remover, the welcome-size blowup on re-add — was a *sequence* bug that a
 * single add or a single remove could not surface. This suite drives sequences
 * and asserts the whole contract after each step:
 *
 *   1. membership   — every client agrees on the roster (and the stored record
 *                     matches, since that is what the UI renders)
 *   2. delivery     — every current member receives what any member sends
 *   3. exclusion    — non-members receive nothing new and cannot send
 *   4. events       — the client-visible event stream says what happened
 *   5. size         — sealed material stays inside the envelope bucket, so the
 *                     Nth round works as well as the first
 */

import { cborEncode, type PdsClient, type PdsRecordView, type PutResult } from "@atsms/dcgka";
import { Database } from "bun:sqlite";
import { expect, test } from "bun:test";

import { ATSMS, type ATSMSConversation } from "../lib/client/atsms.js";
import { textOf } from "../lib/format/index.js";
import { ATSMSDeviceIdentity } from "../lib/identity/device-identity.js";
import { SQLiteAdapter } from "../lib/storage/sqlite-adapter.js";
import type { EnvelopeTransport } from "../lib/transport/envelope-transport.js";
import { generateTestEndpointCertificate } from "./test-certificates.js";

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
const rngOf = (seed: number) => {
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

class SharedPds {
  private store = new Map<string, unknown>();
  forDid(myDid: string): PdsClient {
    const key = (repo: string, c: string, rk: string) => `${repo} ${c} ${rk}`;
    return {
      putRecord: async (c, rk, value): Promise<PutResult> => {
        this.store.set(key(myDid, c, rk), value);
        return { uri: `at://${myDid}/${c}/${rk}` };
      },
      deleteRecord: async (c, rk): Promise<void> => {
        this.store.delete(key(myDid, c, rk));
      },
      getRecord: async (repo, c, rk): Promise<PdsRecordView | null> => {
        const v = this.store.get(key(repo, c, rk));
        return v === undefined ? null : { uri: `at://${repo}/${c}/${rk}`, value: v };
      },
      listRecords: async (repo, c): Promise<PdsRecordView[]> => {
        const out: PdsRecordView[] = [];
        for (const [k, v] of this.store) {
          const [r, coll, rk] = k.split(" ");
          if (r === repo && coll === c) out.push({ uri: `at://${repo}/${coll}/${rk}`, value: v });
        }
        return out;
      },
    };
  }
}

/** DID-routed relay: one envelope reaches every device of the addressed DID,
 *  exactly like the worker's fan-out — and records the largest envelope seen. */
class Relay {
  private handlers = new Map<string, Set<(e: Uint8Array) => Promise<void>>>();
  private queue: Array<{ did: string; env: Uint8Array }> = [];
  largestEnvelope = 0;
  /** Swallow envelopes addressed to a DID — a relay that loses first contact. */
  blackhole: string | null = null;
  post(did: string, env: Uint8Array): void {
    this.largestEnvelope = Math.max(this.largestEnvelope, env.length);
    if (did === this.blackhole) return;
    this.queue.push({ did, env });
  }
  async flush(): Promise<void> {
    let guard = 0;
    while (this.queue.length > 0) {
      if (guard++ > 20000) throw new Error("livelock");
      const { did, env } = this.queue.shift()!;
      for (const h of this.handlers.get(did) ?? []) await h(env);
    }
  }
  transportFor(did: string): EnvelopeTransport {
    let mine: ((e: Uint8Array) => Promise<void>) | null = null;
    return {
      ingressUrl: `loop://${encodeURIComponent(did)}`,
      deliverToUrl: async (url, env) => this.post(decodeURIComponent(url.replace("loop://", "")), env),
      deliverToDid: async (target, env) => this.post(target, env),
      start: async (onEnvelope) => {
        let set = this.handlers.get(did);
        if (set === undefined) this.handlers.set(did, (set = new Set()));
        set.add(onEnvelope);
        mine = onEnvelope;
      },
      stop: async () => {
        if (mine !== null) this.handlers.get(did)?.delete(mine);
        mine = null;
      },
    };
  }
}

interface Device {
  label: string;
  did: string;
  storage: SQLiteAdapter;
  atsms: ATSMS;
  identity: ATSMSDeviceIdentity;
  events: string[];
}

/** One device. Several devices sharing a DID model a multi-device user. */
async function device(relay: Relay, pds: SharedPds, seed: number, did: string, label: string): Promise<Device> {
  const { cert, privateKey } = await generateTestEndpointCertificate(did, `${seed}.example`, "atsms.email");
  const storage = new SQLiteAdapter(new Wrap() as never);
  const rng = rngOf(seed);
  const myPds = pds.forDid(did);
  const identity = await ATSMSDeviceIdentity.load({ did, certificatePEM: cert, privateKeyPEM: privateKey, storage, rng });
  await myPds.putRecord("at.atsms.x509", identity.fingerprint, { $type: "at.atsms.x509", certificate: cert });
  const events: string[] = [];
  const atsms = await ATSMS.create({
    identity,
    storage,
    transport: relay.transportFor(did),
    pds: myPds,
    rng,
    onEvent: (kind, detail) => events.push(`${kind}: ${detail}`),
    genesisWaitMs: 0,
    peerMaxAgeMs: 0, // roster changes must be seen immediately in tests
  });
  return { label, did, storage, atsms, identity, events };
}

const texts = async (d: Device, convoId: string): Promise<string[]> =>
  (await d.storage.getMessages(convoId)).map((m) => textOf(m.content) ?? "");

/** The full contract check, run after every churn step. */
async function assertGroupState(
  convoId: string,
  all: Device[],
  expectedMemberDids: string[],
  note: string,
): Promise<void> {
  const expected = [...new Set(expectedMemberDids)].sort();
  for (const d of all) {
    const convo = await d.atsms.conversations.get(convoId);
    if (convo === null) continue; // never joined — nothing to assert
    const isMember = expected.includes(d.did);

    // (1) membership, from the engine AND from the stored record the UI reads.
    expect(convo.amMember, `${note}: ${d.label} amMember`).toBe(isMember);
    if (isMember) {
      expect([...convo.members].sort(), `${note}: ${d.label} roster`).toEqual(expected);
      const record = await d.storage.getConversation(convoId);
      expect(record?.metadata?.removed ?? false, `${note}: ${d.label} record.removed`).toBe(false);
      expect([...(record?.participantIds ?? [])].sort(), `${note}: ${d.label} record roster`).toEqual(expected);
    } else {
      const record = await d.storage.getConversation(convoId);
      expect(record?.metadata?.removed, `${note}: ${d.label} record.removed`).toBe(true);
    }
  }
}

/** Everyone in `members` hears `speaker`; everyone in `excluded` does not. */
async function assertDelivery(
  relay: Relay,
  convoId: string,
  speaker: Device,
  members: Device[],
  excluded: Device[],
  text: string,
): Promise<void> {
  const convo = await speaker.atsms.conversations.get(convoId);
  await convo!.send(text);
  await relay.flush();
  for (const m of members) {
    expect(await texts(m, convoId), `${m.label} should hear "${text}" from ${speaker.label}`).toContain(text);
  }
  for (const e of excluded) {
    expect(await texts(e, convoId), `${e.label} must NOT hear "${text}"`).not.toContain(text);
  }
}

test("churn: add, re-add and remove a multi-device DID repeatedly", async () => {
  const relay = new Relay();
  const pds = new SharedPds();
  const AL = "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa";
  const BO = "did:plc:bbbbbbbbbbbbbbbbbbbbbbbb";
  const CA = "did:plc:cccccccccccccccccccccccc";

  const alice = await device(relay, pds, 1, AL, "alice");
  const bob = await device(relay, pds, 2, BO, "bob");
  // Carol has THREE devices — the live shape that produced three add ops per
  // add, three remove ops per remove, and three welcomes per round.
  const carol1 = await device(relay, pds, 3, CA, "carol/1");
  const carol2 = await device(relay, pds, 4, CA, "carol/2");
  const carol3 = await device(relay, pds, 5, CA, "carol/3");
  const carols = [carol1, carol2, carol3];
  const all = [alice, bob, ...carols];

  // ── open a 2-party conversation ───────────────────────────────────────────
  const convo = await alice.atsms.conversations.createGroup({ members: [bob.did] });
  await relay.flush();
  await assertGroupState(convo.id, all, [AL, BO], "after open");
  await assertDelivery(relay, convo.id, alice, [alice, bob], carols, "m1 hello bob");

  // Three churn rounds: each adds Carol (3 devices), talks, removes her, talks.
  for (let round = 1; round <= 3; round++) {
    // ── add ────────────────────────────────────────────────────────────────
    await convo.addMember(CA);
    await relay.flush();
    await assertGroupState(convo.id, all, [AL, BO, CA], `round ${round} after add`);

    // Every Carol device joined — not just the first.
    for (const c of carols) {
      expect((await c.atsms.conversations.get(convo.id))?.amMember, `round ${round}: ${c.label} joined`).toBe(true);
    }
    // Everyone hears everyone, in both directions.
    await assertDelivery(relay, convo.id, alice, [bob, carol1, carol2, carol3], [], `r${round} from alice`);
    await assertDelivery(relay, convo.id, carol2, [alice, bob, carol1, carol3], [], `r${round} from carol2`);

    // ── remove ─────────────────────────────────────────────────────────────
    await convo.removeMember(CA);
    await relay.flush();
    await assertGroupState(convo.id, all, [AL, BO], `round ${round} after remove`);

    // (4) the removed devices were TOLD, and say so to their UI.
    for (const c of carols) {
      expect(
        c.events.some((e) => e.startsWith("removed-from-conversation")),
        `round ${round}: ${c.label} was told it was removed`,
      ).toBe(true);
      const convoC = (await c.atsms.conversations.get(convo.id)) as ATSMSConversation;
      await expect(convoC.send("i should not be able to")).rejects.toThrow(/no longer a member/);
      c.events.length = 0; // reset for the next round's assertion
    }
    // (3) exclusion: post-removal traffic reaches the remaining members only.
    await assertDelivery(relay, convo.id, bob, [alice], carols, `r${round} after remove`);
  }

  // (5) size: sealed material stays well inside the 64 KiB bucket even after
  // repeated add/remove rounds. Welcomes used to nest welcomes and blow it.
  expect(relay.largestEnvelope, "largest sealed envelope across all churn").toBeLessThan(64 * 1024);

  // Final transcript sanity: the two constant members agree on everything.
  expect(await texts(alice, convo.id)).toEqual(await texts(bob, convo.id));
}, 60000);

test("churn: a removed member's devices can be re-added and talk again", async () => {
  const relay = new Relay();
  const pds = new SharedPds();
  const AL = "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa";
  const BO = "did:plc:bbbbbbbbbbbbbbbbbbbbbbbb";
  const alice = await device(relay, pds, 1, AL, "alice");
  const bob1 = await device(relay, pds, 2, BO, "bob/1");
  const bob2 = await device(relay, pds, 3, BO, "bob/2");

  const convo = await alice.atsms.conversations.createGroup({ members: [BO] });
  await relay.flush();
  await assertDelivery(relay, convo.id, alice, [bob1, bob2], [], "before removal");

  await convo.removeMember(BO);
  await relay.flush();
  await assertGroupState(convo.id, [alice, bob1, bob2], [AL], "after removing bob");

  // Re-add: the welcome must still fit, and BOTH devices must come back.
  await convo.addMember(BO);
  await relay.flush();
  await assertGroupState(convo.id, [alice, bob1, bob2], [AL, BO], "after re-adding bob");
  await assertDelivery(relay, convo.id, alice, [bob1, bob2], [], "after re-add");
  await assertDelivery(relay, convo.id, bob2, [alice, bob1], [], "re-added device speaks");

  // The record's removed flag cleared on re-admission.
  for (const b of [bob1, bob2]) {
    expect((await b.storage.getConversation(convo.id))!.metadata?.removed, `${b.label} flag cleared`).toBe(false);
  }
  expect(relay.largestEnvelope).toBeLessThan(64 * 1024);
}, 60000);

test("churn: a device that re-keyed since the directory snapshot is still re-addable", async () => {
  // Live 2026-08-03: aib0b was removed, its browser storage was cleared (same
  // passkey ⇒ same cert and fingerprint, but a FRESH prekey ring, republishing
  // its prekey), and the re-add sealed its welcome to the prekey the adder had
  // cached minutes earlier. The device could not open it and sat there saying
  // "you were removed" while everyone else saw it re-added.
  const relay = new Relay();
  const pds = new SharedPds();
  const AL = "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa";
  const BO = "did:plc:bbbbbbbbbbbbbbbbbbbbbbbb";

  // Alice's directory tolerates staleness — the production default.
  const { cert: aCert, privateKey: aKey } = await generateTestEndpointCertificate(AL, "1.example", "atsms.email");
  const aStorage = new SQLiteAdapter(new Wrap() as never);
  const aRng = rngOf(1);
  const aPds = pds.forDid(AL);
  const aIdentity = await ATSMSDeviceIdentity.load({
    did: AL, certificatePEM: aCert, privateKeyPEM: aKey, storage: aStorage, rng: aRng,
  });
  await aPds.putRecord("at.atsms.x509", aIdentity.fingerprint, { $type: "at.atsms.x509", certificate: aCert });
  const aEvents: string[] = [];
  const alice: Device = {
    label: "alice", did: AL, storage: aStorage, events: aEvents, identity: aIdentity,
    atsms: await ATSMS.create({
      identity: aIdentity, storage: aStorage, transport: relay.transportFor(AL), pds: aPds, rng: aRng,
      onEvent: (k, d) => aEvents.push(`${k}: ${d}`), genesisWaitMs: 0,
      peerMaxAgeMs: 15 * 60 * 1000,
    }),
  };

  // Bob: ONE identity (cert + key), two successive storages — the wipe.
  const { cert: bCert, privateKey: bKey } = await generateTestEndpointCertificate(BO, "2.example", "atsms.email");
  const bPds = pds.forDid(BO);
  const bootBob = async (seed: number, label: string): Promise<Device> => {
    const storage = new SQLiteAdapter(new Wrap() as never);
    const rng = rngOf(seed);
    const identity = await ATSMSDeviceIdentity.load({
      did: BO, certificatePEM: bCert, privateKeyPEM: bKey, storage, rng,
    });
    await bPds.putRecord("at.atsms.x509", identity.fingerprint, { $type: "at.atsms.x509", certificate: bCert });
    const events: string[] = [];
    const atsms = await ATSMS.create({
      identity, storage, transport: relay.transportFor(BO), pds: bPds, rng,
      onEvent: (k, d) => events.push(`${k}: ${d}`), genesisWaitMs: 0, peerMaxAgeMs: 0,
    });
    return { label, did: BO, storage, atsms, identity, events };
  };

  const bob = await bootBob(2, "bob");
  const convo = await alice.atsms.conversations.createGroup({ members: [BO] });
  await relay.flush();
  await assertDelivery(relay, convo.id, alice, [bob], [], "before");

  await convo.removeMember(BO);
  await relay.flush();
  expect((await bob.atsms.conversations.get(convo.id))!.amMember).toBe(false);
  await bob.atsms.close();

  // The wipe: same cert and fingerprint, brand-new prekey ring, republished.
  // Alice's warm snapshot still holds the PREVIOUS prekey for this device.
  const bob2 = await bootBob(99, "bob(rekeyed)");
  await relay.flush();

  // Re-add. Admission material must be refetched despite the warm snapshot.
  await convo.addMember(BO);
  await relay.flush();

  // Diagnostic on failure: what did the re-keyed device actually see?
  const seen = bob2.events.join(" | ");
  expect(
    bob2.events.some((e) => e.startsWith("re-admission-failed")),
    `a failed re-admission must never be silent — events: ${seen}`,
  ).toBe(false);
  expect((await bob2.atsms.conversations.get(convo.id)) !== null, `bob2 has no conversation — events: ${seen}`).toBe(true);
  expect((await bob2.atsms.conversations.get(convo.id))?.amMember, "the re-keyed device rejoined").toBe(true);
  await assertDelivery(relay, convo.id, alice, [bob2], [], "after re-add of a re-keyed device");
  await assertDelivery(relay, convo.id, bob2, [alice], [], "the re-keyed device speaks");
}, 60000);

test("leave: the leaver goes quiet, the group heals lazily, and the story is 'left'", async () => {
  const relay = new Relay();
  const pds = new SharedPds();
  const AL = "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa";
  const BO = "did:plc:bbbbbbbbbbbbbbbbbbbbbbbb";
  const CA = "did:plc:cccccccccccccccccccccccc";
  const alice = await device(relay, pds, 1, AL, "alice");
  const bob = await device(relay, pds, 2, BO, "bob");
  // Carol has two devices — leaving must take BOTH out.
  const carol1 = await device(relay, pds, 3, CA, "carol/1");
  const carol2 = await device(relay, pds, 4, CA, "carol/2");
  const all = [alice, bob, carol1, carol2];

  const convo = await alice.atsms.conversations.createGroup({ members: [BO, CA] });
  await relay.flush();
  await assertDelivery(relay, convo.id, alice, [bob, carol1, carol2], [], "before leaving");

  // Carol leaves from ONE of her devices. She is not an admin — leaving needs
  // no permission (same-DID removal is never admin-gated).
  await (await carol1.atsms.conversations.get(convo.id))!.leave();
  await relay.flush();

  await assertGroupState(convo.id, all, [AL, BO], "after carol left");
  for (const c of [carol1, carol2]) {
    const convoC = await c.atsms.conversations.get(convo.id);
    expect(convoC!.departure, `${c.label} knows it LEFT, not that it was removed`).toBe("left");
    expect((await c.storage.getConversation(convo.id))!.metadata?.left, `${c.label} record.left`).toBe(true);
    await expect(convoC!.send("still here?")).rejects.toThrow(/you left/);
  }
  expect(carol1.events.some((e) => e.startsWith("left-conversation"))).toBe(true);

  // The remaining members were NOT healed by the leaver — the next sender
  // heals lazily, and everyone converges without any extra machinery.
  await assertDelivery(relay, convo.id, bob, [alice], [carol1, carol2], "after the leave");
  await assertDelivery(relay, convo.id, alice, [bob], [carol1, carol2], "and back again");

  // History is kept on the leaver's side (leave is not forget).
  expect((await texts(carol1, convo.id)).length).toBeGreaterThan(0);
}, 60000);

test("leave: a sole admin must appoint a successor first", async () => {
  const relay = new Relay();
  const pds = new SharedPds();
  const AL = "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa";
  const BO = "did:plc:bbbbbbbbbbbbbbbbbbbbbbbb";
  const alice = await device(relay, pds, 1, AL, "alice"); // creator ⇒ sole admin
  const bob = await device(relay, pds, 2, BO, "bob");

  const convo = await alice.atsms.conversations.createGroup({ members: [BO] });
  await relay.flush();

  const aliceConvo = await alice.atsms.conversations.get(convo.id);
  expect(aliceConvo!.wouldStrandGroup, "a UI should offer succession first").toBe(true);
  await expect(aliceConvo!.leave()).rejects.toThrow(/LastAdmin/);
  expect(aliceConvo!.amMember, "a refused leave changes nothing").toBe(true);

  // Appoint Bob, then leaving is allowed and Bob can still run the group.
  await aliceConvo!.grantAdmin(BO);
  await relay.flush();
  expect(aliceConvo!.wouldStrandGroup).toBe(false);
  await convo.leave();
  await relay.flush();

  expect(aliceConvo!.departure).toBe("left");
  const bobConvo = await bob.atsms.conversations.get(convo.id);
  expect(bobConvo!.amMember).toBe(true);
  expect(bobConvo!.members).toEqual([BO]);

  // The successor's admin rights are real: he can still add someone.
  const CA = "did:plc:cccccccccccccccccccccccc";
  const carol = await device(relay, pds, 3, CA, "carol");
  await bobConvo!.addMember(CA);
  await relay.flush();
  expect((await carol.atsms.conversations.get(convo.id))?.amMember, "the successor could still add").toBe(true);
}, 60000);

test("leave: the last member out is a local act, and a leaver can be re-added", async () => {
  const relay = new Relay();
  const pds = new SharedPds();
  const AL = "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa";
  const BO = "did:plc:bbbbbbbbbbbbbbbbbbbbbbbb";
  const alice = await device(relay, pds, 1, AL, "alice");
  const bob = await device(relay, pds, 2, BO, "bob");

  const convo = await alice.atsms.conversations.createGroup({ members: [BO] });
  await relay.flush();
  await assertDelivery(relay, convo.id, alice, [bob], [], "before bob leaves");

  // Bob leaves, then Alice invites him back: re-admission after a LEAVE is the
  // same path as after a removal, and it must clear the left/removed story.
  await (await bob.atsms.conversations.get(convo.id))!.leave();
  await relay.flush();
  expect((await bob.atsms.conversations.get(convo.id))!.departure).toBe("left");

  await convo.addMember(BO);
  await relay.flush();
  const bobConvo = await bob.atsms.conversations.get(convo.id);
  expect(bobConvo!.amMember, "the leaver came back").toBe(true);
  expect(bobConvo!.departure).toBe(null);
  const record = await bob.storage.getConversation(convo.id);
  expect(record!.metadata?.left).toBe(false);
  expect(record!.metadata?.removed).toBe(false);
  // The way back in is the WELCOME. A device that left can still decrypt
  // fan-out copies for a while, and must not walk itself back in by ingesting
  // the add op from someone else's copy — it would believe it was a member
  // without the material the welcome carries, and its next message would be
  // sealed under state nobody shares.
  expect(bob.events.some((e) => e.startsWith("rejoined")), "bob rejoined via his welcome").toBe(true);
  await assertDelivery(relay, convo.id, bob, [alice], [], "the returning member speaks");

  // Now Alice is alone: leaving is recorded locally, with no ops on the wire.
  await convo.removeMember(BO);
  await relay.flush();
  const before = relay.largestEnvelope;
  await convo.leave();
  const aliceConvo = await alice.atsms.conversations.get(convo.id);
  expect(aliceConvo!.departure, "last one out still reads as 'left'").toBe("left");
  expect((await alice.storage.getConversation(convo.id))!.metadata?.left).toBe(true);
  expect(relay.largestEnvelope, "nothing was sent — there was nobody to tell").toBe(before);
}, 60000);

test("a healthy member is never told it might have been removed (C-fallback false positive)", async () => {
  // Live 2026-08-04: after a member left, the creator — still a member, still
  // chatting — saw a burst of unopenable envelopes (stale buffered traffic
  // from earlier churn) and was told "possibly-removed-from-conversation".
  // Unopenable traffic alone means nothing; the state worth suspecting is
  // "nothing has worked for a long time".
  const relay = new Relay();
  const pds = new SharedPds();
  const AL = "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa";
  const BO = "did:plc:bbbbbbbbbbbbbbbbbbbbbbbb";
  const alice = await device(relay, pds, 1, AL, "alice");
  const bob = await device(relay, pds, 2, BO, "bob");

  const convo = await alice.atsms.conversations.createGroup({ members: [BO] });
  await relay.flush();
  await assertDelivery(relay, convo.id, bob, [alice], [], "healthy traffic");

  // A burst of envelopes Alice cannot open (sealed under an epoch she does not
  // hold) — shaped like a sym envelope so it reaches the pending buffer.
  const rng = rngOf(1234);
  for (let i = 0; i < 12; i++) {
    relay.post(AL, cborEncode([1, 2, rng(8), rng(24), rng(64)]));
  }
  await relay.flush();

  const aliceConvo = await alice.atsms.conversations.get(convo.id);
  expect(aliceConvo!.inner.unopenableCount, "the junk really did fail to open").toBeGreaterThan(0);
  // Give the health tick several chances to jump to conclusions.
  await new Promise((r) => setTimeout(r, 400));
  expect(
    alice.events.filter((e) => e.startsWith("possibly-removed-from-conversation")),
    "a member with recent working traffic is never suspected",
  ).toEqual([]);

  // And she is plainly fine: still a member, still talking both ways.
  expect(aliceConvo!.amMember).toBe(true);
  await assertDelivery(relay, convo.id, alice, [bob], [], "still working after the junk");
}, 60000);

test("DM vs group: kind is fixed at creation, and each rule holds", async () => {
  const relay = new Relay();
  const pds = new SharedPds();
  const AL = "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa";
  const BO = "did:plc:bbbbbbbbbbbbbbbbbbbbbbbb";
  const CA = "did:plc:cccccccccccccccccccccccc";
  const alice = await device(relay, pds, 1, AL, "alice");
  const bob = await device(relay, pds, 2, BO, "bob");
  const carol = await device(relay, pds, 3, CA, "carol");

  // R1: exactly one DM per pair — opening it again returns the same one.
  const dm = await alice.atsms.conversations.with(BO);
  await relay.flush();
  expect(dm.kind).toBe("dm");
  const dmAgain = await alice.atsms.conversations.with(BO);
  expect(dmAgain.id, "the DM with Bob is a single conversation").toBe(dm.id);
  // …and both sides agree on the kind, because it rides in the create op.
  expect((await bob.atsms.conversations.get(dm.id))!.kind).toBe("dm");

  // R2: you cannot add to a DM — a group with all three is the way.
  await expect((await alice.atsms.conversations.get(dm.id))!.addMember(CA)).rejects.toThrow(/DirectConversation/);
  const group = await alice.atsms.conversations.createGroup({ members: [BO, CA] });
  await relay.flush();
  expect(group.kind).toBe("group");
  expect(group.id, "the group is a NEW conversation, not the DM grown").not.toBe(dm.id);
  // The DM is untouched and still works.
  await assertDelivery(relay, dm.id, alice, [bob], [], "the DM still works");

  // R3: the same people may share any number of groups.
  const group2 = await alice.atsms.conversations.createGroup({ members: [BO, CA] });
  await relay.flush();
  expect(group2.id, "a second group with the same members is its own conversation").not.toBe(group.id);

  // R4: a group that shrinks to two is still a group — it keeps its member
  // panel, its name, and the ability to change membership.
  await (await alice.atsms.conversations.get(group.id))!.removeMember(CA);
  await relay.flush();
  expect(group.members.length).toBe(2);
  expect(group.kind, "still a group at two members").toBe("group");
  expect((await alice.storage.getConversation(group.id))!.metadata?.kind).toBe("group");
  await expect((await alice.atsms.conversations.get(group.id))!.addMember(CA)).resolves.toBeUndefined();
  await relay.flush();

  // …and it is still NOT the DM with Bob: opening that returns the DM.
  const dmStill = await alice.atsms.conversations.with(BO);
  expect(dmStill.id).toBe(dm.id);
}, 60000);

/**
 * §8.2 first-contact recovery. A `create`/`welcome` is the one message no
 * repair reaches: repair belongs to a conversation, and whoever missed their
 * invitation has none. Nothing is acknowledged either, so the loss shows up
 * only as a member everybody's roster contains and nobody has heard from.
 */
test("re-invite: a joiner whose welcome was lost can be brought in later", async () => {
  const relay = new Relay();
  const pds = new SharedPds();
  const AL = "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa";
  const BO = "did:plc:bbbbbbbbbbbbbbbbbbbbbbbb";
  const CA = "did:plc:cccccccccccccccccccccccc";

  const alice = await device(relay, pds, 41, AL, "alice");
  const bob = await device(relay, pds, 42, BO, "bob");
  const carol = await device(relay, pds, 43, CA, "carol");

  const convo = await alice.atsms.conversations.createGroup({ members: [bob.did] });
  await relay.flush();

  // A member who has joined but never spoken is indistinguishable from one who
  // never arrived — that is inherent, since nothing is acknowledged. Bob speaks,
  // so the rest of this test can attribute silence to the loss and not to him.
  expect(convo.pendingMembers, "bob has joined but not yet said anything").toEqual([BO]);
  await assertDelivery(relay, convo.id, bob, [alice], [], "bob says hello");
  expect(convo.pendingMembers, "now we have heard from him").toEqual([]);

  // Carol is added — and everything addressed to her is lost, welcome included.
  relay.blackhole = CA;
  await convo.addMember(CA);
  await relay.flush();
  relay.blackhole = null;

  // The group believes she is a member; she has never heard of the group.
  expect(convo.members).toContain(CA);
  expect(await carol.atsms.conversations.get(convo.id), "carol never joined").toBeNull();
  expect(convo.pendingMembers, "alice sees an invitation that never landed").toEqual([CA]);
  const bobConvo = (await bob.atsms.conversations.get(convo.id))!;
  expect(bobConvo.pendingMembers, "so does bob — it is derived state, not the adder's memory").toEqual([CA]);

  // Neither Alice nor Bob is pending: we have heard from both.
  expect(convo.pendingMembers).not.toContain(BO);

  // The group carries on without her, moving several epochs ahead.
  await assertDelivery(relay, convo.id, alice, [bob], [carol], "while carol is missing");
  await assertDelivery(relay, convo.id, bob, [alice], [carol], "still missing");

  // Re-invite: a rebuilt welcome, pinned to the original add.
  await convo.reinvite(CA);
  await relay.flush();

  // She is in, at the CURRENT state, and the roster agrees everywhere.
  const carolConvo = await carol.atsms.conversations.get(convo.id);
  expect(carolConvo, "carol joined from the rebuilt welcome").not.toBeNull();
  expect(carolConvo!.amMember).toBe(true);
  await assertGroupState(convo.id, [alice, bob, carol], [AL, BO, CA], "after re-invite");

  // She can speak and be heard, both ways, and nobody is pending any more.
  await assertDelivery(relay, convo.id, carol, [alice, bob], [], "carol speaks at last");
  await assertDelivery(relay, convo.id, alice, [bob, carol], [], "and is heard by her");
  expect(convo.pendingMembers, "no longer pending once she has spoken").toEqual([]);

  // A person with a second device that never speaks is still PRESENT. Carol's
  // other device joins the group and stays silent forever — which is what a
  // phone in a drawer looks like, and what made a live group show a member as
  // "invited" indefinitely after they had already spoken.
  const carol2 = await device(relay, pds, 44, CA, "carol/2");
  await carol2.atsms.close(); // …and is switched off before it ever joins
  await convo.addMember(CA); // adds carol's newly published second device
  await relay.flush();
  expect(convo.members).toContain(CA);
  expect(convo.pendingMembers, "carol is here — one of her devices has spoken").toEqual([]);
  expect(
    convo.pendingDevices.length,
    "…but the silent device is visible at device level",
  ).toBeGreaterThan(0);
  void carol2;

  // A device that re-keyed after being admitted cannot be re-invited at all:
  // the conversation seals to the prekey it admitted, whose secret that device
  // no longer holds. Live shape (2026-08-06): a client kept cert.pem/key.pem —
  // so the same fingerprint — while its database was wiped, losing the ring.
  // Re-invitation reused the dead pin and failed as silently as the loss it was
  // meant to repair, so it must refuse and name the fix instead.
  const dave = await device(relay, pds, 45, "did:plc:dddddddddddddddddddddddd", "dave");
  relay.blackhole = dave.did;
  await convo.addMember(dave.did);
  await relay.flush();
  relay.blackhole = null;
  expect(convo.pendingMembers).toContain(dave.did);
  // Dave rotates his prekey under the SAME device fingerprint — what a device
  // does when it comes back with its identity key but a fresh ring.
  await dave.identity.ensurePrekeyPublished(pds.forDid(dave.did), Date.now() + 400 * 86_400_000);
  await alice.atsms.peers.invalidate(dave.did);
  await expect(convo.reinvite(dave.did)).rejects.toThrow(/re-keyed-device/);

  // Re-inviting someone we HAVE heard from is a no-op, not a duplicate group.
  const before = await alice.storage.getConversations();
  await convo.reinvite(CA);
  await relay.flush();
  expect((await alice.storage.getConversations()).length, "no second conversation").toBe(before.length);
  expect(carolConvo!.id, "and carol is still in the one group").toBe(convo.id);
}, 60000);
