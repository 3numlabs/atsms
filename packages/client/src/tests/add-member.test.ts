/**
 * Regression: adding a member must not break the EXISTING members' receive
 * path. The welcome is point-to-point (only the joiner gets it); it used to
 * consume a slot in the adder's broadcast ctrlSeq chain, so every existing
 * member buffered all post-add control frames forever — the adder's messages
 * then reached the newcomer but never the original peer (live add-flow
 * partition, 2026-08-02). Delivery here is realistically DID-routed: the
 * welcome goes to the joiner only, never broadcast.
 */

import type { PdsClient, PdsRecordView, PutResult } from "@atsms/dcgka";
import { Database } from "bun:sqlite";
import { expect, test } from "bun:test";

import { ATSMS } from "../lib/client/atsms.js";
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
const newStore = () => new SQLiteAdapter(new Wrap() as never);
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

/** DID-routed hub: each envelope goes only to its addressed DID's handler —
 *  welcomes reach the joiner alone, exactly like the worker relay. */
class Hub {
  private handlers = new Map<string, Set<(e: Uint8Array) => Promise<void>>>();
  private queue: Array<{ did: string; env: Uint8Array }> = [];
  post(did: string, env: Uint8Array): void {
    this.queue.push({ did, env });
  }
  async flush(): Promise<void> {
    let guard = 0;
    while (this.queue.length > 0) {
      if (guard++ > 10000) throw new Error("livelock");
      const { did, env } = this.queue.shift()!;
      for (const h of this.handlers.get(did) ?? []) await h(env);
    }
  }
  transportFor(did: string): EnvelopeTransport {
    return {
      ingressUrl: `loop://${encodeURIComponent(did)}`,
      deliverToUrl: async (url, env) => this.post(decodeURIComponent(url.replace("loop://", "")), env),
      deliverToDid: async (target, env) => this.post(target, env),
      start: async (onEnvelope) => {
        let set = this.handlers.get(did);
        if (set === undefined) this.handlers.set(did, (set = new Set()));
        set.add(onEnvelope);
      },
      stop: async () => {},
    };
  }
}

async function client(hub: Hub, pds: SharedPds, seed: number, did: string) {
  const { cert, privateKey } = await generateTestEndpointCertificate(did, `${seed}.example`, "atsms.email");
  const storage = newStore();
  const rng = rngOf(seed);
  const myPds = pds.forDid(did);
  const identity = await ATSMSDeviceIdentity.load({ did, certificatePEM: cert, privateKeyPEM: privateKey, storage, rng });
  await myPds.putRecord("at.atsms.x509", identity.fingerprint, { $type: "at.atsms.x509", certificate: cert });
  const events: string[] = [];
  const atsms = await ATSMS.create({
    identity,
    storage,
    transport: hub.transportFor(did),
    pds: myPds,
    rng,
    onEvent: (kind, detail) => events.push(`${kind}: ${detail}`),
    genesisWaitMs: 0,
  });
  return { did, storage, atsms, events };
}
const texts = async (c: Awaited<ReturnType<typeof client>>, convoId: string) =>
  (await c.storage.getMessages(convoId)).map((m) => textOf(m.content));

test("consecutive adds keep the existing member receiving (welcome is point-to-point)", async () => {
  const hub = new Hub();
  const pds = new SharedPds();
  const alice = await client(hub, pds, 1, "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa");
  const bob = await client(hub, pds, 2, "did:plc:bbbbbbbbbbbbbbbbbbbbbbbb");
  const carol = await client(hub, pds, 3, "did:plc:cccccccccccccccccccccccc");
  const dave = await client(hub, pds, 4, "did:plc:dddddddddddddddddddddddd");

  // Two-party conversation, both directions working.
  const convo = await alice.atsms.open({ members: [bob.did] });
  await hub.flush();
  await convo.send("yo");
  await hub.flush();
  const bobConvo = await bob.atsms.get(convo.id);
  await bobConvo!.send("yoko");
  await hub.flush();
  expect(await texts(alice, convo.id)).toEqual(["yo", "yoko"]);
  expect(await texts(bob, convo.id)).toEqual(["yo", "yoko"]);

  // Alice adds Carol then Dave — two add→update→welcome rounds, like adding a
  // DID with several devices. Each welcome routes to its joiner only; the
  // SECOND round's control frames are where a ctrlSeq-numbered welcome used to
  // strand Bob (the frame after a welcome jumps the gap the welcome left).
  await alice.atsms.addMember(convo.id, carol.did);
  await hub.flush();
  await alice.atsms.addMember(convo.id, dave.did);
  await hub.flush();

  // Alice speaks: Bob (existing) and both newcomers must hear it.
  await convo.send("welcome both");
  await hub.flush();
  expect(await texts(bob, convo.id)).toEqual(["yo", "yoko", "welcome both"]);
  expect(await texts(carol, convo.id)).toContain("welcome both");
  expect(await texts(dave, convo.id)).toContain("welcome both");

  // And Bob can still speak to everyone.
  await bobConvo!.send("hi all");
  await hub.flush();
  expect(await texts(alice, convo.id)).toEqual(["yo", "yoko", "welcome both", "hi all"]);
  expect(await texts(carol, convo.id)).toContain("hi all");
  expect(await texts(dave, convo.id)).toContain("hi all");
}, 20000);

test("removeMember: strong remove — the removed member reads nothing after; others converge", async () => {
  const hub = new Hub();
  const pds = new SharedPds();
  const alice = await client(hub, pds, 1, "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa");
  const bob = await client(hub, pds, 2, "did:plc:bbbbbbbbbbbbbbbbbbbbbbbb");
  const carol = await client(hub, pds, 3, "did:plc:cccccccccccccccccccccccc");

  const convo = await alice.atsms.open({ members: [bob.did, carol.did] });
  await hub.flush();
  await convo.send("hello all three");
  await hub.flush();
  expect(await texts(carol, convo.id)).toEqual(["hello all three"]);

  // Alice (admin) removes Carol — one batched round (removes + healing update).
  await alice.atsms.removeMember(convo.id, carol.did);
  await hub.flush();

  // Rosters shrink everywhere — including on Bob, who only RECEIVED the ops.
  expect(convo.members.sort()).toEqual([alice.did, bob.did].sort());
  const bobConvo = await bob.atsms.get(convo.id);
  expect(bobConvo!.members.sort()).toEqual([alice.did, bob.did].sort());
  expect((await bob.storage.getConversation(convo.id))!.participantIds.sort()).toEqual(
    [alice.did, bob.did].sort(),
  );

  // Post-remove traffic: Bob converges, Carol reads NOTHING new (strong remove).
  await convo.send("carol is gone");
  await hub.flush();
  await bobConvo!.send("copy that");
  await hub.flush();
  expect(await texts(alice, convo.id)).toEqual(["hello all three", "carol is gone", "copy that"]);
  expect(await texts(bob, convo.id)).toEqual(["hello all three", "carol is gone", "copy that"]);
  expect(await texts(carol, convo.id)).toEqual(["hello all three"]);

  // Guards: a non-member and self are rejected loudly.
  await expect(alice.atsms.removeMember(convo.id, carol.did)).rejects.toThrow(/not a member/);
  await expect(alice.atsms.removeMember(convo.id, alice.did)).rejects.toThrow(/leave\(\)/);

  // Non-admin removal is rejected by the engine (dgm §4).
  await expect(bob.atsms.removeMember(convo.id, alice.did)).rejects.toThrow(/Unauthorized/);
}, 20000);

test("a removed member's later messages are rejected by everyone — including the remover", async () => {
  // Live failure 2026-08-03: after aib0b removed chaosmokey, chaosmokey (who
  // never learns it was removed — the remove is not sealed to it) sent a
  // message. The REMOVER displayed it; the third member correctly did not.
  // Two causes, both fixed in dcgka: the remover's receive tag table was not
  // rebuilt after its own local op, and app frames had no membership gate.
  const hub = new Hub();
  const pds = new SharedPds();
  const alice = await client(hub, pds, 1, "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa");
  const bob = await client(hub, pds, 2, "did:plc:bbbbbbbbbbbbbbbbbbbbbbbb");
  const carol = await client(hub, pds, 3, "did:plc:cccccccccccccccccccccccc");

  const convo = await alice.atsms.open({ members: [bob.did, carol.did] });
  await hub.flush();
  // Everyone speaks first — this is what populates each member's receive tag
  // table with entries for the member about to be removed (the live shape).
  await convo.send("alice here");
  await hub.flush();
  const carolConvo = await carol.atsms.get(convo.id);
  await carolConvo!.send("carol here");
  await hub.flush();
  const bobConvo = await bob.atsms.get(convo.id);
  await bobConvo!.send("bob here");
  await hub.flush();
  expect(await texts(alice, convo.id)).toEqual(["alice here", "carol here", "bob here"]);

  await alice.atsms.removeMember(convo.id, carol.did);
  await hub.flush();

  // Carol's own client now refuses the send (always-notify: her removal was
  // sealed to her, so she knows). The receive-side gate below is what protects
  // members from a client that DOESN'T know — a lost notice, or a hostile
  // build with the check removed; the dcgka suite covers that path directly.
  await expect(carolConvo!.send("hey again")).rejects.toThrow(/no longer a member/);
  await hub.flush();

  const after = ["alice here", "carol here", "bob here"];
  expect(await texts(alice, convo.id), "the remover must not accept it").toEqual(after);
  expect(await texts(bob, convo.id), "nor any other member").toEqual(after);

  // The group keeps working between the remaining members.
  await convo.send("carry on");
  await hub.flush();
  expect(await texts(bob, convo.id)).toEqual([...after, "carry on"]);
}, 20000);

test("the removed member is told: amMember flips, sends are refused, the record says so", async () => {
  const hub = new Hub();
  const pds = new SharedPds();
  const alice = await client(hub, pds, 1, "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa");
  const bob = await client(hub, pds, 2, "did:plc:bbbbbbbbbbbbbbbbbbbbbbbb");
  const carol = await client(hub, pds, 3, "did:plc:cccccccccccccccccccccccc");

  const convo = await alice.atsms.open({ members: [bob.did, carol.did] });
  await hub.flush();
  await convo.send("hello all");
  await hub.flush();
  const carolConvo = await carol.atsms.get(convo.id);
  expect(carolConvo!.amMember).toBe(true);

  await alice.atsms.removeMember(convo.id, carol.did);
  await hub.flush();

  // Always-notify: the removal op is sealed to the device it removes.
  expect(carolConvo!.amMember, "the removed device learns it was removed").toBe(false);
  expect(carol.events.some((e) => e.startsWith("removed-from-conversation"))).toBe(true);
  // …persisted, so a reloading client renders read-only without the engine.
  expect((await carol.storage.getConversation(convo.id))!.metadata?.removed).toBe(true);
  // …and the send is refused with a plain reason, NOT healed into a fork.
  await expect(carolConvo!.send("hey again")).rejects.toThrow(/no longer a member/);

  // The remaining members are unaffected and still see each other.
  expect(alice.atsms.peers !== undefined).toBe(true);
  const bobConvo = await bob.atsms.get(convo.id);
  expect(bobConvo!.amMember).toBe(true);
  await bobConvo!.send("still here");
  await hub.flush();
  expect(await texts(alice, convo.id)).toEqual(["hello all", "still here"]);
  expect((await alice.storage.getConversation(convo.id))!.metadata?.removed).toBe(false);
}, 20000);
