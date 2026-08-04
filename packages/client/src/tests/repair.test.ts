/**
 * §8 gap repair, wired end-to-end (ordering-auth §8): a lossy relay drops a
 * control frame; the receiver's ordering buffer holds everything after it.
 * The client's repair timer detects the persistent gap, sends a sealed repair
 * request (asym — deliverable even mid-divergence), a member re-serves the
 * signed frame it retains, and the buffered frames drain. Without the trigger
 * the group stalls forever — that was the failure mode behind two live bugs.
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
const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));
const until = async (cond: () => Promise<boolean> | boolean, ms = 5000): Promise<void> => {
  const deadline = Date.now() + ms;
  while (Date.now() < deadline && !(await cond())) await sleep(20);
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

/** DID-routed hub that can be told to DROP the next N envelopes to a DID —
 *  a withholding/lossy relay. Deliveries are immediate otherwise. */
class LossyHub {
  private handlers = new Map<string, Set<(e: Uint8Array) => Promise<void>>>();
  private queue: Array<{ did: string; env: Uint8Array }> = [];
  dropNext = new Map<string, number>();
  dropped = 0;
  post(did: string, env: Uint8Array): void {
    const n = this.dropNext.get(did) ?? 0;
    if (n > 0) {
      this.dropNext.set(did, n - 1);
      this.dropped++;
      return; // the relay "loses" it — never delivered, never retried
    }
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

async function client(hub: LossyHub, pds: SharedPds, seed: number, did: string, repairAfterMs: number) {
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
    repairAfterMs,
  });
  return { did, storage, atsms, events };
}
const texts = async (c: Awaited<ReturnType<typeof client>>, convoId: string) =>
  (await c.storage.getMessages(convoId)).map((m) => textOf(m.content));

/** The lossy scenario with a DISCOVERABLE gap (ordering-buffer shape, like the
 *  live add-flow bugs): the relay loses the ADD frame — the post-add update
 *  still seals under the epoch the victim holds, so it opens and buffers with
 *  a missing dep. That hole is what buildRepairRequest can name. (A lost
 *  UPDATE instead makes all later epochs unopenable — an opaque, seal-layer
 *  gap that needs head reconciliation / §8.1, not this trigger.) */
async function addWithDroppedAddFrame(repairAfterMs: number) {
  const hub = new LossyHub();
  const pds = new SharedPds();
  const alice = await client(hub, pds, 1, "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa", repairAfterMs);
  const bob = await client(hub, pds, 2, "did:plc:bbbbbbbbbbbbbbbbbbbbbbbb", repairAfterMs);
  const carol = await client(hub, pds, 3, "did:plc:cccccccccccccccccccccccc", repairAfterMs);

  const convo = await alice.atsms.open({ members: [bob.did], kind: "group" });
  await hub.flush();
  await convo.send("yo");
  await hub.flush();

  // The relay loses the next envelope to Bob: the ADD of Carol's device. The
  // post-add update then reaches Bob, opens, and buffers on the missing dep.
  hub.dropNext.set(bob.did, 1);
  await alice.atsms.addMember(convo.id, carol.did);
  await hub.flush();
  await convo.send("welcome carol");
  await hub.flush();
  return { hub, alice, bob, carol, convo };
}

test("a dropped add frame heals via a §8 repair request", async () => {
  const { hub, alice, bob, carol, convo } = await addWithDroppedAddFrame(120);
  expect(hub.dropped).toBe(1);
  expect(await texts(bob, convo.id)).toEqual(["yo"]); // stalled pre-repair
  const bobConvo = await bob.atsms.get(convo.id);
  expect(bobConvo!.inner.bufferedFrames).toBeGreaterThan(0);

  // The §8 trigger fires (gap persisted past repairAfterMs), the sealed repair
  // request reaches the members, Alice re-serves the retained add, Bob drains
  // — and the pending post-add message opens on the refresh.
  await until(async () => {
    await hub.flush(); // let request/response rounds actually deliver
    return (await texts(bob, convo.id)).includes("welcome carol");
  });
  expect(await texts(bob, convo.id)).toEqual(["yo", "welcome carol"]);
  expect(bob.events.some((e) => e.startsWith("repair-requested"))).toBe(true);
  expect(bobConvo!.inner.bufferedFrames).toBe(0);

  // Everyone converged: both directions and the newcomer still work.
  await bobConvo!.send("made it");
  await hub.flush();
  expect(await texts(alice, convo.id)).toEqual(["yo", "welcome carol", "made it"]);
  expect(await texts(carol, convo.id)).toContain("made it");

  await alice.atsms.close();
  await bob.atsms.close();
  await carol.atsms.close();
}, 20000);

test("repair disabled (repairAfterMs 0): the gap never heals — the control", async () => {
  // The negative control proving the trigger (not luck) does the healing.
  const { hub, alice, bob, carol, convo } = await addWithDroppedAddFrame(0);
  await sleep(500); // longer than the positive test's repair window
  await hub.flush();
  expect(await texts(bob, convo.id)).toEqual(["yo"]); // still stalled
  const bobConvo = await bob.atsms.get(convo.id);
  expect(bobConvo!.inner.bufferedFrames).toBeGreaterThan(0);

  await alice.atsms.close();
  await bob.atsms.close();
  await carol.atsms.close();
}, 20000);
