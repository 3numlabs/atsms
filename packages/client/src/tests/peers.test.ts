/**
 * `atsms.peers` — the local peer directory (sdk-shape.md, third noun): warm
 * operations read the snapshot with ZERO discovery fetches; staleness is
 * healed by failure-driven invalidation, not per-operation refetching; UX
 * binds to observe(). The e2e suite runs with `peerMaxAgeMs: 0` (always
 * revalidate — the old semantics); this suite is where the caching contract
 * itself is pinned.
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

/** SharedPds that COUNTS reads — the caching assertions are fetch counts. */
class CountingPds {
  private store = new Map<string, unknown>();
  reads = 0;
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
        if (repo !== myDid) this.reads++;
        const v = this.store.get(key(repo, c, rk));
        return v === undefined ? null : { uri: `at://${repo}/${c}/${rk}`, value: v };
      },
      listRecords: async (repo, c): Promise<PdsRecordView[]> => {
        if (repo !== myDid) this.reads++;
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

class Hub {
  private handlers = new Map<string, Set<(e: Uint8Array) => Promise<void>>>();
  private queue: Array<{ did: string; env: Uint8Array }> = [];
  /** URLs whose next N posts fail (delivery-failure invalidation test). */
  failNext = new Map<string, number>();
  post(target: string, env: Uint8Array): void {
    this.queue.push({ did: target, env });
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
      deliverToUrl: async (url, env) => {
        const n = this.failNext.get(url) ?? 0;
        if (n > 0) {
          this.failNext.set(url, n - 1);
          throw new Error(`delivery failed: ${url}`);
        }
        this.post(decodeURIComponent(url.replace("loop://", "")), env);
      },
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

async function client(hub: Hub, pds: CountingPds, seed: number, did: string) {
  const { cert, privateKey } = await generateTestEndpointCertificate(did, `${seed}.example`, "atsms.email");
  const storage = newStore();
  const rng = rngOf(seed);
  const myPds = pds.forDid(did);
  const identity = await ATSMSDeviceIdentity.load({ did, certificatePEM: cert, privateKeyPEM: privateKey, storage, rng });
  await myPds.putRecord("at.atsms.x509", identity.fingerprint, { $type: "at.atsms.x509", certificate: cert });
  // Publish an inbox record so directory routing has an https endpoint.
  await myPds.putRecord("at.atsms.inbox", "self", {
    $type: "at.atsms.inbox",
    endpoints: [{ uri: `loop://${encodeURIComponent(did)}` }, { uri: `mailto:x@example` }],
  });
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

test("warm operations do zero discovery fetches; snapshots persist and observe() emits", async () => {
  const hub = new Hub();
  const pds = new CountingPds();
  const alice = await client(hub, pds, 1, "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa");
  const bob = await client(hub, pds, 2, "did:plc:bbbbbbbbbbbbbbbbbbbbbbbb");

  const seen: string[] = [];
  alice.atsms.peers.observe(bob.did).subscribe((s) => seen.push(s.reachability));

  // Cold: reachability populates the directory (one refresh round).
  expect(await alice.atsms.reachability(bob.did)).toBe("conversation");
  const afterCold = pds.reads;
  expect(afterCold).toBeGreaterThan(0);

  // Warm: open + message exchange do ZERO further discovery reads.
  const convo = await alice.atsms.conversations.with(bob.did);
  await hub.flush();
  await convo.send("yo");
  await hub.flush();
  const bobConvo = await bob.atsms.conversations.get(convo.id);
  await bobConvo!.send("yoko");
  await hub.flush();
  expect(await texts(alice, convo.id)).toEqual(["yo", "yoko"]);

  // Warm steady state: further traffic does ZERO discovery reads anywhere
  // (both directions ride snapshots + in-band adverts).
  const readsAfterExchange = pds.reads;
  await convo.send("again");
  await hub.flush();
  await bobConvo!.send("and again");
  await hub.flush();
  expect(await texts(alice, convo.id)).toEqual(["yo", "yoko", "again", "and again"]);
  expect(pds.reads).toBe(readsAfterExchange);

  // The snapshot is local + observed.
  const snap = await alice.atsms.peers.get(bob.did);
  expect(snap?.reachability).toBe("conversation");
  expect(snap?.devices.length).toBe(1);
  expect(seen.length).toBeGreaterThan(0);
});

test("delivery failure invalidates the snapshot and retries on fresh data", async () => {
  const hub = new Hub();
  const pds = new CountingPds();
  const alice = await client(hub, pds, 1, "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa");
  const bob = await client(hub, pds, 2, "did:plc:bbbbbbbbbbbbbbbbbbbbbbbb");

  const convo = await alice.atsms.conversations.with(bob.did);
  await hub.flush();
  await convo.send("yo");
  await hub.flush();
  expect(await texts(bob, convo.id)).toEqual(["yo"]);

  // The recorded ingress fails once (relay hiccup / stale endpoint). The
  // failure must invalidate the snapshot, refetch, and retry — the message
  // still lands, within the same send() call.
  hub.failNext.set(`loop://${encodeURIComponent(bob.did)}`, 1);
  const readsBefore = pds.reads;
  await convo.send("after relay hiccup");
  await hub.flush();
  expect(await texts(bob, convo.id)).toEqual(["yo", "after relay hiccup"]);
  expect(pds.reads).toBeGreaterThan(readsBefore); // the invalidate → refetch happened
});
