/**
 * Does a peer's OFFLINE second device break the online path? It must not — a
 * cleanly offline additional device is basic multi-device (the epoch is
 * encrypted to every member leaf's prekey at create, so the online device
 * holds it and the offline one derives it whenever it appears). This isolates
 * the question the live 2-party reply failure raised.
 */

import type { PdsClient, PdsRecordView, PutResult } from "@atsms/dcgka";
import { Database } from "bun:sqlite";
import { describe, expect, test } from "bun:test";

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

/** Buffered, multi-handler-per-DID hub. A device is "offline" simply by never
 *  calling start() — the relay fanout (post → all registered handlers of a DID)
 *  then skips it, exactly like an inbox no one is polling. */
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
    let mine: ((e: Uint8Array) => Promise<void>) | null = null;
    return {
      ingressUrl: `loop://${encodeURIComponent(did)}`,
      deliverToUrl: async (url, env) => this.post(decodeURIComponent(url.replace("loop://", "")), env),
      deliverToDid: async (target, env) => this.post(target, env),
      start: async (onEnvelope) => {
        mine = onEnvelope;
        let set = this.handlers.get(did);
        if (set === undefined) this.handlers.set(did, (set = new Set()));
        set.add(onEnvelope);
      },
      stop: async () => {
        if (mine) this.handlers.get(did)?.delete(mine);
      },
    };
  }
}

async function client(hub: Hub, pds: SharedPds, seed: number, did: string, online = true) {
  const { cert, privateKey } = await generateTestEndpointCertificate(did, `${seed}.example`, "atsms.email");
  const storage = newStore();
  const rng = rngOf(seed);
  const myPds = pds.forDid(did);
  const identity = await ATSMSDeviceIdentity.load({ did, certificatePEM: cert, privateKeyPEM: privateKey, storage, rng });
  // Publish the device's x509 so a peer's capability discovery finds it — even
  // if this device never comes online (that is the offline-device case).
  await myPds.putRecord("at.atsms.x509", identity.fingerprint, { $type: "at.atsms.x509", certificate: cert });
  const events: string[] = [];
  const transport = hub.transportFor(did);
  const atsms = await ATSMS.create({
    identity,
    storage,
    transport,
    pds: myPds,
    rng,
    onEvent: (kind, detail) => events.push(`${kind}: ${detail}`),
    genesisWaitMs: 0,
  });
  if (!online) await transport.stop(); // published, but polling nobody: offline
  return { did, storage, atsms, events, identity };
}
const texts = async (c: Awaited<ReturnType<typeof client>>, convoId: string) =>
  (await c.storage.getMessages(convoId)).map((m) => textOf(m.content));

describe("peer with an OFFLINE second device", () => {
  test("creator ↔ online device works both ways; offline device just misses out", async () => {
    const hub = new Hub();
    const pds = new SharedPds();
    const a = await client(hub, pds, 201, "did:plc:a");
    // Bob = two devices, same DID. b1 online, b2 published-but-offline.
    const b1 = await client(hub, pds, 202, "did:plc:bob", true);
    const b2 = await client(hub, pds, 203, "did:plc:bob", false);

    // A opens knowing only Bob's DID → discovery pulls in BOTH bob devices.
    const convo = await a.atsms.conversations.with(b1.did);
    await hub.flush();
    await convo.send("yo");
    await hub.flush();

    // Online device b1 must see it; offline b2 does not (yet).
    expect(await texts(b1, convo.id)).toContain("yo");
    expect(await texts(b2, convo.id)).not.toContain("yo");

    // The reply direction — the exact live failure.
    const b1h = await b1.atsms.conversations.get(convo.id);
    expect(b1h).not.toBeNull();
    await b1h!.send("yo back");
    await hub.flush();

    expect(await texts(a, convo.id)).toContain("yo back");
  });

  test("peer with THREE online devices, async delivery: all converge both ways", async () => {
    const hub = new Hub();
    const pds = new SharedPds();
    const a = await client(hub, pds, 211, "did:plc:a");
    const b1 = await client(hub, pds, 212, "did:plc:bob", true);
    const b2 = await client(hub, pds, 213, "did:plc:bob", true);
    const b3 = await client(hub, pds, 214, "did:plc:bob", true);

    const convo = await a.atsms.conversations.with(b1.did);
    await hub.flush();
    await convo.send("yo");
    await hub.flush();
    for (const b of [b1, b2, b3]) expect(await texts(b, convo.id)).toContain("yo");

    // A reply from one device must reach A (and, ideally, the sibling devices).
    const h = await b1.atsms.conversations.get(convo.id);
    await h!.send("yo back");
    await hub.flush();
    expect(await texts(a, convo.id)).toContain("yo back");
  });
});
