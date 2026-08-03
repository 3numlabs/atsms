/**
 * onMetric instrumentation: with a sink configured, the PDS and transport
 * seams emit timing samples and operations emit spans with phase breakdowns.
 * Without a sink, nothing is wrapped (zero overhead).
 */

import type { PdsClient, PdsRecordView, PutResult } from "@atsms/dcgka";
import { Database } from "bun:sqlite";
import { expect, test } from "bun:test";

import { ATSMS } from "../lib/client/atsms.js";
import type { ATSMSMetric } from "../lib/client/metrics.js";
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

class Hub {
  private handlers = new Map<string, Set<(e: Uint8Array) => Promise<void>>>();
  private queue: Array<{ did: string; env: Uint8Array }> = [];
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
        this.queue.push({ did: decodeURIComponent(url.replace("loop://", "")), env });
      },
      deliverToDid: async (target, env) => {
        this.queue.push({ did: target, env });
      },
      start: async (onEnvelope) => {
        let set = this.handlers.get(did);
        if (set === undefined) this.handlers.set(did, (set = new Set()));
        set.add(onEnvelope);
      },
      stop: async () => {},
    };
  }
}

async function client(hub: Hub, pds: SharedPds, seed: number, did: string, sink?: (m: ATSMSMetric) => void) {
  const { cert, privateKey } = await generateTestEndpointCertificate(did, `${seed}.example`, "atsms.email");
  const storage = new SQLiteAdapter(new Wrap() as never);
  const rng = rngOf(seed);
  const myPds = pds.forDid(did);
  const identity = await ATSMSDeviceIdentity.load({ did, certificatePEM: cert, privateKeyPEM: privateKey, storage, rng });
  await myPds.putRecord("at.atsms.x509", identity.fingerprint, { $type: "at.atsms.x509", certificate: cert });
  await myPds.putRecord("at.atsms.inbox", "self", {
    $type: "at.atsms.inbox",
    endpoints: [{ uri: `loop://${encodeURIComponent(did)}` }, { uri: "mailto:x@example" }],
  });
  const atsms = await ATSMS.create({
    identity,
    storage,
    transport: hub.transportFor(did),
    pds: myPds,
    rng,
    genesisWaitMs: 0,
    ...(sink !== undefined ? { onMetric: sink } : {}),
  });
  return { did, storage, atsms };
}

test("with a sink: seams emit timing samples, operations emit phase spans", async () => {
  const hub = new Hub();
  const pds = new SharedPds();
  const samples: ATSMSMetric[] = [];
  const alice = await client(hub, pds, 1, "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa", (m) => samples.push(m));
  const bob = await client(hub, pds, 2, "did:plc:bbbbbbbbbbbbbbbbbbbbbbbb");

  const convo = await alice.atsms.open({ members: [bob.did] });
  await hub.flush();
  await convo.send("yo");
  await hub.flush();

  const kinds = new Set(samples.map((m) => m.kind));
  expect(kinds.has("pds.read")).toBe(true); // discovery fetches were timed
  expect(kinds.has("pds.write")).toBe(true); // prekey publish on create()
  expect(kinds.has("transport.post")).toBe(true); // deliveries were timed

  const openSpan = samples.find((m) => m.kind === "op" && m.name === "open");
  expect(openSpan).toBeDefined();
  expect(openSpan!.ok).toBe(true);
  expect(openSpan!.detail).toMatchObject({ members: 1 });
  for (const phase of ["discoveryMs", "sealMs", "deliverMs"]) {
    expect(typeof openSpan!.detail![phase]).toBe("number");
  }
  expect(openSpan!.ms).toBeGreaterThanOrEqual(0);

  // Samples are JSON-safe (the CLI appends them to a JSONL file verbatim).
  for (const m of samples) expect(() => JSON.stringify(m)).not.toThrow();
});

test("addMember emits a span with rounds/envelopes; no sink means no wrapping", async () => {
  const hub = new Hub();
  const pds = new SharedPds();
  const samples: ATSMSMetric[] = [];
  const alice = await client(hub, pds, 1, "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa", (m) => samples.push(m));
  const bob = await client(hub, pds, 2, "did:plc:bbbbbbbbbbbbbbbbbbbbbbbb"); // no sink — must not throw anywhere
  const carol = await client(hub, pds, 3, "did:plc:cccccccccccccccccccccccc");

  const convo = await alice.atsms.open({ members: [bob.did] });
  await hub.flush();
  await alice.atsms.addMember(convo.id, carol.did);
  await hub.flush();

  const addSpan = samples.find((m) => m.kind === "op" && m.name === "addMember");
  expect(addSpan).toBeDefined();
  expect(addSpan!.target).toBe(carol.did);
  expect(addSpan!.detail).toMatchObject({ devices: 1, rounds: 1 });
  expect(addSpan!.detail!.envelopes as number).toBeGreaterThan(0);
});
