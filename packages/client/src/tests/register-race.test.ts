/**
 * Regression: a `conversations$` subscriber that calls `atsms.get()` (the
 * reference CLI's live feed does) races `open()`. The create is persisted —
 * and observers notified — before `open()` registers the handle, so `get()`
 * misses `openConvos`, restores the create-only snapshot, and used to
 * register that epochless "zombie" over the live session. Inbound sym
 * envelopes then dispatched to the zombie (unknown epoch → silently buffered
 * → acked → gone) and its next persist clobbered the good engine state.
 * Live symptom: the creator's peer answers, the reply never arrives.
 *
 * The transport here models a real relay: every delivery costs a macrotask
 * delay, which is what opens the race window (loopback-synchronous tests
 * never see it).
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
const until = async (cond: () => Promise<boolean>, ms = 3000): Promise<void> => {
  const deadline = Date.now() + ms;
  while (Date.now() < deadline && !(await cond())) await sleep(10);
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

/** A relay with latency: deliveries settle on later macrotasks, like HTTPS
 *  POSTs and inbox polls — this is what lets observers interleave with open(). */
class SlowHub {
  private handlers = new Map<string, (e: Uint8Array) => Promise<void>>();
  private inflight: Promise<void>[] = [];
  constructor(private readonly latencyMs: number) {}
  private post(did: string, env: Uint8Array): void {
    this.inflight.push(
      sleep(this.latencyMs).then(async () => {
        await this.handlers.get(did)?.(env);
      }),
    );
  }
  async settle(): Promise<void> {
    // Drain including deliveries triggered by deliveries.
    for (let i = 0; i < 20; i++) {
      const batch = this.inflight;
      this.inflight = [];
      await Promise.all(batch);
      await sleep(this.latencyMs + 5);
      if (this.inflight.length === 0) break;
    }
  }
  transportFor(did: string): EnvelopeTransport {
    return {
      ingressUrl: `loop://${encodeURIComponent(did)}`,
      deliverToUrl: async (url, env) => {
        await sleep(this.latencyMs); // the outbound POST round-trip
        this.post(decodeURIComponent(url.replace("loop://", "")), env);
      },
      deliverToDid: async (target, env) => {
        await sleep(this.latencyMs);
        this.post(target, env);
      },
      start: async (onEnvelope) => {
        this.handlers.set(did, onEnvelope);
      },
      stop: async () => {
        this.handlers.delete(did);
      },
    };
  }
}

async function client(hub: SlowHub, pds: SharedPds, seed: number, did: string) {
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

test("a conversations$-driven get() during open() must not shadow the live session", async () => {
  const hub = new SlowHub(15);
  const pds = new SharedPds();
  const creator = await client(hub, pds, 1, "did:plc:creatorcreatorcreatorcre");
  const responder = await client(hub, pds, 2, "did:plc:responderresponderrespo");

  // The reference CLI's live feed, verbatim: eagerly grab a handle for every
  // conversation the storage observer reports. This is the racing call.
  const handles: unknown[] = [];
  creator.atsms.conversations$.subscribe((convos) => {
    void (async () => {
      for (const c of convos) handles.push(await creator.atsms.get(c.id));
    })();
  });

  const convo = await creator.atsms.open({ members: [responder.did] });
  await hub.settle();
  await convo.send("yo");
  await hub.settle();

  // The responder bootstrapped and sees the message.
  const rConvos = await responder.storage.getConversations();
  expect(rConvos.length).toBe(1);
  const rHandle = await responder.atsms.get(rConvos[0]!.id);
  expect((await responder.storage.getMessages(rConvos[0]!.id)).map((m) => textOf(m.content))).toContain("yo");

  // The reply must reach the creator (pre-fix: dispatched to the zombie,
  // silently buffered, never stored).
  await rHandle!.send("yoyo");
  await hub.settle();
  await until(async () =>
    (await creator.storage.getMessages(convo.id)).some((m) => textOf(m.content) === "yoyo"),
  );
  expect((await creator.storage.getMessages(convo.id)).map((m) => textOf(m.content))).toEqual(["yo", "yoyo"]);

  // And the persisted engine state must still hold the established epoch
  // (pre-fix: the zombie's persist clobbered it back to the create-only,
  // epochless snapshot).
  const reloaded = await creator.atsms.get(convo.id);
  expect(reloaded!.inner.awaitingFirstEpoch).toBe(false);
}, 15000);
