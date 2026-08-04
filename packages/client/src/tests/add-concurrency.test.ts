/**
 * Add-a-member under concurrency — reproduces the live 3-way split (2026-08-01):
 * A+B converge, A adds C, then A's post-add send and C's post-join heal race.
 * Uses a CONTROLLABLE hub (buffered delivery) so the race is deterministic,
 * unlike the synchronous LoopbackHub in atsms-e2e (whose serialized delivery
 * hides it — which is why the passing "add carol" e2e test never caught this).
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

/** Buffered delivery hub — posts queue until an explicit flush(); lets us hold
 *  the add-heal and join-heal both in flight before either lands. */
class ControllableHub {
  private handlers = new Map<string, (env: Uint8Array) => Promise<void>>();
  private queue: Array<{ did: string; env: Uint8Array }> = [];

  post(did: string, env: Uint8Array): void {
    this.queue.push({ did, env });
  }
  /** Deliver everything currently queued, chasing cascades to quiescence. */
  async flush(): Promise<void> {
    let guard = 0;
    while (this.queue.length > 0) {
      if (guard++ > 10000) throw new Error("flush did not settle (livelock)");
      const { did, env } = this.queue.shift()!;
      await this.handlers.get(did)?.(env);
    }
  }
  transportFor(did: string): EnvelopeTransport {
    return {
      ingressUrl: `loop://${encodeURIComponent(did)}`,
      deliverToUrl: async (url, env) => this.post(decodeURIComponent(url.replace("loop://", "")), env),
      deliverToDid: async (target, env) => this.post(target, env),
      start: async (onEnvelope) => {
        this.handlers.set(did, onEnvelope);
      },
      stop: async () => {
        this.handlers.delete(did);
      },
    };
  }
}

async function client(hub: ControllableHub, pds: SharedPds, seed: number, did: string) {
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

describe("add a member under concurrency (live 3-way repro)", () => {
  test("serialized add (control): all three converge", async () => {
    const hub = new ControllableHub();
    const pds = new SharedPds();
    const a = await client(hub, pds, 1, "did:plc:a");
    const b = await client(hub, pds, 2, "did:plc:b");
    const c = await client(hub, pds, 3, "did:plc:c");

    const convo = await a.atsms.conversations.createGroup({ members: [b.did] });
    await hub.flush();
    await convo.send("yo");
    await hub.flush();
    expect(await texts(b, convo.id)).toContain("yo");

    // Add C, then let everything settle BEFORE anyone sends (serialized).
    await convo.addMember(c.did);
    await hub.flush();
    await convo.send("three way");
    await hub.flush();

    for (const m of [a, b, c]) expect(await texts(m, convo.id)).toContain("three way");
  });

  test("concurrent add-heal vs join-heal: all three must still converge", async () => {
    const hub = new ControllableHub();
    const pds = new SharedPds();
    const a = await client(hub, pds, 11, "did:plc:a");
    const b = await client(hub, pds, 12, "did:plc:b");
    const c = await client(hub, pds, 13, "did:plc:c");

    const convo = await a.atsms.conversations.createGroup({ members: [b.did] });
    await hub.flush();
    await convo.send("yo");
    await hub.flush();

    // A adds C: add→B and welcome→C are now queued (not yet delivered).
    await convo.addMember(c.did);
    // A sends immediately — self-heals (root blanked by add) BEFORE C's join is
    // delivered: A's heal and C's coming join-heal will be concurrent.
    await a.atsms.conversations.get(convo.id).then((h) => h!.send("three way"));
    // Now let the whole storm settle.
    await hub.flush();

    // C sends after joining.
    const ch = await c.atsms.conversations.get(convo.id);
    expect(ch).not.toBeNull();
    await ch!.send("hey from c");
    await hub.flush();

    // The property that live testing violated: everyone sees everyone.
    for (const [name, m] of [["a", a], ["b", b], ["c", c]] as const) {
      const t = await texts(m, convo.id);
      expect(t).toContain("three way");
      expect(t).toContain("hey from c");
    }
  });
});
