/**
 * `open()` must not leave a half-built conversation. A transient delivery
 * failure (relay 5xx, network blip) used to abort open() AFTER the create was
 * persisted and registered but BEFORE the first update established an epoch —
 * leaving a conversation that every later open() reused forever, permanently
 * unable to send or decrypt. Live-observed 2026-08-02 (persisted state:
 * frames=1, ctrlSeq=1, no epoch).
 */

import { cborDecode, type PdsClient, type PdsRecordView, type PutResult } from "@atsms/dcgka";
import { Database } from "bun:sqlite";
import { expect, test } from "bun:test";

import { ATSMS } from "../lib/client/atsms.js";
import { ATSMSDeviceIdentity } from "../lib/identity/device-identity.js";
import { SQLiteAdapter } from "../lib/storage/sqlite-adapter.js";
import type { EnvelopeTransport } from "../lib/transport/envelope-transport.js";
import { generateTestEndpointCertificate } from "./test-certificates.js";

class Wrap {
  private db = new Database(":memory:");
  exec(s: string): void { this.db.exec(s); }
  prepare(s: string) {
    const st = this.db.prepare(s);
    return {
      run: (...p: unknown[]) => st.run(...(p as never[])),
      get: (...p: unknown[]) => st.get(...(p as never[])),
      all: (...p: unknown[]) => st.all(...(p as never[])),
    };
  }
  transaction<T>(fn: () => T): T { return this.db.transaction(fn)(); }
}
const rngOf = (s0: number) => {
  let s = s0 >>> 0;
  return (n: number) => {
    const o = new Uint8Array(n);
    for (let i = 0; i < n; i++) { s = (s * 1664525 + 1013904223) >>> 0; o[i] = (s >>> 24) & 0xff; }
    return o;
  };
};
class Pds {
  private m = new Map<string, unknown>();
  forDid(me: string): PdsClient {
    const k = (r: string, c: string, rk: string) => `${r} ${c} ${rk}`;
    return {
      putRecord: async (c, rk, v): Promise<PutResult> => { this.m.set(k(me, c, rk), v); return { uri: `at://${me}/${c}/${rk}` }; },
      deleteRecord: async (c, rk) => { this.m.delete(k(me, c, rk)); },
      getRecord: async (r, c, rk): Promise<PdsRecordView | null> => {
        const v = this.m.get(k(r, c, rk));
        return v === undefined ? null : { uri: `at://${r}/${c}/${rk}`, value: v };
      },
      listRecords: async (r, c): Promise<PdsRecordView[]> => {
        const o: PdsRecordView[] = [];
        for (const [key, v] of this.m) {
          const [rr, cc, rk] = key.split(" ");
          if (rr === r && cc === c) o.push({ uri: `at://${r}/${cc}/${rk}`, value: v });
        }
        return o;
      },
    };
  }
}

test("a delivery failure during open() leaves usable local state, and reopen repairs", async () => {
  const pds = new Pds();
  const storage = new SQLiteAdapter(new Wrap() as never);
  const rng = rngOf(7);
  let failDelivery = true;
  const transport: EnvelopeTransport = {
    ingressUrl: "loop://a",
    deliverToUrl: async () => { if (failDelivery) throw new Error("relay 503"); },
    deliverToDid: async () => { if (failDelivery) throw new Error("relay 503"); },
    start: async () => {}, stop: async () => {},
  };

  const me = await generateTestEndpointCertificate("did:plc:a", "a.example", "atsms.email");
  const identity = await ATSMSDeviceIdentity.load({ did: "did:plc:a", certificatePEM: me.cert, privateKeyPEM: me.privateKey, storage, rng });
  await pds.forDid("did:plc:a").putRecord("at.atsms.x509", identity.fingerprint, { certificate: me.cert });

  const peerStore = new SQLiteAdapter(new Wrap() as never);
  const peer = await generateTestEndpointCertificate("did:plc:b", "b.example", "atsms.email");
  const peerId = await ATSMSDeviceIdentity.load({ did: "did:plc:b", certificatePEM: peer.cert, privateKeyPEM: peer.privateKey, storage: peerStore, rng: rngOf(8) });
  await pds.forDid("did:plc:b").putRecord("at.atsms.x509", peerId.fingerprint, { certificate: peer.cert });
  await peerId.ensurePrekeyPublished(pds.forDid("did:plc:b"));

  const atsms = await ATSMS.create({ identity, storage, transport, pds: pds.forDid("did:plc:a"), rng, genesisWaitMs: 0 });

  // open() fails at delivery — but the epoch must already be established locally.
  await expect(atsms.conversations.with("did:plc:b")).rejects.toThrow();
  const groupId = (await storage.listEngineStateIds())[0]!;
  const blob: any = cborDecode((await storage.loadEngineState(groupId))!);
  expect(blob[6]).toBeGreaterThan(1); // ctrlSeq > 1 ⇒ the update was minted, not just the create

  // Reopening once delivery works returns a USABLE conversation (not the old
  // permanently-epochless one).
  failDelivery = false;
  const handle = await atsms.conversations.with("did:plc:b");
  expect(handle.inner.hasSendableEpoch).toBe(true);
  await handle.send("works now"); // must not throw
});
