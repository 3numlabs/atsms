/**
 * Tests for the identity module: the @atsms/dcgka PdsClient adapter, DID→PDS
 * resolution (incl. did:web), and the cert→identity-pubkey bridge.
 */

import { p256 } from "@noble/curves/p256";
import { buildPrekeyRecord, resolvePrekey, verifyPrekeyRecord } from "@atsms/dcgka";
import { afterEach, describe, expect, test } from "bun:test";

import { ATSMSPdsClient, resolveDidToPds } from "../lib/identity/pds-client.js";
import { identityPublicKeyFromCert } from "../lib/identity/cert-key.js";
import { cryptoProvider } from "../lib/crypto-provider.js";
import { generateTestEndpointCertificate } from "./test-certificates.js";

const enc = (s: string) => new TextEncoder().encode(s);
async function sha256(data: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await cryptoProvider.subtle.digest("SHA-256", data));
}

/** A mock AtpAgent: an in-memory single-repo (`myDid`) store over com.atproto.repo.*. */
function mockAgent(myDid: string) {
  const store = new Map<string, unknown>();
  const key = (c: string, rk: string) => `${c}/${rk}`;
  const calls: Array<{ op: string; collection: string; rkey: string }> = [];
  const agent = {
    _store: store,
    _calls: calls,
    com: {
      atproto: {
        repo: {
          putRecord: async ({ collection, rkey, record }: any) => {
            calls.push({ op: "put", collection, rkey });
            store.set(key(collection, rkey), record);
            return { data: { uri: `at://${myDid}/${collection}/${rkey}`, cid: "cid1" } };
          },
          deleteRecord: async ({ collection, rkey }: any) => {
            calls.push({ op: "delete", collection, rkey });
            store.delete(key(collection, rkey));
            return { data: {} };
          },
          getRecord: async ({ repo, collection, rkey }: any) => {
            const v = store.get(key(collection, rkey));
            if (v === undefined) throw { error: "RecordNotFound", message: "Could not locate record" };
            return { data: { uri: `at://${repo}/${collection}/${rkey}`, cid: "cid1", value: v } };
          },
          listRecords: async ({ repo, collection }: any) => {
            const records = [...store.entries()]
              .filter(([k]) => k.startsWith(`${collection}/`))
              .map(([k, value]) => ({ uri: `at://${repo}/${collection}/${k}`, cid: "cid1", value }));
            return { data: { records } };
          },
        },
      },
    },
  };
  return agent;
}

const DID = "did:plc:alice";

describe("ATSMSPdsClient", () => {
  test("put → get → list → delete round-trips over the agent", async () => {
    const agent = mockAgent(DID);
    const pds = new ATSMSPdsClient(agent as any, DID);

    const value = { $type: "at.atsms.inbox", endpoints: [{ uri: "mailto:a@b" }] };
    const put = await pds.putRecord("at.atsms.inbox", "self", value);
    expect(put.uri).toBe(`at://${DID}/at.atsms.inbox/self`);

    const got = await pds.getRecord(DID, "at.atsms.inbox", "self");
    expect(got?.value).toEqual(value);

    const listed = await pds.listRecords(DID, "at.atsms.inbox");
    expect(listed).toHaveLength(1);

    await pds.deleteRecord("at.atsms.inbox", "self");
    expect(await pds.getRecord(DID, "at.atsms.inbox", "self")).toBeNull();
  });

  test("getRecord returns null (not throw) on RecordNotFound", async () => {
    const pds = new ATSMSPdsClient(mockAgent(DID) as any, DID);
    expect(await pds.getRecord(DID, "at.atsms.prekey", "missing")).toBeNull();
  });

  test("Uint8Array record fields survive the round-trip (bytes handling)", async () => {
    const agent = mockAgent(DID);
    const pds = new ATSMSPdsClient(agent as any, DID);
    const bytes = new Uint8Array([1, 2, 3, 250, 0, 255]);
    await pds.putRecord("at.atsms.prekey", "fp", { $type: "at.atsms.prekey", signedPrekey: bytes });
    const got = await pds.getRecord(DID, "at.atsms.prekey", "fp");
    expect(Array.from((got!.value as any).signedPrekey)).toEqual(Array.from(bytes));
  });
});

describe("resolveDidToPds", () => {
  const realFetch = globalThis.fetch;
  afterEach(() => {
    globalThis.fetch = realFetch;
  });

  test("resolves did:plc via the PLC directory", async () => {
    globalThis.fetch = (async (url: string) => {
      expect(url).toContain("plc.directory");
      return { ok: true, json: async () => ({ service: [{ id: "#atproto_pds", type: "AtprotoPersonalDataServer", serviceEndpoint: "https://pds.example" }] }) };
    }) as any;
    expect(await resolveDidToPds("did:plc:abc")).toBe("https://pds.example");
  });

  test("resolves did:web via well-known (fixes the plc-only gap)", async () => {
    globalThis.fetch = (async (url: string) => {
      expect(url).toBe("https://example.com/.well-known/did.json");
      return { ok: true, json: async () => ({ service: [{ id: "#atproto_pds", type: "AtprotoPersonalDataServer", serviceEndpoint: "https://pds.example.com" }] }) };
    }) as any;
    expect(await resolveDidToPds("did:web:example.com")).toBe("https://pds.example.com");
  });

  test("rejects an unsupported DID method", async () => {
    await expect(resolveDidToPds("did:key:zabc")).rejects.toThrow(/Unsupported DID method/);
  });
});

describe("identityPublicKeyFromCert", () => {
  test("extracts a well-formed P-256 point that verifies the cert's signatures", async () => {
    const { cert, privateKey } = await generateTestEndpointCertificate(DID, "alice.example", "atsms.email");
    const pub = await identityPublicKeyFromCert(cert);

    expect(pub.length).toBe(65);
    expect(pub[0]).toBe(0x04); // uncompressed point
    expect(() => p256.Point.fromHex(pub)).not.toThrow(); // @noble accepts it

    // Correctness: a signature made by the cert's private key verifies under the
    // extracted public key — exactly what prekey bundleSig verification relies on.
    const der = pemToDer(privateKey);
    const sk = await cryptoProvider.subtle.importKey("pkcs8", der, { name: "ECDSA", namedCurve: "P-256" }, false, ["sign"]);
    const msg = enc("prekey-bundle-under-cert-key");
    const sig = new Uint8Array(await cryptoProvider.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, sk, msg));
    expect(p256.verify(sig, await sha256(msg), pub, { lowS: false })).toBe(true);
  });

  test("end-to-end: a dcgka prekey signed with the identity key resolves + verifies through the adapter", async () => {
    // Derive a raw P-256 scalar to act as the identity signing key, and build a
    // matching "cert" pub for verification (the cert path is covered above; here
    // we exercise the adapter ⋈ dcgka resolve/verify loop).
    const identitySk = await sha256(enc("id-scalar"));
    const identityPub = p256.getPublicKey(identitySk);
    const signedPrekey = await sha256(enc("x25519-stand-in")); // 32-byte stand-in for an X25519 pub
    const record = buildPrekeyRecord(
      { signedPrekey, createdAt: "2026-07-26T00:00:00.000Z", expiresAt: "2026-08-02T00:00:00.000Z" },
      identitySk,
    );
    expect(verifyPrekeyRecord(record, identityPub).ok).toBe(true);

    const agent = mockAgent(DID);
    const pds = new ATSMSPdsClient(agent as any, DID);
    await pds.putRecord("at.atsms.prekey", "fp", record);
    const resolved = await resolvePrekey(pds, DID, "fp", identityPub);
    expect(resolved.ok).toBe(true);
  });
});

function pemToDer(pem: string): Uint8Array {
  const b64 = pem.replace(/-----[^-]+-----/g, "").replace(/\s+/g, "");
  const bin = atob(b64);
  const der = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) der[i] = bin.charCodeAt(i);
  return der;
}
