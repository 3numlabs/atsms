/**
 * Tests for the identity module: the @atsms/dcgka PdsClient adapter, DID→PDS
 * resolution (incl. did:web), and the cert→identity-pubkey bridge.
 */

import { p256 } from "@noble/curves/p256";
import { buildPrekeyRecord, resolvePrekey, verifyPrekeyRecord } from "@atsms/dcgka";
import { afterEach, describe, expect, test } from "bun:test";

import { ATSMSPdsClient, resolveDidToPds } from "../lib/identity/pds-client.js";
import { deviceFingerprintFromCert, identityPublicKeyFromCert } from "../lib/identity/cert-key.js";
import {
  capableDevices,
  isDcgkaCapable,
  resolveDeviceCapabilities,
  selectGroupPath,
} from "../lib/identity/capability.js";
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

function b64urlToBytes(s: string): Uint8Array {
  const b64 = s.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((s.length + 3) % 4);
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

/** Extract the raw 32-byte P-256 scalar from a PKCS#8 private-key PEM (the identity signing key). */
async function p256Scalar(privateKeyPEM: string): Promise<Uint8Array> {
  const key = await cryptoProvider.subtle.importKey(
    "pkcs8",
    pemToDer(privateKeyPEM),
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["sign"],
  );
  const jwk = await cryptoProvider.subtle.exportKey("jwk", key);
  return b64urlToBytes(jwk.d!);
}

const T0 = Date.parse("2026-07-26T00:00:00.000Z");
const WEEK = 7 * 24 * 60 * 60 * 1000;
const iso = (ms: number) => new Date(ms).toISOString();

/** Seed one device (cert + optionally a prekey) into a mock repo; returns its fingerprint. */
async function seedDevice(
  pds: ATSMSPdsClient,
  rkey: string,
  opts: { prekey?: "valid" | "expired" | "tampered" } = { prekey: "valid" },
): Promise<string> {
  const { cert, privateKey } = await generateTestEndpointCertificate(DID, `${rkey}.example`, "atsms.email");
  await pds.putRecord("at.atsms.x509", rkey, { certificate: cert, $type: "at.atsms.x509" });
  const fp = await deviceFingerprintFromCert(cert);
  if (opts.prekey) {
    const scalar = await p256Scalar(privateKey);
    const signedPrekey = await sha256(enc(`sp-${rkey}`));
    const expiresAt = opts.prekey === "expired" ? iso(T0 - WEEK) : iso(T0 + WEEK);
    const record = buildPrekeyRecord({ signedPrekey, createdAt: iso(T0 - WEEK), expiresAt }, scalar);
    if (opts.prekey === "tampered") record.signedPrekey = new Uint8Array(32); // breaks bundleSig
    await pds.putRecord("at.atsms.prekey", fp, record);
  }
  return fp;
}

describe("capability discovery (§3)", () => {
  test("a device with a valid prekey is capable; the DID is capable; capableDevices returns its bundle", async () => {
    const pds = new ATSMSPdsClient(mockAgent(DID) as any, DID);
    const fp = await seedDevice(pds, "dev1", { prekey: "valid" });

    const caps = await resolveDeviceCapabilities(pds, DID, T0);
    expect(caps).toHaveLength(1);
    expect(caps[0]).toMatchObject({ fingerprint: fp, capable: true });
    expect(caps[0].prekey).toBeDefined();

    expect(await isDcgkaCapable(pds, DID, T0)).toBe(true);
    const devs = await capableDevices(pds, DID, T0);
    expect(devs.map((d) => d.fingerprint)).toEqual([fp]);
  });

  test("no prekey → not capable (not-found)", async () => {
    const pds = new ATSMSPdsClient(mockAgent(DID) as any, DID);
    await seedDevice(pds, "dev1", { prekey: undefined });
    const caps = await resolveDeviceCapabilities(pds, DID, T0);
    expect(caps[0]).toMatchObject({ capable: false, reason: "not-found" });
    expect(await isDcgkaCapable(pds, DID, T0)).toBe(false);
  });

  test("expired prekey → not capable (expired)", async () => {
    const pds = new ATSMSPdsClient(mockAgent(DID) as any, DID);
    await seedDevice(pds, "dev1", { prekey: "expired" });
    expect((await resolveDeviceCapabilities(pds, DID, T0))[0].reason).toBe("expired");
  });

  test("tampered prekey → not capable (bad-signature)", async () => {
    const pds = new ATSMSPdsClient(mockAgent(DID) as any, DID);
    await seedDevice(pds, "dev1", { prekey: "tampered" });
    expect((await resolveDeviceCapabilities(pds, DID, T0))[0].reason).toBe("bad-signature");
  });

  test("DID is capable if ≥1 of several devices is", async () => {
    const pds = new ATSMSPdsClient(mockAgent(DID) as any, DID);
    await seedDevice(pds, "dev1", { prekey: undefined }); // incapable
    await seedDevice(pds, "dev2", { prekey: "valid" }); // capable
    const caps = await resolveDeviceCapabilities(pds, DID, T0);
    expect(caps.filter((d) => d.capable)).toHaveLength(1);
    expect(await isDcgkaCapable(pds, DID, T0)).toBe(true);
  });

  test("selectGroupPath: dcgka when all capable, x509 (with incapable list) otherwise", async () => {
    const capablePds = new ATSMSPdsClient(mockAgent(DID) as any, DID);
    await seedDevice(capablePds, "dev1", { prekey: "valid" });
    expect(await selectGroupPath(capablePds, [DID], T0)).toEqual({ protocol: "dcgka", incapable: [] });

    const floorPds = new ATSMSPdsClient(mockAgent(DID) as any, DID);
    await seedDevice(floorPds, "dev1", { prekey: undefined });
    expect(await selectGroupPath(floorPds, [DID], T0)).toEqual({ protocol: "x509", incapable: [DID] });
  });
});
