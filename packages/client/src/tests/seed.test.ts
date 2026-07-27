/**
 * Seed-derived identity (the passkey/PRF flow): deterministic, domain-
 * separated, and stable across "recoveries" — the same seed always yields the
 * same device fingerprint, so the passkey alone recovers the identity.
 */

import { describe, expect, test } from "bun:test";

import { ATSMSEndpointCertificate } from "../lib/certificates/index.js";
import {
  deriveFromSeed,
  deriveIdentityKeyPEM,
  deriveStorageKey,
  SEED_LABEL_IDENTITY,
  SEED_LABEL_STORAGE_KEY,
} from "../lib/identity/seed.js";

const seed = (fill: number) => new Uint8Array(32).fill(fill);

describe("seed-derived identity", () => {
  test("same seed → same key PEM; different seed → different key", async () => {
    const a1 = await deriveIdentityKeyPEM(seed(1));
    const a2 = await deriveIdentityKeyPEM(seed(1));
    const b = await deriveIdentityKeyPEM(seed(2));
    expect(a1).toBe(a2);
    expect(a1).not.toBe(b);
    expect(a1).toContain("BEGIN PRIVATE KEY");
  });

  test("recovery invariant: same seed → same device fingerprint across fresh certs", async () => {
    const keyPEM = await deriveIdentityKeyPEM(seed(3));
    const cert1 = await ATSMSEndpointCertificate.generateWithKey(keyPEM, "did:plc:seedtest", "a.example", "a.example");
    const cert2 = await ATSMSEndpointCertificate.generateWithKey(keyPEM, "did:plc:seedtest", "a.example", "a.example");
    // Different certs (fresh serial/validity) — same device.
    expect(cert1.serialNumber).not.toBe(cert2.serialNumber);
    expect(await cert1.getDeviceFingerprint()).toBe(await cert2.getDeviceFingerprint());
    // And the derived key actually signs: the cert is self-signed with it.
    expect(cert1.isValid()).toBe(true);
  });

  test("labels are domain-separated: identity and storage keys are independent", async () => {
    const ident = await deriveFromSeed(seed(4), SEED_LABEL_IDENTITY, 32);
    const store = await deriveStorageKey(seed(4));
    expect(store).toHaveLength(32);
    expect(Buffer.from(ident).toString("hex")).not.toBe(Buffer.from(store).toString("hex"));
  });

  test("rejects a too-short seed", async () => {
    await expect(deriveFromSeed(new Uint8Array(8), SEED_LABEL_STORAGE_KEY, 32)).rejects.toThrow(/seed too short/);
  });
});
