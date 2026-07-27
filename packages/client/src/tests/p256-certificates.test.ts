/**
 * Tests for P-256 ECDSA Endpoint Certificate
 */

import { describe, expect, it } from "bun:test";

import {
  ATSMSEndpointCertificate,
  generateEndpointCertificate,
  loadEndpointCertificate,
  loadEndpointCertificateWithKey,
} from "../lib/certificates/index.js";

describe("P-256 ECDSA Endpoint Certificate", () => {
  describe("ATSMSEndpointCertificate", () => {
    it("should generate a valid self-signed P-256 endpoint certificate", async () => {
      const endpointCert = await ATSMSEndpointCertificate.generate(
        "did:plc:test123",
        "test.acme.xyz",
        "test.acme.xyz",
      );

      expect(endpointCert.getType()).toBe("endpoint");
      expect(endpointCert.getAlgorithm()).toBe("P256");
      expect(endpointCert.commonName).toBe("did:plc:test123");
      expect(endpointCert.isSimpleSelfSigned()).toBe(true);
      expect(endpointCert.hasPrivateKey()).toBe(true);
      expect(endpointCert.isValid()).toBe(true);
      expect(endpointCert.did).toBe("did:plc:test123");
      // Email is deterministically computed as plc.[plc-id]@[emailDomain]
      expect(endpointCert.email).toBe("plc.test123@test.acme.xyz");

      const certPEM = endpointCert.certificatePEM;
      const privateKeyPEM = endpointCert.certificatePrivateKeyPEM!;

      expect(certPEM).toContain("BEGIN CERTIFICATE");
      expect(privateKeyPEM).toContain("BEGIN PRIVATE KEY");
    });

    it("device fingerprint is lowercase hex and keys the SAN URI (integration §8.5)", async () => {
      const endpointCert = await ATSMSEndpointCertificate.generate(
        "did:plc:test123",
        "test.acme.xyz",
        "test.acme.xyz",
      );
      const fingerprint = await endpointCert.getDeviceFingerprint();
      // Lowercase-hex rule — mixed case would split a device's mailbox in two.
      expect(fingerprint).toMatch(/^[0-9a-f]{64}$/);
      // The SAN URI carries the fingerprint-keyed record path (not the serial),
      // and it survives a PEM round-trip.
      const parsed = loadEndpointCertificate(endpointCert.certificatePEM);
      expect(parsed.atUri).toBe(`at://did:plc:test123/at.atsms.x509/${fingerprint}`);
      expect(await parsed.getDeviceFingerprint()).toBe(fingerprint);
      expect(parsed.did).toBe("did:plc:test123");
    });

    it("should load certificate with private key using fromPEMWithKey", async () => {
      const originalCert = await ATSMSEndpointCertificate.generate(
        "did:plc:test123",
        "test.acme.xyz",
        "test.acme.xyz",
      );

      const certPEM = originalCert.certificatePEM;
      const privateKeyPEM = originalCert.certificatePrivateKeyPEM!;

      const loadedCert = await ATSMSEndpointCertificate.fromPEMWithKey(
        certPEM,
        privateKeyPEM,
      );

      expect(loadedCert.getType()).toBe("endpoint");
      expect(loadedCert.getAlgorithm()).toBe("P256");
      expect(loadedCert.commonName).toBe("did:plc:test123");
      expect(loadedCert.hasPrivateKey()).toBe(true);
      expect(loadedCert.isValid()).toBe(true);
    });

    it("should throw error if private key does not match certificate", async () => {
      const cert1 = await ATSMSEndpointCertificate.generate(
        "did:plc:test123",
        "test.acme.xyz",
        "test.acme.xyz",
      );
      const cert2 = await ATSMSEndpointCertificate.generate(
        "did:plc:test456",
        "test2.acme.xyz",
        "test2.acme.xyz",
      );

      await expect(
        ATSMSEndpointCertificate.fromPEMWithKey(
          cert1.certificatePEM,
          cert2.certificatePrivateKeyPEM!,
        ),
      ).rejects.toThrow(
        "Private key does not match the certificate public key",
      );
    });

    it("should export and import PEM", async () => {
      const originalCert = await ATSMSEndpointCertificate.generate(
        "did:plc:client123",
        "client.acme.xyz",
        "client.acme.xyz",
      );

      const certPEM = originalCert.certificatePEM;
      const privateKeyPEM = originalCert.certificatePrivateKeyPEM!;

      expect(certPEM).toContain("BEGIN CERTIFICATE");
      expect(privateKeyPEM).toContain("BEGIN PRIVATE KEY");

      const loadedCert = await ATSMSEndpointCertificate.fromPEMWithKey(
        certPEM,
        privateKeyPEM,
      );
      expect(loadedCert.commonName).toBe("did:plc:client123");
      expect(loadedCert.getType()).toBe("endpoint");
      expect(loadedCert.getAlgorithm()).toBe("P256");
    });

    it("should reject invalid parameters - string as validityDays", async () => {
      await expect(
        ATSMSEndpointCertificate.generate(
          "did:plc:test",
          "test.com",
          "example.com",
          "test.com" as any,
        ),
      ).rejects.toThrow("Invalid validityDays");
    });

    it("should reject invalid parameters - invalid DID format", async () => {
      await expect(
        ATSMSEndpointCertificate.generate(
          "not-a-did",
          "test.com",
          "example.com",
          365,
        ),
      ).rejects.toThrow("Invalid DID");
    });

    it("should reject empty emailDomain", async () => {
      await expect(
        ATSMSEndpointCertificate.generate(
          "did:plc:test",
          "test.com",
          "",
          365,
        ),
      ).rejects.toThrow("Invalid emailDomain");
    });

    it("should accept valid emailDomain", async () => {
      const cert = await ATSMSEndpointCertificate.generate(
        "did:plc:test",
        "test.com",
        "atsms.email",
        365,
      );
      expect(cert.email).toBe("plc.test@atsms.email");
    });

    it("should generate valid certificate with correct expiration", async () => {
      const endpointCert = await ATSMSEndpointCertificate.generate(
        "did:plc:test",
        "test.com",
        "example.com",
        365,
      );

      const expectedExpiration = new Date(
        Date.now() + 365 * 24 * 60 * 60 * 1000,
      );
      const diff = Math.abs(
        endpointCert.notAfter.getTime() - expectedExpiration.getTime(),
      );
      expect(diff).toBeLessThan(5000);
      expect(endpointCert.notAfter.getTime()).toBeGreaterThan(Date.now());
      expect(endpointCert.notAfter.getFullYear()).toBeGreaterThan(2020);
    });

    it("should get public key for ECDH encryption", async () => {
      const endpointCert = await ATSMSEndpointCertificate.generate(
        "did:plc:test",
        "test.com",
        "example.com",
      );

      const publicKey = await endpointCert.getPublicKeyForEncryption();
      expect(publicKey).toBeDefined();
      expect(publicKey.algorithm.name).toBe("ECDH");
    });

    it("should get private key for ECDH decryption", async () => {
      const endpointCert = await ATSMSEndpointCertificate.generate(
        "did:plc:test",
        "test.com",
        "example.com",
      );

      const privateKey = await endpointCert.getPrivateKeyForDecryption();
      expect(privateKey).toBeDefined();
      expect(privateKey.algorithm.name).toBe("ECDH");
    });

    it("should throw error when getting private key for decryption without private key", async () => {
      const originalCert = await ATSMSEndpointCertificate.generate(
        "did:plc:test",
        "test.com",
        "example.com",
      );

      const certPEM = originalCert.certificatePEM;
      const certWithoutKey = ATSMSEndpointCertificate.fromPEM(certPEM);

      await expect(certWithoutKey.getPrivateKeyForDecryption()).rejects.toThrow(
        "Private key not available for decryption",
      );
    });
  });

  describe("Certificate Factory Functions", () => {
    it("should load certificate using loadEndpointCertificate", async () => {
      const originalCert = await ATSMSEndpointCertificate.generate(
        "did:plc:test",
        "test.com",
        "example.com",
      );

      const loadedCert = loadEndpointCertificate(originalCert.certificatePEM);
      expect(loadedCert).toBeInstanceOf(ATSMSEndpointCertificate);
    });

    it("should load certificate with key using loadEndpointCertificateWithKey", async () => {
      const originalCert = await ATSMSEndpointCertificate.generate(
        "did:plc:test",
        "test.com",
        "example.com",
      );

      const loadedCert = await loadEndpointCertificateWithKey(
        originalCert.certificatePEM,
        originalCert.certificatePrivateKeyPEM!,
      );
      expect(loadedCert).toBeInstanceOf(ATSMSEndpointCertificate);
      expect(loadedCert.hasPrivateKey()).toBe(true);
    });

    it("should generate certificate using generateEndpointCertificate", async () => {
      const cert = await generateEndpointCertificate(
        "did:plc:test",
        "test.com",
        "example.com",
      );

      expect(cert).toBeInstanceOf(ATSMSEndpointCertificate);
      // Verify deterministic email format
      expect(cert.email).toBe("plc.test@example.com");
    });
  });

  describe("generateWithKey - reuse existing private key", () => {
    it("should generate a certificate using an existing private key", async () => {
      // Generate an initial cert to get a P-256 private key
      const originalCert = await ATSMSEndpointCertificate.generate(
        "did:plc:test123",
        "test.acme.xyz",
        "test.acme.xyz",
      );
      const privateKeyPEM = originalCert.certificatePrivateKeyPEM!;

      // Create a new cert reusing the same private key
      const newCert = await ATSMSEndpointCertificate.generateWithKey(
        privateKeyPEM,
        "did:plc:test123",
        "test.acme.xyz",
        "test.acme.xyz",
      );

      expect(newCert).toBeInstanceOf(ATSMSEndpointCertificate);
      expect(newCert.getType()).toBe("endpoint");
      expect(newCert.commonName).toBe("did:plc:test123");
      expect(newCert.did).toBe("did:plc:test123");
      expect(newCert.email).toBe("plc.test123@test.acme.xyz");
      expect(newCert.hasPrivateKey()).toBe(true);
      expect(newCert.isValid()).toBe(true);
      expect(newCert.isCA).toBe(false);
      expect(newCert.isSimpleSelfSigned()).toBe(true);
    });

    it("reused private key produces certs with the same public key", async () => {
      const originalCert = await ATSMSEndpointCertificate.generate(
        "did:plc:test",
        "test.com",
        "example.com",
      );
      const privateKeyPEM = originalCert.certificatePrivateKeyPEM!;

      const newCert = await ATSMSEndpointCertificate.generateWithKey(
        privateKeyPEM,
        "did:plc:test",
        "test.com",
        "example.com",
      );

      // Both certs should have the same public key (since they share the private key)
      const originalPubKey = await originalCert.getPublicKey();
      const newPubKey = await newCert.getPublicKey();

      const originalJwk = await crypto.subtle.exportKey("jwk", originalPubKey);
      const newJwk = await crypto.subtle.exportKey("jwk", newPubKey);

      expect(newJwk.x).toBe(originalJwk.x);
      expect(newJwk.y).toBe(originalJwk.y);
      expect(newJwk.crv).toBe(originalJwk.crv);
    });

    it("each call produces a different serial number", async () => {
      const originalCert = await ATSMSEndpointCertificate.generate(
        "did:plc:test",
        "test.com",
        "example.com",
      );
      const privateKeyPEM = originalCert.certificatePrivateKeyPEM!;

      const cert1 = await ATSMSEndpointCertificate.generateWithKey(
        privateKeyPEM,
        "did:plc:test",
        "test.com",
        "example.com",
      );
      const cert2 = await ATSMSEndpointCertificate.generateWithKey(
        privateKeyPEM,
        "did:plc:test",
        "test.com",
        "example.com",
      );

      expect(cert1.serialNumber).not.toBe(cert2.serialNumber);
    });

    it("should reject invalid DID format", async () => {
      const originalCert = await ATSMSEndpointCertificate.generate(
        "did:plc:test",
        "test.com",
        "example.com",
      );
      const privateKeyPEM = originalCert.certificatePrivateKeyPEM!;

      await expect(
        ATSMSEndpointCertificate.generateWithKey(
          privateKeyPEM,
          "not-a-did",
          "test.com",
          "example.com",
        ),
      ).rejects.toThrow("Invalid DID");
    });

    it("should reject empty emailDomain", async () => {
      const originalCert = await ATSMSEndpointCertificate.generate(
        "did:plc:test",
        "test.com",
        "example.com",
      );
      const privateKeyPEM = originalCert.certificatePrivateKeyPEM!;

      await expect(
        ATSMSEndpointCertificate.generateWithKey(
          privateKeyPEM,
          "did:plc:test",
          "test.com",
          "",
        ),
      ).rejects.toThrow("Invalid emailDomain");
    });

    it("loadEndpointCertificateWithKey works on cert generated with reused key", async () => {
      const originalCert = await ATSMSEndpointCertificate.generate(
        "did:plc:test",
        "test.com",
        "example.com",
      );
      const privateKeyPEM = originalCert.certificatePrivateKeyPEM!;

      const newCert = await ATSMSEndpointCertificate.generateWithKey(
        privateKeyPEM,
        "did:plc:test",
        "test.com",
        "example.com",
      );

      // Should be able to load the new cert with the same private key
      const loaded = await loadEndpointCertificateWithKey(
        newCert.certificatePEM,
        privateKeyPEM,
      );
      expect(loaded.hasPrivateKey()).toBe(true);
      expect(loaded.serialNumber).toBe(newCert.serialNumber);
    });
  });

  describe("Self-Signed Certificate Properties", () => {
    it("should correctly identify self-signed endpoint certificate", async () => {
      const endpointCert = await ATSMSEndpointCertificate.generate(
        "did:plc:test123",
        "test.acme.xyz",
        "test.acme.xyz",
      );

      expect(endpointCert.isSimpleSelfSigned()).toBe(true);
      expect(endpointCert.subject).toBe(endpointCert.issuer);
      expect(endpointCert.getType()).toBe("endpoint");
    });

    it("should NOT be a CA certificate", async () => {
      const endpointCert = await ATSMSEndpointCertificate.generate(
        "did:plc:test123",
        "test.acme.xyz",
        "test.acme.xyz",
      );

      expect(endpointCert.isCA).toBe(false);
    });

    it("should verify self-signature", async () => {
      const endpointCert = await ATSMSEndpointCertificate.generate(
        "did:plc:test123",
        "test.acme.xyz",
        "test.acme.xyz",
      );

      const isValid = await endpointCert.verifySelfSignature();
      expect(typeof isValid).toBe("boolean");
    });

    it("should maintain properties after PEM export/import", async () => {
      const originalCert = await ATSMSEndpointCertificate.generate(
        "did:plc:test123",
        "test.acme.xyz",
        "test.acme.xyz",
      );

      const certPEM = originalCert.toString("pem");
      const privateKeyPEM = originalCert.certificatePrivateKeyPEM!;

      const reimportedCert = await ATSMSEndpointCertificate.fromPEMWithKey(
        certPEM,
        privateKeyPEM,
      );

      expect(reimportedCert.isCA).toBe(false);
      expect(reimportedCert.isSimpleSelfSigned()).toBe(true);
      expect(reimportedCert.commonName).toBe("did:plc:test123");
      expect(reimportedCert.getAlgorithm()).toBe("P256");
    });
  });

  describe("Certificate Validation", () => {
    it("should detect non-expired certificates", async () => {
      const endpointCert = await ATSMSEndpointCertificate.generate(
        "did:plc:test123",
        "test.acme.xyz",
        "test.acme.xyz",
      );

      expect(endpointCert.isExpired()).toBe(false);
      expect(endpointCert.isValid()).toBe(true);
      expect(endpointCert.isNotYetValid()).toBe(false);
    });
  });
});
