/**
 * Tests for P-256 ECDSA Certificate classes
 */

import { describe, expect, it } from "bun:test";

import {
  ATSMSEndpointCertificate,
  ATSMSP256EndpointCertificate,
  detectCertificateAlgorithm,
  generateEndpointCertificate,
  isP256Certificate,
  isRSACertificate,
  loadEndpointCertificate,
  loadEndpointCertificateWithKey,
} from "../lib/certificates/index.js";

describe("P-256 ECDSA Certificate Classes", () => {
  describe("ATSMSP256EndpointCertificate", () => {
    it("should generate a valid self-signed P-256 endpoint certificate", async () => {
      const endpointCert = await ATSMSP256EndpointCertificate.generate(
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

    it("should load certificate with private key using fromPEMWithKey", async () => {
      const originalCert = await ATSMSP256EndpointCertificate.generate(
        "did:plc:test123",
        "test.acme.xyz",
        "test.acme.xyz",
      );

      const certPEM = originalCert.certificatePEM;
      const privateKeyPEM = originalCert.certificatePrivateKeyPEM!;

      const loadedCert = await ATSMSP256EndpointCertificate.fromPEMWithKey(
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
      const cert1 = await ATSMSP256EndpointCertificate.generate(
        "did:plc:test123",
        "test.acme.xyz",
        "test.acme.xyz",
      );
      const cert2 = await ATSMSP256EndpointCertificate.generate(
        "did:plc:test456",
        "test2.acme.xyz",
        "test2.acme.xyz",
      );

      await expect(
        ATSMSP256EndpointCertificate.fromPEMWithKey(
          cert1.certificatePEM,
          cert2.certificatePrivateKeyPEM!,
        ),
      ).rejects.toThrow(
        "Private key does not match the certificate public key",
      );
    });

    it("should export and import PEM", async () => {
      const originalCert = await ATSMSP256EndpointCertificate.generate(
        "did:plc:client123",
        "client.acme.xyz",
        "client.acme.xyz",
      );

      const certPEM = originalCert.certificatePEM;
      const privateKeyPEM = originalCert.certificatePrivateKeyPEM!;

      expect(certPEM).toContain("BEGIN CERTIFICATE");
      expect(privateKeyPEM).toContain("BEGIN PRIVATE KEY");

      const loadedCert = await ATSMSP256EndpointCertificate.fromPEMWithKey(
        certPEM,
        privateKeyPEM,
      );
      expect(loadedCert.commonName).toBe("did:plc:client123");
      expect(loadedCert.getType()).toBe("endpoint");
      expect(loadedCert.getAlgorithm()).toBe("P256");
    });

    it("should reject invalid parameters - string as validityDays", async () => {
      await expect(
        ATSMSP256EndpointCertificate.generate(
          "did:plc:test",
          "test.com",
          "example.com",
          "test.com" as any,
        ),
      ).rejects.toThrow("Invalid validityDays");
    });

    it("should reject invalid parameters - invalid DID format", async () => {
      await expect(
        ATSMSP256EndpointCertificate.generate(
          "not-a-did",
          "test.com",
          "example.com",
          365,
        ),
      ).rejects.toThrow("Invalid DID");
    });

    it("should reject empty emailDomain", async () => {
      await expect(
        ATSMSP256EndpointCertificate.generate(
          "did:plc:test",
          "test.com",
          "",
          365,
        ),
      ).rejects.toThrow("Invalid emailDomain");
    });

    it("should accept valid emailDomain", async () => {
      const cert = await ATSMSP256EndpointCertificate.generate(
        "did:plc:test",
        "test.com",
        "atsms.email",
        365,
      );
      expect(cert.email).toBe("plc.test@atsms.email");
    });

    it("should generate valid certificate with correct expiration", async () => {
      const endpointCert = await ATSMSP256EndpointCertificate.generate(
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
      const endpointCert = await ATSMSP256EndpointCertificate.generate(
        "did:plc:test",
        "test.com",
        "example.com",
      );

      const publicKey = await endpointCert.getPublicKeyForEncryption();
      expect(publicKey).toBeDefined();
      expect(publicKey.algorithm.name).toBe("ECDH");
    });

    it("should get private key for ECDH decryption", async () => {
      const endpointCert = await ATSMSP256EndpointCertificate.generate(
        "did:plc:test",
        "test.com",
        "example.com",
      );

      const privateKey = await endpointCert.getPrivateKeyForDecryption();
      expect(privateKey).toBeDefined();
      expect(privateKey.algorithm.name).toBe("ECDH");
    });

    it("should throw error when getting private key for decryption without private key", async () => {
      const originalCert = await ATSMSP256EndpointCertificate.generate(
        "did:plc:test",
        "test.com",
        "example.com",
      );

      const certPEM = originalCert.certificatePEM;
      const certWithoutKey = ATSMSP256EndpointCertificate.fromPEM(certPEM);

      await expect(certWithoutKey.getPrivateKeyForDecryption()).rejects.toThrow(
        "Private key not available for decryption",
      );
    });
  });

  describe("Certificate Factory Functions", () => {
    it("should detect P-256 certificate algorithm", async () => {
      const p256Cert = await ATSMSP256EndpointCertificate.generate(
        "did:plc:test",
        "test.com",
        "example.com",
      );

      const algorithm = detectCertificateAlgorithm(p256Cert.certificatePEM);
      expect(algorithm).toBe("P256");
    });

    it("should detect RSA certificate algorithm", async () => {
      const rsaCert = await ATSMSEndpointCertificate.generate(
        "did:plc:test",
        "test.com",
        "example.com",
      );

      const algorithm = detectCertificateAlgorithm(rsaCert.certificatePEM);
      expect(algorithm).toBe("RSA");
    });

    it("should load P-256 certificate using loadEndpointCertificate", async () => {
      const originalCert = await ATSMSP256EndpointCertificate.generate(
        "did:plc:test",
        "test.com",
        "example.com",
      );

      const loadedCert = loadEndpointCertificate(originalCert.certificatePEM);
      expect(loadedCert).toBeInstanceOf(ATSMSP256EndpointCertificate);
      expect(isP256Certificate(loadedCert)).toBe(true);
      expect(isRSACertificate(loadedCert)).toBe(false);
    });

    it("should load RSA certificate using loadEndpointCertificate", async () => {
      const originalCert = await ATSMSEndpointCertificate.generate(
        "did:plc:test",
        "test.com",
        "example.com",
      );

      const loadedCert = loadEndpointCertificate(originalCert.certificatePEM);
      expect(loadedCert).toBeInstanceOf(ATSMSEndpointCertificate);
      expect(isP256Certificate(loadedCert)).toBe(false);
      expect(isRSACertificate(loadedCert)).toBe(true);
    });

    it("should load P-256 certificate with key using loadEndpointCertificateWithKey", async () => {
      const originalCert = await ATSMSP256EndpointCertificate.generate(
        "did:plc:test",
        "test.com",
        "example.com",
      );

      const loadedCert = await loadEndpointCertificateWithKey(
        originalCert.certificatePEM,
        originalCert.certificatePrivateKeyPEM!,
      );
      expect(loadedCert).toBeInstanceOf(ATSMSP256EndpointCertificate);
      expect(loadedCert.hasPrivateKey()).toBe(true);
    });

    it("should load RSA certificate with key using loadEndpointCertificateWithKey", async () => {
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

    it("should generate P-256 certificate using generateEndpointCertificate", async () => {
      const cert = await generateEndpointCertificate(
        "P256",
        "did:plc:test",
        "test.com",
        "example.com",
      );

      expect(cert).toBeInstanceOf(ATSMSP256EndpointCertificate);
      expect(isP256Certificate(cert)).toBe(true);
      // Verify deterministic email format
      expect(cert.email).toBe("plc.test@example.com");
    });

    it("should generate RSA certificate using generateEndpointCertificate", async () => {
      const cert = await generateEndpointCertificate(
        "RSA",
        "did:plc:test",
        "test.com",
        "example.com",
      );

      expect(cert).toBeInstanceOf(ATSMSEndpointCertificate);
      expect(isRSACertificate(cert)).toBe(true);
      // Verify deterministic email format
      expect(cert.email).toBe("plc.test@example.com");
    });
  });

  describe("P-256 Self-Signed Certificate Properties", () => {
    it("should correctly identify self-signed P-256 endpoint certificate", async () => {
      const endpointCert = await ATSMSP256EndpointCertificate.generate(
        "did:plc:test123",
        "test.acme.xyz",
        "test.acme.xyz",
      );

      expect(endpointCert.isSimpleSelfSigned()).toBe(true);
      expect(endpointCert.subject).toBe(endpointCert.issuer);
      expect(endpointCert.getType()).toBe("endpoint");
    });

    it("should NOT be a CA certificate", async () => {
      const endpointCert = await ATSMSP256EndpointCertificate.generate(
        "did:plc:test123",
        "test.acme.xyz",
        "test.acme.xyz",
      );

      expect(endpointCert.isCA).toBe(false);
    });

    it("should verify self-signature", async () => {
      const endpointCert = await ATSMSP256EndpointCertificate.generate(
        "did:plc:test123",
        "test.acme.xyz",
        "test.acme.xyz",
      );

      const isValid = await endpointCert.verifySelfSignature();
      expect(typeof isValid).toBe("boolean");
    });

    it("should maintain properties after PEM export/import", async () => {
      const originalCert = await ATSMSP256EndpointCertificate.generate(
        "did:plc:test123",
        "test.acme.xyz",
        "test.acme.xyz",
      );

      const certPEM = originalCert.toString("pem");
      const privateKeyPEM = originalCert.certificatePrivateKeyPEM!;

      const reimportedCert = await ATSMSP256EndpointCertificate.fromPEMWithKey(
        certPEM,
        privateKeyPEM,
      );

      expect(reimportedCert.isCA).toBe(false);
      expect(reimportedCert.isSimpleSelfSigned()).toBe(true);
      expect(reimportedCert.commonName).toBe("did:plc:test123");
      expect(reimportedCert.getAlgorithm()).toBe("P256");
    });
  });

  describe("P-256 Certificate Validation", () => {
    it("should detect non-expired certificates", async () => {
      const endpointCert = await ATSMSP256EndpointCertificate.generate(
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
