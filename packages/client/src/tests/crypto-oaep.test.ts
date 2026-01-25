/**
 * Tests for RSA-OAEP encryption/decryption functions
 */

import { describe, expect, test } from "bun:test";

import { ATSMSEndpointCertificate } from "../lib/certificates/index.js";
import { decryptMessageOAEP, encryptMessageOAEP } from "../lib/crypto-oaep.js";

describe("RSA-OAEP Encryption/Decryption", () => {
  test("should encrypt and decrypt message successfully", async () => {
    // Generate self-signed endpoint certificate
    const endpointCert = await ATSMSEndpointCertificate.generate(
      "did:test:123",
      "test.acme.xyz",
      "test@test.acme.xyz",
    );

    // Test message
    const testMessage =
      "Hello, World! This is a test message for RSA-OAEP encryption.";
    const messageBytes = new TextEncoder().encode(testMessage);

    // Encrypt the message
    const encryptedContent = await encryptMessageOAEP(messageBytes, [
      endpointCert,
    ]);

    // Verify encrypted content is different from original
    expect(encryptedContent).not.toEqual(messageBytes);
    expect(encryptedContent.length).toBeGreaterThan(0);

    // Decrypt the message
    const decryptedContent = await decryptMessageOAEP(
      encryptedContent,
      endpointCert,
    );

    // Convert back to string
    const decryptedMessage = new TextDecoder().decode(decryptedContent);

    // Verify decryption worked
    expect(decryptedMessage).toBe(testMessage);
  });

  test("should handle multiple recipients", async () => {
    // Generate self-signed endpoint certificates for multiple recipients
    const recipient1 = await ATSMSEndpointCertificate.generate(
      "did:test:recipient1",
      "recipient1.acme.xyz",
      "recipient1@recipient1.acme.xyz",
    );
    const recipient2 = await ATSMSEndpointCertificate.generate(
      "did:test:recipient2",
      "recipient2.acme.xyz",
      "recipient2@recipient2.acme.xyz",
    );

    // Test message
    const testMessage = "Multi-recipient test message";
    const messageBytes = new TextEncoder().encode(testMessage);

    // Encrypt for both recipients
    const encryptedContent = await encryptMessageOAEP(messageBytes, [
      recipient1,
      recipient2,
    ]);

    // Each recipient should be able to decrypt
    const decrypted1 = await decryptMessageOAEP(encryptedContent, recipient1);
    const decrypted2 = await decryptMessageOAEP(encryptedContent, recipient2);

    const message1 = new TextDecoder().decode(decrypted1);
    const message2 = new TextDecoder().decode(decrypted2);

    expect(message1).toBe(testMessage);
    expect(message2).toBe(testMessage);
  });

  test("should fail to decrypt without private key", async () => {
    // Generate self-signed endpoint certificate with private key
    const clientCertWithKey = await ATSMSEndpointCertificate.generate(
      "did:test:123",
      "test.acme.xyz",
      "test@test.acme.xyz",
    );

    // Create certificate without private key (simulate external certificate)
    const certPEM = clientCertWithKey.certificatePEM;
    const clientCertNoKey = ATSMSEndpointCertificate.fromPEM(certPEM);

    // Test message
    const testMessage = "Test message";
    const messageBytes = new TextEncoder().encode(testMessage);

    // Encrypt the message
    const encryptedContent = await encryptMessageOAEP(messageBytes, [
      clientCertWithKey,
    ]);

    // Try to decrypt without private key - should fail
    await expect(
      decryptMessageOAEP(encryptedContent, clientCertNoKey),
    ).rejects.toThrow("Certificate must contain private key for decryption");
  });

  test("should fail to decrypt with wrong certificate", async () => {
    // Generate self-signed endpoint certificates
    const rightCert = await ATSMSEndpointCertificate.generate(
      "did:test:right",
      "right.acme.xyz",
      "right@right.acme.xyz",
    );
    const wrongCert = await ATSMSEndpointCertificate.generate(
      "did:test:wrong",
      "wrong.acme.xyz",
      "wrong@wrong.acme.xyz",
    );

    // Test message
    const testMessage = "Secret message";
    const messageBytes = new TextEncoder().encode(testMessage);

    // Encrypt for rightCert only
    const encryptedContent = await encryptMessageOAEP(messageBytes, [
      rightCert,
    ]);

    // Try to decrypt with wrong certificate - should fail
    await expect(
      decryptMessageOAEP(encryptedContent, wrongCert),
    ).rejects.toThrow();
  });

  test("should handle large messages", async () => {
    // Generate self-signed endpoint certificate
    const endpointCert = await ATSMSEndpointCertificate.generate(
      "did:test:123",
      "test.acme.xyz",
      "test@test.acme.xyz",
    );

    // Create a large message (but within RSA limits)
    const largeMessage = "x".repeat(100); // 100 bytes should be fine for RSA
    const messageBytes = new TextEncoder().encode(largeMessage);

    // Encrypt and decrypt
    const encryptedContent = await encryptMessageOAEP(messageBytes, [
      endpointCert,
    ]);
    const decryptedContent = await decryptMessageOAEP(
      encryptedContent,
      endpointCert,
    );

    const decryptedMessage = new TextDecoder().decode(decryptedContent);
    expect(decryptedMessage).toBe(largeMessage);
  });

  test("should handle binary data", async () => {
    // Generate self-signed endpoint certificate
    const endpointCert = await ATSMSEndpointCertificate.generate(
      "did:test:123",
      "test.acme.xyz",
      "test@test.acme.xyz",
    );

    // Create binary data
    const binaryData = new Uint8Array([0x00, 0x01, 0x02, 0xff, 0xfe, 0xfd]);

    // Encrypt and decrypt
    const encryptedContent = await encryptMessageOAEP(binaryData, [
      endpointCert,
    ]);
    const decryptedContent = await decryptMessageOAEP(
      encryptedContent,
      endpointCert,
    );

    expect(decryptedContent).toEqual(binaryData);
  });

  test("should handle empty message", async () => {
    // Generate self-signed endpoint certificate
    const endpointCert = await ATSMSEndpointCertificate.generate(
      "did:test:123",
      "test.acme.xyz",
      "test@test.acme.xyz",
    );

    // Empty message
    const emptyMessage = new Uint8Array(0);

    // Encrypt and decrypt
    const encryptedContent = await encryptMessageOAEP(emptyMessage, [
      endpointCert,
    ]);
    const decryptedContent = await decryptMessageOAEP(
      encryptedContent,
      endpointCert,
    );

    expect(decryptedContent.length).toBe(0);
  });

  describe("encryptMessageOAEP specific tests", () => {
    test("should handle empty recipient array", async () => {
      const testMessage = new TextEncoder().encode("test");

      // Encrypting with no recipients should throw a clear error
      await expect(encryptMessageOAEP(testMessage, [])).rejects.toThrow(
        "Cannot encrypt message: Recipient has no AT-SMS certificates",
      );
    });

    test("should produce different ciphertext for same message", async () => {
      // Generate self-signed endpoint certificate
      const endpointCert = await ATSMSEndpointCertificate.generate(
        "did:test:123",
        "test.acme.xyz",
        "test@test.acme.xyz",
      );

      const testMessage = new TextEncoder().encode("Same message");

      // Encrypt the same message twice
      const encrypted1 = await encryptMessageOAEP(testMessage, [endpointCert]);
      const encrypted2 = await encryptMessageOAEP(testMessage, [endpointCert]);

      // Due to randomization in encryption, ciphertexts should be different
      expect(encrypted1).not.toEqual(encrypted2);

      // But both should decrypt to the same message
      const decrypted1 = await decryptMessageOAEP(encrypted1, endpointCert);
      const decrypted2 = await decryptMessageOAEP(encrypted2, endpointCert);

      expect(decrypted1).toEqual(decrypted2);
      expect(new TextDecoder().decode(decrypted1)).toBe("Same message");
    });

    test("should work with certificate without private key for encryption", async () => {
      // Generate self-signed endpoint certificate with private key
      const clientCertWithKey = await ATSMSEndpointCertificate.generate(
        "did:test:123",
        "test.acme.xyz",
        "test@test.acme.xyz",
      );

      // Create certificate without private key (only public cert needed for encryption)
      const certPEM = clientCertWithKey.certificatePEM;
      const clientCertNoKey = ATSMSEndpointCertificate.fromPEM(certPEM);

      const testMessage = new TextEncoder().encode("Test message");

      // Should be able to encrypt with certificate that has no private key
      const encryptedContent = await encryptMessageOAEP(testMessage, [
        clientCertNoKey,
      ]);

      // Verify encryption worked
      expect(encryptedContent.length).toBeGreaterThan(0);

      // Should be able to decrypt with the certificate that has the private key
      const decryptedContent = await decryptMessageOAEP(
        encryptedContent,
        clientCertWithKey,
      );
      expect(new TextDecoder().decode(decryptedContent)).toBe("Test message");
    });

    test("should handle mixed recipient types", async () => {
      // Generate self-signed endpoint certificates
      const cert1WithKey = await ATSMSEndpointCertificate.generate(
        "did:test:one",
        "one.acme.xyz",
        "one@one.acme.xyz",
      );
      const cert2WithKey = await ATSMSEndpointCertificate.generate(
        "did:test:two",
        "two.acme.xyz",
        "two@two.acme.xyz",
      );

      // Create one without private key
      const cert2NoKey = ATSMSEndpointCertificate.fromPEM(
        cert2WithKey.certificatePEM,
      );

      const testMessage = new TextEncoder().encode("Mixed recipients");

      // Encrypt for both (one with key, one without)
      const encryptedContent = await encryptMessageOAEP(testMessage, [
        cert1WithKey,
        cert2NoKey,
      ]);

      // Both original certificates with keys should be able to decrypt
      const decrypted1 = await decryptMessageOAEP(
        encryptedContent,
        cert1WithKey,
      );
      const decrypted2 = await decryptMessageOAEP(
        encryptedContent,
        cert2WithKey,
      );

      expect(new TextDecoder().decode(decrypted1)).toBe("Mixed recipients");
      expect(new TextDecoder().decode(decrypted2)).toBe("Mixed recipients");
    });
  });
});
