/**
 * Tests for ECDH encryption/decryption functions (P-256)
 */

import { describe, expect, test } from "bun:test";

import { ATSMSEndpointCertificate } from "../lib/certificates/index.js";
import {
  decryptAndVerifyMessageSignature,
  encryptMessage,
  signMessage,
} from "../lib/crypto.js";
import { decryptMessageOAEP, encryptMessageOAEP } from "../lib/crypto-oaep.js";

describe("P-256 ECDH Encryption/Decryption", () => {
  test("should encrypt and decrypt message with P-256 certificate", async () => {
    const endpointCert = await ATSMSEndpointCertificate.generate(
      "did:test:123",
      "test.acme.xyz",
      "test.acme.xyz",
    );

    const testMessage =
      "Hello, World! This is a test message for P-256 ECDH encryption.";
    const messageBytes = new TextEncoder().encode(testMessage);

    const encryptedContent = await encryptMessageOAEP(messageBytes, [
      endpointCert,
    ]);

    expect(encryptedContent).not.toEqual(messageBytes);
    expect(encryptedContent.length).toBeGreaterThan(0);

    const decryptedContent = await decryptMessageOAEP(
      encryptedContent,
      endpointCert,
    );
    const decryptedMessage = new TextDecoder().decode(decryptedContent);

    expect(decryptedMessage).toBe(testMessage);
  });

  test("should handle multiple P-256 recipients", async () => {
    const recipient1 = await ATSMSEndpointCertificate.generate(
      "did:test:recipient1",
      "recipient1.acme.xyz",
      "recipient1.acme.xyz",
    );
    const recipient2 = await ATSMSEndpointCertificate.generate(
      "did:test:recipient2",
      "recipient2.acme.xyz",
      "recipient2.acme.xyz",
    );

    const testMessage = "Multi-recipient P-256 test message";
    const messageBytes = new TextEncoder().encode(testMessage);

    const encryptedContent = await encryptMessageOAEP(messageBytes, [
      recipient1,
      recipient2,
    ]);

    const decrypted1 = await decryptMessageOAEP(encryptedContent, recipient1);
    const decrypted2 = await decryptMessageOAEP(encryptedContent, recipient2);

    expect(new TextDecoder().decode(decrypted1)).toBe(testMessage);
    expect(new TextDecoder().decode(decrypted2)).toBe(testMessage);
  });

  test("should fail to decrypt P-256 message without private key", async () => {
    const certWithKey = await ATSMSEndpointCertificate.generate(
      "did:test:123",
      "test.acme.xyz",
      "test.acme.xyz",
    );

    const certNoKey = ATSMSEndpointCertificate.fromPEM(
      certWithKey.certificatePEM,
    );

    const testMessage = "Test message";
    const messageBytes = new TextEncoder().encode(testMessage);

    const encryptedContent = await encryptMessageOAEP(messageBytes, [
      certWithKey,
    ]);

    await expect(
      decryptMessageOAEP(encryptedContent, certNoKey),
    ).rejects.toThrow("Certificate must contain private key for decryption");
  });

  test("should fail to decrypt P-256 message with wrong certificate", async () => {
    const rightCert = await ATSMSEndpointCertificate.generate(
      "did:test:right",
      "right.acme.xyz",
      "right.acme.xyz",
    );
    const wrongCert = await ATSMSEndpointCertificate.generate(
      "did:test:wrong",
      "wrong.acme.xyz",
      "wrong.acme.xyz",
    );

    const testMessage = "Secret message";
    const messageBytes = new TextEncoder().encode(testMessage);

    const encryptedContent = await encryptMessageOAEP(messageBytes, [
      rightCert,
    ]);

    await expect(
      decryptMessageOAEP(encryptedContent, wrongCert),
    ).rejects.toThrow();
  });

  test("should handle binary data with P-256", async () => {
    const endpointCert = await ATSMSEndpointCertificate.generate(
      "did:test:123",
      "test.acme.xyz",
      "test.acme.xyz",
    );

    const binaryData = new Uint8Array([0x00, 0x01, 0x02, 0xff, 0xfe, 0xfd]);

    const encryptedContent = await encryptMessageOAEP(binaryData, [
      endpointCert,
    ]);
    const decryptedContent = await decryptMessageOAEP(
      encryptedContent,
      endpointCert,
    );

    expect(decryptedContent).toEqual(binaryData);
  });

  test("should handle empty message with P-256", async () => {
    const endpointCert = await ATSMSEndpointCertificate.generate(
      "did:test:123",
      "test.acme.xyz",
      "test.acme.xyz",
    );

    const emptyMessage = new Uint8Array(0);

    const encryptedContent = await encryptMessageOAEP(emptyMessage, [
      endpointCert,
    ]);
    const decryptedContent = await decryptMessageOAEP(
      encryptedContent,
      endpointCert,
    );

    expect(decryptedContent.length).toBe(0);
  });

  test("should produce different ciphertext for same message with P-256", async () => {
    const endpointCert = await ATSMSEndpointCertificate.generate(
      "did:test:123",
      "test.acme.xyz",
      "test.acme.xyz",
    );

    const testMessage = new TextEncoder().encode("Same message");

    const encrypted1 = await encryptMessageOAEP(testMessage, [endpointCert]);
    const encrypted2 = await encryptMessageOAEP(testMessage, [endpointCert]);

    // Due to ECDH ephemeral keys, ciphertexts should be different
    expect(encrypted1).not.toEqual(encrypted2);

    const decrypted1 = await decryptMessageOAEP(encrypted1, endpointCert);
    const decrypted2 = await decryptMessageOAEP(encrypted2, endpointCert);

    expect(decrypted1).toEqual(decrypted2);
  });
});

describe("Mixed RSA and P-256 Encryption", () => {
  test("should encrypt for mixed RSA and P-256 recipients", async () => {
    const rsaCert = await ATSMSEndpointCertificate.generate(
      "did:test:rsa",
      "rsa.acme.xyz",
      "rsa.acme.xyz",
    );
    const p256Cert = await ATSMSEndpointCertificate.generate(
      "did:test:p256",
      "p256.acme.xyz",
      "p256.acme.xyz",
    );

    const testMessage = "Mixed RSA and P-256 recipients";
    const messageBytes = new TextEncoder().encode(testMessage);

    const encryptedContent = await encryptMessageOAEP(messageBytes, [
      rsaCert,
      p256Cert,
    ]);

    // RSA recipient should be able to decrypt
    const decryptedRSA = await decryptMessageOAEP(encryptedContent, rsaCert);
    expect(new TextDecoder().decode(decryptedRSA)).toBe(testMessage);

    // P-256 recipient should be able to decrypt
    const decryptedP256 = await decryptMessageOAEP(encryptedContent, p256Cert);
    expect(new TextDecoder().decode(decryptedP256)).toBe(testMessage);
  });

  test("should work with P-256 certificate without private key for encryption", async () => {
    const certWithKey = await ATSMSEndpointCertificate.generate(
      "did:test:123",
      "test.acme.xyz",
      "test.acme.xyz",
    );

    const certNoKey = ATSMSEndpointCertificate.fromPEM(
      certWithKey.certificatePEM,
    );

    const testMessage = new TextEncoder().encode("Test message");

    // Should be able to encrypt with certificate that has no private key
    const encryptedContent = await encryptMessageOAEP(testMessage, [certNoKey]);
    expect(encryptedContent.length).toBeGreaterThan(0);

    // Should be able to decrypt with the certificate that has the private key
    const decryptedContent = await decryptMessageOAEP(
      encryptedContent,
      certWithKey,
    );
    expect(new TextDecoder().decode(decryptedContent)).toBe("Test message");
  });
});

describe("P-256 Signing and Encryption Full Flow", () => {
  test("should sign with P-256, encrypt for P-256, and decrypt/verify", async () => {
    const senderCert = await ATSMSEndpointCertificate.generate(
      "did:test:sender",
      "sender.acme.xyz",
      "sender.acme.xyz",
    );
    const recipientCert = await ATSMSEndpointCertificate.generate(
      "did:test:recipient",
      "recipient.acme.xyz",
      "recipient.acme.xyz",
    );

    const message = "Hello from P-256 sender!";

    // Sign with sender cert
    const signedContent = await signMessage(message, senderCert);
    expect(signedContent.length).toBeGreaterThan(0);

    // Encrypt for recipient
    const encryptedContent = await encryptMessage(signedContent, [
      recipientCert,
    ]);
    expect(encryptedContent.length).toBeGreaterThan(0);

    // Decrypt and verify
    const result = await decryptAndVerifyMessageSignature(
      encryptedContent,
      recipientCert,
    );

    expect(result.messageSigner).toBeDefined();
    expect(result.messageSigner.commonName).toBe("did:test:sender");
    expect(new TextDecoder().decode(result.decryptedContent)).toBe(message);
  });

  test("should sign with RSA, encrypt for P-256, and decrypt/verify", async () => {
    const senderCert = await ATSMSEndpointCertificate.generate(
      "did:test:sender",
      "sender.acme.xyz",
      "sender.acme.xyz",
    );
    const recipientCert = await ATSMSEndpointCertificate.generate(
      "did:test:recipient",
      "recipient.acme.xyz",
      "recipient.acme.xyz",
    );

    const message = "Hello from RSA sender to P-256 recipient!";

    const signedContent = await signMessage(message, senderCert);
    const encryptedContent = await encryptMessage(signedContent, [
      recipientCert,
    ]);
    const result = await decryptAndVerifyMessageSignature(
      encryptedContent,
      recipientCert,
    );

    expect(result.messageSigner.commonName).toBe("did:test:sender");
    expect(new TextDecoder().decode(result.decryptedContent)).toBe(message);
  });

  test("should sign with P-256, encrypt for RSA, and decrypt/verify", async () => {
    const senderCert = await ATSMSEndpointCertificate.generate(
      "did:test:sender",
      "sender.acme.xyz",
      "sender.acme.xyz",
    );
    const recipientCert = await ATSMSEndpointCertificate.generate(
      "did:test:recipient",
      "recipient.acme.xyz",
      "recipient.acme.xyz",
    );

    const message = "Hello from P-256 sender to RSA recipient!";

    const signedContent = await signMessage(message, senderCert);
    const encryptedContent = await encryptMessage(signedContent, [
      recipientCert,
    ]);
    const result = await decryptAndVerifyMessageSignature(
      encryptedContent,
      recipientCert,
    );

    expect(result.messageSigner.commonName).toBe("did:test:sender");
    expect(new TextDecoder().decode(result.decryptedContent)).toBe(message);
  });

  test("should sign with RSA, encrypt for mixed recipients, and decrypt/verify", async () => {
    const senderCert = await ATSMSEndpointCertificate.generate(
      "did:test:sender",
      "sender.acme.xyz",
      "sender.acme.xyz",
    );
    const rsaRecipient = await ATSMSEndpointCertificate.generate(
      "did:test:rsa-recipient",
      "rsa-recipient.acme.xyz",
      "rsa.recipient.acme.xyz",
    );
    const p256Recipient = await ATSMSEndpointCertificate.generate(
      "did:test:p256-recipient",
      "p256-recipient.acme.xyz",
      "p256.recipient.acme.xyz",
    );

    const message = "Hello to both RSA and P-256 recipients!";

    const signedContent = await signMessage(message, senderCert);
    const encryptedContent = await encryptMessage(signedContent, [
      rsaRecipient,
      p256Recipient,
    ]);

    // RSA recipient can decrypt
    const rsaResult = await decryptAndVerifyMessageSignature(
      encryptedContent,
      rsaRecipient,
    );
    expect(rsaResult.messageSigner.commonName).toBe("did:test:sender");
    expect(new TextDecoder().decode(rsaResult.decryptedContent)).toBe(message);

    // P-256 recipient can decrypt
    const p256Result = await decryptAndVerifyMessageSignature(
      encryptedContent,
      p256Recipient,
    );
    expect(p256Result.messageSigner.commonName).toBe("did:test:sender");
    expect(new TextDecoder().decode(p256Result.decryptedContent)).toBe(message);
  });

  test("should reject message with tampered signed content", async () => {
    const senderCert = await ATSMSEndpointCertificate.generate(
      "did:test:sender",
      "sender.acme.xyz",
      "sender.acme.xyz",
    );
    const recipientCert = await ATSMSEndpointCertificate.generate(
      "did:test:recipient",
      "recipient.acme.xyz",
      "recipient.acme.xyz",
    );

    // Sign a message normally
    const signedContent = await signMessage(
      "Original message",
      senderCert,
    );

    // Tamper with the signed content by flipping bytes near the end
    // (the content portion of the SignedData)
    const tampered = new Uint8Array(signedContent);
    const offset = tampered.length - 20;
    tampered[offset] ^= 0xff;
    tampered[offset + 1] ^= 0xff;

    // Encrypt the tampered signed content for the recipient
    const encryptedContent = await encryptMessage(tampered, [recipientCert]);

    // Decryption should succeed but signature verification should fail
    await expect(
      decryptAndVerifyMessageSignature(encryptedContent, recipientCert),
    ).rejects.toThrow();
  });
});
