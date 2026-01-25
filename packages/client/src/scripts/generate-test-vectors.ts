#!/usr/bin/env bun
/**
 * Generate test vectors for AT-SMS encryption/decryption testing
 *
 * These vectors can be used by client libraries in any language to verify
 * their S/MIME encryption implementation is compatible with the AT-SMS protocol.
 *
 * Generates test vectors for both RSA-2048 and P-256 ECDSA/ECDH algorithms.
 *
 * Usage: bun src/scripts/generate-test-vectors.ts > src/tests/fixtures/test-vectors.json
 */

import {
  type ATSMSAnyEndpointCertificate,
  type ATSMSCertificateAlgorithm,
  generateEndpointCertificate,
} from "../lib/certificates/index.js";
import {
  decryptAndVerifyMessageSignature,
  encryptMessage,
  signMessage,
} from "../lib/crypto.js";
import { createMessagePayload, createTextContent } from "../lib/messages.js";

interface ParticipantVectors {
  did: string;
  domain: string;
  email: string;
  algorithm: ATSMSCertificateAlgorithm;
  endpointCertificate: {
    pem: string;
    privateKeyPem: string;
    serialNumber: string;
    notBefore: string;
    notAfter: string;
  };
}

interface CryptoVectors {
  _comment: string;
  signedMessage: {
    _description: string;
    base64: string;
    algorithm: string;
    format: string;
  };
  encryptedMessage: {
    _description: string;
    base64: string;
    keyEncryptionAlgorithm: string;
    contentEncryptionAlgorithm: string;
    format: string;
  };
}

async function generateParticipant(
  role: string,
  did: string,
  domain: string,
  algorithm: ATSMSCertificateAlgorithm,
): Promise<{ participant: ParticipantVectors; cert: ATSMSAnyEndpointCertificate }> {
  const email = `${role}@atsms-test.example`;

  console.error(`Generating ${algorithm} certificate for ${role}...`);
  const cert = await generateEndpointCertificate(algorithm, did, domain, email);

  return {
    participant: {
      did,
      domain,
      email,
      algorithm,
      endpointCertificate: {
        pem: cert.certificatePEM,
        privateKeyPem: cert.certificatePrivateKeyPEM!,
        serialNumber: cert.serialNumber,
        notBefore: cert.notBefore.toISOString(),
        notAfter: cert.notAfter.toISOString(),
      },
    },
    cert,
  };
}

async function generateCryptoVectors(
  senderCert: ATSMSAnyEndpointCertificate,
  receiverCert: ATSMSAnyEndpointCertificate,
  messagePayloadJson: string,
  senderAlgorithm: ATSMSCertificateAlgorithm,
  receiverAlgorithm: ATSMSCertificateAlgorithm,
): Promise<CryptoVectors> {
  // Sign message
  const signedMessage = await signMessage(messagePayloadJson, senderCert);

  // Encrypt message
  const encryptedMessage = await encryptMessage(signedMessage, [receiverCert]);

  // Verify decryption works
  const decrypted = await decryptAndVerifyMessageSignature(
    encryptedMessage,
    receiverCert,
  );
  const decryptedPayload = JSON.parse(
    new TextDecoder().decode(decrypted.decryptedContent),
  );
  const originalPayload = JSON.parse(messagePayloadJson);

  if (decryptedPayload.id !== originalPayload.id) {
    throw new Error(
      `Verification failed for ${senderAlgorithm}->${receiverAlgorithm}: message ID mismatch`,
    );
  }

  const signatureAlgorithm = senderAlgorithm === "P256" ? "ECDSA-SHA256" : "RSA-SHA256";
  const keyEncryptionAlgorithm =
    receiverAlgorithm === "P256"
      ? "ECDH-ES with AES-256 key wrap"
      : "RSA-OAEP with SHA-256";

  return {
    _comment: `Sender: ${senderAlgorithm}, Receiver: ${receiverAlgorithm}`,
    signedMessage: {
      _description: "PKCS#7 SignedData containing the message payload, signed by sender",
      base64: Buffer.from(signedMessage).toString("base64"),
      algorithm: signatureAlgorithm,
      format: "PKCS#7 SignedData (DER encoded)",
    },
    encryptedMessage: {
      _description:
        "PKCS#7 EnvelopedData containing the signed message, encrypted for receiver",
      base64: Buffer.from(encryptedMessage).toString("base64"),
      keyEncryptionAlgorithm,
      contentEncryptionAlgorithm: "AES-256-CBC",
      format: "PKCS#7 EnvelopedData (DER encoded)",
    },
  };
}

async function generateTestVectors() {
  console.error("Generating test vectors...");

  // === PARTICIPANT SETUP ===
  const senderDid = "did:plc:sender123456789";
  const senderDomain = "sender.test";
  const receiverDid = "did:plc:receiver987654321";
  const receiverDomain = "receiver.test";

  // Generate RSA certificates
  const { participant: rsaSender, cert: rsaSenderCert } = await generateParticipant(
    "sender-rsa",
    senderDid,
    senderDomain,
    "RSA",
  );
  const { participant: rsaReceiver, cert: rsaReceiverCert } = await generateParticipant(
    "receiver-rsa",
    receiverDid,
    receiverDomain,
    "RSA",
  );

  // Generate P-256 certificates
  const { participant: p256Sender, cert: p256SenderCert } = await generateParticipant(
    "sender-p256",
    senderDid,
    senderDomain,
    "P256",
  );
  const { participant: p256Receiver, cert: p256ReceiverCert } = await generateParticipant(
    "receiver-p256",
    receiverDid,
    receiverDomain,
    "P256",
  );

  // === MESSAGE CREATION ===
  const plainTextMessage =
    "Hello, this is a test message for AT-SMS encryption verification!";
  const messageContent = createTextContent(plainTextMessage);

  const messagePayload = createMessagePayload(
    senderDid,
    [receiverDid],
    messageContent,
    "atsms/text",
    "test-conversation-123",
  );

  const messagePayloadJson = JSON.stringify(messagePayload);

  // === GENERATE CRYPTO VECTORS FOR ALL COMBINATIONS ===
  console.error("Generating cryptographic test vectors...");

  // RSA -> RSA
  const rsaToRsa = await generateCryptoVectors(
    rsaSenderCert,
    rsaReceiverCert,
    messagePayloadJson,
    "RSA",
    "RSA",
  );
  console.error("  RSA -> RSA: OK");

  // P256 -> P256
  const p256ToP256 = await generateCryptoVectors(
    p256SenderCert,
    p256ReceiverCert,
    messagePayloadJson,
    "P256",
    "P256",
  );
  console.error("  P256 -> P256: OK");

  // RSA -> P256 (mixed: RSA signature, ECDH encryption)
  const rsaToP256 = await generateCryptoVectors(
    rsaSenderCert,
    p256ReceiverCert,
    messagePayloadJson,
    "RSA",
    "P256",
  );
  console.error("  RSA -> P256: OK");

  // P256 -> RSA (mixed: ECDSA signature, RSA-OAEP encryption)
  const p256ToRsa = await generateCryptoVectors(
    p256SenderCert,
    rsaReceiverCert,
    messagePayloadJson,
    "P256",
    "RSA",
  );
  console.error("  P256 -> RSA: OK");

  // === BUILD TEST VECTOR OUTPUT ===
  const testVectors = {
    _comment: "AT-SMS Test Vectors for S/MIME Encryption/Decryption",
    _generated: new Date().toISOString(),
    _version: "2.0",
    _description: [
      "These test vectors verify S/MIME encryption compatibility for AT-SMS.",
      "Version 2.0 adds P-256 ECDSA/ECDH support alongside RSA-2048.",
      "Endpoint certificates are self-signed (no root CA).",
      "All combinations of RSA and P-256 sender/receiver are tested.",
    ],

    participants: {
      rsa: {
        sender: rsaSender,
        receiver: rsaReceiver,
      },
      p256: {
        sender: p256Sender,
        receiver: p256Receiver,
      },
    },

    message: {
      plainText: plainTextMessage,
      contentType: "atsms/text",
      content: messageContent,
      payloadJson: messagePayloadJson,
      payload: messagePayload,
    },

    cryptographic: {
      rsaToRsa,
      p256ToP256,
      rsaToP256,
      p256ToRsa,
    },

    algorithms: {
      rsa: {
        endpointCertificate: {
          keyType: "RSA",
          keySize: 2048,
          signatureAlgorithm: "RSA-PSS with SHA-256 (self-signed)",
          usage: "Message signing and encryption",
        },
        messageSignature: {
          algorithm: "RSA-SHA256",
          format: "PKCS#7 SignedData",
          hashAlgorithm: "SHA-256",
        },
        messageEncryption: {
          keyEncryption: "RSA-OAEP",
          oaepHash: "SHA-256",
          contentEncryption: "AES-256-CBC",
          format: "PKCS#7 EnvelopedData (KeyTransRecipientInfo)",
        },
      },
      p256: {
        endpointCertificate: {
          keyType: "EC",
          curve: "P-256 (secp256r1/prime256v1)",
          signatureAlgorithm: "ECDSA with SHA-256 (self-signed)",
          usage: "Message signing and encryption (via ECDH)",
        },
        messageSignature: {
          algorithm: "ECDSA-SHA256",
          format: "PKCS#7 SignedData",
          hashAlgorithm: "SHA-256",
        },
        messageEncryption: {
          keyEncryption: "ECDH-ES (Ephemeral-Static)",
          keyDerivation: "HKDF with SHA-256",
          keyWrap: "AES-256 key wrap",
          contentEncryption: "AES-256-CBC",
          format: "PKCS#7 EnvelopedData (KeyAgreeRecipientInfo)",
        },
      },
    },

    testCases: [
      {
        name: "rsa_decrypt_and_verify",
        description:
          "Decrypt RSA-encrypted message and verify RSA signature (RSA -> RSA)",
        input: {
          encryptedMessage: "cryptographic.rsaToRsa.encryptedMessage.base64",
          receiverPrivateKey: "participants.rsa.receiver.endpointCertificate.privateKeyPem",
          receiverCertificate: "participants.rsa.receiver.endpointCertificate.pem",
        },
        expectedOutput: {
          signerCertificate: "participants.rsa.sender.endpointCertificate.pem",
          decryptedContent: "message.payloadJson",
        },
      },
      {
        name: "p256_decrypt_and_verify",
        description:
          "Decrypt ECDH-encrypted message and verify ECDSA signature (P256 -> P256)",
        input: {
          encryptedMessage: "cryptographic.p256ToP256.encryptedMessage.base64",
          receiverPrivateKey:
            "participants.p256.receiver.endpointCertificate.privateKeyPem",
          receiverCertificate: "participants.p256.receiver.endpointCertificate.pem",
        },
        expectedOutput: {
          signerCertificate: "participants.p256.sender.endpointCertificate.pem",
          decryptedContent: "message.payloadJson",
        },
      },
      {
        name: "mixed_rsa_to_p256",
        description:
          "RSA-signed message encrypted for P256 recipient (RSA signature, ECDH encryption)",
        input: {
          encryptedMessage: "cryptographic.rsaToP256.encryptedMessage.base64",
          receiverPrivateKey:
            "participants.p256.receiver.endpointCertificate.privateKeyPem",
          receiverCertificate: "participants.p256.receiver.endpointCertificate.pem",
        },
        expectedOutput: {
          signerCertificate: "participants.rsa.sender.endpointCertificate.pem",
          decryptedContent: "message.payloadJson",
        },
      },
      {
        name: "mixed_p256_to_rsa",
        description:
          "P256-signed message encrypted for RSA recipient (ECDSA signature, RSA-OAEP encryption)",
        input: {
          encryptedMessage: "cryptographic.p256ToRsa.encryptedMessage.base64",
          receiverPrivateKey: "participants.rsa.receiver.endpointCertificate.privateKeyPem",
          receiverCertificate: "participants.rsa.receiver.endpointCertificate.pem",
        },
        expectedOutput: {
          signerCertificate: "participants.p256.sender.endpointCertificate.pem",
          decryptedContent: "message.payloadJson",
        },
      },
      {
        name: "rsa_sign_message",
        description: "Sign a message payload using RSA private key",
        input: {
          payload: "message.payloadJson",
          senderPrivateKey: "participants.rsa.sender.endpointCertificate.privateKeyPem",
          senderCertificate: "participants.rsa.sender.endpointCertificate.pem",
        },
        expectedOutput: {
          signedMessage: "cryptographic.rsaToRsa.signedMessage.base64",
        },
        note: "Signature includes timestamp so output may differ, but must be verifiable",
      },
      {
        name: "p256_sign_message",
        description: "Sign a message payload using P-256 ECDSA private key",
        input: {
          payload: "message.payloadJson",
          senderPrivateKey: "participants.p256.sender.endpointCertificate.privateKeyPem",
          senderCertificate: "participants.p256.sender.endpointCertificate.pem",
        },
        expectedOutput: {
          signedMessage: "cryptographic.p256ToP256.signedMessage.base64",
        },
        note: "Signature includes timestamp so output may differ, but must be verifiable",
      },
      {
        name: "rsa_encrypt_for_recipient",
        description: "Encrypt signed message for RSA receiver using RSA-OAEP",
        input: {
          signedMessage: "cryptographic.rsaToRsa.signedMessage.base64",
          receiverCertificate: "participants.rsa.receiver.endpointCertificate.pem",
        },
        expectedOutput: {
          encryptedMessage: "cryptographic.rsaToRsa.encryptedMessage.base64",
        },
        note: "Encryption uses random IV so output will differ, but must be decryptable",
      },
      {
        name: "p256_encrypt_for_recipient",
        description: "Encrypt signed message for P-256 receiver using ECDH",
        input: {
          signedMessage: "cryptographic.p256ToP256.signedMessage.base64",
          receiverCertificate: "participants.p256.receiver.endpointCertificate.pem",
        },
        expectedOutput: {
          encryptedMessage: "cryptographic.p256ToP256.encryptedMessage.base64",
        },
        note: "Encryption uses ephemeral key so output will differ, but must be decryptable",
      },
    ],

    verification: {
      _comment: "Expected results after decryption and signature verification",
      rsaToRsa: {
        expectedSignerDid: senderDid,
        expectedSignerEmail: rsaSender.email,
        expectedSignerCertSerial: rsaSender.endpointCertificate.serialNumber,
      },
      p256ToP256: {
        expectedSignerDid: senderDid,
        expectedSignerEmail: p256Sender.email,
        expectedSignerCertSerial: p256Sender.endpointCertificate.serialNumber,
      },
      rsaToP256: {
        expectedSignerDid: senderDid,
        expectedSignerEmail: rsaSender.email,
        expectedSignerCertSerial: rsaSender.endpointCertificate.serialNumber,
      },
      p256ToRsa: {
        expectedSignerDid: senderDid,
        expectedSignerEmail: p256Sender.email,
        expectedSignerCertSerial: p256Sender.endpointCertificate.serialNumber,
      },
      expectedContent: messageContent,
      expectedPayload: messagePayload,
    },
  };

  return testVectors;
}

// Run and output
generateTestVectors()
  .then((vectors) => {
    console.log(JSON.stringify(vectors, null, 2));
    console.error("Test vectors generated successfully!");
  })
  .catch((error) => {
    console.error("Failed to generate test vectors:", error);
    process.exit(1);
  });
