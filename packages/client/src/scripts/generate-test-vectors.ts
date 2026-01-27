#!/usr/bin/env bun
/**
 * Generate test vectors for AT-SMS encryption/decryption testing
 *
 * These vectors can be used by client libraries in any language to verify
 * their S/MIME encryption implementation is compatible with the AT-SMS protocol.
 *
 * Generates test vectors for both RSA-2048 and P-256 ECDSA/ECDH algorithms.
 * Includes all intermediate cryptographic values for step-by-step verification.
 *
 * Usage: bun src/scripts/generate-test-vectors.ts > src/tests/fixtures/test-vectors.json
 */

import * as asn1js from "asn1js";
import * as pkijs from "pkijs";
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

interface ECDHIntermediateValues {
  _description: string;
  ephemeralPublicKey: {
    _description: string;
    x: string; // hex
    y: string; // hex
    uncompressed: string; // hex (04 || x || y)
  };
  ukm: {
    _description: string;
    hex: string;
    base64: string;
  };
  recipientIdentifier: {
    _description: string;
    value: string; // hex - serial number or subject key identifier
  };
  wrappedKey: {
    _description: string;
    hex: string;
    base64: string;
  };
  contentEncryption: {
    iv: string; // hex
    algorithm: string;
  };
}

interface RSAIntermediateValues {
  _description: string;
  recipientIdentifier: {
    _description: string;
    issuerCN: string;
    serialNumber: string; // hex
  };
  encryptedKey: {
    _description: string;
    hex: string;
    base64: string;
  };
  contentEncryption: {
    iv: string; // hex
    algorithm: string;
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
  intermediateValues?: ECDHIntermediateValues | RSAIntermediateValues;
}

/**
 * Extract intermediate cryptographic values from an encrypted envelope
 * This allows other implementations to verify their encryption logic step-by-step
 */
function extractIntermediateValues(
  encryptedBytes: Uint8Array,
  receiverAlgorithm: ATSMSCertificateAlgorithm,
): ECDHIntermediateValues | RSAIntermediateValues {
  // Parse ContentInfo
  const contentInfo = asn1js.fromBER(encryptedBytes.buffer as ArrayBuffer);
  const cmsContent = new pkijs.ContentInfo({ schema: contentInfo.result });
  const envelopedData = new pkijs.EnvelopedData({ schema: cmsContent.content });

  // Get the IV from encryptedContentInfo
  const encContentInfo = envelopedData.encryptedContentInfo;
  const contentEncAlg = encContentInfo.contentEncryptionAlgorithm;
  const ivOctetString = contentEncAlg.algorithmParams as asn1js.OctetString;
  const iv = Buffer.from(ivOctetString.valueBlock.valueHexView).toString("hex");

  // Get the first recipient info
  const recipientInfo = envelopedData.recipientInfos[0];

  if (receiverAlgorithm === "P256") {
    // ECDH - KeyAgreeRecipientInfo (variant 2)
    const kari = recipientInfo.value as pkijs.KeyAgreeRecipientInfo;

    // Extract ephemeral public key from originator
    const originator = kari.originator;
    const originatorKey = originator.value as pkijs.OriginatorPublicKeyInfo;
    const publicKeyBits = originatorKey.publicKey.valueBlock.valueHexView;

    // The public key is in uncompressed format: 04 || x || y
    const uncompressed = Buffer.from(publicKeyBits).toString("hex");
    const x = uncompressed.slice(2, 66); // 32 bytes = 64 hex chars
    const y = uncompressed.slice(66, 130); // 32 bytes = 64 hex chars

    // Extract UKM (User Keying Material)
    const ukmValue = kari.ukm!.valueBlock.valueHexView;
    const ukmHex = Buffer.from(ukmValue).toString("hex");
    const ukmBase64 = Buffer.from(ukmValue).toString("base64");

    // Extract recipient identifier and wrapped key
    // pkijs structure: kari.recipientEncryptedKeys.encryptedKeys[0]
    const recipientEncKeysObj = kari.recipientEncryptedKeys as any;
    const recipientEncKey = recipientEncKeysObj.encryptedKeys[0];

    // Get recipient identifier - could be IssuerAndSerialNumber or RecipientKeyIdentifier
    let recipientIdInfo = "";
    if (recipientEncKey.rid) {
      const rid = recipientEncKey.rid;
      if (rid.serialNumber) {
        // IssuerAndSerialNumber
        recipientIdInfo = Buffer.from(
          rid.serialNumber.valueBlock.valueHexView,
        ).toString("hex");
      } else if (rid.subjectKeyIdentifier) {
        // RecipientKeyIdentifier
        recipientIdInfo = Buffer.from(
          rid.subjectKeyIdentifier.valueBlock.valueHexView,
        ).toString("hex");
      }
    }

    // Wrapped key (encrypted CEK)
    const wrappedKeyBytes = recipientEncKey.encryptedKey.valueBlock.valueHexView;
    const wrappedKeyHex = Buffer.from(wrappedKeyBytes).toString("hex");
    const wrappedKeyBase64 = Buffer.from(wrappedKeyBytes).toString("base64");

    return {
      _description:
        "ECDH intermediate values for step-by-step verification. Use these to verify your ECDH key agreement and key derivation.",
      ephemeralPublicKey: {
        _description:
          "Ephemeral public key generated for this encryption (P-256 uncompressed point)",
        x,
        y,
        uncompressed,
      },
      ukm: {
        _description:
          "User Keying Material - random bytes used in key derivation function",
        hex: ukmHex,
        base64: ukmBase64,
      },
      recipientIdentifier: {
        _description: "Identifies which recipient certificate this is encrypted for",
        value: recipientIdInfo,
      },
      wrappedKey: {
        _description:
          "Content Encryption Key (CEK) wrapped with the derived Key Encryption Key (KEK) using AES-256 key wrap",
        hex: wrappedKeyHex,
        base64: wrappedKeyBase64,
      },
      contentEncryption: {
        iv,
        algorithm: "AES-256-CBC",
      },
    };
  } else {
    // RSA - KeyTransRecipientInfo (variant 1)
    const ktri = recipientInfo.value as pkijs.KeyTransRecipientInfo;

    // Extract recipient identifier (issuer and serial)
    const rid = ktri.rid as pkijs.IssuerAndSerialNumber;
    const issuer = rid.issuer;

    // Get CN from issuer
    let issuerCN = "";
    for (const rdn of issuer.typesAndValues) {
      if (rdn.type === "2.5.4.3") {
        // commonName OID
        issuerCN = rdn.value.valueBlock.value;
        break;
      }
    }

    const serialNumber = Buffer.from(
      rid.serialNumber.valueBlock.valueHexView,
    ).toString("hex");

    // Encrypted key
    const encryptedKeyBytes = ktri.encryptedKey.valueBlock.valueHexView;
    const encryptedKeyHex = Buffer.from(encryptedKeyBytes).toString("hex");
    const encryptedKeyBase64 = Buffer.from(encryptedKeyBytes).toString("base64");

    return {
      _description:
        "RSA-OAEP intermediate values for step-by-step verification.",
      recipientIdentifier: {
        _description: "Identifies which recipient certificate this is encrypted for",
        issuerCN,
        serialNumber,
      },
      encryptedKey: {
        _description:
          "Content Encryption Key (CEK) encrypted with recipient's RSA public key using RSA-OAEP",
        hex: encryptedKeyHex,
        base64: encryptedKeyBase64,
      },
      contentEncryption: {
        iv,
        algorithm: "AES-256-CBC",
      },
    };
  }
}

const TEST_EMAIL_DOMAIN = "atsms-test.example";

async function generateParticipant(
  role: string,
  did: string,
  domain: string,
  algorithm: ATSMSCertificateAlgorithm,
): Promise<{ participant: ParticipantVectors; cert: ATSMSAnyEndpointCertificate }> {
  console.error(`Generating ${algorithm} certificate for ${role}...`);
  const cert = await generateEndpointCertificate(algorithm, did, domain, TEST_EMAIL_DOMAIN);

  // Get the computed email from the certificate
  const email = cert.email!;

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

  // Extract intermediate values for step-by-step verification
  const intermediateValues = extractIntermediateValues(
    encryptedMessage,
    receiverAlgorithm,
  );

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
    intermediateValues,
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
          keyDerivation: "dhSinglePass-stdDH-sha256kdf-scheme (RFC 5753)",
          keyWrap: "AES-256 key wrap (RFC 3394)",
          contentEncryption: "AES-256-CBC",
          format: "PKCS#7 EnvelopedData (KeyAgreeRecipientInfo)",
        },
      },
    },

    ecdhKeyDerivation: {
      _description:
        "Step-by-step ECDH key derivation process for P-256 encryption (RFC 5753)",
      steps: [
        "1. Generate ephemeral P-256 key pair (d_e, Q_e) for this encryption",
        "2. Generate random UKM (User Keying Material) - typically 64 bytes",
        "3. Perform ECDH: SharedSecret = d_e * Q_recipient (recipient's public key)",
        "4. Derive KEK using KDF: KEK = KDF(SharedSecret, keyEncryptionAlgorithm, ukm)",
        "5. Generate random CEK (Content Encryption Key) for AES-256-CBC",
        "6. Wrap CEK with KEK using AES-256 key wrap: WrappedCEK = AES-WRAP(KEK, CEK)",
        "7. Encrypt content: Ciphertext = AES-256-CBC(CEK, IV, SignedMessage)",
      ],
      kdfDetails: {
        algorithm: "dhSinglePass-stdDH-sha256kdf-scheme",
        oid: "1.3.132.1.11.1",
        input: "SharedInfo = AlgorithmIdentifier || [ukm]",
        output: "256-bit KEK for AES key wrap",
      },
      cmsStructure: {
        envelopedDataVersion: 2,
        recipientInfoType: "KeyAgreeRecipientInfo [1]",
        kariVersion: 3,
        originatorType: "originatorKey [1] (ephemeral public key)",
        ukmRequired: true,
        recipientIdentifier: "issuerAndSerialNumber (SEQUENCE, no tag) - NOT rKeyId",
      },
      asn1Notes: [
        "KeyAgreeRecipientInfo uses IMPLICIT [1] tag in RecipientInfo CHOICE",
        "originatorKey uses IMPLICIT [1] tag - replaces OriginatorPublicKeyInfo SEQUENCE",
        "ukm uses EXPLICIT [1] tag",
        "For recipientIdentifier, use issuerAndSerialNumber (no tag), NOT rKeyId [0]",
        "If using rKeyId [0], it must use IMPLICIT tagging (no SEQUENCE wrapper)",
      ],
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
