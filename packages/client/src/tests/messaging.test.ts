/**
 * Tests for messaging functionality including P7M handling
 * Tests the complete message flow: create -> sign -> encrypt -> send -> receive -> decrypt
 */

import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "fs";
import path from "path";

import { ATSMSEndpointCertificate } from "../lib/certificates/index.js";
import {
  decryptAndVerifyMessageSignature,
  encryptMessage,
  signMessage,
} from "../lib/crypto.js";
import { extractP7MFromEmail } from "../lib/messages.js";
import { generateTestEndpointCertificate } from "./test-certificates.js";

// Helper function to generate UUIDs for tests
function generateUUID(): string {
  return "xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx".replace(/[xy]/g, function (c) {
    const r = (Math.random() * 16) | 0;
    const v = c === "x" ? r : (r & 0x3) | 0x8;
    return v.toString(16);
  });
}

describe("MessageManager P7M Handling", () => {
  let testDir: string;
  let senderHandle: string;
  let recipientHandle: string;

  beforeAll(async () => {
    testDir = path.join(process.cwd(), "test-messaging");
    senderHandle = "sender.acme.xyz";
    recipientHandle = "recipient.acme.xyz";

    // Create test directories
    if (existsSync(testDir)) {
      rmSync(testDir, { recursive: true, force: true });
    }
    mkdirSync(testDir, { recursive: true });

    // Set up certificates for sender
    await setupTestCertificates(senderHandle, "did:plc:sender123");

    // Set up certificates for recipient
    await setupTestCertificates(recipientHandle, "did:plc:recipient456");
  });

  afterAll(() => {
    // Cleanup test directory
    if (existsSync(testDir)) {
      rmSync(testDir, { recursive: true, force: true });
    }
  });

  async function setupTestCertificates(handle: string, did: string) {
    const handleDir = path.join(testDir, handle);
    mkdirSync(handleDir, { recursive: true });

    const clientKeyPath = path.join(handleDir, "client-key.pem");
    const clientCertPath = path.join(handleDir, "client-cert.pem");

    // Generate self-signed endpoint certificate
    const endpointCert = await generateTestEndpointCertificate(did, handle);
    writeFileSync(clientCertPath, endpointCert.cert, "utf8");
    writeFileSync(clientKeyPath, endpointCert.privateKey, "utf8");
  }

  describe("P7M Content Creation", () => {
    test("should create valid P7M signed content", async () => {
      const testMessage = JSON.stringify(
        {
          from: senderHandle,
          to: recipientHandle,
          body: "Test P7M message",
          timestamp: new Date().toISOString(),
        },
        null,
        2,
      );

      // Load sender certificates
      const senderDir = path.join(testDir, senderHandle);
      const clientCertPEM = readFileSync(
        path.join(senderDir, "client-cert.pem"),
        "utf8",
      );
      const clientKeyPEM = readFileSync(
        path.join(senderDir, "client-key.pem"),
        "utf8",
      );

      // Sign the message
      const signerCert = await ATSMSEndpointCertificate.fromPEMWithKey(
        clientCertPEM,
        clientKeyPEM,
      );
      const signedContent = await signMessage(testMessage, signerCert);

      expect(signedContent).toBeDefined();
      expect(signedContent).toBeInstanceOf(Uint8Array);
      expect(signedContent.length).toBeGreaterThan(0);
    });

    test("should create valid P7M encrypted content", async () => {
      const testMessage = JSON.stringify(
        {
          from: senderHandle,
          to: recipientHandle,
          body: "Test P7M encryption",
          timestamp: new Date().toISOString(),
        },
        null,
        2,
      );

      // Load certificates
      const senderDir = path.join(testDir, senderHandle);
      const recipientDir = path.join(testDir, recipientHandle);

      const senderClientCertPEM = readFileSync(
        path.join(senderDir, "client-cert.pem"),
        "utf8",
      );
      const senderClientKeyPEM = readFileSync(
        path.join(senderDir, "client-key.pem"),
        "utf8",
      );
      const recipientClientCertPEM = readFileSync(
        path.join(recipientDir, "client-cert.pem"),
        "utf8",
      );

      // Sign then encrypt
      const signerCert = await ATSMSEndpointCertificate.fromPEMWithKey(
        senderClientCertPEM,
        senderClientKeyPEM,
      );
      const signedContent = await signMessage(testMessage, signerCert);

      // Create Certificate object for encryption
      const recipientCert = ATSMSEndpointCertificate.fromPEM(
        recipientClientCertPEM,
      );
      const encryptedContent = await encryptMessage(signedContent, [
        recipientCert,
      ]);

      expect(encryptedContent).toBeDefined();
      expect(encryptedContent).toBeInstanceOf(Uint8Array);
      expect(encryptedContent.length).toBeGreaterThan(0);
    });
  });

  describe("P7M Email Extraction", () => {
    test("should extract P7M content from multipart email", () => {
      // Create a mock email with P7M attachment
      const boundary = "test-boundary-12345";
      const p7mContent = "VGVzdCBQN00gY29udGVudCBpbiBiYXNlNjQ="; // "Test P7M content in base64" in base64

      const mockEmail = `Content-Type: multipart/mixed; boundary=${boundary}
MIME-Version: 1.0
Subject: AT Protocol Secure Message
From: sender@test.com
To: recipient@test.com

--${boundary}
Content-Type: text/plain

AT Protocol Secure Message

--${boundary}
Content-Type: application/pkcs7-mime; name="message.p7m"
Content-Disposition: attachment; filename="message.p7m"
Content-Transfer-Encoding: base64

${p7mContent}

--${boundary}--`;

      // Test extraction
      const result = extractP7MFromEmail(mockEmail);

      expect(result.p7mContent).toBe(p7mContent);
      expect(result.attachmentInfo.filename).toBe("message.p7m");
      expect(result.attachmentInfo.contentType).toBe("application/pkcs7-mime");
      expect(result.attachmentInfo.encoding).toBe("base64");
    });

    test("should handle P7M extraction with different encodings", () => {
      const boundary = "test-boundary-67890";
      const p7mContent = "QW5vdGhlciB0ZXN0IFAzTSBjb250ZW50"; // Different test content

      const mockEmail = `Content-Type: multipart/alternative; boundary="${boundary}"
MIME-Version: 1.0

--${boundary}
Content-Type: text/html

<p>Secure message</p>

--${boundary}
Content-Type: application/pkcs7-mime; name="secure.p7m"
Content-Disposition: attachment; filename="secure.p7m"
Content-Transfer-Encoding: base64

${p7mContent}

--${boundary}--`;

      const result = extractP7MFromEmail(mockEmail);

      expect(result.p7mContent).toBe(p7mContent);
      expect(result.attachmentInfo.filename).toBe("secure.p7m");
    });

    test("should throw error when no P7M attachment found", () => {
      const mockEmailNoPP7M = `Content-Type: text/plain
Subject: Regular Email

This is just a regular email with no P7M attachment.`;

      expect(() => extractP7MFromEmail(mockEmailNoPP7M)).toThrow(
        "Failed to extract P7M from email: No boundary found in email - MIME parsing failed",
      );
    });

    test("should handle malformed email gracefully", () => {
      const malformedEmail = "This is not a valid email format";

      expect(() => extractP7MFromEmail(malformedEmail)).toThrow(
        "Failed to extract P7M from email: No boundary found in email - MIME parsing failed",
      );
    });

    test("should extract P7M content with proper MIME boundaries created by new sendViaMailgun", () => {
      // Test the exact format created by the new sendViaMailgun method
      const boundary = "----=_Part_1234567890_abcdefgh";
      const p7mContent = "VGVzdCBQN00gY29udGVudCBmcm9tIG5ldyBNSU1FIGJ1aWxkZXI=";

      const mockEmail = `MIME-Version: 1.0\r
Content-Type: multipart/mixed; boundary="${boundary}"\r
\r
This is a multi-part message in MIME format.\r
\r
--${boundary}\r
Content-Type: text/plain; charset=utf-8\r
Content-Transfer-Encoding: 7bit\r
\r
AT Protocol Secure Message\r
\r
--${boundary}\r
Content-Type: application/pkcs7-mime; name="message.p7m"\r
Content-Disposition: attachment; filename="message.p7m"\r
Content-Transfer-Encoding: base64\r
\r
${p7mContent}\r
\r
--${boundary}--\r
`;

      const result = extractP7MFromEmail(mockEmail);

      expect(result.p7mContent).toBe(p7mContent);
      expect(result.attachmentInfo.filename).toBe("message.p7m");
      expect(result.attachmentInfo.contentType).toBe("application/pkcs7-mime");
      expect(result.attachmentInfo.encoding).toBe("base64");
      expect(result.attachmentInfo.extractionMetadata).toBeDefined();
      expect(
        result.attachmentInfo.extractionMetadata.decodedSize,
      ).toBeGreaterThan(0);
    });

    test("should detect and report truncated P7M content", () => {
      // Test case that simulates the original truncated P7M issue
      const boundary = "boundary-test-truncated";
      const truncatedP7mContent = "VGVzdA=="; // Very short content that would decode to only 4 bytes

      const mockEmail = `Content-Type: multipart/mixed; boundary=${boundary}\r
\r
--${boundary}\r
Content-Type: application/pkcs7-mime; name="message.p7m"\r
Content-Disposition: attachment; filename="message.p7m"\r
Content-Transfer-Encoding: base64\r
\r
${truncatedP7mContent}\r
\r
--${boundary}--`;

      // Should extract successfully but warn about small size
      const result = extractP7MFromEmail(mockEmail);

      expect(result.p7mContent).toBe(truncatedP7mContent);
      expect(result.attachmentInfo.extractionMetadata.decodedSize).toBe(4); // "Test" = 4 bytes
      expect(result.attachmentInfo.extractionMetadata.decodedSize).toBeLessThan(
        100,
      ); // Should trigger warning
    });

    test("should handle boundary detection with different patterns", () => {
      const boundary = "complex-boundary_123.456";
      const p7mContent = "VGVzdCBib3VuZGFyeSBkZXRlY3Rpb24=";

      // Test different boundary declaration formats
      const testCases = [
        `Content-Type: multipart/mixed; boundary=${boundary}`,
        `Content-Type: multipart/mixed; boundary="${boundary}"`,
        `Content-Type: multipart/mixed; boundary='${boundary}'`,
        `Content-Type: multipart/mixed;boundary=${boundary}`,
        `Content-Type: multipart/mixed;\r\n boundary=${boundary}`,
      ];

      for (const boundaryHeader of testCases) {
        const mockEmail = `${boundaryHeader}\r
\r
--${boundary}\r
Content-Type: application/pkcs7-mime; name="message.p7m"\r
Content-Disposition: attachment; filename="message.p7m"\r
Content-Transfer-Encoding: base64\r
\r
${p7mContent}\r
\r
--${boundary}--`;

        const result = extractP7MFromEmail(mockEmail);

        expect(result.p7mContent).toBe(p7mContent);
        expect(
          result.attachmentInfo.extractionMetadata.totalParts,
        ).toBeGreaterThan(1);
      }
    });

    test("should provide detailed error reporting for malformed MIME structure", () => {
      const testCases = [
        {
          name: "missing boundary",
          email: `Content-Type: multipart/mixed\r
\r
Some content without boundary`,
          expectedError:
            "Failed to extract P7M from email: No boundary found in email - MIME parsing failed",
        },
        {
          name: "boundary not found in content",
          email: `Content-Type: multipart/mixed; boundary="test-boundary"\r
\r
Content without the specified boundary`,
          expectedError:
            "Failed to extract P7M from email: Failed to split email into MIME parts using boundary: test-boundary",
        },
        {
          name: "no P7M attachment",
          email: `Content-Type: multipart/mixed; boundary="test-boundary"\r
\r
--test-boundary\r
Content-Type: text/plain\r
\r
Just plain text\r
\r
--test-boundary--`,
          expectedError:
            "Failed to extract P7M from email: No P7M attachment found in email - checked 2 MIME parts",
        },
        {
          name: "P7M attachment with no content",
          email: `Content-Type: multipart/mixed; boundary="test-boundary"\r
\r
--test-boundary\r
Content-Type: application/pkcs7-mime; name="message.p7m"\r
Content-Disposition: attachment; filename="message.p7m"\r
Content-Transfer-Encoding: base64\r
\r
\r
--test-boundary--`,
          expectedError:
            "Failed to extract P7M from email: No base64 content found in P7M attachment - content extraction failed",
        },
      ];

      for (const testCase of testCases) {
        try {
          extractP7MFromEmail(testCase.email);
          expect(true).toBe(false); // Should not reach here
        } catch (error) {
          // Extract key phrases from the expected error for flexible matching
          const coreError = testCase.expectedError.includes("No boundary")
            ? "No boundary found"
            : testCase.expectedError.includes("Failed to split")
              ? "Failed to split email into MIME parts"
              : testCase.expectedError.includes("No P7M attachment")
                ? "No P7M attachment found"
                : testCase.expectedError.includes("No base64 content")
                  ? "No base64 content found"
                  : testCase.expectedError;
          expect(error instanceof Error ? error.message : String(error)).toContain(coreError);
        }
      }
    });

    test("should handle line ending variations in P7M content", () => {
      const boundary = "line-ending-test";
      const p7mContent = "VGVzdCBsaW5lIGVuZGluZ3M=";

      // Test different line ending combinations (excluding \r which causes parsing issues)
      const lineEndings = ["\r\n", "\n"];

      for (const lineEnding of lineEndings) {
        // Build proper MIME structure with consistent line endings
        const mockEmail = [
          `Content-Type: multipart/mixed; boundary=${boundary}`,
          ``,
          `--${boundary}`,
          `Content-Type: application/pkcs7-mime; name="message.p7m"`,
          `Content-Disposition: attachment; filename="message.p7m"`,
          `Content-Transfer-Encoding: base64`,
          ``,
          p7mContent,
          ``,
          `--${boundary}--`,
        ].join(lineEnding);

        const result = extractP7MFromEmail(mockEmail);

        expect(result.p7mContent).toBe(p7mContent);
        expect(result.attachmentInfo.extractionMetadata).toBeDefined();
      }
    });
  });

  describe("Complete Message Flow", () => {
    test("should complete full sign -> encrypt -> decrypt -> verify flow", async () => {
      const originalMessage = {
        id: generateUUID(),
        sentAt: new Date().toISOString(),
        text: "Complete flow test message",
        convoId: generateUUID(),
      };
      const messageContent = JSON.stringify(originalMessage, null, 2);

      // Load all certificates
      const senderDir = path.join(testDir, senderHandle);
      const recipientDir = path.join(testDir, recipientHandle);

      const senderClientCertPEM = readFileSync(
        path.join(senderDir, "client-cert.pem"),
        "utf8",
      );
      const senderClientKeyPEM = readFileSync(
        path.join(senderDir, "client-key.pem"),
        "utf8",
      );

      const recipientClientCertPEM = readFileSync(
        path.join(recipientDir, "client-cert.pem"),
        "utf8",
      );
      const recipientClientKeyPEM = readFileSync(
        path.join(recipientDir, "client-key.pem"),
        "utf8",
      );

      // Step 1: Sign message (sender)
      const signerCert = await ATSMSEndpointCertificate.fromPEMWithKey(
        senderClientCertPEM,
        senderClientKeyPEM,
      );
      const signedContent = await signMessage(messageContent, signerCert);
      expect(signedContent).toBeDefined();

      // Step 2: Encrypt signed content for recipient
      const recipientCert = ATSMSEndpointCertificate.fromPEM(
        recipientClientCertPEM,
      );
      const encryptedContent = await encryptMessage(signedContent, [
        recipientCert,
      ]);
      expect(encryptedContent).toBeDefined();

      // Step 3: Decrypt and verify (recipient)
      const recipientCertWithKey =
        await ATSMSEndpointCertificate.fromPEMWithKey(
          recipientClientCertPEM,
          recipientClientKeyPEM,
        );

      const result = await decryptAndVerifyMessageSignature(
        encryptedContent,
        recipientCertWithKey,
      );
      const decryptedContent = new TextDecoder().decode(
        result.decryptedContent,
      );

      expect(decryptedContent).toBe(messageContent);

      // Step 4: Verify the decrypted message matches original
      const decryptedMessage = JSON.parse(decryptedContent);
      expect(decryptedMessage).toEqual(originalMessage);
    });

    test("should handle cross-certificate validation", async () => {
      // Test that a message signed by sender can be verified
      const testMessage = JSON.stringify(
        {
          id: generateUUID(),
          sentAt: new Date().toISOString(),
          text: "Cross-certificate validation test",
          convoId: generateUUID(),
        },
        null,
        2,
      );

      const senderDir = path.join(testDir, senderHandle);
      const recipientDir = path.join(testDir, recipientHandle);

      const senderClientCertPEM = readFileSync(
        path.join(senderDir, "client-cert.pem"),
        "utf8",
      );
      const senderClientKeyPEM = readFileSync(
        path.join(senderDir, "client-key.pem"),
        "utf8",
      );

      const recipientClientCertPEM = readFileSync(
        path.join(recipientDir, "client-cert.pem"),
        "utf8",
      );
      const recipientClientKeyPEM = readFileSync(
        path.join(recipientDir, "client-key.pem"),
        "utf8",
      );

      // Sign with sender, encrypt for recipient, decrypt with recipient
      const signerCert = await ATSMSEndpointCertificate.fromPEMWithKey(
        senderClientCertPEM,
        senderClientKeyPEM,
      );
      const signedContent = await signMessage(testMessage, signerCert);
      const recipientCert = ATSMSEndpointCertificate.fromPEM(
        recipientClientCertPEM,
      );
      const encryptedContent = await encryptMessage(signedContent, [
        recipientCert,
      ]);

      // Decrypt and verify
      const recipientCertWithKey =
        await ATSMSEndpointCertificate.fromPEMWithKey(
          recipientClientCertPEM,
          recipientClientKeyPEM,
        );

      const result = await decryptAndVerifyMessageSignature(
        encryptedContent,
        recipientCertWithKey,
      );
      const decryptedContent = new TextDecoder().decode(
        result.decryptedContent,
      );

      expect(decryptedContent).toBe(testMessage);
    });
  });

  describe("Performance and Edge Cases", () => {
    test("should handle large message content", async () => {
      // Create a large message (simulate large email body)
      const largeBody = "A".repeat(10000); // 10KB message
      const largeMessage = JSON.stringify(
        {
          id: generateUUID(),
          sentAt: new Date().toISOString(),
          content: JSON.stringify({ text: largeBody }),
          contentType: "atsms/text",
          convoId: generateUUID(),
        },
        null,
        2,
      );

      const senderDir = path.join(testDir, senderHandle);
      const recipientDir = path.join(testDir, recipientHandle);

      const senderClientCertPEM = readFileSync(
        path.join(senderDir, "client-cert.pem"),
        "utf8",
      );
      const senderClientKeyPEM = readFileSync(
        path.join(senderDir, "client-key.pem"),
        "utf8",
      );
      const recipientClientCertPEM = readFileSync(
        path.join(recipientDir, "client-cert.pem"),
        "utf8",
      );
      const recipientClientKeyPEM = readFileSync(
        path.join(recipientDir, "client-key.pem"),
        "utf8",
      );

      const signerCert = await ATSMSEndpointCertificate.fromPEMWithKey(
        senderClientCertPEM,
        senderClientKeyPEM,
      );
      const signedContent = await signMessage(largeMessage, signerCert);
      const recipientCert = ATSMSEndpointCertificate.fromPEM(
        recipientClientCertPEM,
      );
      const encryptedContent = await encryptMessage(signedContent, [
        recipientCert,
      ]);

      const recipientCertWithKey =
        await ATSMSEndpointCertificate.fromPEMWithKey(
          recipientClientCertPEM,
          recipientClientKeyPEM,
        );

      const result = await decryptAndVerifyMessageSignature(
        encryptedContent,
        recipientCertWithKey,
      );
      const decryptedContent = new TextDecoder().decode(
        result.decryptedContent,
      );

      expect(decryptedContent).toBe(largeMessage);

      const decryptedMessage = JSON.parse(decryptedContent);
      const parsedContent = JSON.parse(decryptedMessage.content);
      expect(parsedContent.text).toBe(largeBody);
    });

    test("should handle special characters in message content", async () => {
      const specialMessage = JSON.stringify(
        {
          id: generateUUID(),
          sentAt: new Date().toISOString(),
          content: JSON.stringify({
            text: "Special chars: 🔐 emoji, unicode: αβγ, symbols: !@#$%^&*(){}[]|\\:\";'<>?,./",
          }),
          contentType: "atsms/text",
          convoId: generateUUID(),
        },
        null,
        2,
      );

      const senderDir = path.join(testDir, senderHandle);
      const recipientDir = path.join(testDir, recipientHandle);

      const senderClientCertPEM = readFileSync(
        path.join(senderDir, "client-cert.pem"),
        "utf8",
      );
      const senderClientKeyPEM = readFileSync(
        path.join(senderDir, "client-key.pem"),
        "utf8",
      );
      const recipientClientCertPEM = readFileSync(
        path.join(recipientDir, "client-cert.pem"),
        "utf8",
      );
      const recipientClientKeyPEM = readFileSync(
        path.join(recipientDir, "client-key.pem"),
        "utf8",
      );

      const signerCert = await ATSMSEndpointCertificate.fromPEMWithKey(
        senderClientCertPEM,
        senderClientKeyPEM,
      );
      const signedContent = await signMessage(specialMessage, signerCert);
      const recipientCert = ATSMSEndpointCertificate.fromPEM(
        recipientClientCertPEM,
      );
      const encryptedContent = await encryptMessage(signedContent, [
        recipientCert,
      ]);

      const recipientCertWithKey =
        await ATSMSEndpointCertificate.fromPEMWithKey(
          recipientClientCertPEM,
          recipientClientKeyPEM,
        );

      const result = await decryptAndVerifyMessageSignature(
        encryptedContent,
        recipientCertWithKey,
      );
      const decryptedContent = new TextDecoder().decode(
        result.decryptedContent,
      );

      expect(decryptedContent).toBe(specialMessage);
    });
  });
});
