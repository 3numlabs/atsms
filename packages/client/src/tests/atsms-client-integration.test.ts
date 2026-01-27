/**
 * Integration tests for ATSMSClient certificate storage
 * This test requires environment variables to be set for a real AT Protocol account
 */

import { AtpAgent } from "@atproto/api";
import { describe, expect, test } from "bun:test";

import { ATSMSClient } from "../lib/atsms-client.js";
import { ATSMSEndpointCertificate } from "../lib/certificates/index.js";

// Skip these tests unless credentials are provided
const ATSMS_TEST_HANDLE = process.env.ATSMS_TEST_HANDLE;
const ATSMS_TEST_PASSWORD = process.env.ATSMS_TEST_PASSWORD;

describe.skipIf(!ATSMS_TEST_HANDLE || !ATSMS_TEST_PASSWORD)(
  "ATSMSClient Integration - Certificate Storage",
  () => {
    let client: ATSMSClient;

    test("should store and retrieve certificates from PDS", async () => {
      // Create AtpAgent and login
      const agent = new AtpAgent({ service: "https://bsky.social" });
      console.log(`Logging in as ${ATSMS_TEST_HANDLE}...`);
      const response = await agent.login({
        identifier: ATSMS_TEST_HANDLE!,
        password: ATSMS_TEST_PASSWORD!,
      });
      const did = response.data.did;
      console.log(`Logged in with DID: ${did}`);

      // Create client with authenticated agent
      client = new ATSMSClient(agent, did);

      // Generate self-signed endpoint certificate
      console.log("Generating test certificate...");
      const emailDomain = ATSMS_TEST_HANDLE!.split(".").slice(-2).join(".") || "bsky.social";
      const endpointCert = await ATSMSEndpointCertificate.generate(
        did,
        ATSMS_TEST_HANDLE!,
        emailDomain,
      );
      const clientCertPEM = endpointCert.toString("pem");

      // Store endpoint certificate
      console.log("Storing endpoint certificate...");
      await client.storeEndpointCertificate(endpointCert);

      // Retrieve certificates
      console.log("Retrieving certificates...");
      const userCerts = await client.getUserCertificates(did);

      // Verify certificates were stored
      expect(userCerts.endpointCerts.length).toBeGreaterThan(0);

      const storedEndpointCert = userCerts.endpointCerts.find(
        (cert) => cert.serialNumber === endpointCert.serialNumber,
      );
      expect(storedEndpointCert).toBeDefined();
      expect(storedEndpointCert?.certificatePEM).toBe(clientCertPEM);

      console.log(
        "✅ Certificates successfully stored and retrieved from PDS!",
      );
    }, 30000); // 30 second timeout for integration test
  },
);
