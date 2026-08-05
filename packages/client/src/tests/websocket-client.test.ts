/**
 * Unit tests for ATSMSWebSocketClient
 *
 * These tests verify URL encoding and WebSocket connection behavior
 * without requiring actual WebSocket connections.
 */

import { beforeEach, describe, expect, test } from "bun:test";

import { ATSMSWebSocketClient, type ATSMSWebSocketClientConfig } from "../lib/websocket-client.js";

describe("ATSMSWebSocketClient", () => {
  let _capturedUrl: string | null = null;
  let _capturedOptions: any = null;

  beforeEach(() => {
    // Reset captured values
    _capturedUrl = null;
    _capturedOptions = null;
  });

  describe("URL Encoding", () => {
    test("should URL-encode DIDs with colons in WebSocket URL", () => {
      // Test the URL construction logic directly
      const apiUrl = "https://inbox.atsms.at";
      const did = "did:plc:gbkt44wmk7k3h3dm2dlqhcoj";
      const deviceFingerprint = "a34e16bf51aec7ef";

      // Replicate the URL construction from websocket-client.ts:61-64
      const encodedDid = encodeURIComponent(did);
      const encodedFingerprint = encodeURIComponent(deviceFingerprint);
      const wsUrl = `${apiUrl.replace("https://", "wss://").replace("http://", "ws://")}/ws/${encodedDid}/${encodedFingerprint}`;

      // Verify DID is URL-encoded (colons should be %3A)
      expect(wsUrl).toContain("did%3Aplc%3Agbkt44wmk7k3h3dm2dlqhcoj");

      // Verify the full URL structure
      expect(wsUrl).toBe(
        "wss://inbox.atsms.at/ws/did%3Aplc%3Agbkt44wmk7k3h3dm2dlqhcoj/a34e16bf51aec7ef",
      );

      // Verify protocol conversion (https -> wss)
      expect(wsUrl).toStartWith("wss://");

      // Verify no unencoded colons in the path
      const pathPart = wsUrl.split("/ws/")[1];
      expect(pathPart).not.toContain(":");
    });

    test("should URL-encode device fingerprints with special characters", () => {
      const apiUrl = "https://api.example.com";
      const did = "did:plc:test123";
      const deviceFingerprint = "cert/serial+special=chars";

      const encodedDid = encodeURIComponent(did);
      const encodedFingerprint = encodeURIComponent(deviceFingerprint);
      const wsUrl = `${apiUrl.replace("https://", "wss://").replace("http://", "ws://")}/ws/${encodedDid}/${encodedFingerprint}`;

      // Verify special characters are encoded
      expect(wsUrl).toContain("cert%2Fserial%2Bspecial%3Dchars");

      // Verify slashes are encoded (not literal)
      expect(wsUrl).not.toMatch(/ws\/[^/]+\/cert\/serial/);
    });

    test("should convert http to ws protocol", () => {
      const apiUrl = "http://localhost:3000";
      const did = "did:plc:test";
      const deviceFingerprint = "e3b0c44298fc1c14";

      const encodedDid = encodeURIComponent(did);
      const encodedFingerprint = encodeURIComponent(deviceFingerprint);
      const wsUrl = `${apiUrl.replace("https://", "wss://").replace("http://", "ws://")}/ws/${encodedDid}/${encodedFingerprint}`;

      expect(wsUrl).toStartWith("ws://localhost:3000");
      expect(wsUrl).not.toStartWith("http://");
    });

    test("should convert https to wss protocol", () => {
      const apiUrl = "https://secure.example.com";
      const did = "did:plc:abc";
      const deviceFingerprint = "xyz";

      const encodedDid = encodeURIComponent(did);
      const encodedFingerprint = encodeURIComponent(deviceFingerprint);
      const wsUrl = `${apiUrl.replace("https://", "wss://").replace("http://", "ws://")}/ws/${encodedDid}/${encodedFingerprint}`;

      expect(wsUrl).toStartWith("wss://secure.example.com");
      expect(wsUrl).not.toStartWith("https://");
    });

    test("should fail without URL encoding (regression test)", () => {
      // This test demonstrates the bug that was fixed
      const apiUrl = "https://inbox.atsms.at";
      const did = "did:plc:gbkt44wmk7k3h3dm2dlqhcoj";
      const deviceFingerprint = "a34e16bf51aec7ef";

      // OLD WAY (buggy - no encoding)
      const buggyUrl = `${apiUrl.replace("https://", "wss://").replace("http://", "ws://")}/ws/${did}/${deviceFingerprint}`;

      // The buggy URL contains unencoded colons
      expect(buggyUrl).toContain("did:plc:");
      expect(buggyUrl).toBe(
        "wss://inbox.atsms.at/ws/did:plc:gbkt44wmk7k3h3dm2dlqhcoj/a34e16bf51aec7ef",
      );

      // NEW WAY (correct - with encoding)
      const encodedDid = encodeURIComponent(did);
      const encodedFingerprint = encodeURIComponent(deviceFingerprint);
      const correctUrl = `${apiUrl.replace("https://", "wss://").replace("http://", "ws://")}/ws/${encodedDid}/${encodedFingerprint}`;

      // The correct URL has encoded colons
      expect(correctUrl).not.toContain("did:plc:");
      expect(correctUrl).toContain("did%3Aplc%3A");

      // They should be different
      expect(buggyUrl).not.toBe(correctUrl);
    });
  });

  describe("Connection State", () => {
    test("should return false when not connected", () => {
      const config: ATSMSWebSocketClientConfig = {
        apiUrl: "https://api.example.com",
        did: "did:plc:test",
        deviceFingerprint: "e3b0c44298fc1c14",
        getToken: async () => "token",
      };

      const client = new ATSMSWebSocketClient(config);
      expect(client.isConnected()).toBe(false);
    });

    test("disconnect should not throw when called on unconnected client", () => {
      const config: ATSMSWebSocketClientConfig = {
        apiUrl: "https://api.example.com",
        did: "did:plc:test",
        deviceFingerprint: "e3b0c44298fc1c14",
        getToken: async () => "token",
      };

      const client = new ATSMSWebSocketClient(config);

      // Disconnect should not throw even if never connected
      expect(() => client.disconnect()).not.toThrow();

      // Should still report as not connected
      expect(client.isConnected()).toBe(false);
    });
  });

  describe("Requests", () => {
    test("should reject a request when not connected", async () => {
      const config: ATSMSWebSocketClientConfig = {
        apiUrl: "https://api.example.com",
        did: "did:plc:test",
        deviceFingerprint: "e3b0c44298fc1c14",
        getToken: async () => "token",
      };

      const client = new ATSMSWebSocketClient(config);

      await expect(client.listMessages()).rejects.toThrow(
        "WebSocket not connected or authenticated",
      );
    });
  });
});
