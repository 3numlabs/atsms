/**
 * Tests for ATSMSApiClient
 */

import { beforeEach, describe, expect, test } from "bun:test";

import { ATSMSApiClient } from "../lib/atsms-api.js";
import { type ATSMSConfig } from "../lib/types.js";

describe("ATSMSApiClient", () => {
  let client: ATSMSApiClient;
  const testConfig: ATSMSConfig = {
    apiUrl: "https://test.api.acme.xyz",
  };

  beforeEach(() => {
    client = new ATSMSApiClient(testConfig);
  });

  describe("Authentication", () => {
    test("should set auth token", () => {
      const token = "test-jwt-token";
      client.setAuthToken(token);
      expect(client).toBeDefined();
    });

    test("should include auth headers when token is set", async () => {
      const token = "test-jwt-token";
      client.setAuthToken(token);

      // Mock fetch to verify headers
      const originalFetch = global.fetch;
      let capturedHeaders: HeadersInit | undefined;

      global.fetch = async (input: RequestInfo | URL, init?: RequestInit) => {
        capturedHeaders = init?.headers;
        return new Response(
          JSON.stringify({
            messages: [],
            latestSeq: 0,
            hasMore: false,
            totalCount: 0,
          }),
          {
            status: 200,
            headers: { "Content-Type": "application/json" },
          },
        );
      };

      try {
        await client.listMessages("did:plc:test", "cert-serial");
        expect(capturedHeaders).toBeDefined();
        expect((capturedHeaders as any)["Authorization"]).toBe(
          `Bearer ${token}`,
        );
      } finally {
        global.fetch = originalFetch;
      }
    });
  });

  describe("listMessages", () => {
    test("should construct URL without after parameter when afterSequence is not provided", async () => {
      client.setAuthToken("test-token");

      // Mock fetch to capture the URL
      const originalFetch = global.fetch;
      let capturedUrl = "";

      global.fetch = async (input: RequestInfo | URL) => {
        capturedUrl = input.toString();
        return new Response(
          JSON.stringify({
            messages: [],
            latestSeq: 0,
            hasMore: false,
            totalCount: 0,
          }),
          {
            status: 200,
            headers: { "Content-Type": "application/json" },
          },
        );
      };

      try {
        await client.listMessages("did:plc:test", "cert123");
        expect(capturedUrl).toBe(
          "https://test.api.acme.xyz/messages/did:plc:test/cert123/list",
        );
      } finally {
        global.fetch = originalFetch;
      }
    });

    test("should construct URL with after parameter when afterSequence is provided", async () => {
      client.setAuthToken("test-token");

      // Mock fetch to capture the URL
      const originalFetch = global.fetch;
      let capturedUrl = "";

      global.fetch = async (input: RequestInfo | URL) => {
        capturedUrl = input.toString();
        return new Response(
          JSON.stringify({
            messages: [],
            latestSeq: 42,
            hasMore: false,
            totalCount: 0,
          }),
          {
            status: 200,
            headers: { "Content-Type": "application/json" },
          },
        );
      };

      try {
        await client.listMessages("did:plc:test", "cert123", 42);
        expect(capturedUrl).toBe(
          "https://test.api.acme.xyz/messages/did:plc:test/cert123/list?after=42",
        );
      } finally {
        global.fetch = originalFetch;
      }
    });

    test("should handle afterSequence of 0", async () => {
      client.setAuthToken("test-token");

      // Mock fetch to capture the URL
      const originalFetch = global.fetch;
      let capturedUrl = "";

      global.fetch = async (input: RequestInfo | URL) => {
        capturedUrl = input.toString();
        return new Response(
          JSON.stringify({
            messages: [],
            latestSeq: 0,
            hasMore: false,
            totalCount: 0,
          }),
          {
            status: 200,
            headers: { "Content-Type": "application/json" },
          },
        );
      };

      try {
        await client.listMessages("did:plc:test", "cert123", 0);
        expect(capturedUrl).toBe(
          "https://test.api.acme.xyz/messages/did:plc:test/cert123/list?after=0",
        );
      } finally {
        global.fetch = originalFetch;
      }
    });

    test("should handle API errors gracefully", async () => {
      const originalFetch = global.fetch;

      global.fetch = async () => {
        return new Response("Not Found", {
          status: 404,
          statusText: "Not Found",
        });
      };

      try {
        await expect(
          client.listMessages("did:plc:test", "cert-serial"),
        ).rejects.toThrow("Failed to list messages");
      } finally {
        global.fetch = originalFetch;
      }
    });
  });

  describe("downloadMessage", () => {
    test("should download message with correct URL", async () => {
      const did = "did:plc:test123";
      const certSerial = "test-cert-serial";
      const messageId = "msg-123";

      const originalFetch = global.fetch;
      let capturedUrl = "";

      global.fetch = async (input: RequestInfo | URL) => {
        capturedUrl = input.toString();
        return new Response(
          JSON.stringify({
            message: {
              id: messageId,
              content: "encrypted-content",
            },
          }),
          {
            status: 200,
            headers: { "Content-Type": "application/json" },
          },
        );
      };

      try {
        const result = await client.downloadMessage(did, certSerial, messageId);
        expect(capturedUrl).toBe(
          `${testConfig.apiUrl}/messages/${did}/${certSerial}/${messageId}`,
        );
        expect(result.id).toBe(messageId);
      } finally {
        global.fetch = originalFetch;
      }
    });
  });

  describe("sendMessage", () => {
    test("should send atsms message with correct payload", async () => {
      const originalFetch = global.fetch;
      let capturedBody: any;
      let capturedUrl = "";

      global.fetch = async (input: RequestInfo | URL, init?: RequestInit) => {
        capturedUrl = input.toString();
        capturedBody = init?.body ? JSON.parse(init.body as string) : undefined;
        return new Response(
          JSON.stringify({
            success: true,
            results: [
              { certSerial: "1a2b3c4d", success: true, seq: 5 },
            ],
          }),
          { status: 200, headers: { "Content-Type": "application/json" } },
        );
      };

      try {
        await client.sendMessage("did:plc:recipient", "base64content==");
        expect(capturedUrl).toBe(`${testConfig.apiUrl}/send-message`);
        expect(capturedBody).toEqual({
          did: "did:plc:recipient",
          encryptedContent: "base64content==",
        });
      } finally {
        global.fetch = originalFetch;
      }
    });

    test("should include messageType when not atsms", async () => {
      const originalFetch = global.fetch;
      let capturedBody: any;

      global.fetch = async (_input: RequestInfo | URL, init?: RequestInit) => {
        capturedBody = init?.body ? JSON.parse(init.body as string) : undefined;
        return new Response(
          JSON.stringify({ success: true, results: [] }),
          { status: 200, headers: { "Content-Type": "application/json" } },
        );
      };

      try {
        await client.sendMessage(
          "did:plc:recipient",
          "base64content==",
          "atsms-email",
        );
        expect(capturedBody.messageType).toBe("atsms-email");
      } finally {
        global.fetch = originalFetch;
      }
    });
  });

  describe("sendMessageLegacy", () => {
    test("should send message with correct payload using legacy method", async () => {
      const recipientDID = "did:plc:recipient";
      const encryptedContent = "base64encodedcontent==";

      const originalFetch = global.fetch;
      let capturedBody: any;
      let capturedMethod: string | undefined;
      let capturedUrl = "";

      global.fetch = async (input: RequestInfo | URL, init?: RequestInit) => {
        capturedUrl = input.toString();
        capturedMethod = init?.method;
        capturedBody = init?.body ? JSON.parse(init.body as string) : undefined;
        return new Response("", { status: 200 });
      };

      try {
        await client.sendMessageLegacy(recipientDID, encryptedContent);
        expect(capturedUrl).toBe(`${testConfig.apiUrl}/send-message`);
        expect(capturedMethod).toBe("POST");
        expect(capturedBody).toEqual({
          did: recipientDID,
          encryptedContent: encryptedContent,
        });
      } finally {
        global.fetch = originalFetch;
      }
    });

    test("should handle send errors in legacy method", async () => {
      const originalFetch = global.fetch;

      global.fetch = async () => {
        return new Response("Server Error", {
          status: 500,
          statusText: "Internal Server Error",
        });
      };

      try {
        await expect(
          client.sendMessageLegacy("did:plc:test", "content"),
        ).rejects.toThrow("Failed to send message");
      } finally {
        global.fetch = originalFetch;
      }
    });
  });

  describe("deleteMessage", () => {
    test("should delete message with correct URL and method", async () => {
      const did = "did:plc:test123";
      const certSerial = "test-cert-serial";
      const messageId = "msg-123";

      const originalFetch = global.fetch;
      let capturedUrl = "";
      let capturedMethod: string | undefined;

      global.fetch = async (input: RequestInfo | URL, init?: RequestInit) => {
        capturedUrl = input.toString();
        capturedMethod = init?.method;
        return new Response("", { status: 200 });
      };

      try {
        await client.deleteMessage(did, certSerial, messageId);
        expect(capturedUrl).toBe(
          `${testConfig.apiUrl}/messages/${did}/${certSerial}/${messageId}`,
        );
        expect(capturedMethod).toBe("DELETE");
      } finally {
        global.fetch = originalFetch;
      }
    });
  });

  describe("getStats", () => {
    test("should get stats with correct URL", async () => {
      const did = "did:plc:test123";
      const certSerial = "test-cert-serial";

      const originalFetch = global.fetch;
      let capturedUrl = "";

      global.fetch = async (input: RequestInfo | URL) => {
        capturedUrl = input.toString();
        return new Response(
          JSON.stringify({
            messageCount: 10,
            latestSeq: 42,
            connectedClients: 3,
          }),
          {
            status: 200,
            headers: { "Content-Type": "application/json" },
          },
        );
      };

      try {
        const stats = await client.getStats(did, certSerial);
        expect(capturedUrl).toBe(
          `${testConfig.apiUrl}/messages/${did}/${certSerial}/stats`,
        );
        expect(stats.messageCount).toBe(10);
        expect(stats.latestSeq).toBe(42);
        expect(stats.connectedClients).toBe(3);
      } finally {
        global.fetch = originalFetch;
      }
    });
  });
});
