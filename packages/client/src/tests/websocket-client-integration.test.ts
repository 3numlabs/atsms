/**
 * Integration tests for WebSocket client
 * Tests real-time message notifications with the AT-SMS WebSocket server
 *
 * Requires environment variables:
 * - ATSMS_TEST_HANDLE: AT Protocol handle (e.g., aib0b.bsky.social)
 * - ATSMS_TEST_PASSWORD: AT Protocol password/app-password
 * - ATSMS_API_URL: ATSMS API URL (e.g., https://inbox.atsms.at)
 */

import { AtpAgent } from "@atproto/api";
import { afterAll, beforeAll, describe, expect, test } from "bun:test";

import { ATSMSClient } from "../lib/atsms-client.js";
import { ATSMSEndpointCertificate } from "../lib/certificates/index.js";
import { generateJWT } from "../lib/jwt-auth.js";
import { ATSMSWebSocketClient } from "../lib/websocket-client.js";

// Skip these tests unless credentials are provided
const ATSMS_TEST_HANDLE = process.env.ATSMS_TEST_HANDLE;
const ATSMS_TEST_PASSWORD = process.env.ATSMS_TEST_PASSWORD;
const ATSMS_API_URL = process.env.ATSMS_API_URL || "https://inbox.atsms.at";

describe.skipIf(!ATSMS_TEST_HANDLE || !ATSMS_TEST_PASSWORD)(
  "WebSocket Client Integration",
  () => {
    let agent: AtpAgent;
    let did: string;
    let atsmsClient: ATSMSClient;
    let endpointCert: ATSMSEndpointCertificate;
    let certSerial: string;
    let wsClient: ATSMSWebSocketClient | null = null;

    beforeAll(async () => {
      // Create AtpAgent and login
      agent = new AtpAgent({ service: "https://bsky.social" });
      console.log(`Logging in as ${ATSMS_TEST_HANDLE}...`);
      const response = await agent.login({
        identifier: ATSMS_TEST_HANDLE!,
        password: ATSMS_TEST_PASSWORD!,
      });
      did = response.data.did;
      console.log(`Logged in with DID: ${did}`);

      // Create ATSMS client
      atsmsClient = new ATSMSClient(agent, did);

      // Generate fresh self-signed endpoint certificate for testing
      console.log("Generating fresh test certificate...");
      const emailDomain = ATSMS_TEST_HANDLE!.split(".").slice(-2).join(".") || "bsky.social";
      endpointCert = await ATSMSEndpointCertificate.generate(
        did,
        ATSMS_TEST_HANDLE!,
        emailDomain,
      );
      certSerial = endpointCert.serialNumber;

      // Store certificate in PDS
      console.log("Storing certificate in PDS...");
      await atsmsClient.storeEndpointCertificate(endpointCert);

      console.log(`Generated certificate, serial: ${certSerial}`);
    }, 60000); // 60 second timeout for setup

    afterAll(async () => {
      // Cleanup: disconnect any active WebSocket connections
      if (wsClient) {
        wsClient.disconnect();
        wsClient = null;
      }
    });

    test("should connect and authenticate with header-based auth (Node.js)", async () => {
      return new Promise<void>((resolve, reject) => {
        const timeout = setTimeout(() => {
          reject(
            new Error(
              "Test timeout: WebSocket did not connect within 10 seconds",
            ),
          );
        }, 10000);

        let connected = false;

        wsClient = new ATSMSWebSocketClient({
          apiUrl: ATSMS_API_URL,
          did: did,
          certSerial: certSerial,
          getToken: async () => {
            // Generate JWT token for authentication using client certificate private key
            if (!endpointCert.certificatePrivateKeyPEM) {
              throw new Error("Client certificate private key not available");
            }
            return await generateJWT(
              endpointCert.certificatePrivateKeyPEM,
              certSerial,
              did,
            );
          },
          onConnect: () => {
            console.log("✅ WebSocket connected and authenticated");
            connected = true;
            clearTimeout(timeout);

            // Give it a moment to stabilize
            setTimeout(() => {
              expect(wsClient!.isConnected()).toBe(true);
              resolve();
            }, 100);
          },
          onError: (error) => {
            console.error("WebSocket error:", error);
            clearTimeout(timeout);
            reject(error);
          },
          onDisconnect: (code, reason) => {
            if (!connected) {
              clearTimeout(timeout);
              reject(
                new Error(
                  `WebSocket disconnected before connecting: ${code} - ${reason}`,
                ),
              );
            }
          },
        });

        wsClient.connect().catch((error) => {
          clearTimeout(timeout);
          reject(error);
        });
      });
    }, 15000);

    test("should maintain connection with ping keepalive", async () => {
      if (!wsClient || !wsClient.isConnected()) {
        throw new Error("WebSocket not connected from previous test");
      }

      // Send a ping to verify the connection is alive
      console.log("Sending ping...");
      wsClient.send({ type: "ping", timestamp: Date.now() });

      // Wait a moment to ensure the connection doesn't close
      await new Promise((resolve) => setTimeout(resolve, 1000));

      // Verify connection is still active
      expect(wsClient.isConnected()).toBe(true);
      console.log("✅ Connection maintained after ping");
    }, 5000);

    test("should receive new_message broadcasts", async () => {
      if (!wsClient || !wsClient.isConnected()) {
        throw new Error("WebSocket not connected from previous test");
      }

      return new Promise<void>(async (resolve, reject) => {
        const timeout = setTimeout(() => {
          reject(
            new Error(
              "Test timeout: Did not receive message broadcast within 15 seconds",
            ),
          );
        }, 15000);

        // Store original onMessage handler
        const originalConfig = (wsClient as any).config;
        const originalOnMessage = originalConfig.onMessage;

        // Set up message handler to catch broadcasts
        originalConfig.onMessage = (message: ATSMSWebSocketMessage) => {
          console.log("Received WebSocket message:", message.type);

          if (message.type === "new_message") {
            console.log("✅ Received new_message broadcast");
            expect(message.message).toBeDefined();
            expect(message.message.id).toBeDefined();
            expect(message.message.seq).toBeGreaterThan(0);
            expect(message.message.encryptedContent).toBeDefined();

            clearTimeout(timeout);

            // Restore original handler
            originalConfig.onMessage = originalOnMessage;

            resolve();
          } else if (originalOnMessage) {
            // Forward other messages to original handler
            originalOnMessage(message);
          }
        };

        try {
          // Send a test message to ourselves to trigger the broadcast
          // This uses the ATSMS API to store a message in our own inbox
          console.log("Sending test message to trigger broadcast...");

          const testContent = Buffer.from(
            "Test WebSocket broadcast message",
          ).toString("base64");

          const response = await fetch(`${ATSMS_API_URL}/send-message`, {
            method: "POST",
            headers: {
              "Content-Type": "application/json",
            },
            body: JSON.stringify({
              did: did,
              encryptedContent: testContent,
            }),
          });

          if (!response.ok) {
            const errorText = await response.text();
            clearTimeout(timeout);
            reject(
              new Error(
                `Failed to send test message: ${response.status} - ${errorText}`,
              ),
            );
            return;
          }

          const result = await response.json();
          console.log(
            `Test message sent successfully, delivered to ${result.delivered} inbox(es)`,
          );
        } catch (error) {
          clearTimeout(timeout);
          reject(error);
        }
      });
    }, 20000);

    test("should handle disconnect and cleanup", async () => {
      if (!wsClient) {
        throw new Error("WebSocket not initialized");
      }

      return new Promise<void>((resolve, reject) => {
        const timeout = setTimeout(() => {
          reject(
            new Error(
              "Test timeout: Disconnect did not complete within 5 seconds",
            ),
          );
        }, 5000);

        // Store original onDisconnect handler
        const originalConfig = (wsClient as any).config;
        const originalOnDisconnect = originalConfig.onDisconnect;

        // Override disconnect handler to verify clean shutdown
        originalConfig.onDisconnect = (code: number, reason: string) => {
          console.log(`✅ WebSocket disconnected: ${code} - ${reason}`);

          // Restore original handler
          originalConfig.onDisconnect = originalOnDisconnect;

          clearTimeout(timeout);

          // Verify client is no longer connected
          expect(wsClient!.isConnected()).toBe(false);

          resolve();
        };

        // Disconnect
        wsClient!.disconnect();
      });
    }, 10000);

    test("should reconnect after disconnect (if max attempts not reached)", async () => {
      // Create a new client with reconnection enabled
      return new Promise<void>((resolve, reject) => {
        const timeout = setTimeout(() => {
          if (wsClient) {
            wsClient.disconnect();
          }
          reject(
            new Error(
              "Test timeout: Reconnection did not complete within 20 seconds",
            ),
          );
        }, 20000);

        let connectCount = 0;
        let firstDisconnect = false;

        wsClient = new ATSMSWebSocketClient({
          apiUrl: ATSMS_API_URL,
          did: did,
          certSerial: certSerial,
          reconnectDelay: 1000, // 1 second delay for faster testing
          maxReconnectAttempts: 3,
          getToken: async () => {
            // Generate JWT token for authentication using client certificate private key
            if (!endpointCert.certificatePrivateKeyPEM) {
              throw new Error("Client certificate private key not available");
            }
            return await generateJWT(
              endpointCert.certificatePrivateKeyPEM,
              certSerial,
              did,
            );
          },
          onConnect: () => {
            connectCount++;
            console.log(`✅ WebSocket connected (attempt ${connectCount})`);

            if (connectCount === 1) {
              // First connection - disconnect to test reconnection
              console.log("Disconnecting to test reconnection...");
              setTimeout(() => {
                wsClient!.disconnect();
              }, 500);
            } else if (connectCount === 2) {
              // Second connection - reconnection successful
              console.log("✅ Reconnection successful");
              clearTimeout(timeout);

              // Clean up
              wsClient!.disconnect();

              resolve();
            }
          },
          onDisconnect: (code, reason) => {
            console.log(`WebSocket disconnected: ${code} - ${reason}`);

            if (connectCount === 1 && !firstDisconnect) {
              firstDisconnect = true;
              console.log(
                "First disconnect detected, waiting for reconnection...",
              );
              // Don't resolve or reject - wait for reconnection
            }
          },
          onError: (error) => {
            console.error("WebSocket error during reconnection test:", error);
            // Don't reject on errors during reconnection attempts
          },
        });

        wsClient.connect().catch((error) => {
          clearTimeout(timeout);
          reject(error);
        });
      });
    }, 25000);
  },
);
