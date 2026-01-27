#!/usr/bin/env bun

/**
 * Advanced API client for AT-SMS
 * Supports all API endpoints including WebSocket
 *
 * NOTE: This CLI tool uses dynamic imports for optional dependencies:
 * - 'bun:sqlite' for accessing cached credentials
 * - 'jose' for JWT generation
 * These are loaded on-demand to avoid requiring them for all operations.
 */

// @ts-expect-error - bun:sqlite is a built-in Bun module
import Database from "bun:sqlite";
import { readFileSync } from "fs";
import { request as httpsRequest, type RequestOptions } from "https";
import { importPKCS8, SignJWT } from "jose";
import { homedir } from "os";
import { join } from "path";
import { WebSocket } from "ws";

// Colors for console output
const colors = {
  reset: "\x1b[0m",
  bright: "\x1b[1m",
  red: "\x1b[31m",
  green: "\x1b[32m",
  yellow: "\x1b[33m",
  blue: "\x1b[34m",
  magenta: "\x1b[35m",
  cyan: "\x1b[36m",
} as const;

// API configuration
const API_BASE = "https://atsms-api.enumdao.workers.dev";
const WS_BASE = "wss://atsms-api.enumdao.workers.dev";
const DEFAULT_DATA_DIR = join(homedir(), ".atsms");

// Type definitions
interface JWTPayload {
  sub: string;
  iss: string;
  exp: number;
  aud: string;
}

interface JWTInfo {
  did: string;
  certSerial: string;
  iss: string;
  exp: number;
}

interface AuthCache {
  [handle: string]: {
    did: string;
    accessJwt: string;
    refreshJwt: string;
    pdsUrl: string;
  };
}

interface CertificateRow {
  serialNumber: string;
  privateKeyPEM: string;
  privateKeyEncrypted: number;
}

interface MessageMetadata {
  id: string;
  seq: number;
  storedAt: string;
}

interface ListMessagesResponse {
  messages: MessageMetadata[];
  totalCount: number;
  hasMore: boolean;
  latestSeq: number;
}

interface StatsResponse {
  messageCount: number;
  unreadCount: number;
  latestSeq: number;
  connectedClients: number;
}

interface RecipientEndpoint {
  certSerial: string;
  email: string;
}

interface Recipient {
  did: string;
  endpoints: RecipientEndpoint[];
}

interface SendResult {
  did: string;
  certSerial: string;
  email: string;
  status: "sent" | "failed";
  error?: string;
}

interface WebSocketMessage {
  type: string;
  requestId?: string;
  deadline?: string;
  did?: string;
  certSerial?: string;
  message?: MessageMetadata;
  messageId?: string;
  results?: SendResult[];
  error?: string;
}

// Parse command line arguments
const rawArgs = process.argv.slice(2);
let dataDir = DEFAULT_DATA_DIR;
let verbose = false;
const filteredArgs: string[] = [];

// Extract options
for (let i = 0; i < rawArgs.length; i++) {
  const arg = rawArgs[i];
  if (arg === "--data-dir" && i + 1 < rawArgs.length) {
    dataDir = rawArgs[++i];
  } else if (arg.startsWith("--data-dir=")) {
    dataDir = arg.split("=")[1];
  } else if (arg === "-v" || arg === "--verbose") {
    verbose = true;
  } else {
    filteredArgs.push(arg);
  }
}

const command = filteredArgs[0];
const handle = filteredArgs[1];
const args = filteredArgs; // Keep for compatibility with command handlers

if (!command) {
  showUsage();
  process.exit(1);
}

// Load or generate JWT token from data directory
async function loadOrGenerateJWT(handle: string): Promise<string> {
  const configDir = dataDir;

  // Try old location first (backward compatibility)
  const oldTokenPath = join("./", ".atsms", handle, "jwt-token.json");
  try {
    const tokenData = JSON.parse(readFileSync(oldTokenPath, "utf8"));
    console.log(
      `${colors.yellow}Note: Using JWT from old location (${oldTokenPath})${colors.reset}`,
    );
    console.log(
      `${colors.yellow}Consider regenerating JWT to use new cache location${colors.reset}`,
    );
    return tokenData.token;
  } catch {
    // Old location doesn't exist, try generating from cached data
  }

  // Try to generate JWT from cached auth and certificates
  try {
    // Load auth cache to get DID
    const authCachePath = join(configDir, "auth-cache.json");
    const authCache: AuthCache = JSON.parse(
      readFileSync(authCachePath, "utf8"),
    );
    const auth = authCache[handle];

    if (!auth || !auth.did) {
      throw new Error("No cached authentication found for handle");
    }

    const did = auth.did;

    // Load certificate from database
    const dbPath = join(configDir, "messages.db");
    const db = new Database(dbPath);

    const stmt = db.prepare(`
      SELECT serialNumber, privateKeyPEM, privateKeyEncrypted
      FROM certificates
      WHERE did = ? AND type = 'endpoint'
      LIMIT 1
    `);
    const cert = stmt.get(did) as CertificateRow | null;
    db.close();

    if (!cert || !cert.serialNumber || !cert.privateKeyPEM) {
      throw new Error("No client certificate with private key found");
    }

    if (cert.privateKeyEncrypted === 1) {
      throw new Error(
        "Certificate private key is encrypted - cannot auto-generate JWT",
      );
    }

    // Generate JWT using jose library
    // Detect key type by trying to import as EC first (P-256 is the new default)
    const userId = `at://${did}/at.atsms.x509/${cert.serialNumber}`;
    let privateKey: CryptoKey;
    let algorithm: string;

    try {
      privateKey = await importPKCS8(cert.privateKeyPEM, "ES256");
      algorithm = "ES256";
    } catch {
      // Fall back to RSA
      privateKey = await importPKCS8(cert.privateKeyPEM, "RS256");
      algorithm = "RS256";
    }

    const token = await new SignJWT({
      sub: userId,
      iss: did,
      aud: "atsms-api",
    })
      .setProtectedHeader({
        alg: algorithm,
        typ: "JWT",
        kid: cert.serialNumber,
      })
      .setIssuedAt()
      .setExpirationTime("1h")
      .sign(privateKey);

    if (verbose) {
      console.log(
        `${colors.green}✓ Generated new JWT from cached credentials${colors.reset}`,
      );
    }
    return token;
  } catch (error: any) {
    // Could not generate JWT
    console.error(
      `${colors.red}Error: Could not load or generate JWT token${colors.reset}`,
    );
    console.error(`${colors.yellow}Reason: ${error.message}${colors.reset}`);
    console.error(`${colors.yellow}Data directory: ${configDir}${colors.reset}`);
    console.error("");
    console.error(`${colors.yellow}Please authenticate first:${colors.reset}`);
    console.error(`  Run: ${colors.cyan}bun run chat${colors.reset}`);
    console.error(
      `  Or: ${colors.cyan}bun src/client/atsms-chat.ts ${handle}${colors.reset}`,
    );
    console.error("");
    console.error(
      `${colors.yellow}Or specify a different data directory with --data-dir${colors.reset}`,
    );
    process.exit(1);
  }
}

// Extract DID and certificate serial from JWT
function parseJWT(token: string): JWTInfo {
  try {
    const payload: JWTPayload = JSON.parse(
      Buffer.from(token.split(".")[1], "base64").toString(),
    );
    const subject = payload.sub;

    // Parse at://did/at.atsms.x509/serial format
    const match = subject.match(/^at:\/\/([^/]+)\/at\.atsms\.x509\/([^/]+)$/);
    if (!match) {
      throw new Error("Invalid JWT subject format");
    }

    return {
      did: match[1],
      certSerial: match[2],
      iss: payload.iss,
      exp: payload.exp,
    };
  } catch {
    console.error(`${colors.red}Error: Could not parse JWT${colors.reset}`);
    process.exit(1);
  }
}

// Make HTTPS request
function makeRequest(options: RequestOptions, data: any = null): Promise<any> {
  return new Promise((resolve, reject) => {
    const req = httpsRequest(options, (res) => {
      let body = "";

      res.on("data", (chunk) => {
        body += chunk;
      });

      res.on("end", () => {
        if (res.statusCode && res.statusCode >= 200 && res.statusCode < 300) {
          try {
            resolve(JSON.parse(body));
          } catch {
            resolve(body);
          }
        } else {
          console.error(
            `${colors.red}Error: HTTP ${res.statusCode}${colors.reset}`,
          );
          try {
            console.error(JSON.stringify(JSON.parse(body), null, 2));
          } catch {
            console.error(body);
          }
          reject(new Error(`HTTP ${res.statusCode}`));
        }
      });
    });

    req.on("error", reject);

    if (data) {
      req.write(JSON.stringify(data));
    }

    req.end();
  });
}

// API request helper
async function apiRequest(
  method: string,
  path: string,
  data: any = null,
  token: string,
): Promise<any> {
  const url = new URL(API_BASE + path);

  const options: RequestOptions = {
    hostname: url.hostname,
    port: url.port || 443,
    path: url.pathname + url.search,
    method: method,
    headers: {
      Authorization: `Bearer ${token}`,
      "Content-Type": "application/json",
    },
  };

  return makeRequest(options, data);
}

// Command handler type
type CommandHandler = (
  token: string,
  jwtInfo: JWTInfo,
  ...args: string[]
) => Promise<void>;
type AuthCommandHandler = (handle: string) => Promise<void>;

// Command handlers
const commands: Record<string, CommandHandler | AuthCommandHandler> = {
  async auth(handle: string) {
    // Auth command to generate new JWT
    console.log(
      `${colors.yellow}Authenticating and generating new JWT for ${handle}...${colors.reset}`,
    );
    console.log("");
    console.log(
      `${colors.red}Note: The auth command requires the AT-SMS client to be installed.${colors.reset}`,
    );
    console.log(
      `${colors.yellow}Please use the main AT-SMS client instead:${colors.reset}`,
    );
    console.log("");
    console.log(`  ${colors.cyan}bun run atsms login ${handle}${colors.reset}`);
    console.log("");
    console.log(
      "This will authenticate with AT Protocol and generate a new JWT token.",
    );
    console.log("");
    console.log(
      `${colors.yellow}Alternative: If JWT is expired but you have valid certificates:${colors.reset}`,
    );
    console.log(
      `  1. Run: ${colors.cyan}bun run atsms login ${handle}${colors.reset}`,
    );
    console.log(`  2. The JWT will be automatically regenerated`);
    console.log("");
    process.exit(0);
  },

  async health(token: string, _jwtInfo: JWTInfo) {
    if (verbose) console.log(`${colors.yellow}Checking API health...${colors.reset}`);
    const result = await apiRequest("GET", "/health", null, token);
    console.log(JSON.stringify(result, null, 2));
  },

  async list(
    token: string,
    jwtInfo: JWTInfo,
    limitStr = "50",
    afterStr?: string,
  ) {
    if (verbose) console.log(`${colors.yellow}Listing messages...${colors.reset}`);
    const limit = parseInt(limitStr, 10);
    let query = `?limit=${limit}`;
    if (afterStr) query += `&after=${afterStr}`;

    const result: ListMessagesResponse = await apiRequest(
      "GET",
      `/messages/${jwtInfo.did}/${jwtInfo.certSerial}${query}`,
      null,
      token,
    );

    if (verbose) {
      console.log(
        `${colors.green}Messages (${result.totalCount} total):${colors.reset}`,
      );
    }
    result.messages.forEach((msg) => {
      const timestamp = new Date(msg.storedAt).toLocaleString();
      console.log(`${msg.id}\t${msg.seq}\t${timestamp}`);
    });

    if (verbose && result.hasMore) {
      console.log(
        `${colors.yellow}More messages available. Use --after ${result.latestSeq} to see more.${colors.reset}`,
      );
    }
  },

  async get(token: string, jwtInfo: JWTInfo, messageId?: string) {
    if (!messageId) {
      console.error(`${colors.red}Error: Message ID required${colors.reset}`);
      process.exit(1);
    }

    if (verbose) {
      console.log(
        `${colors.yellow}Getting message ${messageId}...${colors.reset}`,
      );
    }
    const result = await apiRequest(
      "GET",
      `/messages/${jwtInfo.did}/${jwtInfo.certSerial}/${messageId}`,
      null,
      token,
    );
    console.log(JSON.stringify(result, null, 2));
  },

  async delete(token: string, jwtInfo: JWTInfo, messageId?: string) {
    if (!messageId) {
      console.error(`${colors.red}Error: Message ID required${colors.reset}`);
      process.exit(1);
    }

    if (verbose) {
      console.log(
        `${colors.yellow}Deleting message ${messageId}...${colors.reset}`,
      );
    }
    await apiRequest(
      "DELETE",
      `/messages/${jwtInfo.did}/${jwtInfo.certSerial}/${messageId}`,
      null,
      token,
    );
    console.log(`${colors.green}✓ Deleted ${messageId}${colors.reset}`);
  },

  async stats(token: string, jwtInfo: JWTInfo) {
    if (verbose) console.log(`${colors.yellow}Getting inbox statistics...${colors.reset}`);
    const result: StatsResponse = await apiRequest(
      "GET",
      `/messages/${jwtInfo.did}/${jwtInfo.certSerial}/stats`,
      null,
      token,
    );

    if (verbose) {
      console.log(`${colors.green}Inbox Statistics:${colors.reset}`);
      console.log(
        `  Total messages: ${colors.cyan}${result.messageCount}${colors.reset}`,
      );
      console.log(
        `  Unread messages: ${colors.cyan}${result.unreadCount}${colors.reset}`,
      );
      console.log(
        `  Latest sequence: ${colors.cyan}${result.latestSeq}${colors.reset}`,
      );
      console.log(
        `  Connected clients: ${colors.cyan}${result.connectedClients}${colors.reset}`,
      );
    } else {
      console.log(JSON.stringify(result));
    }
  },

  async send(
    token: string,
    jwtInfo: JWTInfo,
    encryptedContentPath?: string,
    ...recipientArgs: string[]
  ) {
    if (!encryptedContentPath || recipientArgs.length === 0) {
      console.error(
        `${colors.red}Error: Encrypted content file and at least one recipient required${colors.reset}`,
      );
      console.error(
        `${colors.yellow}Usage: send <handle> <encrypted-content-file> <recipient1> [recipient2] ...${colors.reset}`,
      );
      console.error(
        `${colors.yellow}Recipient format: did:certSerial:email${colors.reset}`,
      );
      console.error(
        `${colors.yellow}Example: send aib0b.bsky.social ./message.p7m did:plc:abc:4d18ac7f:user@atsms.example.com${colors.reset}`,
      );
      process.exit(1);
    }

    // Load encrypted content from file
    let encryptedContent: string;
    try {
      const fileContent = readFileSync(encryptedContentPath);
      encryptedContent = fileContent.toString("base64");
    } catch (error: any) {
      console.error(
        `${colors.red}Error: Could not read encrypted content file: ${error.message}${colors.reset}`,
      );
      process.exit(1);
    }

    // Parse recipients and group by DID (format: did:certSerial:email)
    const recipientMap = new Map<string, RecipientEndpoint[]>();

    for (const arg of recipientArgs) {
      const parts = arg.split(":");
      if (parts.length < 4) {
        console.error(
          `${colors.red}Error: Invalid recipient format: ${arg}${colors.reset}`,
        );
        console.error(
          `${colors.yellow}Expected: did:plc:xxx:certSerial:email${colors.reset}`,
        );
        process.exit(1);
      }

      // Reconstruct DID (may contain colons)
      const email = parts[parts.length - 1];
      const certSerial = parts[parts.length - 2];
      const did = parts.slice(0, parts.length - 2).join(":");

      // Group endpoints by DID
      if (!recipientMap.has(did)) {
        recipientMap.set(did, []);
      }
      recipientMap.get(did)!.push({ certSerial, email });
    }

    // Convert map to array format for API
    const recipients: Recipient[] = Array.from(recipientMap.entries()).map(
      ([did, endpoints]) => ({
        did,
        endpoints,
      }),
    );

    const totalEndpoints = recipientArgs.length;
    const uniqueDids = recipients.length;
    if (verbose) {
      console.log(
        `${colors.yellow}Connecting to WebSocket to send message...${colors.reset}`,
      );
      console.log(
        `${colors.blue}Recipients: ${uniqueDids} DID(s) with ${totalEndpoints} endpoint(s)${colors.reset}`,
      );
    }

    const wsUrl = `${WS_BASE}/ws/${jwtInfo.did}/${jwtInfo.certSerial}`;
    const ws = new WebSocket(wsUrl);
    let requestId: string | null = null;

    ws.on("open", () => {
      if (verbose) console.log(`${colors.green}✓ Connected to WebSocket${colors.reset}`);
    });

    ws.on("message", (data) => {
      try {
        const msg: WebSocketMessage = JSON.parse(data.toString());

        switch (msg.type) {
          case "auth_required":
            if (verbose) console.log(`${colors.yellow}Authenticating...${colors.reset}`);
            ws.send(
              JSON.stringify({
                type: "auth",
                token: token,
              }),
            );
            break;

          case "auth_success":
            if (verbose) {
              console.log(`${colors.green}✓ Authenticated${colors.reset}`);
              console.log(`${colors.yellow}Sending message...${colors.reset}`);
            }

            // Send the message
            requestId = `send-${Date.now()}`;
            ws.send(
              JSON.stringify({
                type: "send",
                requestId,
                to: recipients,
                encryptedContent,
              }),
            );
            break;

          case "send_response":
            if (msg.requestId === requestId) {
              if (verbose) {
                console.log(`${colors.green}✓ Send completed${colors.reset}`);
                console.log(`${colors.green}Results:${colors.reset}`);
                msg.results?.forEach((result) => {
                  const statusColor =
                    result.status === "sent" ? colors.green : colors.red;
                  console.log(
                    `  ${result.email} (${result.did}:${result.certSerial})`,
                  );
                  console.log(
                    `    Status: ${statusColor}${result.status}${colors.reset}`,
                  );
                  if (result.error)
                    console.log(
                      `    Error: ${colors.red}${result.error}${colors.reset}`,
                    );
                });
              } else {
                // Compact output: status for each recipient
                msg.results?.forEach((result) => {
                  const statusColor =
                    result.status === "sent" ? colors.green : colors.red;
                  console.log(
                    `${statusColor}${result.status}${colors.reset}\t${result.email}`,
                  );
                });
              }

              ws.close();
              process.exit(0);
            }
            break;

          case "error":
            if (msg.requestId === requestId) {
              console.error(
                `${colors.red}Error sending message: ${msg.error}${colors.reset}`,
              );
              ws.close();
              process.exit(1);
            }
            break;
        }
      } catch (error: any) {
        console.error(
          `${colors.red}Error parsing message: ${error.message}${colors.reset}`,
        );
      }
    });

    ws.on("error", (error) => {
      console.error(
        `${colors.red}WebSocket error: ${error.message}${colors.reset}`,
      );
      process.exit(1);
    });

    ws.on("close", (code, reason) => {
      if (code === 1008) {
        console.log(
          `${colors.red}WebSocket closed: Authentication failed - ${reason}${colors.reset}`,
        );
      } else {
        console.log(
          `${colors.yellow}WebSocket closed: ${code} ${reason}${colors.reset}`,
        );
      }
      process.exit(code === 1000 ? 0 : 1);
    });

    // Timeout after 30 seconds
    setTimeout(() => {
      console.error(`${colors.red}Timeout waiting for response${colors.reset}`);
      ws.close();
      process.exit(1);
    }, 30000);
  },

  async watch(token: string, jwtInfo: JWTInfo) {
    if (verbose) {
      console.log(
        `${colors.yellow}Connecting to WebSocket for real-time updates...${colors.reset}`,
      );
    }

    // Use the new /ws/ path that doesn't require auth at the API level
    const wsUrl = `${WS_BASE}/ws/${jwtInfo.did}/${jwtInfo.certSerial}`;
    if (verbose) console.log(`${colors.blue}WebSocket URL: ${wsUrl}${colors.reset}`);

    // Connect without Authorization header (browser-style)
    const ws = new WebSocket(wsUrl);

    ws.on("open", () => {
      if (verbose) {
        console.log(`${colors.green}✓ Connected to WebSocket${colors.reset}`);
        console.log(
          `${colors.yellow}Waiting for auth_required message...${colors.reset}`,
        );
      }
      // Don't send auth immediately - wait for auth_required message
    });

    ws.on("message", (data) => {
      try {
        const msg: WebSocketMessage = JSON.parse(data.toString());
        const timestamp = new Date().toLocaleTimeString();

        // Debug: log all messages
        // console.log(`${colors.cyan}[${timestamp}] Received message type: ${msg.type}${colors.reset}`)

        switch (msg.type) {
          case "auth_required":
            if (verbose) {
              console.log(
                `${colors.yellow}[${timestamp}] Authentication required (deadline: ${new Date(msg.deadline!).toLocaleTimeString()})${colors.reset}`,
              );
              console.log(
                `${colors.blue}Sending auth token (length: ${token.length})${colors.reset}`,
              );
            }
            ws.send(
              JSON.stringify({
                type: "auth",
                token: token,
              }),
            );
            break;
          case "auth_success":
            console.log(
              `${colors.green}✓ Connected${colors.reset}`,
            );
            if (verbose) {
              console.log(
                `${colors.green}[${timestamp}] DID: ${msg.did}, Certificate: ${msg.certSerial}${colors.reset}`,
              );
            }
            break;
          case "connected":
            if (verbose) {
              console.log(
                `${colors.green}[${timestamp}] Connected successfully${colors.reset}`,
              );
            }
            break;
          case "new_message":
            console.log(
              `${colors.cyan}[${timestamp}] New message:${colors.reset} ${msg.message!.id} with seq ${msg.message!.seq}`,
            );
            break;
          case "message_read":
            console.log(
              `${colors.blue}[${timestamp}] Message read:${colors.reset} ${msg.messageId}`,
            );
            break;
          case "message_deleted":
            console.log(
              `${colors.magenta}[${timestamp}] Message deleted:${colors.reset} ${msg.messageId}`,
            );
            break;
          case "pong":
            // Ignore pong messages
            break;
          default:
            console.log(
              `${colors.yellow}[${timestamp}] ${msg.type}:${colors.reset}`,
              msg,
            );
        }
      } catch {
        console.log(
          `${colors.yellow}[${new Date().toLocaleTimeString()}] Raw message:${colors.reset}`,
          data.toString(),
        );
      }
    });

    ws.on("error", (error) => {
      console.error(
        `${colors.red}WebSocket error:${colors.reset}`,
        error.message,
      );
    });

    ws.on("close", (code, reason) => {
      if (code === 1008) {
        console.log(
          `${colors.red}WebSocket closed: Authentication failed - ${reason}${colors.reset}`,
        );
      } else {
        console.log(
          `${colors.yellow}WebSocket closed: ${code} ${reason}${colors.reset}`,
        );
      }
      process.exit(0);
    });

    // Send periodic pings to keep connection alive
    const pingInterval = setInterval(() => {
      if (ws.readyState === WebSocket.OPEN) {
        ws.send(JSON.stringify({ type: "ping" }));
      }
    }, 30000);

    // Clean up on exit
    process.on("SIGINT", () => {
      clearInterval(pingInterval);
      ws.close();
      process.exit(0);
    });
  },
};

// Show usage information
function showUsage() {
  console.log(`${colors.bright}AT-SMS API Client${colors.reset}`);
  console.log("");
  console.log(
    "Usage: bun src/client/api-client.ts [options] <command> <handle> [args...]",
  );
  console.log("");
  console.log("Options:");
  console.log(
    "  --data-dir <path>         Directory for auth cache and messages (default: ~/.atsms)",
  );
  console.log("  -v, --verbose             Show detailed output");
  console.log("");
  console.log("Commands:");
  console.log(
    "  auth <handle>             - Authenticate and generate new JWT token",
  );
  console.log("  health <handle>           - Check API health");
  console.log("  list <handle> [limit] [after] - List messages");
  console.log("  get <handle> <message-id> - Get a specific message");
  console.log("  delete <handle> <message-id> - Delete a message");
  console.log("  stats <handle>            - Get inbox statistics");
  console.log(
    "  send <handle> <encrypted-file> <recipient1> [recipient2] ... - Send message via WebSocket",
  );
  console.log(
    "  watch <handle>            - Connect to WebSocket for real-time updates",
  );
  console.log("");
  console.log("Examples:");
  console.log("  bun src/client/api-client.ts auth aib0b.bsky.social");
  console.log("  bun src/client/api-client.ts list aib0b.bsky.social");
  console.log("  bun src/client/api-client.ts get aib0b.bsky.social msg-123");
  console.log("  bun src/client/api-client.ts delete aib0b.bsky.social msg-123");
  console.log(
    "  bun src/client/api-client.ts send aib0b.bsky.social ./message.p7m did:plc:abc:4d18ac7f:user@atsms.example.com",
  );
  console.log("  bun src/client/api-client.ts watch aib0b.bsky.social");
  console.log("");
  console.log("  # With custom data directory:");
  console.log(
    "  bun src/client/api-client.ts --data-dir ./chaos-dot-atsms list chaosmokey.skyfi.social",
  );
}

// Main execution
async function main() {
  try {
    // Check if command exists
    const handler = commands[command];
    if (!handler) {
      console.error(
        `${colors.red}Error: Unknown command '${command}'${colors.reset}`,
      );
      showUsage();
      process.exit(1);
    }

    // Special handling for auth command (doesn't require existing JWT)
    if (command === "auth") {
      if (!handle) {
        console.error(
          `${colors.red}Error: Handle required for auth command${colors.reset}`,
        );
        showUsage();
        process.exit(1);
      }
      await (handler as AuthCommandHandler)(handle);
      return;
    }

    // For all other commands, handle is required and JWT must exist
    if (!handle) {
      console.error(`${colors.red}Error: Handle required${colors.reset}`);
      showUsage();
      process.exit(1);
    }

    // Load or generate JWT
    const token = await loadOrGenerateJWT(handle);
    const jwtInfo = parseJWT(token);

    // Check token expiry
    const expiry = new Date(jwtInfo.exp * 1000);
    const now = new Date();
    if (expiry < now) {
      console.error(
        `${colors.red}Error: JWT token expired on ${expiry.toLocaleString()}${colors.reset}`,
      );
      console.error(
        `${colors.yellow}Please run 'bun src/client/api-client.ts auth ${handle}' to refresh${colors.reset}`,
      );
      process.exit(1);
    }

    if (verbose) {
      console.log(`${colors.blue}AT-SMS API Client${colors.reset}`);
      if (dataDir !== DEFAULT_DATA_DIR) {
        console.log(`Data dir: ${colors.yellow}${dataDir}${colors.reset}`);
      }
      console.log(`Handle: ${colors.green}${handle}${colors.reset}`);
      console.log(`DID: ${colors.green}${jwtInfo.did}${colors.reset}`);
      console.log(
        `Certificate: ${colors.green}${jwtInfo.certSerial}${colors.reset}`,
      );
      console.log(
        `Token expires: ${colors.yellow}${expiry.toLocaleString()}${colors.reset}`,
      );
      console.log("");
    }

    // Execute command - pass remaining args after handle
    await (handler as CommandHandler)(token, jwtInfo, ...args.slice(2));
  } catch (error: any) {
    console.error(`${colors.red}Error: ${error.message}${colors.reset}`);
    process.exit(1);
  }
}

// Run the client
main();
