#!/usr/bin/env bun
/**
 * AT-SMS Chat Client
 * Modern IRC-style chat client with REPL support and WebSocket connectivity
 */

import { AtpAgent } from "@atproto/api";
// @ts-expect-error - bun:sqlite is a built-in Bun module
import { Database } from "bun:sqlite";
import chalk from "chalk";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import prompts from "prompts";
import * as readline from "readline";

import { ATSMSClient } from "../lib/atsms-client";
import {
  type ATSMSAnyEndpointCertificate,
  generateEndpointCertificate,
  loadEndpointCertificateWithKey,
} from "../lib/certificates/index";
import { PasswordEncryption } from "../lib/crypto/password-encryption";
import { parseTextContent, parseWebRTCContent } from "../lib/messages";
import { ATSMSStorageManager } from "../lib/storage/manager";
import { SQLiteAdapter } from "../lib/storage/sqlite-adapter";
import { type ATSMSConfig, type ATSMSWebRTCContent } from "../lib/types";
import { ATSMSWebSocketClient } from "../lib/websocket-client";

// AT-SMS API Configuration
const ATSMS_API_DOMAIN = "atsms-api.enumdao.workers.dev";

// Default configuration directory
const DEFAULT_DATA_DIR = path.join(os.homedir(), ".atsms");

// ANSI color codes for better terminal output
const colors = {
  system: chalk.gray,
  error: chalk.red,
  success: chalk.green,
  info: chalk.cyan,
  prompt: chalk.yellow,
  sent: chalk.blue,
  received: chalk.magenta,
  timestamp: chalk.gray,
  warning: chalk.yellow,
};

// SQLite wrapper for Bun compatibility
class BunSQLiteWrapper {
  private db: Database;

  constructor(path: string) {
    this.db = new Database(path);
  }

  exec(sql: string): void {
    this.db.exec(sql);
  }

  prepare(sql: string) {
    const stmt = this.db.prepare(sql);
    return {
      run: (...params: any[]) => stmt.run(...params),
      get: (...params: any[]) => stmt.get(...params),
      all: (...params: any[]) => stmt.all(...params),
    };
  }

  transaction<T>(fn: () => T): T {
    return this.db.transaction(fn)();
  }

  close() {
    this.db.close();
  }
}

interface AuthCache {
  [handle: string]: {
    did: string;
    accessJwt: string;
    refreshJwt: string;
    expiresAt: number;
    pdsUrl?: string;
  };
}

interface ChatState {
  handle: string;
  did: string;
  agent: AtpAgent;
  atsmsClient: ATSMSClient;
  storageManager: ATSMSStorageManager;
  wsClient: ATSMSWebSocketClient | null;
  currentConversation: string | null;
  endpointCert: ATSMSAnyEndpointCertificate | null;
}

class ChatClient {
  private rl: readline.Interface;
  private state: ChatState | null = null;
  private authCache: AuthCache = {};
  private db: BunSQLiteWrapper;
  private commandHistory: string[] = [];
  private debug: boolean = false;
  private replActive: boolean = false; // Track if REPL has started
  private config: ATSMSConfig = {
    apiUrl: `https://${ATSMS_API_DOMAIN}`,
  };

  // Configurable paths
  private dataDir: string;
  private authCacheFile: string;
  private historyFile: string;
  private dbFile: string;

  constructor(dataDir?: string) {
    // Set data directory (use provided or default)
    this.dataDir = dataDir || DEFAULT_DATA_DIR;
    this.authCacheFile = path.join(this.dataDir, "auth-cache.json");
    this.historyFile = path.join(this.dataDir, "chat-history.txt");
    this.dbFile = path.join(this.dataDir, "messages.db");

    // Ensure config directory exists
    if (!fs.existsSync(this.dataDir)) {
      fs.mkdirSync(this.dataDir, { recursive: true });
    }

    // Initialize SQLite database
    this.db = new BunSQLiteWrapper(this.dbFile);

    // Load auth cache
    this.loadAuthCache();

    // Setup readline interface with history support and tab completion
    this.rl = readline.createInterface({
      input: process.stdin,
      output: process.stdout,
      historySize: 1000,
      prompt: "> ",
      completer: (line: string) => this.handleTabCompletion(line),
    });

    // Load command history
    this.loadHistory();

    // Setup history persistence
    this.rl.on("line", (line) => {
      if (line.trim()) {
        this.commandHistory.push(line);
        this.saveHistory();
      }
    });

    // Handle Ctrl+C gracefully
    this.rl.on("SIGINT", () => {
      this.cleanup();
      process.exit(0);
    });
  }

  private loadAuthCache() {
    try {
      if (fs.existsSync(this.authCacheFile)) {
        const data = fs.readFileSync(this.authCacheFile, "utf-8");
        this.authCache = JSON.parse(data);
      }
    } catch (error) {
      console.error(colors.error("Failed to load auth cache:", error));
    }
  }

  private saveAuthCache() {
    try {
      fs.writeFileSync(
        this.authCacheFile,
        JSON.stringify(this.authCache, null, 2),
      );
    } catch (error) {
      console.error(colors.error("Failed to save auth cache:", error));
    }
  }

  private loadHistory() {
    try {
      if (fs.existsSync(this.historyFile)) {
        const history = fs
          .readFileSync(this.historyFile, "utf-8")
          .split("\n")
          .filter((line) => line.trim());

        // Add to readline history (in reverse order for proper history navigation)
        history.reverse().forEach((line) => {
          (this.rl as any).history.push(line);
        });

        this.commandHistory = history;
      }
    } catch (error) {
      console.error(colors.error("Failed to load history:", error));
    }
  }

  private saveHistory() {
    try {
      // Keep last 1000 commands
      const recentHistory = this.commandHistory.slice(-1000);
      fs.writeFileSync(this.historyFile, recentHistory.join("\n"));
    } catch (error) {
      console.error(colors.error("Failed to save history:", error));
    }
  }

  /**
   * Recreate readline interface and restore all event listeners
   * This is needed after prompts that close readline (like password prompts)
   */
  private recreateReadline(history: string[]) {
    this.rl = readline.createInterface({
      input: process.stdin,
      output: process.stdout,
      historySize: 1000,
      prompt: "> ",
      completer: (line: string) => this.handleTabCompletion(line),
    });

    // Restore history
    if (history.length > 0) {
      (this.rl as any).history = history;
    }

    // Re-setup SIGINT handler
    this.rl.on("SIGINT", () => {
      this.cleanup();
      process.exit(0);
    });

    // Re-setup history persistence handler (from constructor)
    this.rl.on("line", (line) => {
      if (line.trim()) {
        this.commandHistory.push(line);
        this.saveHistory();
      }
    });

    // Only add command handler if REPL has already started
    // (otherwise startRepl() will add it)
    if (this.replActive) {
      this.rl.on("line", async (input) => {
        const trimmed = input.trim();

        if (!trimmed) {
          this.updatePrompt();
          return;
        }

        // Check for commands (must start with '/')
        if (trimmed.startsWith("/")) {
          await this.handleCommand(trimmed.substring(1));
        } else if (this.state?.currentConversation) {
          // In conversation mode - send message
          await this.sendMessage(trimmed);
        } else {
          // Not in conversation - show warning
          console.log(
            colors.warning(
              "⚠ You need to be in a conversation to send messages",
            ),
          );
          console.log(
            colors.info(
              "Use /msg <handle> to start a conversation, or type /help for all commands",
            ),
          );
        }

        this.updatePrompt();
      });
    }
  }

  private async promptPassword(message: string): Promise<string> {
    // Save readline history before closing
    const history = (this.rl as any).history
      ? [...(this.rl as any).history]
      : [];

    // Completely close readline to avoid conflicts
    this.rl.close();

    const response = await prompts({
      type: "password",
      name: "password",
      message: message,
    });

    // Recreate readline and restore all event listeners
    this.recreateReadline(history);

    return response.password || "";
  }

  private cleanup() {
    console.log(colors.system("\n\nGoodbye!"));
    this.rl.close();
    this.state?.wsClient?.disconnect();
    this.db.close();
  }

  async start(initialHandle?: string) {
    console.log(
      colors.info(`
╔═══════════════════════════════════════╗
║       AT-SMS Chat Client v1.0         ║
║  Type '/?' for help, '/quit' to exit  ║
╚═══════════════════════════════════════╝
`),
    );

    // Get handle from argument, cached auth, or prompt
    let handle = initialHandle;

    if (!handle) {
      // Check for cached authentication
      const cachedHandles = Object.keys(this.authCache);
      if (cachedHandles.length === 1) {
        // Single cached account - use it automatically
        handle = cachedHandles[0];
        console.log(colors.info(`Using cached account: ${handle}`));
      } else if (cachedHandles.length > 1) {
        // Multiple cached accounts - let user choose
        console.log(colors.info("Multiple cached accounts found:"));
        cachedHandles.forEach((h, i) => {
          const entry = this.authCache[h];
          const expired = entry.expiresAt <= Date.now();
          const status = expired ? colors.warning(" (expired)") : "";
          console.log(colors.info(`  ${i + 1}. ${h}${status}`));
        });
        handle = await this.promptForHandle();
      } else {
        // No cached accounts - prompt for handle
        handle = await this.promptForHandle();
      }
    }

    // Authenticate
    await this.authenticate(handle);

    // Start main REPL loop
    this.startRepl();
  }

  private async promptForHandle(): Promise<string> {
    return new Promise((resolve) => {
      this.rl.question(
        colors.prompt("Enter your handle or DID (e.g., alice.bsky.social): "),
        (answer) => {
          resolve(answer.trim());
        },
      );
    });
  }

  private async authenticate(identifier: string) {
    try {
      // Parse identifier (handle or DID) to get PDS URL
      const pdsUrl = await this.resolvePDS(identifier);

      // Check for cached auth
      // If input is a DID, find cached entry by DID; otherwise by handle
      let cached = this.authCache[identifier];
      let cachedHandle = identifier;

      if (!cached && identifier.startsWith("did:")) {
        // Look up by DID in cached entries
        for (const [handle, entry] of Object.entries(this.authCache)) {
          if (entry.did === identifier && entry.expiresAt > Date.now()) {
            cached = entry;
            cachedHandle = handle;
            break;
          }
        }
      }

      if (cached && cached.expiresAt > Date.now()) {
        if (this.debug) {
          console.log(colors.success("[DEBUG] Using cached authentication"));
        }
        try {
          if (this.debug) {
            console.log(
              colors.success("[DEBUG] About to call setupSession..."),
            );
          }
          await this.setupSession(
            cachedHandle,
            cached.did,
            cached.accessJwt,
            cached.refreshJwt,
            pdsUrl,
          );
          return;
        } catch (error: any) {
          console.log(
            colors.error(
              `[CAUGHT ERROR] ${error?.error || error?.message || error}`,
            ),
          );
          // Check if token expired - try to refresh
          const isExpiredToken =
            error?.error === "ExpiredToken" ||
            error?.message?.includes("expired") ||
            error?.message?.includes("Expired") ||
            String(error).includes("ExpiredToken");

          if (this.debug) {
            console.log(
              colors.warning(
                `[DEBUG] Cached auth failed: ${error?.error || error?.message || error}`,
              ),
            );
            console.log(
              colors.warning(`[DEBUG] Is expired token: ${isExpiredToken}`),
            );
          }

          if (isExpiredToken) {
            if (this.debug) {
              console.log(
                colors.warning(
                  "[DEBUG] Cached token expired, attempting refresh...",
                ),
              );
            }
            try {
              // Try to refresh using the refresh token
              const agent = new AtpAgent({ service: pdsUrl });
              agent.resumeSession({
                did: cached.did,
                accessJwt: cached.accessJwt,
                refreshJwt: cached.refreshJwt,
                handle: cachedHandle,
                active: true,
              });
              const refreshed = await agent.refreshSession();
              if (refreshed.success) {
                // Update cache with new tokens
                this.authCache[cachedHandle] = {
                  ...cached,
                  accessJwt: refreshed.data.accessJwt,
                  refreshJwt: refreshed.data.refreshJwt,
                  expiresAt: Date.now() + 2 * 60 * 60 * 1000, // 2 hours (match actual token lifetime)
                };
                this.saveAuthCache();
                if (this.debug) {
                  console.log(
                    colors.success("[DEBUG] Token refreshed successfully"),
                  );
                }
                await this.setupSession(
                  cachedHandle,
                  cached.did,
                  refreshed.data.accessJwt,
                  refreshed.data.refreshJwt,
                  pdsUrl,
                );
                return;
              }
            } catch (refreshError: any) {
              if (this.debug) {
                console.log(
                  colors.warning(
                    `[DEBUG] Token refresh failed: ${refreshError?.message || refreshError}`,
                  ),
                );
              }
            }
            // Clear invalid cache entry
            delete this.authCache[cachedHandle];
            this.saveAuthCache();
            console.log(
              colors.warning("Session expired. Please log in again."),
            );
            // Fall through to fresh authentication
          } else {
            // For non-token-expiry errors, also fall through but log it
            if (this.debug) {
              console.log(
                colors.warning(
                  "[DEBUG] Non-expiry auth error, will re-authenticate",
                ),
              );
            }
            delete this.authCache[cachedHandle];
            this.saveAuthCache();
            console.log(
              colors.warning("Authentication issue. Please log in again."),
            );
            // Fall through to fresh authentication
          }
        }
      }

      // Need to authenticate
      console.log(colors.info(`Authenticating with PDS at ${pdsUrl}...`));

      // Get password
      const password = await this.promptForPassword();

      // Create agent and authenticate
      const agent = new AtpAgent({ service: pdsUrl });
      const response = await agent.login({
        identifier,
        password,
      });

      // Use resolved handle from login response (handles DID input)
      const resolvedHandle = response.data.handle;

      // Cache the auth with resolved handle as key
      // Note: AT Protocol access tokens expire in ~2 hours, but we store refresh token too
      this.authCache[resolvedHandle] = {
        did: response.data.did,
        accessJwt: response.data.accessJwt,
        refreshJwt: response.data.refreshJwt,
        expiresAt: Date.now() + 2 * 60 * 60 * 1000, // 2 hours (will auto-refresh if needed)
        pdsUrl,
      };
      this.saveAuthCache();

      await this.setupSession(
        resolvedHandle,
        response.data.did,
        response.data.accessJwt,
        response.data.refreshJwt,
        pdsUrl,
      );
    } catch (error) {
      console.error(colors.error(`Authentication failed: ${error}`));
      process.exit(1);
    }
  }

  private async resolvePDS(identifier: string): Promise<string> {
    // Handle DID input - resolve PDS from plc.directory
    if (identifier.startsWith("did:plc:")) {
      try {
        const plcResponse = await fetch(`https://plc.directory/${identifier}`);
        if (plcResponse.ok) {
          const didDoc = await plcResponse.json();
          const pdsService = didDoc.service?.find(
            (s: any) => s.id === "#atproto_pds",
          );
          if (pdsService?.serviceEndpoint) {
            return pdsService.serviceEndpoint;
          }
        }
      } catch {
        // Fall through to default
      }
      return "https://bsky.social";
    }

    // Try to resolve via .well-known/atproto-did on the handle's domain
    if (identifier.endsWith(".bsky.social")) {
      return "https://bsky.social";
    }

    // For custom domain handles, try to resolve the DID first
    // The domain part of the handle should serve .well-known/atproto-did
    const parts = identifier.split(".");
    if (parts.length >= 2) {
      // Try the full domain first (e.g., skyfi.social for chaosmokey.skyfi.social)
      const domain = parts.slice(1).join(".");
      try {
        const response = await fetch(
          `https://${domain}/.well-known/atproto-did`,
        );
        if (response.ok) {
          const did = (await response.text()).trim();
          // Now resolve the DID to get the PDS URL
          if (did.startsWith("did:plc:")) {
            const plcResponse = await fetch(`https://plc.directory/${did}`);
            if (plcResponse.ok) {
              const didDoc = await plcResponse.json();
              const pdsService = didDoc.service?.find(
                (s: any) => s.id === "#atproto_pds",
              );
              if (pdsService?.serviceEndpoint) {
                return pdsService.serviceEndpoint;
              }
            }
          } else if (did.startsWith("did:web:")) {
            // For did:web, the PDS is typically on the same domain
            return `https://${domain}`;
          }
        }
      } catch {
        // Fall through to default
      }
    }

    // Default to bsky.social
    return "https://bsky.social";
  }

  private async promptForPassword(): Promise<string> {
    // Save readline history before closing
    const history = (this.rl as any).history
      ? [...(this.rl as any).history]
      : [];

    // Completely close readline to avoid conflicts
    this.rl.close();

    const response = await prompts({
      type: "password",
      name: "password",
      message: "Password",
    });

    // Recreate readline and restore all event listeners
    this.recreateReadline(history);

    return response.password || "";
  }

  private async setupSession(
    handle: string,
    did: string,
    accessJwt: string,
    refreshJwt: string,
    pdsUrl: string,
  ) {
    // Create agent with auth
    const agent = new AtpAgent({ service: pdsUrl });
    agent.resumeSession({
      did,
      accessJwt,
      refreshJwt,
      handle,
      active: true,
    });

    // Create ATSMS client
    const atsmsClient = new ATSMSClient(agent, did);

    // Setup storage early so we can check for local certificates
    const storage = new SQLiteAdapter(this.db);

    // Check for endpoint certificate
    let endpointCert: ATSMSAnyEndpointCertificate | null = null;
    let hasPrivateKey = false;

    try {
      const certs = await atsmsClient.getUserCertificates(did);
      const localCerts = await storage.listCertificates(did);

      // Check for endpoint certificates
      if (certs.endpointCerts && certs.endpointCerts.length > 0) {
        if (this.debug) {
          console.log(
            colors.info(
              `[DEBUG] Found ${certs.endpointCerts.length} endpoint cert(s) on PDS: ${certs.endpointCerts.map((c) => c.serialNumber).join(", ")}`,
            ),
          );
        }
        // Find a certificate with private key (in memory first)
        for (const cert of certs.endpointCerts) {
          if (cert.privateKey || cert.certificatePrivateKeyPEM) {
            endpointCert = cert;
            hasPrivateKey = true;
            if (this.debug) {
              console.log(
                colors.success(
                  "[DEBUG] ✓ Endpoint certificate with private key loaded",
                ),
              );
            }
            break;
          }
        }

        // If no private key in memory, check local storage
        if (!hasPrivateKey) {
          for (const cert of certs.endpointCerts) {
            const localCert = localCerts.find(
              (c) =>
                c.type === "endpoint" && c.serialNumber === cert.serialNumber,
            );
            if (localCert?.hasPrivateKey && localCert.privateKeyPEM) {
              try {
                // Reconstruct proper endpoint certificate instance with private key
                const privateKeyPEM = localCert.privateKeyPEM;

                if (localCert.isEncrypted) {
                  // Set encrypted flag so password will be prompted when needed
                  const certWithEncryptedKey = {
                    ...cert,
                    encryptedPrivateKeyPEM: localCert.privateKeyPEM,
                    serialNumber: cert.serialNumber,
                  };
                  endpointCert = certWithEncryptedKey as any;
                  hasPrivateKey = true;
                  if (this.debug) {
                    console.log(
                      colors.success(
                        "[DEBUG] ✓ Endpoint certificate found with encrypted private key in local storage",
                      ),
                    );
                    console.log(
                      colors.info(
                        "[DEBUG]   (Password will be required when sending messages)",
                      ),
                    );
                  }
                } else {
                  // Load certificate with unencrypted private key
                  endpointCert = await loadEndpointCertificateWithKey(
                    localCert.certificatePEM,
                    privateKeyPEM,
                  );
                  hasPrivateKey = true;
                  if (this.debug) {
                    console.log(
                      colors.success(
                        "[DEBUG] ✓ Endpoint certificate found with private key in local storage",
                      ),
                    );
                  }
                }
                break;
              } catch (innerError: any) {
                console.log(
                  colors.error(
                    `Failed to create cert with key: ${innerError.message}`,
                  ),
                );
              }
            }
          }
        }

        if (!hasPrivateKey && certs.endpointCerts.length > 0) {
          endpointCert = certs.endpointCerts[0];
          console.log(
            colors.warning(
              "⚠ Endpoint certificate found but private key not available locally",
            ),
          );
          console.log(
            colors.error(
              "❌ Cannot send messages - endpoint certificate private key required",
            ),
          );
          console.log(
            colors.info(
              "\nCertificates exist but were created on a different device.",
            ),
          );
          console.log(colors.info("\nYour options:"));
          console.log(
            colors.info("  1. Import your certificates from the other device"),
          );
          console.log(
            colors.info(
              '  2. Type "/gencert" to create a NEW certificate for this device',
            ),
          );
        }
      } else {
        console.log(colors.error("\n⚠ No AT-SMS certificates found!"));
        console.log(
          colors.info(
            "\nYou need a certificate to send and receive AT-SMS messages.",
          ),
        );
        console.log(colors.info("\nTo get started:"));
        console.log(
          colors.info('  1. Type "/gencert" to generate a certificate'),
        );
        console.log(
          colors.info('  2. Type "/listcerts" to verify your certificate'),
        );
        console.log(
          colors.info("\nAlternatively, run: bun atsms.ts init " + handle),
        );
      }
    } catch (error: any) {
      console.log(
        colors.error(
          `⚠ Could not check certificates: ${error?.message || error}`,
        ),
      );
      if (error?.stack) {
        // Show more of the stack to find the exact line
        const stack = error.stack.split("\n");
        console.log(
          colors.system(`Stack trace: ${stack.slice(0, 3).join("\n")}`),
        );
      }
      console.log(colors.info("\nTo initialize certificates:"));
      console.log(colors.info('  Type "/gencert" to generate a certificate'));
    }
    const storageManager = new ATSMSStorageManager({
      storage,
      atsmsClient,
      inboxUrl: `https://${ATSMS_API_DOMAIN}`,
      onMessageAdded: (message) => {
        this.handleNewMessage(message.convoId, message.id);
      },
      onConversationUpdated: (convoId) => {
        this.handleConversationUpdate(convoId);
      },
    });

    // Start transport if endpoint certificate is available and DID exists
    if (endpointCert) {
      const existingDid = await storageManager.getDid(did);
      if (existingDid) {
        // DID already saved, just start transport
        await storageManager.startTransport(did);
      }
      // Note: If DID doesn't exist, user needs to run /genendpoint to save it
    }

    // Setup WebSocket connection using library factory
    let wsClient: ATSMSWebSocketClient | null = null;

    if (endpointCert && endpointCert.certificatePrivateKeyPEM) {
      try {
        // Use the library's createWebSocketClient factory method
        // This handles all message processing automatically
        wsClient = await storageManager.createWebSocketClient(endpointCert, {
          onError: (error: Error) => {
            if (this.debug) {
              console.error(colors.error("[WebSocket Error]"), error);
            } else {
              console.log(
                colors.warning(
                  `⚠ WebSocket connection issue: ${error.message || "Connection failed"}`,
                ),
              );
            }
          },
          onDisconnect: (code: number, reason: string) => {
            if (this.debug) {
              console.log(
                colors.system(`[DEBUG] WebSocket closed: ${code} - ${reason}`),
              );
            } else if (code !== 1000) {
              // Only show disconnect message for unexpected disconnects (not normal closure)
              console.log(colors.warning("⚠ WebSocket disconnected"));
            }
          },
          onConnect: () => {
            if (this.debug) {
              console.log(colors.success("[DEBUG] ✓ Connected to WebSocket"));
            }
          },
        });

        await wsClient!.connect();
        if (this.debug) {
          console.log(colors.success("[DEBUG] ✓ Connected to WebSocket"));
        }
      } catch (error: any) {
        if (this.debug) {
          console.error(colors.error("Failed to connect to WebSocket:"), error);
        } else {
          console.log(
            colors.warning(
              `⚠ Could not connect to WebSocket: ${error.message || "Connection failed"}`,
            ),
          );
        }
      }
    } else if (endpointCert) {
      console.log(
        colors.warning(
          "⚠ WebSocket not connected - private key not available",
        ),
      );
    }

    // Save state
    this.state = {
      handle,
      did,
      agent,
      atsmsClient,
      storageManager,
      wsClient,
      currentConversation: null,
      endpointCert,
    };

    console.log(colors.success(`\n✓ Logged in as ${handle} (${did})`));

    // Pre-populate handle cache from conversations for tab completion
    this.populateHandleCache();
  }

  private async handleNewMessage(convoId: string, messageId: string) {
    // If we're in the conversation, show the message and mark as read
    if (this.state?.currentConversation === convoId) {
      await this.displayNewMessage(messageId);
      // Mark conversation as read since we're viewing it
      await this.state.storageManager.markConversationRead(convoId);
    } else {
      // Show notification
      this.showNotification(convoId, messageId);
    }
  }

  private handleConversationUpdate(convoId: string) {
    // Refresh conversation view if we're in it
    if (this.state?.currentConversation === convoId) {
      // Conversation metadata updated
    }
  }

  private async displayNewMessage(messageId: string) {
    if (!this.state) return;

    try {
      // Access storage through the storage manager's storage property
      const storage = (this.state.storageManager as any).storage;
      const message = await storage.getMessage(messageId);
      if (message) {
        const isSent = message.senderId === this.state.did;
        const prefix = isSent ? colors.sent("→") : colors.received("←");
        const sender = isSent ? "You" : this.getHandleFromDid(message.senderId);
        const time = colors.timestamp(
          new Date(message.createdAt).toLocaleTimeString(),
        );
        const messageText = this.getMessageText(message);

        console.log(`\n${prefix} ${time} ${sender}: ${messageText}`);
        this.updatePrompt();
      }
    } catch (error) {
      console.error(colors.error("Error displaying message:", error));
    }
  }

  private async showNotification(convoId: string, messageId: string) {
    if (!this.state) return;

    try {
      const message = await (
        this.state.storageManager as any
      ).storage.getMessage(messageId);
      if (message && message.senderId !== this.state.did) {
        const sender = this.getHandleFromDid(message.senderId);
        console.log(colors.info(`\n[New message from ${sender}]`));
        this.updatePrompt();
      }
    } catch {
      // Silently fail notifications
    }
  }

  private getHandleFromDid(did: string): string {
    // Check if we have a cached handle for this DID
    const handles = (this.state as any)?.didToHandle || {};
    if (handles[did]) {
      return handles[did];
    }

    // Return truncated DID as fallback
    // The caller should resolve this if needed
    return did.substring(0, 15) + "...";
  }

  private async resolveHandleFromDid(did: string): Promise<string> {
    // First check cache
    const cachedHandle = this.getHandleFromDid(did);
    if (!cachedHandle.endsWith("...")) {
      return cachedHandle;
    }

    // Try to resolve via AT Protocol
    if (this.state?.agent) {
      try {
        const response = await this.state.agent.api.app.bsky.actor.getProfile({
          actor: did,
        });
        if (response.data.handle) {
          // Cache the resolved handle
          this.cacheHandleForDid(did, response.data.handle);
          return response.data.handle;
        }
      } catch {
        // Failed to resolve, return truncated DID
      }
    }

    return cachedHandle;
  }

  private cacheHandleForDid(did: string, handle: string) {
    if (!this.state) return;
    (this.state as any).didToHandle = (this.state as any).didToHandle || {};
    (this.state as any).didToHandle[did] = handle;
  }

  private async populateHandleCache() {
    if (!this.state) return;

    try {
      // Get all conversations
      const conversations = await this.state.storageManager.listConversations();

      // Resolve handles for all participants
      const resolvePromises: Promise<void>[] = [];

      for (const conv of conversations) {
        const otherParticipant = conv.participantIds.find(
          (id) => id !== this.state!.did,
        );
        if (otherParticipant) {
          // Check if we already have this handle cached
          const cached = this.getHandleFromDid(otherParticipant);
          if (cached.endsWith("...")) {
            // Need to resolve this DID
            resolvePromises.push(
              this.resolveHandleFromDid(otherParticipant).then(() => {}),
            );
          }
        }
      }

      // Resolve all handles in parallel
      await Promise.all(resolvePromises);
    } catch {
      // Silently fail, tab completion will work with whatever we have
    }
  }

  private handleTabCompletion(line: string): [string[], string] {
    // Split the line to get the command and arguments
    const parts = line.trim().split(/\s+/);
    const cmd = parts[0] || "";
    const lastPart = parts[parts.length - 1] || "";

    // If we're in a conversation, don't complete commands
    if (this.state?.currentConversation) {
      return [[], line];
    }

    // If typing the first word, complete commands
    if (parts.length <= 1) {
      const commands = [
        "help",
        "?",
        "quit",
        "exit",
        "msg",
        "message",
        "list",
        "ls",
        "back",
        "leave",
        "refresh",
        "sync",
        "info",
        "gencert",
        "genendpoint",
        "listcerts",
        "certs",
        "clear",
        "whoami",
      ];

      const matches = commands.filter((c) => c.startsWith(cmd.toLowerCase()));
      return [matches, cmd];
    }

    // If typing after 'msg' or 'message', complete with handles
    if ((cmd === "msg" || cmd === "message") && parts.length === 2) {
      // Get all known handles from cache
      const handles: string[] = [];

      // Add handles from didToHandle cache
      if (this.state && (this.state as any).didToHandle) {
        const cache = (this.state as any).didToHandle;
        for (const did in cache) {
          const handle = cache[did];
          if (handle && !handle.endsWith("...")) {
            handles.push(handle);
          }
        }
      }

      // Add handles from recent conversations if available
      if (this.state?.storageManager) {
        // This is async, but completer needs sync, so we use cached handles only
        // In a real implementation, we'd maintain a separate handle cache
      }

      // Filter handles that match the input
      const matches = handles.filter((h) =>
        h.toLowerCase().startsWith(lastPart.toLowerCase()),
      );

      // If no matches but partial input, return the partial to prevent clearing
      if (matches.length === 0 && lastPart) {
        return [[lastPart], lastPart];
      }

      return [matches, lastPart];
    }

    return [[], line];
  }

  private startRepl() {
    this.replActive = true; // Mark REPL as active for recreateReadline()
    this.updatePrompt();

    this.rl.on("line", async (input) => {
      const trimmed = input.trim();

      if (!trimmed) {
        this.updatePrompt();
        return;
      }

      // Check for commands (must start with '/')
      if (trimmed.startsWith("/")) {
        await this.handleCommand(trimmed.substring(1));
      } else if (this.state?.currentConversation) {
        // In conversation mode - send message
        await this.sendMessage(trimmed);
      } else {
        // Not in conversation - show warning
        console.log(
          colors.warning(
            "⚠ You need to be in a conversation to send messages",
          ),
        );
        console.log(
          colors.info(
            "Use /msg <handle> to start a conversation, or type /help for all commands",
          ),
        );
      }

      this.updatePrompt();
    });
  }

  private async handleCommand(command: string) {
    const parts = command.split(" ");
    const cmd = parts[0].toLowerCase();
    const args = parts.slice(1);

    switch (cmd) {
      case "?":
      case "help":
        this.showHelp();
        break;

      case "msg":
      case "message":
        if (args.length > 0) {
          await this.enterConversation(args[0]);
        } else {
          console.log(colors.error("Usage: msg <handle or DID>"));
        }
        break;

      case "list":
      case "ls":
        await this.listConversations();
        break;

      case "back":
      case "leave":
      case "exit":
        if (this.state?.currentConversation) {
          this.exitConversation();
        } else {
          console.log(colors.info("Not in a conversation"));
        }
        break;

      case "refresh":
      case "sync":
        await this.syncMessages();
        break;

      case "info":
        this.showInfo();
        break;

      case "gencert":
      case "genendpoint":
        await this.generateCertificate();
        break;

      case "listcerts":
      case "certs":
        await this.listCertificates();
        break;

      case "call":
        if (this.state?.currentConversation) {
          const mediaType = (args[0] || "audio") as "audio" | "video";
          await this.sendTestWebRTCOffer(mediaType);
        } else {
          console.log(colors.error("Must be in a conversation to send call"));
        }
        break;

      case "quit":
      case "q":
        this.cleanup();
        process.exit(0);
        break;

      default:
        console.log(
          colors.error(`Unknown command: ${cmd}. Type '/?' for help`),
        );
    }
  }

  private showHelp() {
    console.log(
      colors.info(`
Available commands:
  /?                    Show this help
  /msg <handle>         Start conversation with user
  /list                 List all conversations
  /back                 Exit current conversation
  /refresh              Sync messages from server
  /info                 Show account info

Certificate Management:
  /gencert              Generate a self-signed certificate
  /listcerts            List all certificates

WebRTC Testing (Debug):
  /call [audio|video]   Send test WebRTC call offer (does not create real call)

  /quit                 Exit chat client

In conversation mode:
  - Type message and press Enter to send
  - Type /back to exit conversation
  - Type /? for help
`),
    );
  }

  private async enterConversation(recipient: string) {
    if (!this.state) return;

    try {
      // Resolve recipient to DID if needed
      let recipientDid = recipient;
      let recipientHandle = recipient;

      if (!recipient.startsWith("did:")) {
        // All handles need to be resolved to DIDs, including AT-SMS handles
        try {
          let resolved = null;

          // Try different PDS endpoints
          const pdsUrls = [
            "https://bsky.social",
            `https://${recipient.split(".").slice(-2).join(".")}`, // Try domain-based PDS
          ];

          for (const pdsUrl of pdsUrls) {
            try {
              const agent = new AtpAgent({ service: pdsUrl });
              resolved = await agent.resolveHandle({ handle: recipient });
              if (resolved?.data?.did) {
                recipientDid = resolved.data.did;
                console.log(
                  colors.system(`Resolved ${recipient} to ${recipientDid}`),
                );
                break;
              }
            } catch {
              // Try next PDS
              continue;
            }
          }

          if (!recipientDid || recipientDid === recipient) {
            console.log(
              colors.error(`Could not resolve handle ${recipient} to DID`),
            );
            console.log(
              colors.info(
                `Please ensure the handle is correct and the user has an AT Protocol account`,
              ),
            );
            return;
          }
        } catch {
          console.log(colors.error(`Failed to resolve ${recipient}: ${error}`));
          return;
        }
      } else {
        // It's already a DID, try to get handle
        recipientHandle = recipientDid;
      }

      // Validate recipient has AT-SMS setup (at least one endpoint certificate)
      console.log(
        colors.system(`Checking AT-SMS setup for ${recipientHandle}...`),
      );
      try {
        const recipientCerts =
          await this.state.atsmsClient.getUserCertificates(recipientDid);

        if (recipientCerts.error === "NOT_ATPROTO_USER") {
          console.log(
            colors.error(
              `✗ ${recipientHandle} is not a valid AT Protocol user`,
            ),
          );
          console.log(colors.info("  Please verify the handle/DID is correct"));
          return;
        }

        if (recipientCerts.error === "NO_ATSMS_CERTS") {
          console.log(
            colors.error(`✗ ${recipientHandle} has not set up AT-SMS`),
          );
          console.log(
            colors.info(
              "  They need to run /gencert to generate a certificate before receiving encrypted messages",
            ),
          );
          return;
        }

        if (
          recipientCerts.error === "NO_ENDPOINT_CERTS" ||
          recipientCerts.endpointCerts.length === 0
        ) {
          console.log(
            colors.error(`✗ ${recipientHandle} has no endpoint certificates`),
          );
          console.log(
            colors.info("  They need to run /gencert to create a certificate"),
          );
          return;
        }

        if (recipientCerts.error === "FETCH_ERROR") {
          console.log(
            colors.warning(
              `⚠ Could not verify AT-SMS setup for ${recipientHandle}`,
            ),
          );
          console.log(
            colors.info(
              "  Network error - continuing anyway, but sending messages may fail",
            ),
          );
        } else {
          // Success - show certificate info
          console.log(
            colors.success(
              `✓ ${recipientHandle} has ${recipientCerts.endpointCerts.length} endpoint certificate(s)`,
            ),
          );
          if (this.debug) {
            console.log(
              colors.info(
                `[DEBUG] Endpoint cert serials: ${recipientCerts.endpointCerts.map((c) => c.serialNumber).join(", ")}`,
              ),
            );
          }
        }
      } catch (error: any) {
        console.log(
          colors.warning(
            `⚠ Failed to validate AT-SMS setup for ${recipientHandle}: ${error.message}`,
          ),
        );
        console.log(
          colors.info("  Continuing anyway, but sending messages may fail"),
        );
      }

      // Find or create conversation using library method
      const conversation =
        await this.state.storageManager.getOrCreateConversation([
          this.state.did,
          recipientDid,
        ]);

      this.state.currentConversation = conversation.id;

      // Store handle mapping for display
      (this.state as any).conversationHandles =
        (this.state as any).conversationHandles || {};
      (this.state as any).conversationHandles[conversation.id] =
        recipientHandle;

      // Cache DID to handle mapping
      this.cacheHandleForDid(recipientDid, recipientHandle);

      // Show conversation header
      console.log(
        colors.info(`\n═══ Conversation with ${recipientHandle} ═══`),
      );

      // Load and display message history
      await this.displayConversationHistory(conversation.id);

      // Mark conversation as read when entering it
      await this.state.storageManager.markConversationRead(conversation.id);

      console.log(colors.system("(Type /back to exit conversation)\n"));
    } catch {
      console.error(colors.error("Failed to enter conversation"));
    }
  }

  private async displayConversationHistory(convoId: string) {
    if (!this.state) return;

    try {
      const messages = await this.state.storageManager.getMessages(convoId, 20);

      if (messages.length === 0) {
        console.log(colors.system("(No messages yet)"));
        return;
      }

      // Collect unique sender DIDs that need resolution
      const senderDids = new Set<string>();
      messages.forEach((msg) => {
        if (msg.senderId !== this.state!.did) {
          const cached = this.getHandleFromDid(msg.senderId);
          if (cached.endsWith("...")) {
            senderDids.add(msg.senderId);
          }
        }
      });

      // Resolve all unknown handles in parallel
      const handlePromises = Array.from(senderDids).map((did) =>
        this.resolveHandleFromDid(did),
      );
      await Promise.all(handlePromises);

      // Display messages in chronological order (already sorted ascending by storage layer)
      messages.forEach((message) => {
        const isSent = message.senderId === this.state!.did;
        const prefix = isSent ? colors.sent("→") : colors.received("←");
        const sender = isSent ? "You" : this.getHandleFromDid(message.senderId);
        const time = colors.timestamp(
          new Date(message.createdAt).toLocaleTimeString(),
        );
        const messageText = this.getMessageText(message);

        console.log(`${prefix} ${time} ${sender}: ${messageText}`);
      });
    } catch {
      console.error(colors.error("Failed to load message history"));
    }
  }

  private exitConversation() {
    if (!this.state) return;

    this.state.currentConversation = null;
    console.log(colors.info("Exited conversation"));
  }

  private async sendMessage(text: string) {
    if (!this.state || !this.state.currentConversation) return;

    if (!this.state.endpointCert) {
      console.log(
        colors.error("\n⚠ Cannot send messages without endpoint certificate"),
      );
      console.log(colors.info("To fix this:"));
      console.log(colors.info("  1. Type /back to exit conversation"));
      console.log(
        colors.info('  2. Type "/listcerts" to check your certificates'),
      );
      console.log(
        colors.info('  3. If no certificates, type "/gencert" to generate one'),
      );
      console.log(colors.info("  4. Try sending again"));
      return;
    }

    // Check for private key - first in memory, then in local storage
    let endpointCertWithKey = this.state.endpointCert;
    const hasMemoryKey =
      this.state.endpointCert.privateKey ||
      this.state.endpointCert.certificatePrivateKeyPEM;

    if (!hasMemoryKey) {
      // Try to load from local storage
      const storage = this.state.storageManager.getStorage() as SQLiteAdapter;
      const localCert = await storage.getCertificate(
        this.state.did,
        "endpoint",
        this.state.endpointCert.serialNumber,
      );

      if (localCert && localCert.privateKeyPEM) {
        let privateKeyPEM = localCert.privateKeyPEM;

        if (localCert.isEncrypted) {
          const password = await this.promptPassword(
            "Enter password to decrypt endpoint certificate: ",
          );
          if (!password) {
            console.log(
              colors.error("Password required to decrypt private key"),
            );
            return;
          }
          try {
            privateKeyPEM = PasswordEncryption.decrypt(
              localCert.privateKeyPEM,
              password,
            );
          } catch {
            console.log(
              colors.error("Failed to decrypt private key. Wrong password?"),
            );
            return;
          }
        }

        // Reconstruct proper endpoint certificate instance with private key
        try {
          // Get the certificate PEM from local storage
          const localCertData = await storage.getCertificate(
            this.state.did,
            "endpoint",
            this.state.endpointCert.serialNumber,
          );
          if (!localCertData) {
            throw new Error("Certificate not found in local storage");
          }

          endpointCertWithKey = await loadEndpointCertificateWithKey(
            localCertData.certificatePEM,
            privateKeyPEM,
          );
        } catch {
          console.log(
            colors.error(
              "Failed to load endpoint certificate with private key",
            ),
          );
          return;
        }
      } else {
        console.log(
          colors.error("\n⚠ Your certificate doesn't have a private key"),
        );
        console.log(
          colors.info(
            "You have a certificate but cannot sign messages without the private key.",
          ),
        );
        console.log(colors.info("\nTo fix this:"));
        console.log(colors.info("  1. Type /back to exit conversation"));
        console.log(
          colors.info(
            '  2. Type "/genendpoint" to generate a new endpoint certificate with private key',
          ),
        );
        console.log(colors.info("  3. Try sending again"));
        return;
      }
    }

    try {
      const conversation = await this.state.storageManager.getConversation(
        this.state.currentConversation,
      );
      if (!conversation) {
        console.log(colors.error("Conversation not found"));
        return;
      }

      // Get recipient DID
      const recipientDid = conversation.participantIds.find(
        (id) => id !== this.state!.did,
      );
      if (!recipientDid) {
        console.log(colors.error("No recipient in conversation"));
        return;
      }

      // Send message
      await this.state.storageManager.sendMessage(
        this.state.currentConversation,
        text,
        endpointCertWithKey,
      );

      // Display sent message
      const time = colors.timestamp(new Date().toLocaleTimeString());
      console.log(`${colors.sent("→")} ${time} You: ${text}`);
    } catch (error: any) {
      // Only show the error message, not the stack trace
      const errorMessage = error.message || "Unknown error occurred";
      console.log(colors.error("Failed to send message: " + errorMessage));

      // Check if this is a WebSocket connection issue
      if (
        errorMessage.includes("HTTPS send-message endpoint not yet implemented")
      ) {
        if (!this.state.wsClient || !this.state.wsClient.isConnected()) {
          console.log(colors.info("\n💡 WebSocket is not connected"));
          console.log(colors.info("This can happen if:"));
          console.log(colors.info("  • WebSocket failed to authenticate"));
          console.log(colors.info("  • WebSocket disconnected"));
          console.log(colors.info("  • No internet connection"));
          console.log(colors.info("\nTry:"));
          console.log(
            colors.info('  1. Type "/quit" and restart the chat client'),
          );
          console.log(colors.info("  2. Check your internet connection"));
          if (this.debug) {
            console.log(
              colors.system(
                `[DEBUG] WebSocket client exists: ${!!this.state.wsClient}`,
              ),
            );
            console.log(
              colors.system(
                `[DEBUG] WebSocket connected: ${this.state.wsClient?.isConnected()}`,
              ),
            );
          }
        }
      }
    }
  }

  private async listConversations() {
    if (!this.state) return;

    try {
      const conversations = await this.state.storageManager.listConversations();

      if (conversations.length === 0) {
        console.log(colors.system("No conversations yet"));
        return;
      }

      console.log(colors.info("\nConversations:"));
      for (const conv of conversations) {
        const otherParticipant = conv.participantIds.find(
          (id) => id !== this.state!.did,
        );

        if (!otherParticipant || otherParticipant === "Unknown") {
          console.log(
            `  Unknown participant - Last: ${new Date(conv.lastMessageAt).toLocaleString()}`,
          );
          continue;
        }

        // Try to resolve DID to handle
        let handle = this.getHandleFromDid(otherParticipant);

        // If we only have a truncated DID, try to resolve the actual handle
        if (handle.endsWith("...")) {
          try {
            // Use the app.bsky.actor.getProfile method
            const response =
              await this.state!.agent.api.app.bsky.actor.getProfile({
                actor: otherParticipant,
              });
            if (response.data.handle) {
              handle = response.data.handle;
              // Cache the resolved handle
              this.cacheHandleForDid(otherParticipant, handle);
            }
          } catch {
            // Failed to resolve, keep the truncated DID
            // Could be a deleted account or network issue
          }
        }

        const lastMsg = new Date(conv.lastMessageAt).toLocaleString();
        const unread =
          conv.unreadCount > 0
            ? colors.error(` (${conv.unreadCount} unread)`)
            : "";

        console.log(`  ${handle} - Last: ${lastMsg}${unread}`);
      }
      console.log("");
    } catch {
      console.error(colors.error("Failed to list conversations:", error));
    }
  }

  private async syncMessages() {
    if (!this.state) return;

    if (this.debug) {
      console.log(colors.info("Checking for new messages..."));
    }

    try {
      // Check if we have a endpoint certificate with serial number
      if (!this.state.endpointCert?.serialNumber) {
        console.log(colors.error("No endpoint certificate available"));
        console.log(
          colors.info("You need a endpoint certificate to receive messages"),
        );
        return;
      }

      // Check if we have the private key
      let privateKeyPEM: string | undefined =
        this.state.endpointCert.certificatePrivateKeyPEM;

      // If private key is encrypted, we need to decrypt it
      if (
        !privateKeyPEM &&
        (this.state.endpointCert as any).encryptedPrivateKeyPEM
      ) {
        const password = await this.promptPassword(
          "Enter password to decrypt private key: ",
        );
        try {
          privateKeyPEM = PasswordEncryption.decrypt(
            (this.state.endpointCert as any).encryptedPrivateKeyPEM,
            password,
          );
        } catch {
          console.log(colors.error("Failed to decrypt private key"));
          return;
        }
      }

      if (!privateKeyPEM) {
        console.log(
          colors.error("Endpoint certificate private key not available"),
        );
        console.log(
          colors.info(
            "You need the private key to authenticate with the server",
          ),
        );
        console.log(colors.info("\nTo fix this:"));
        console.log(
          colors.info("  1. If you have the key on another device, import it"),
        );
        console.log(
          colors.info(
            '  2. Or generate a new endpoint certificate: type "/genendpoint"',
          ),
        );
        return;
      }

      // Temporarily set the decrypted private key on the certificate for the sync
      const originalPrivateKey =
        this.state.endpointCert.certificatePrivateKeyPEM;
      (this.state.endpointCert as any).privateKeyPEM = privateKeyPEM;

      try {
        // Use the library's syncMessages method
        await this.state.storageManager.syncMessages(this.state.endpointCert);
      } finally {
        // Restore original state (remove decrypted key from memory)
        (this.state.endpointCert as any).privateKeyPEM = originalPrivateKey;
      }

      console.log(colors.success("Sync complete"));

      // If user is in a conversation, refresh the display
      if (this.state.currentConversation) {
        console.log(colors.info("\n═══ Updated Conversation ═══"));
        await this.displayConversationHistory(this.state.currentConversation);
      }
    } catch (error: any) {
      console.error(
        colors.error("Sync failed:"),
        error?.message || String(error),
      );
    }
  }

  private showInfo() {
    if (!this.state) {
      console.log(colors.error("Not logged in"));
      return;
    }

    console.log(
      colors.info(`
Account Info:
  Handle: ${this.state.handle}
  DID: ${this.state.did}
  Certificate: ${this.state.endpointCert ? "✓ Loaded" : "✗ Not found"}
  WebSocket: ${this.state.wsClient ? "✓ Connected" : "✗ Disconnected"}
  Data Directory: ${this.dataDir}
`),
    );
  }

  private updatePrompt() {
    if (this.state?.currentConversation) {
      // In conversation mode
      const handles = (this.state as any).conversationHandles || {};
      const recipient = handles[this.state.currentConversation] || "user";
      this.rl.setPrompt(colors.prompt(`${recipient}> `));
    } else {
      // Normal mode
      this.rl.setPrompt(colors.prompt("> "));
    }
    this.rl.prompt();
  }

  private async generateCertificate() {
    if (!this.state) {
      console.log(colors.error("Not logged in"));
      return;
    }

    try {
      // Check if certificates already exist
      const certs = await this.state.atsmsClient.getUserCertificates(
        this.state.did,
      );

      if (certs.endpointCerts && certs.endpointCerts.length > 0) {
        console.log(
          colors.warning("\n⚠ Endpoint certificate(s) already exist!"),
        );
        console.log(
          colors.info(
            `  Found ${certs.endpointCerts.length} existing certificate(s)`,
          ),
        );
        console.log(
          colors.warning(
            "\nGenerating a new certificate will add another certificate to your account.",
          ),
        );

        // Save readline state and close it
        const history = (this.rl as any).history
          ? [...(this.rl as any).history]
          : [];
        this.rl.close();

        const confirmation = await prompts({
          type: "confirm",
          name: "value",
          message: "Do you want to generate a new certificate?",
          initial: false,
        });

        // Recreate readline and restore all event listeners
        this.recreateReadline(history);

        if (!confirmation.value) {
          console.log(colors.info("Certificate generation cancelled"));
          this.updatePrompt();
          return;
        }
      }

      if (this.debug) {
        console.log(
          colors.info("[DEBUG] Generating self-signed endpoint certificate..."),
        );
      }

      // Generate self-signed endpoint certificate (P-256 ECDSA by default)
      // Email is computed deterministically from DID and email domain
      const endpointCert = await generateEndpointCertificate(
        "P256",
        this.state.did,
        this.state.handle,
        ATSMS_API_DOMAIN,
      );

      // Ask for password to encrypt the private key
      const password = await this.promptPassword(
        "Enter password to encrypt private key (or press Enter to skip): ",
      );

      // Store locally in SQLite with optional encryption
      const storage = this.state.storageManager.getStorage() as SQLiteAdapter;
      if (password) {
        const encryptedKey = PasswordEncryption.encrypt(
          endpointCert.certificatePrivateKeyPEM!,
          password,
        );
        await storage.saveCertificate(
          this.state.did,
          "endpoint",
          endpointCert.serialNumber,
          endpointCert.certificatePEM,
          encryptedKey,
          true,
          { domain: this.state.handle, handle: this.state.handle },
        );
        console.log(
          colors.success("✓ Private key encrypted and stored locally"),
        );
      } else {
        await storage.saveCertificate(
          this.state.did,
          "endpoint",
          endpointCert.serialNumber,
          endpointCert.certificatePEM,
          endpointCert.certificatePrivateKeyPEM,
          false,
          { domain: this.state.handle, handle: this.state.handle },
        );
        console.log(
          colors.warning("⚠ Private key stored unencrypted locally"),
        );
      }

      // Store in PDS (without private key)
      if (this.debug) {
        console.log(colors.info("[DEBUG] Storing certificate in PDS..."));
      }
      await this.state.atsmsClient.storeEndpointCertificate(endpointCert);

      console.log(colors.success("✓ Certificate generated and stored"));
      console.log(colors.info(`  Serial: ${endpointCert.serialNumber}`));
      console.log(
        colors.info(
          `  Valid until: ${endpointCert.notAfter.toLocaleDateString()}`,
        ),
      );

      // Save locally for use in this session
      this.state.endpointCert = endpointCert;

      // Save DID and restart transport to enable messaging operations with new certificate
      try {
        await this.state.storageManager.saveDid(
          this.state.did,
          this.state.handle,
          endpointCert,
        );

        // Stop existing transport if active (to pick up new certificate)
        if (this.state.storageManager.isTransportActive(this.state.did)) {
          await this.state.storageManager.stopTransport(this.state.did);
          if (this.debug) {
            console.log(
              colors.info(
                "[DEBUG] Stopped existing transport to pick up new certificate",
              ),
            );
          }
        }

        // Start transport with new certificate
        await this.state.storageManager.startTransport(this.state.did);
        if (this.debug) {
          console.log(
            colors.success("[DEBUG] ✓ DID saved and transport started"),
          );
        }
      } catch (transportError: any) {
        console.log(
          colors.warning(
            `⚠ Transport setup failed: ${transportError.message || "Unknown error"}`,
          ),
        );
        console.log(colors.info("  You may need to restart the chat client"));
      }

      console.log(colors.success("\n✓ You can now send encrypted messages!"));
    } catch (error: any) {
      console.log(
        colors.error(
          "Failed to generate certificate: " +
            (error.message || "Unknown error"),
        ),
      );
    }
  }

  private async listCertificates() {
    if (!this.state) {
      console.log(colors.error("Not logged in"));
      return;
    }

    try {
      console.log(colors.info("Fetching certificates..."));

      // Get certificates from PDS
      const certs = await this.state.atsmsClient.getUserCertificates(
        this.state.did,
      );

      // Get certificates from local storage
      const storage = this.state.storageManager.getStorage() as SQLiteAdapter;
      const localCerts = await storage.listCertificates(this.state.did);

      console.log(colors.info("\n═══ Your Certificates ═══\n"));

      // Endpoint certificates
      if (certs.endpointCerts && certs.endpointCerts.length > 0) {
        console.log(
          colors.success(`Certificates (${certs.endpointCerts.length}):`),
        );

        for (const cert of certs.endpointCerts) {
          const hasMemoryKey = cert.privateKey || cert.certificatePrivateKeyPEM;
          const localClient = localCerts.find(
            (c) =>
              c.type === "endpoint" && c.serialNumber === cert.serialNumber,
          );
          const hasLocalKey = localClient?.hasPrivateKey || false;

          console.log(`  ${cert.serialNumber}`);
          console.log(
            `    Valid: ${cert.notBefore.toLocaleDateString()} - ${cert.notAfter.toLocaleDateString()}`,
          );

          if (hasMemoryKey) {
            console.log(
              `    Has private key: ${colors.success("✓ Yes (can send messages)")}`,
            );
          } else if (hasLocalKey) {
            console.log(
              `    Has private key: ${colors.success("✓ Yes (local storage, can send messages)")}`,
            );
          } else {
            console.log(
              `    Has private key: ${colors.warning("✗ No (cannot send messages)")}`,
            );
          }

          if ((hasMemoryKey || hasLocalKey) && !this.state.endpointCert) {
            // Use this certificate if we don't have one
            this.state.endpointCert = cert;
            console.log(
              colors.info("    ↑ Using this certificate for sending"),
            );
          }
        }
        console.log("");
      } else {
        console.log(colors.warning("No certificates found"));
        console.log(colors.info('  Run "/gencert" to generate one\n'));
      }

      // Summary - check both memory and local storage
      let canSend = false;
      if (certs.endpointCerts) {
        for (const cert of certs.endpointCerts) {
          const hasMemoryKey = cert.privateKey || cert.certificatePrivateKeyPEM;
          const localClient = localCerts.find(
            (c) =>
              c.type === "endpoint" && c.serialNumber === cert.serialNumber,
          );
          const hasLocalKey = localClient?.hasPrivateKey || false;
          if (hasMemoryKey || hasLocalKey) {
            canSend = true;
            break;
          }
        }
      }
      const canReceive = certs.endpointCerts && certs.endpointCerts.length > 0;

      console.log(colors.info("═══ Status ═══"));
      console.log(
        `  Can send messages: ${canSend ? colors.success("✓ Yes") : colors.error("✗ No")}`,
      );
      console.log(
        `  Can receive messages: ${canReceive ? colors.success("✓ Yes") : colors.error("✗ No")}`,
      );

      if (!canSend) {
        console.log(colors.info("\nTo enable sending:"));
        console.log(
          colors.info(
            '  Run "/gencert" to generate a certificate with private key',
          ),
        );
      }
    } catch (error: any) {
      console.log(
        colors.error(
          "Failed to list certificates: " + (error.message || "Unknown error"),
        ),
      );
    }
  }

  /**
   * Send a test WebRTC offer (for debugging, doesn't create real call)
   */
  private async sendTestWebRTCOffer(mediaType: "audio" | "video" = "audio") {
    if (!this.state?.currentConversation || !this.state.endpointCert) {
      return;
    }

    try {
      console.log(colors.info(`\nSending test WebRTC ${mediaType} offer...`));

      const webrtcContent: ATSMSWebRTCContent = {
        type: "offer",
        callId:
          Date.now().toString(36) + Math.random().toString(36).substr(2, 9),
        sdp:
          "v=0\r\no=- 123456789 2 IN IP4 127.0.0.1\r\ns=Test WebRTC Offer\r\nt=0 0\r\na=group:BUNDLE 0\r\na=msid-semantic: WMS\r\nm=" +
          mediaType +
          " 9 UDP/TLS/RTP/SAVPF 111\r\nc=IN IP4 0.0.0.0\r\na=rtcp:9 IN IP4 0.0.0.0\r\na=ice-ufrag:test\r\na=ice-pwd:testpassword\r\n",
        mediaTypes: mediaType === "video" ? ["audio", "video"] : ["audio"],
        timestamp: Date.now(),
      };

      await this.state.storageManager.sendWebRTC(
        this.state.currentConversation,
        webrtcContent,
        this.state.endpointCert,
      );

      console.log(
        colors.success(
          `✓ Sent ${mediaType} call offer (test only - no real WebRTC connection)`,
        ),
      );
    } catch (error: any) {
      console.error(
        colors.error(`Failed to send call offer: ${error.message}`),
      );
    }
  }

  /**
   * Extract display text from a message's content field
   * Handles parsing atsms/text and atsms/webrtc content types
   */
  private getMessageText(message: any): string {
    try {
      if (message.contentType === "atsms/text") {
        const parsed = parseTextContent(message.content);
        return parsed.text;
      }

      if (message.contentType === "atsms/webrtc") {
        const parsed = parseWebRTCContent(message.content);
        return this.formatWebRTCMessage(parsed);
      }

      // Fallback for unknown content types
      return `[${message.contentType}]`;
    } catch {
      return "[invalid content]";
    }
  }

  /**
   * Format WebRTC signaling messages for display
   */
  private formatWebRTCMessage(webrtc: ATSMSWebRTCContent): string {
    const mediaStr = webrtc.mediaTypes?.join("+") || "media";
    const callIdShort = webrtc.callId.slice(0, 8);

    switch (webrtc.type) {
      case "offer":
        return `📞 WebRTC Call Offer (${mediaStr}) [callId: ${callIdShort}...]`;
      case "answer":
        return `✅ WebRTC Call Answer (${mediaStr}) [callId: ${callIdShort}...]`;
      case "ice-candidate":
        return `🧊 ICE Candidate [callId: ${callIdShort}...]`;
      case "hangup":
        return `📴 Call Ended [callId: ${callIdShort}...]`;
      default:
        return `📞 WebRTC: ${webrtc.type}`;
    }
  }
}

// Main entry point
async function main() {
  const args = process.argv.slice(2);

  // Parse flags
  let debug = false;
  let handle: string | undefined;
  let dataDir: string | undefined;

  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    if (arg === "--debug") {
      debug = true;
    } else if (arg === "--data-dir" && i + 1 < args.length) {
      dataDir = args[++i];
    } else if (arg.startsWith("--data-dir=")) {
      dataDir = arg.split("=")[1];
    } else if (arg === "--help" || arg === "-h") {
      console.log(`
AT-SMS Chat Client

Usage: bun atsms-chat.ts [handle] [options]

Arguments:
  handle              AT Protocol handle or DID to authenticate with

Options:
  --data-dir <path>   Directory for storing auth cache, history, and messages
                      (default: ~/.atsms)
  --debug             Enable debug output
  --help, -h          Show this help message

Examples:
  bun atsms-chat.ts alice.bsky.social
  bun atsms-chat.ts --data-dir ./my-data alice.bsky.social
  bun atsms-chat.ts alice.bsky.social --data-dir=/tmp/atsms-test --debug
`);
      process.exit(0);
    } else if (!arg.startsWith("--")) {
      handle = arg;
    }
  }

  const client = new ChatClient(dataDir);
  client["debug"] = debug; // Set debug flag

  await client.start(handle);
}

// Run the client
main().catch((error) => {
  console.error(colors.error("Fatal error:"), error);
  process.exit(1);
});
