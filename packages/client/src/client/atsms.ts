#!/usr/bin/env bun
/**
 * AT SMS Command Line Tool for Testing and Artifact Generation
 * Pure stateless tool - all inputs/outputs via command line arguments
 * No .atsms directory or persistent state
 */

import { AtpAgent } from "@atproto/api";
import { readFileSync, writeFileSync } from "fs";
import { nanoid } from "nanoid";
import path from "path";
import * as readline from "readline";

import { ATSMSApiClient } from "../lib/atsms-api.js";
import { ATSMSClient } from "../lib/atsms-client.js";
import {
  type ATSMSCertificateAlgorithm,
  generateEndpointCertificate,
  loadEndpointCertificate,
  loadEndpointCertificateWithKey,
} from "../lib/certificates/index.js";
import {
  decryptAndVerifyMessageSignature,
  encryptMessage,
  signMessage,
} from "../lib/crypto.js";
import { generateJWT } from "../lib/jwt-auth.js";
import {
  createMessagePayload,
  prepareMessageForSending,
} from "../lib/messages.js";
import { type ATSMSConfig, type ATSMSDecryptedMessage } from "../lib/types.js";

class ATSMSCLITool {
  private config: ATSMSConfig;
  private atsmsClient: ATSMSClient | null = null;
  private atsmsApiClient: ATSMSApiClient;
  private agent: AtpAgent | null = null;
  private did: string = "";

  constructor(config: ATSMSConfig) {
    this.config = config;
    this.atsmsApiClient = new ATSMSApiClient(config);
  }

  /**
   * Login to PDS
   */
  async login(handle: string, password: string): Promise<void> {
    console.log(`Logging into AT Protocol as ${handle}...`);
    const serviceUrl = "https://bsky.social";
    this.agent = new AtpAgent({ service: serviceUrl });

    const response = await this.agent.login({
      identifier: handle,
      password: password,
    });

    this.did = response.data.did;

    // Create ATSMSClient with authenticated agent
    this.atsmsClient = new ATSMSClient(this.agent, this.did);

    console.log(`✓ Logged in as ${handle} (DID: ${this.did})`);
  }

  /**
   * Generate JWT from certificate files
   */
  private async getJWTFromFiles(
    certPath: string,
    keyPath: string,
  ): Promise<string> {
    const certPEM = readFileSync(certPath, "utf8");
    const keyPEM = readFileSync(keyPath, "utf8");
    const endpointCert = await loadEndpointCertificateWithKey(certPEM, keyPEM);
    return generateJWT(keyPEM, endpointCert.serialNumber, this.did);
  }

  /**
   * Generate certificates and optionally publish to PDS
   */
  async initCertificates(
    handle: string,
    password: string | null,
    endpointCertPath: string,
    endpointKeyPath: string,
    email: string,
    publishToPDS: boolean,
    algorithm: ATSMSCertificateAlgorithm = "P256",
  ): Promise<void> {
    console.log(`Generating certificate for ${handle}...`);

    let did: string;

    if (publishToPDS && password) {
      // Login to get real DID
      await this.login(handle, password);
      did = this.did;
    } else {
      // Generate test DID
      did = `did:plc:${handle.replace(/\./g, "-")}-test`;
      console.log(`Using test DID: ${did}`);
    }

    // Generate self-signed endpoint certificate with specified algorithm
    const algorithmName = algorithm === "P256" ? "P-256 ECDSA" : "RSA-2048";
    console.log(
      `Generating self-signed endpoint certificate (${algorithmName})...`,
    );
    const endpointCert = await generateEndpointCertificate(
      algorithm,
      did,
      handle,
      email,
    );
    const endpointCertPEM = endpointCert.certificatePEM;
    const endpointKeyPEM = endpointCert.certificatePrivateKeyPEM!;

    // Write endpoint certificate and key
    writeFileSync(endpointCertPath, endpointCertPEM, "utf8");
    writeFileSync(endpointKeyPath, endpointKeyPEM, "utf8");
    console.log(`✓ Certificate: ${endpointCertPath}`);
    console.log(`✓ Private key: ${endpointKeyPath}`);

    // Print certificate info
    console.log("\n=== Certificate Info ===");
    console.log(`Algorithm: ${algorithmName}`);
    console.log(`DID: ${did}`);
    console.log(`Serial: ${endpointCert.serialNumber}`);
    console.log(`Valid Until: ${endpointCert.notAfter.toISOString()}`);

    // Publish to PDS if requested
    if (publishToPDS) {
      if (!this.atsmsClient) {
        throw new Error("Not logged in - cannot publish to PDS");
      }
      console.log("\nPublishing certificate to PDS...");
      await this.atsmsClient.storeEndpointCertificate(endpointCert);
      console.log("✓ Certificate published");
    }
  }

  /**
   * Send message
   */
  async sendMessage(
    handle: string,
    password: string,
    senderCertPath: string,
    senderKeyPath: string,
    recipientHandleOrDid: string,
    messageBody: string,
    saveP7MPath?: string,
  ): Promise<void> {
    // Login
    await this.login(handle, password);

    // Load sender certificate (auto-detects RSA or P-256)
    const senderCertPEM = readFileSync(senderCertPath, "utf8");
    const senderKeyPEM = readFileSync(senderKeyPath, "utf8");
    const senderCert = await loadEndpointCertificateWithKey(
      senderCertPEM,
      senderKeyPEM,
    );

    // Resolve recipient DID
    let recipientDid = recipientHandleOrDid;
    if (!recipientHandleOrDid.startsWith("did:")) {
      console.log(`Resolving handle ${recipientHandleOrDid}...`);
      const response = await this.agent!.resolveHandle({
        handle: recipientHandleOrDid,
      });
      recipientDid = response.data.did;
      console.log(`✓ Resolved to ${recipientDid}`);
    }

    // Get recipient certificates from PDS
    console.log("Fetching recipient certificates from PDS...");
    const recipientCerts =
      await this.atsmsClient!.getUserCertificates(recipientDid);

    if (
      !recipientCerts.endpointCerts ||
      recipientCerts.endpointCerts.length === 0
    ) {
      throw new Error(
        `No endpoint certificates found for recipient ${recipientHandleOrDid}`,
      );
    }
    console.log(
      `✓ Found ${recipientCerts.endpointCerts.length} recipient certificate(s)`,
    );

    // Create message
    const message = createMessagePayload(this.did, [recipientDid], messageBody);
    console.log(`Message ID: ${message.id}`);

    // Encrypt message
    console.log("Encrypting message...");
    const encryptedMessage = await prepareMessageForSending(
      message,
      senderCert,
      recipientCerts.endpointCerts,
    );

    // Save P7M if requested
    if (saveP7MPath) {
      writeFileSync(saveP7MPath, Buffer.from(encryptedMessage));
      console.log(`✓ P7M saved to: ${saveP7MPath}`);
      console.log(`  Size: ${encryptedMessage.length} bytes`);
    }

    // Generate JWT and send
    const jwt = await this.getJWTFromFiles(senderCertPath, senderKeyPath);
    this.atsmsApiClient.setAuthToken(jwt);

    console.log("Sending message...");
    const encryptedBase64 = btoa(String.fromCharCode(...encryptedMessage));

    // Use legacy single-recipient send method (for stateless CLI tool)
    // TODO: Once HTTPS send endpoint is implemented, update to use new multi-recipient API
    await this.atsmsApiClient.sendMessageLegacy(recipientDid, encryptedBase64);
    console.log("✓ Message sent successfully");
  }

  /**
   * Receive and decrypt messages
   */
  async receiveMessages(
    handle: string,
    password: string,
    endpointCertPath: string,
    endpointKeyPath: string,
    outputDir?: string,
  ): Promise<void> {
    // Login
    await this.login(handle, password);

    // Load certificate (auto-detects RSA or P-256)
    const endpointCertPEM = readFileSync(endpointCertPath, "utf8");
    const endpointKeyPEM = readFileSync(endpointKeyPath, "utf8");
    const endpointCert = await loadEndpointCertificateWithKey(
      endpointCertPEM,
      endpointKeyPEM,
    );

    // Generate JWT
    const jwt = await this.getJWTFromFiles(endpointCertPath, endpointKeyPath);
    this.atsmsApiClient.setAuthToken(jwt);

    // List messages
    console.log("Fetching messages...");
    const messageList = await this.atsmsApiClient.listMessages(
      this.did,
      endpointCert.serialNumber,
    );

    if (messageList.length === 0) {
      console.log("No messages found");
      return;
    }

    console.log(`Found ${messageList.length} message(s)`);

    // Download and decrypt each message
    const decryptedMessages: any[] = [];

    for (const [index, msgMeta] of messageList.entries()) {
      console.log(`\nProcessing message ${index + 1}/${messageList.length}`);
      console.log(`  ID: ${msgMeta.id}`);
      console.log(`  Seq: ${msgMeta.seq}`);

      try {
        // Download message
        const message = await this.atsmsApiClient.downloadMessage(
          this.did,
          endpointCert.serialNumber,
          msgMeta.id,
        );

        // Decrypt
        const encryptedBytes = Uint8Array.from(
          atob(message.encryptedContent),
          (c) => c.charCodeAt(0),
        );

        const decrypted: ATSMSDecryptedMessage =
          await decryptAndVerifyMessageSignature(encryptedBytes, endpointCert);

        const decryptedContent = new TextDecoder().decode(
          decrypted.decryptedContent,
        );

        // Try to parse as JSON
        let parsedMessage;
        try {
          parsedMessage = JSON.parse(decryptedContent);
        } catch {
          parsedMessage = { text: decryptedContent };
        }

        const result = {
          id: msgMeta.id,
          seq: msgMeta.seq,
          storedAt: msgMeta.storedAt,
          signer: {
            commonName: decrypted.messageSigner.commonName,
            serialNumber: decrypted.messageSigner.serialNumber,
          },
          message: parsedMessage,
        };

        decryptedMessages.push(result);

        console.log(`  ✓ Decrypted`);
        console.log(`  Sender: ${result.signer.commonName}`);
        if (parsedMessage.text) {
          console.log(`  Text: ${parsedMessage.text}`);
        }
      } catch (error) {
        console.log(`  ✗ Failed to decrypt: ${error.message}`);
      }
    }

    // Output results
    if (outputDir) {
      // Save to files
      for (const msg of decryptedMessages) {
        const filePath = path.join(outputDir, `${msg.id}.json`);
        writeFileSync(filePath, JSON.stringify(msg, null, 2), "utf8");
        console.log(`\n✓ Saved: ${filePath}`);
      }
    } else {
      // Print to stdout
      console.log("\n=== Decrypted Messages (JSON) ===");
      console.log(JSON.stringify(decryptedMessages, null, 2));
    }
  }

  /**
   * List messages
   */
  async listMessages(
    handle: string,
    password: string,
    endpointCertPath: string,
    endpointKeyPath: string,
    afterSeq?: number,
  ): Promise<void> {
    // Login
    await this.login(handle, password);

    // Load certificate to get serial (auto-detects RSA or P-256)
    const endpointCertPEM = readFileSync(endpointCertPath, "utf8");
    const endpointKeyPEM = readFileSync(endpointKeyPath, "utf8");
    const endpointCert = await loadEndpointCertificateWithKey(
      endpointCertPEM,
      endpointKeyPEM,
    );

    // Generate JWT
    const jwt = await this.getJWTFromFiles(endpointCertPath, endpointKeyPath);
    this.atsmsApiClient.setAuthToken(jwt);

    // List messages
    console.log("Fetching message list...");
    const messages = await this.atsmsApiClient.listMessages(
      this.did,
      endpointCert.serialNumber,
      afterSeq,
    );

    if (messages.length === 0) {
      console.log("No messages found");
      return;
    }

    console.log(`\n=== ${messages.length} Message(s) ===`);
    messages.forEach((msg, index) => {
      console.log(`${index + 1}. ID: ${msg.id}`);
      console.log(`   Seq: ${msg.seq}`);
      console.log(`   Stored: ${msg.storedAt}`);
      console.log("");
    });
  }

  /**
   * Download message artifacts
   */
  async downloadMessageArtifacts(
    handle: string,
    password: string,
    endpointCertPath: string,
    endpointKeyPath: string,
    messageId: string,
    outputDir: string,
  ): Promise<void> {
    // Login
    await this.login(handle, password);

    // Load certificate (auto-detects RSA or P-256)
    const endpointCertPEM = readFileSync(endpointCertPath, "utf8");
    const endpointKeyPEM = readFileSync(endpointKeyPath, "utf8");
    const endpointCert = await loadEndpointCertificateWithKey(
      endpointCertPEM,
      endpointKeyPEM,
    );

    // Generate JWT
    const jwt = await this.getJWTFromFiles(endpointCertPath, endpointKeyPath);
    this.atsmsApiClient.setAuthToken(jwt);

    // Download message
    console.log(`Downloading message ${messageId}...`);
    const message = await this.atsmsApiClient.downloadMessage(
      this.did,
      endpointCert.serialNumber,
      messageId,
    );

    if (!message.encryptedContent) {
      throw new Error("No encrypted content in message");
    }

    // Save artifacts
    const p7mBase64Path = path.join(outputDir, `${messageId}.p7m.base64`);
    const p7mBinaryPath = path.join(outputDir, `${messageId}.p7m`);
    const infoPath = path.join(outputDir, `${messageId}-info.json`);

    // Save base64
    writeFileSync(p7mBase64Path, message.encryptedContent, "utf8");
    console.log(`✓ P7M base64: ${p7mBase64Path}`);

    // Save binary
    const binaryContent = Buffer.from(message.encryptedContent, "base64");
    writeFileSync(p7mBinaryPath, binaryContent);
    console.log(`✓ P7M binary: ${p7mBinaryPath}`);

    // Save info
    const info = {
      messageId: message.id,
      seq: message.seq,
      storedAt: message.storedAt,
      base64Length: message.encryptedContent.length,
      binaryLength: binaryContent.length,
    };
    writeFileSync(infoPath, JSON.stringify(info, null, 2), "utf8");
    console.log(`✓ Info: ${infoPath}`);
  }

  /**
   * Create P7M file for testing
   */
  async createP7MFile(
    senderCertPath: string,
    senderKeyPath: string,
    recipientCertPath: string,
    messageBody: string,
    outputPath: string,
  ): Promise<void> {
    console.log("Creating P7M file...");

    // Load sender certificate (auto-detects RSA or P-256)
    const senderCertPEM = readFileSync(senderCertPath, "utf8");
    const senderKeyPEM = readFileSync(senderKeyPath, "utf8");
    const senderCert = await loadEndpointCertificateWithKey(
      senderCertPEM,
      senderKeyPEM,
    );

    // Load recipient certificate (public only, auto-detects RSA or P-256)
    const recipientCertPEM = readFileSync(recipientCertPath, "utf8");
    const recipientCert = loadEndpointCertificate(recipientCertPEM);

    // Extract DIDs from certificates
    const senderDid = senderCert.did || "unknown";
    const recipientDid = recipientCert.did || "unknown";

    // Create message payload
    const payload = {
      version: "1.0",
      type: "message",
      id: nanoid(13),
      text: messageBody,
      senderId: senderDid,
      recipientIds: [recipientDid],
      convoId: nanoid(13),
      createdAt: new Date().toISOString(),
    };
    const messageContent = JSON.stringify(payload, null, 2);

    console.log("Signing message...");
    const signedContent = await signMessage(messageContent, senderCert);

    console.log("Encrypting signed message...");
    const encryptedContent = await encryptMessage(signedContent, [
      recipientCert,
    ]);

    // Save P7M file
    const binaryContent = Buffer.from(encryptedContent);
    writeFileSync(outputPath, binaryContent);

    console.log(`✓ P7M file created: ${outputPath}`);
    console.log(`  Size: ${binaryContent.length} bytes`);
    console.log(`  Sender: ${senderDid}`);
    console.log(`  Recipient: ${recipientDid}`);
  }

  /**
   * Delete message
   */
  async deleteMessage(
    handle: string,
    password: string,
    endpointCertPath: string,
    endpointKeyPath: string,
    messageId: string,
  ): Promise<void> {
    // Login
    await this.login(handle, password);

    // Load certificate (auto-detects RSA or P-256)
    const endpointCertPEM = readFileSync(endpointCertPath, "utf8");
    const endpointKeyPEM = readFileSync(endpointKeyPath, "utf8");
    const endpointCert = await loadEndpointCertificateWithKey(
      endpointCertPEM,
      endpointKeyPEM,
    );

    // Generate JWT
    const jwt = await this.getJWTFromFiles(endpointCertPath, endpointKeyPath);
    this.atsmsApiClient.setAuthToken(jwt);

    // Delete
    console.log(`Deleting message ${messageId}...`);
    await this.atsmsApiClient.deleteMessage(
      this.did,
      endpointCert.serialNumber,
      messageId,
    );
    console.log("✓ Message deleted");
  }

  /**
   * Get inbox statistics
   */
  async getStats(
    handle: string,
    password: string,
    endpointCertPath: string,
    endpointKeyPath: string,
  ): Promise<void> {
    // Login
    await this.login(handle, password);

    // Load certificate (auto-detects RSA or P-256)
    const endpointCertPEM = readFileSync(endpointCertPath, "utf8");
    const endpointKeyPEM = readFileSync(endpointKeyPath, "utf8");
    const endpointCert = await loadEndpointCertificateWithKey(
      endpointCertPEM,
      endpointKeyPEM,
    );

    // Generate JWT
    const jwt = await this.getJWTFromFiles(endpointCertPath, endpointKeyPath);
    this.atsmsApiClient.setAuthToken(jwt);

    // Get stats
    console.log("Fetching inbox statistics...");
    const stats = await this.atsmsApiClient.getStats(
      this.did,
      endpointCert.serialNumber,
    );

    console.log("\n📊 Inbox Statistics:");
    console.log(`Total messages: ${stats.totalMessages || 0}`);
    console.log(`Unread messages: ${stats.unreadMessages || 0}`);
    console.log(`Total size: ${stats.totalSize || 0} bytes`);
    if (stats.oldestMessage) {
      console.log(
        `Oldest message: ${new Date(stats.oldestMessage).toLocaleString()}`,
      );
    }
    if (stats.newestMessage) {
      console.log(
        `Newest message: ${new Date(stats.newestMessage).toLocaleString()}`,
      );
    }
  }
}

// Helper function to prompt for password with hidden input
function promptPassword(question: string): Promise<string> {
  return new Promise((resolve, _reject) => {
    // Check if we're in a TTY environment
    if (!process.stdin.isTTY) {
      // If not TTY, use standard readline
      const rl = readline.createInterface({
        input: process.stdin,
        output: process.stdout,
      });
      rl.question(question + " ", (password) => {
        rl.close();
        resolve(password);
      });
      return;
    }

    // For TTY, use hidden input
    const rl = readline.createInterface({
      input: process.stdin,
      output: process.stdout,
      terminal: true,
    });

    // Write the question
    process.stdout.write(question + " ");

    const stdoutWrite = process.stdout.write;

    // Override stdout.write to prevent echoing

    process.stdout.write = function (chunk: any, ...args: any[]): boolean {
      if (chunk === question + " " || chunk === "\n" || chunk === "\r\n") {
        return stdoutWrite.apply(process.stdout, [chunk, ...args]);
      }
      return true;
    };

    rl.question("", (password) => {
      // Restore stdout.write
      process.stdout.write = stdoutWrite;
      process.stdout.write("\n");
      rl.close();
      resolve(password);
    });

    // Set up the hidden input
    if (process.stdin.isTTY) {
      (rl as any)._writeToOutput = function () {
        // Don't write anything (hide the password)
      };
    }
  });
}

// Parse command line arguments
function parseArgs(args: string[]): { [key: string]: string | boolean } {
  const parsed: { [key: string]: string | boolean } = {};
  for (let i = 0; i < args.length; i++) {
    if (args[i].startsWith("--")) {
      const key = args[i].substring(2);
      if (i + 1 < args.length && !args[i + 1].startsWith("--")) {
        parsed[key] = args[i + 1];
        i++;
      } else {
        parsed[key] = true;
      }
    }
  }
  return parsed;
}

// CLI Interface
async function main() {
  const args = process.argv.slice(2);

  if (args.length === 0) {
    console.log(`
AT SMS Command Line Tool for Testing and Artifact Generation

Usage:
  bun atsms.ts <command> [options]

Commands:
  init              Generate self-signed certificate
  send              Send encrypted message
  receive           Receive and decrypt messages
  list              List messages
  download          Download message artifacts
  create-p7m        Create P7M file for testing
  delete            Delete a message
  stats             Get inbox statistics

Options (varies by command):

  init:
    --handle <handle>           User handle (required)
    --endpoint-cert <path>      Output path for endpoint certificate (required)
    --endpoint-key <path>       Output path for endpoint key (required)
    --email <email>             Email for certificate (required)
    --algorithm <p256|rsa>      Certificate algorithm (default: p256)
    --password <password>       PDS password (optional, prompts if not provided)
    --publish-to-pds            Publish certificate to PDS (requires --password)

  send:
    --handle <handle>           Sender handle (required)
    --sender-cert <path>        Sender certificate path (required)
    --sender-key <path>         Sender key path (required)
    --recipient <handle|did>    Recipient handle or DID (required)
    --message <text>            Message text (required)
    --password <password>       PDS password (optional, prompts if not provided)
    --save-p7m <path>           Save P7M artifact to path (optional)

  receive:
    --handle <handle>           User handle (required)
    --endpoint-cert <path>      Endpoint certificate path (required)
    --endpoint-key <path>       Client key path (required)
    --password <password>       PDS password (optional, prompts if not provided)
    --output-dir <path>         Save messages to directory (optional, prints to stdout if omitted)

  list:
    --handle <handle>           User handle (required)
    --endpoint-cert <path>      Endpoint certificate path (required)
    --endpoint-key <path>       Endpoint key path (required)
    --password <password>       PDS password (optional, prompts if not provided)
    --after-seq <number>        List messages after sequence number (optional)

  download:
    --handle <handle>           User handle (required)
    --endpoint-cert <path>      Endpoint certificate path (required)
    --endpoint-key <path>       Endpoint key path (required)
    --message-id <id>           Message ID (required)
    --output-dir <path>         Output directory for artifacts (required)
    --password <password>       PDS password (optional, prompts if not provided)

  create-p7m:
    --sender-cert <path>        Sender certificate path (required)
    --sender-key <path>         Sender key path (required)
    --recipient-cert <path>     Recipient certificate path (required)
    --message <text>            Message text (required)
    --output <path>             Output P7M file path (required)

  delete:
    --handle <handle>           User handle (required)
    --endpoint-cert <path>      Endpoint certificate path (required)
    --endpoint-key <path>       Endpoint key path (required)
    --message-id <id>           Message ID (required)
    --password <password>       PDS password (optional, prompts if not provided)

  stats:
    --handle <handle>           User handle (required)
    --endpoint-cert <path>      Endpoint certificate path (required)
    --endpoint-key <path>       Endpoint key path (required)
    --password <password>       PDS password (optional, prompts if not provided)

Global Options:
  --api-url <url>              API URL (default: https://atsms-api.enumdao.workers.dev)

Examples:
  # Generate P-256 certificate (default, no PDS)
  bun atsms.ts init --handle aib0b.bsky.social \\
    --endpoint-cert ./endpoint.pem --endpoint-key ./endpoint-key.pem --email alice@example.com

  # Generate RSA certificate (legacy)
  bun atsms.ts init --handle aib0b.bsky.social \\
    --endpoint-cert ./endpoint.pem --endpoint-key ./endpoint-key.pem --email alice@example.com --algorithm rsa

  # Generate and publish to PDS
  bun atsms.ts init --handle aib0b.bsky.social \\
    --endpoint-cert ./endpoint.pem --endpoint-key ./endpoint-key.pem --email alice@example.com --publish-to-pds

  # Send message
  bun atsms.ts send --handle aib0b.bsky.social --sender-cert ./endpoint.pem --sender-key ./endpoint-key.pem \\
    --recipient bob.bsky.social --message "Hello Bob!"

  # Send with P7M artifact
  bun atsms.ts send --handle aib0b.bsky.social --sender-cert ./endpoint.pem --sender-key ./endpoint-key.pem \\
    --recipient bob.bsky.social --message "Hello Bob!" --save-p7m ./message.p7m

  # Receive messages (print to stdout)
  bun atsms.ts receive --handle aib0b.bsky.social --endpoint-cert ./endpoint.pem --endpoint-key ./endpoint-key.pem

  # Receive messages (save to files)
  bun atsms.ts receive --handle aib0b.bsky.social --endpoint-cert ./endpoint.pem --endpoint-key ./endpoint-key.pem \\
    --output-dir ./messages

  # Create P7M for testing
  bun atsms.ts create-p7m --sender-cert ./alice-endpoint.pem --sender-key ./alice-endpoint-key.pem \\
    --recipient-cert ./bob-endpoint.pem --message "Test" --output ./test.p7m
`);
    process.exit(1);
  }

  const command = args[0];
  const parsedArgs = parseArgs(args.slice(1));

  const config: ATSMSConfig = {
    apiUrl:
      (parsedArgs["api-url"] as string) ||
      "https://atsms-api.enumdao.workers.dev",
  };

  const tool = new ATSMSCLITool(config);

  try {
    switch (command) {
      case "init": {
        const handle = parsedArgs["handle"] as string;
        const endpointCert = parsedArgs["endpoint-cert"] as string;
        const endpointKey = parsedArgs["endpoint-key"] as string;
        const email = parsedArgs["email"] as string;
        const publishToPDS = parsedArgs["publish-to-pds"] as boolean;
        const algorithmArg = (parsedArgs["algorithm"] as string)?.toLowerCase();

        if (!handle || !endpointCert || !endpointKey || !email) {
          throw new Error(
            "Missing required arguments: --handle, --endpoint-cert, --endpoint-key, --email",
          );
        }

        // Parse algorithm (default to P256)
        let algorithm: ATSMSCertificateAlgorithm = "P256";
        if (algorithmArg) {
          if (algorithmArg === "rsa") {
            algorithm = "RSA";
          } else if (algorithmArg === "p256") {
            algorithm = "P256";
          } else {
            throw new Error('Invalid algorithm. Use "p256" or "rsa"');
          }
        }

        let password: string | null = null;
        if (publishToPDS) {
          password =
            (parsedArgs["password"] as string) ||
            (await promptPassword(`Enter password for ${handle}:`));
        }

        await tool.initCertificates(
          handle,
          password,
          endpointCert,
          endpointKey,
          email,
          publishToPDS,
          algorithm,
        );
        break;
      }

      case "send": {
        const handle = parsedArgs["handle"] as string;
        const senderCert = parsedArgs["sender-cert"] as string;
        const senderKey = parsedArgs["sender-key"] as string;
        const recipient = parsedArgs["recipient"] as string;
        const message = parsedArgs["message"] as string;
        const saveP7M = parsedArgs["save-p7m"] as string | undefined;

        if (!handle || !senderCert || !senderKey || !recipient || !message) {
          throw new Error(
            "Missing required arguments: --handle, --sender-cert, --sender-key, --recipient, --message",
          );
        }

        const password =
          (parsedArgs["password"] as string) ||
          (await promptPassword(`Enter password for ${handle}:`));

        await tool.sendMessage(
          handle,
          password,
          senderCert,
          senderKey,
          recipient,
          message,
          saveP7M,
        );
        break;
      }

      case "receive": {
        const handle = parsedArgs["handle"] as string;
        const endpointCert = parsedArgs["endpoint-cert"] as string;
        const endpointKey = parsedArgs["endpoint-key"] as string;
        const outputDir = parsedArgs["output-dir"] as string | undefined;

        if (!handle || !endpointCert || !endpointKey) {
          throw new Error(
            "Missing required arguments: --handle, --endpoint-cert, --endpoint-key",
          );
        }

        const password =
          (parsedArgs["password"] as string) ||
          (await promptPassword(`Enter password for ${handle}:`));

        await tool.receiveMessages(
          handle,
          password,
          endpointCert,
          endpointKey,
          outputDir,
        );
        break;
      }

      case "list": {
        const handle = parsedArgs["handle"] as string;
        const endpointCert = parsedArgs["endpoint-cert"] as string;
        const endpointKey = parsedArgs["endpoint-key"] as string;
        const afterSeq = parsedArgs["after-seq"]
          ? parseInt(parsedArgs["after-seq"] as string, 10)
          : undefined;

        if (!handle || !endpointCert || !endpointKey) {
          throw new Error(
            "Missing required arguments: --handle, --endpoint-cert, --endpoint-key",
          );
        }

        const password =
          (parsedArgs["password"] as string) ||
          (await promptPassword(`Enter password for ${handle}:`));

        await tool.listMessages(
          handle,
          password,
          endpointCert,
          endpointKey,
          afterSeq,
        );
        break;
      }

      case "download": {
        const handle = parsedArgs["handle"] as string;
        const endpointCert = parsedArgs["endpoint-cert"] as string;
        const endpointKey = parsedArgs["endpoint-key"] as string;
        const messageId = parsedArgs["message-id"] as string;
        const outputDir = parsedArgs["output-dir"] as string;

        if (
          !handle ||
          !endpointCert ||
          !endpointKey ||
          !messageId ||
          !outputDir
        ) {
          throw new Error(
            "Missing required arguments: --handle, --endpoint-cert, --endpoint-key, --message-id, --output-dir",
          );
        }

        const password =
          (parsedArgs["password"] as string) ||
          (await promptPassword(`Enter password for ${handle}:`));

        await tool.downloadMessageArtifacts(
          handle,
          password,
          endpointCert,
          endpointKey,
          messageId,
          outputDir,
        );
        break;
      }

      case "create-p7m": {
        const senderCert = parsedArgs["sender-cert"] as string;
        const senderKey = parsedArgs["sender-key"] as string;
        const recipientCert = parsedArgs["recipient-cert"] as string;
        const message = parsedArgs["message"] as string;
        const output = parsedArgs["output"] as string;

        if (
          !senderCert ||
          !senderKey ||
          !recipientCert ||
          !message ||
          !output
        ) {
          throw new Error(
            "Missing required arguments: --sender-cert, --sender-key, --recipient-cert, --message, --output",
          );
        }

        await tool.createP7MFile(
          senderCert,
          senderKey,
          recipientCert,
          message,
          output,
        );
        break;
      }

      case "delete": {
        const handle = parsedArgs["handle"] as string;
        const endpointCert = parsedArgs["endpoint-cert"] as string;
        const endpointKey = parsedArgs["endpoint-key"] as string;
        const messageId = parsedArgs["message-id"] as string;

        if (!handle || !endpointCert || !endpointKey || !messageId) {
          throw new Error(
            "Missing required arguments: --handle, --endpoint-cert, --endpoint-key, --message-id",
          );
        }

        const password =
          (parsedArgs["password"] as string) ||
          (await promptPassword(`Enter password for ${handle}:`));

        await tool.deleteMessage(
          handle,
          password,
          endpointCert,
          endpointKey,
          messageId,
        );
        break;
      }

      case "stats": {
        const handle = parsedArgs["handle"] as string;
        const endpointCert = parsedArgs["endpoint-cert"] as string;
        const endpointKey = parsedArgs["endpoint-key"] as string;

        if (!handle || !endpointCert || !endpointKey) {
          throw new Error(
            "Missing required arguments: --handle, --endpoint-cert, --endpoint-key",
          );
        }

        const password =
          (parsedArgs["password"] as string) ||
          (await promptPassword(`Enter password for ${handle}:`));

        await tool.getStats(handle, password, endpointCert, endpointKey);
        break;
      }

      default:
        throw new Error(`Unknown command: ${command}`);
    }
  } catch (error) {
    console.error("Error:", error.message);
    process.exit(1);
  }

  process.exit(0);
}

// Export the class for testing
export { ATSMSCLITool };

if (import.meta.main) {
  main();
}
