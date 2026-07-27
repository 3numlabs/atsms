/**
 * AT-SMS Storage Manager
 *
 * Core storage management logic for encrypted messages.
 * This is platform-agnostic and handles the business logic
 * for message storage, sync, and encryption.
 */

import { nanoid } from "nanoid";
import { type Observable, Subject } from "rxjs";
import { z } from "zod";

import { ATSMSApiClient } from "../atsms-api";
import { type ATSMSClient } from "../atsms-client";
import { type ATSMSEndpointCertificate } from "../certificates/index";
import {
  decryptAndVerifyMessageSignature,
  encryptMessage,
  signMessage,
} from "../crypto";
import { generateJWT } from "../jwt-auth";
import {
  createTextContent,
  createWebRTCContent,
  generateDMConvoId,
} from "../messages";
import { ATSMSTransportLayer } from "../transport-layer";
import type {
  ATSMSMessagePayload,
  ATSMSSendRecipient,
  ATSMSTransportMessage,
  ATSMSWebRTCContent,
} from "../types";
import { ATSMSWebSocketClient } from "../websocket-client";
import type { StorageAdapter } from "./interface";
import type {
  ConversationFilter,
  LocalConversation,
  LocalMessage,
} from "./types";

// Zod schema for validating decrypted message data
const MessageDataSchema = z.object({
  version: z.string(),
  createdAt: z.string(),
  id: z.string(),
  convoId: z.string(),
  senderId: z.string(),
  recipientIds: z.array(z.string()),
  contentType: z.string(),
  content: z.string(),
});

export interface ATSMSStorageManagerConfig {
  storage: StorageAdapter;
  inboxUrl: string; // AT-SMS Inbox Provider URL
  atsmsClient: ATSMSClient;
  onSyncCompleted?: () => void;
  onMessageAdded?: (message: LocalMessage) => void;
  onConversationUpdated?: (convoId: string) => void;
}

export interface CertificateCache {
  did: string;
  handle?: string;
  endpointCerts: ATSMSEndpointCertificate[];
}

export class ATSMSStorageManager {
  private storage: StorageAdapter;
  private atsmsClient: ATSMSClient;
  private httpClient: ATSMSApiClient;
  private transports = new Map<string, ATSMSTransportLayer>(); // did -> transport
  private activeTransport: ATSMSTransportLayer | null = null;
  private initialized = false;
  private certificateCache = new Map<string, CertificateCache>();

  // Event emitters
  private syncCompletedSubject = new Subject<void>();
  private messageAddedSubject = new Subject<LocalMessage>();
  private conversationUpdatedSubject = new Subject<string>();

  constructor(config: ATSMSStorageManagerConfig) {
    this.storage = config.storage;
    this.atsmsClient = config.atsmsClient;

    // Initialize AT-SMS API client
    this.httpClient = new ATSMSApiClient({
      apiUrl: config.inboxUrl,
    });

    // Connect event callbacks if provided
    if (config.onSyncCompleted) {
      this.syncCompletedSubject.subscribe(config.onSyncCompleted);
    }
    if (config.onMessageAdded) {
      this.messageAddedSubject.subscribe((message) =>
        config.onMessageAdded!(message),
      );
    }
    if (config.onConversationUpdated) {
      this.conversationUpdatedSubject.subscribe(config.onConversationUpdated);
    }
  }

  /**
   * Ensure database is initialized (auto-called on first use)
   */
  private async ensureInitialized(): Promise<void> {
    if (!this.initialized) {
      // Database schema already initialized in SQLiteAdapter constructor
      // This is here for future initialization needs
      this.initialized = true;
    }
  }

  /**
   * Get the active transport (throws if not started)
   */
  private getTransport(): ATSMSTransportLayer {
    if (!this.activeTransport) {
      throw new Error(
        "Cannot perform operations: No active transport. " +
          "Call startTransport(did) first after saving DID with saveDid().",
      );
    }
    return this.activeTransport;
  }

  /**
   * Get the active DID from the primary DID (throws if not found)
   */
  private async getActiveDid(): Promise<string> {
    const primaryDid = await this.storage.getPrimaryDid();
    if (!primaryDid) {
      throw new Error(
        "Cannot perform operations: No primary DID found. " +
          "Call saveDid() first to save a DID.",
      );
    }
    return primaryDid.did;
  }

  // DID management operations
  async getPrimaryDid(): Promise<import("./types").ATSMSDidInfo | null> {
    await this.ensureInitialized();
    return this.storage.getPrimaryDid();
  }

  async getDid(did: string): Promise<import("./types").ATSMSDidInfo | null> {
    await this.ensureInitialized();
    return this.storage.getDid(did);
  }

  async saveDid(
    did: string,
    handle: string,
    endpointCert: ATSMSEndpointCertificate,
  ): Promise<void> {
    await this.ensureInitialized();
    await this.storage.saveDid(did, handle, endpointCert);
  }

  // Transport lifecycle operations
  async startTransport(did: string): Promise<void> {
    await this.ensureInitialized();

    // Get DID info from database
    const didInfo = await this.storage.getDid(did);
    if (!didInfo) {
      throw new Error(
        `Cannot start transport: DID ${did} not found. Call saveDid() first.`,
      );
    }

    // Create transport if doesn't exist
    if (!this.transports.has(did)) {
      const transport = new ATSMSTransportLayer({
        did: didInfo.did,
        certSerial: didInfo.certSerial,
        httpClient: this.httpClient,
        preferWebSocket: true,
      });
      this.transports.set(did, transport);
    }

    // Set as active transport
    this.activeTransport = this.transports.get(did)!;

    // Note: Initial sync should be performed by caller after connecting WebSocket
    // or by calling syncMessages() with the endpoint certificate
  }

  async stopTransport(did: string): Promise<void> {
    const transport = this.transports.get(did);
    if (transport) {
      // Disconnect WebSocket if connected
      transport.setWebSocketClient(null);
      this.transports.delete(did);

      // Clear active if this was the active transport
      if (this.activeTransport === transport) {
        this.activeTransport = null;
      }
    }
  }

  isTransportActive(did: string): boolean {
    return this.transports.has(did);
  }

  /**
   * Update the WebSocket client for the active transport layer
   */
  setWebSocketClient(wsClient: ATSMSWebSocketClient | null): void {
    if (this.activeTransport) {
      this.activeTransport.setWebSocketClient(wsClient);
    }
  }

  /**
   * Enable or disable WebSocket API operations for active transport
   */
  setPreferWebSocket(prefer: boolean): void {
    if (this.activeTransport) {
      this.activeTransport.setPreferWebSocket(prefer);
    }
  }

  // Validate that a string is a valid DID
  private isValidDID(value: string): boolean {
    return /^did:(web|plc):[a-zA-Z0-9._%-]+/.test(value);
  }

  // Conversation operations
  async listConversations(
    limit?: number,
    cursor?: string,
  ): Promise<LocalConversation[]> {
    return this.storage.getConversations(limit, cursor);
  }

  async getConversation(id: string): Promise<LocalConversation | null> {
    return this.storage.getConversation(id);
  }

  async getMessages(
    convoId: string,
    limit?: number,
    cursor?: string,
  ): Promise<LocalMessage[]> {
    return this.storage.getMessages(convoId, limit, cursor);
  }

  /**
   * Find an existing conversation with the given participants
   * Returns null if no conversation exists with exactly these participants
   */
  async findConversationByParticipants(
    participantDids: string[],
  ): Promise<LocalConversation | null> {
    return this.storage.findConversationByParticipants(participantDids);
  }

  /**
   * Get existing conversation or create new one with the given participants
   * Returns conversation with proper ID (either existing or newly created)
   */
  async getOrCreateConversation(
    participantDids: string[],
  ): Promise<LocalConversation> {
    // Look for existing conversation (database query)
    let conversation =
      await this.storage.findConversationByParticipants(participantDids);

    if (conversation) {
      return conversation;
    }

    // For 1:1 DMs, use deterministic convoId; random for groups
    const convoId =
      participantDids.length === 2
        ? await generateDMConvoId(participantDids[0], participantDids[1])
        : nanoid(13);

    conversation = {
      id: convoId,
      participantIds: participantDids,
      createdAt: new Date(),
      lastMessageAt: new Date(),
      unreadCount: 0,
    };

    await this.storage.saveConversation(conversation);
    return conversation;
  }

  // Observable streams for UI - storage queries
  observeConversations(
    filter?: ConversationFilter,
  ): Observable<LocalConversation[]> {
    return this.storage.observeConversations(filter);
  }

  observeMessages(convoId: string): Observable<LocalMessage[]> {
    return this.storage.observeMessages(convoId);
  }

  observeConversation(convoId: string): Observable<LocalConversation | null> {
    return this.storage.observeConversation(convoId);
  }

  // Observable streams for UI - event notifications
  get messageAdded$(): Observable<LocalMessage> {
    return this.messageAddedSubject.asObservable();
  }

  get conversationUpdated$(): Observable<string> {
    return this.conversationUpdatedSubject.asObservable();
  }

  get syncCompleted$(): Observable<void> {
    return this.syncCompletedSubject.asObservable();
  }

  /**
   * Get the storage adapter (for certificate operations and direct storage access)
   */
  getStorage(): StorageAdapter {
    return this.storage;
  }

  // Start a new encrypted conversation
  async startConversation(
    recipientDIDs: string[],
    content: string,
    endpointCert: ATSMSEndpointCertificate,
    metadata?: { title?: string },
  ): Promise<string> {
    const messageId = nanoid(13);
    const now = new Date();
    const activeDid = await this.getActiveDid();

    // For 1:1 DMs, use deterministic convoId to prevent duplicates
    let convoId: string;
    if (recipientDIDs.length === 1) {
      convoId = await generateDMConvoId(activeDid, recipientDIDs[0]);

      // Check if conversation already exists — send message there instead
      const existing = await this.storage.getConversation(convoId);
      if (existing) {
        await this.sendMessage(convoId, content, endpointCert);
        return convoId;
      }
    } else {
      convoId = nanoid(13);
    }

    // Validate and collect recipient certificates
    const participantDids: string[] = [activeDid];
    const recipientData: CertificateCache[] = [];

    for (const toDID of recipientDIDs) {
      if (!this.isValidDID(toDID)) {
        throw new Error(`Invalid DID: ${toDID}`);
      }

      const cached = await this.getCachedOrFetchCertificatesForDID(toDID);
      participantDids.push(cached.did);
      recipientData.push(cached);
    }

    // Create conversation record
    const conversation: LocalConversation = {
      id: convoId,
      participantIds: participantDids,
      createdAt: now,
      acceptedAt: now, // Auto-accept since we initiated
      lastMessageAt: now,
      unreadCount: 0,
      metadata: {
        title: metadata?.title,
        isGroup: recipientDIDs.length > 1,
      },
    };

    await this.storage.saveConversation(conversation);
    this.conversationUpdatedSubject.next(convoId);

    // Create and send message
    const payload: ATSMSMessagePayload = {
      version: "1.0",
      contentType: "atsms/text",
      id: messageId,
      content: createTextContent(content),
      senderId: activeDid,
      recipientIds: recipientData.map((r) => r.did),
      convoId,
      createdAt: now.toISOString(),
    };

    // Sign and encrypt the message
    const signedContent = await signMessage(
      JSON.stringify(payload),
      endpointCert,
    );

    // Build grouped list of recipients by DID with their endpoints
    const sendRecipients: ATSMSSendRecipient[] = [];

    for (const recipient of recipientData) {
      const endpoints: Array<{ certSerial: string; email: string }> = [];

      // Build endpoints array for this recipient (each device/certificate)
      for (const endpointCert of recipient.endpointCerts) {
        // Email is required in certificate SAN (no backward compatibility yet)
        if (!endpointCert.email) {
          throw new Error(
            `Certificate ${endpointCert.serialNumber} for ${recipient.did} is missing email in Subject Alternative Name. ` +
              `All certificates must include an email address for message routing.`,
          );
        }

        endpoints.push({
          certSerial: await endpointCert.getDeviceFingerprint(), // legacy field name; value = fingerprint (§8.5)
          email: endpointCert.email,
        });
      }

      // Add this recipient with all their endpoints
      sendRecipients.push({
        did: recipient.did,
        endpoints,
      });
    }

    // Encrypt for all recipients
    const allEndpointCerts = recipientData.flatMap((r) => r.endpointCerts);
    const encryptedPayload = await encryptMessage(
      signedContent,
      allEndpointCerts,
    );
    const base64Payload = btoa(String.fromCharCode(...encryptedPayload));

    // Send to all recipients in one call
    await this.ensureAuth(endpointCert);
    try {
      const sendResponse = await this.getTransport().sendMessage(
        sendRecipients,
        base64Payload,
      );

      // Check for any failed deliveries
      const failedResults = sendResponse.results.filter(
        (r) => r.status === "failed",
      );
      if (failedResults.length > 0) {
        const errors = failedResults
          .map((r) => `${r.email}: ${r.error}`)
          .join(", ");
        throw new Error(`Failed to send to some recipients: ${errors}`);
      }
    } catch (error: any) {
      // Don't log the full error object here, just re-throw for the client to handle
      throw error;
    }

    // Save message locally
    const localMessage: LocalMessage = {
      id: messageId,
      convoId,
      senderId: activeDid,
      recipientIds: recipientData.map((r) => r.did),
      content: createTextContent(content),
      contentType: "atsms/text",
      createdAt: now,
      isInvitation: true,
    };
    await this.storage.saveMessage(localMessage);
    this.messageAddedSubject.next(localMessage);

    return convoId;
  }

  // Send a message in existing conversation
  async sendMessage(
    convoId: string,
    content: string,
    endpointCert: ATSMSEndpointCertificate,
  ): Promise<string> {
    // Get conversation
    const conversation = await this.storage.getConversation(convoId);
    if (!conversation) {
      throw new Error(`Conversation ${convoId} not found`);
    }

    const messageId = nanoid(13);
    const now = new Date();
    const activeDid = await this.getActiveDid();

    // Determine recipients
    const isSelfConversation =
      conversation.participantIds.length === 1 &&
      conversation.participantIds[0] === activeDid;

    const recipientDids = isSelfConversation
      ? [activeDid]
      : conversation.participantIds.filter((did) => did !== activeDid);

    // Create message payload
    const payload: ATSMSMessagePayload = {
      version: "1.0",
      contentType: "atsms/text",
      id: messageId,
      content: createTextContent(content),
      senderId: activeDid,
      recipientIds: recipientDids,
      convoId,
      createdAt: now.toISOString(),
    };

    // Sign the message
    const signedContent = await signMessage(
      JSON.stringify(payload),
      endpointCert,
    );

    await this.ensureAuth(endpointCert);

    // Fetch certificates for all recipients and build grouped send list
    const sendRecipients: ATSMSSendRecipient[] = [];
    const allEndpointCerts: ATSMSEndpointCertificate[] = [];

    for (const recipientDid of recipientDids) {
      const recipientData =
        await this.getCachedOrFetchCertificatesForDID(recipientDid);
      const endpoints: Array<{ certSerial: string; email: string }> = [];

      // Build endpoints array for this recipient (each device/certificate)
      for (const cert of recipientData.endpointCerts) {
        // Email is required in certificate SAN (no backward compatibility yet)
        if (!cert.email) {
          throw new Error(
            `Certificate ${cert.serialNumber} for ${recipientDid} is missing email in Subject Alternative Name. ` +
              `All certificates must include an email address for message routing.`,
          );
        }

        endpoints.push({
          certSerial: await cert.getDeviceFingerprint(), // legacy field name; value = fingerprint (§8.5)
          email: cert.email,
        });
        allEndpointCerts.push(cert);
      }

      // Add this recipient with all their endpoints
      sendRecipients.push({
        did: recipientDid,
        endpoints,
      });
    }

    // Encrypt once for all recipients
    const encryptedPayload = await encryptMessage(
      signedContent,
      allEndpointCerts,
    );
    const base64Payload = btoa(String.fromCharCode(...encryptedPayload));

    // Send to all recipients in one call
    try {
      const sendResponse = await this.getTransport().sendMessage(
        sendRecipients,
        base64Payload,
      );

      // Check for any failed deliveries
      const failedResults = sendResponse.results.filter(
        (r) => r.status === "failed",
      );
      if (failedResults.length > 0) {
        const errors = failedResults
          .map((r) => `${r.email}: ${r.error}`)
          .join(", ");
        throw new Error(`Failed to send to some recipients: ${errors}`);
      }
    } catch (error: any) {
      // Don't log the full error object here, just re-throw for the client to handle
      throw error;
    }

    // Save message locally
    const localMessage: LocalMessage = {
      id: messageId,
      convoId,
      senderId: activeDid,
      recipientIds: recipientDids,
      content: createTextContent(content),
      contentType: "atsms/text",
      createdAt: now,
      isInvitation: false,
    };
    await this.storage.saveMessage(localMessage);
    await this.storage.updateConversation(convoId, { lastMessageAt: now });

    this.messageAddedSubject.next(localMessage);
    this.conversationUpdatedSubject.next(convoId);

    return messageId;
  }

  /**
   * Send a WebRTC signaling message in an existing conversation
   * Used for establishing peer-to-peer audio/video calls
   *
   * @param convoId - Conversation ID
   * @param webrtcContent - WebRTC signaling data (offer, answer, ICE candidate, etc.)
   * @param endpointCert - Sender's endpoint certificate with private key
   * @returns Message ID
   */
  async sendWebRTC(
    convoId: string,
    webrtcContent: ATSMSWebRTCContent,
    endpointCert: ATSMSEndpointCertificate,
  ): Promise<string> {
    // 1. Get conversation
    const conversation = await this.storage.getConversation(convoId);
    if (!conversation) {
      throw new Error(`Conversation ${convoId} not found`);
    }

    const messageId = nanoid(13);
    const now = new Date();
    const activeDid = await this.getActiveDid();

    // 2. Determine recipients
    const isSelfConversation =
      conversation.participantIds.length === 1 &&
      conversation.participantIds[0] === activeDid;

    const recipientDids = isSelfConversation
      ? [activeDid]
      : conversation.participantIds.filter((did) => did !== activeDid);

    // 3. Create message payload with WebRTC content
    const payload: ATSMSMessagePayload = {
      version: "1.0",
      contentType: "atsms/webrtc",
      id: messageId,
      content: createWebRTCContent(webrtcContent),
      senderId: activeDid,
      recipientIds: recipientDids,
      convoId,
      createdAt: now.toISOString(),
    };

    // 4. Sign the message
    const signedContent = await signMessage(
      JSON.stringify(payload),
      endpointCert,
    );

    await this.ensureAuth(endpointCert);

    // 5. Get recipient certificates and build send list
    const sendRecipients: ATSMSSendRecipient[] = [];
    const allEndpointCerts: ATSMSEndpointCertificate[] = [];

    for (const recipientDid of recipientDids) {
      const recipientData =
        await this.getCachedOrFetchCertificatesForDID(recipientDid);
      const endpoints: Array<{ certSerial: string; email: string }> = [];

      for (const cert of recipientData.endpointCerts) {
        if (!cert.email) {
          throw new Error(
            `Certificate ${cert.serialNumber} for ${recipientDid} is missing email in Subject Alternative Name. ` +
              `All certificates must include an email address for message routing.`,
          );
        }

        endpoints.push({
          certSerial: await cert.getDeviceFingerprint(), // legacy field name; value = fingerprint (§8.5)
          email: cert.email,
        });
        allEndpointCerts.push(cert);
      }

      sendRecipients.push({
        did: recipientDid,
        endpoints,
      });
    }

    // 6. Encrypt for all recipients
    const encryptedPayload = await encryptMessage(
      signedContent,
      allEndpointCerts,
    );
    const base64Payload = btoa(String.fromCharCode(...encryptedPayload));

    // 7. Send via transport layer
    await this.getTransport().sendMessage(sendRecipients, base64Payload);

    // 8. Save to local database
    const localMessage: LocalMessage = {
      id: messageId,
      convoId,
      senderId: activeDid,
      recipientIds: recipientDids,
      content: createWebRTCContent(webrtcContent),
      contentType: "atsms/webrtc",
      createdAt: now,
      isInvitation: false,
    };
    await this.storage.saveMessage(localMessage);
    await this.storage.updateConversation(convoId, { lastMessageAt: now });

    // 9. Emit events
    this.messageAddedSubject.next(localMessage);
    this.conversationUpdatedSubject.next(convoId);

    return messageId;
  }

  /**
   * Alias for sendWebRTC() - for frontend compatibility
   * Sends a WebRTC signaling message (offer, answer, ICE candidate, or hangup)
   */
  async sendWebRTCSignal(
    convoId: string,
    webrtcContent: ATSMSWebRTCContent,
    endpointCert: ATSMSEndpointCertificate,
  ): Promise<string> {
    return this.sendWebRTC(convoId, webrtcContent, endpointCert);
  }

  /**
   * Process and store a raw transport message from ANY source
   * (WebSocket notification, API sync, direct fetch)
   *
   * This is the ONLY entry point for incoming messages
   */
  async processIncomingTransportMessage(
    transportMessage: ATSMSTransportMessage,
    endpointCert: ATSMSEndpointCertificate,
  ): Promise<{
    messageId: string;
    convoId: string;
    isNew: boolean;
  }> {
    if (!transportMessage?.encryptedContent) {
      throw new Error("Invalid transport message: missing encryptedContent");
    }

    const activeDid = await this.getActiveDid();

    // 1. Decrypt message
    const encryptedContent = Uint8Array.from(
      atob(transportMessage.encryptedContent),
      (c) => c.charCodeAt(0),
    );

    const decrypted = await decryptAndVerifyMessageSignature(
      encryptedContent,
      endpointCert,
    );

    // 2. Extract and verify sender
    // For self-signed certificates, the DID is in the subject CN (same as issuer)
    const verifiedSender = decrypted.messageSigner.subject.replace(/^CN=/, "");
    const contentText = new TextDecoder().decode(decrypted.decryptedContent);
    const messageData = JSON.parse(contentText);

    // 3. Validate data structure
    const validatedData = MessageDataSchema.parse(messageData);

    if (validatedData.senderId !== verifiedSender) {
      throw new Error(
        `Sender mismatch: payload claims ${validatedData.senderId} but signature is from ${verifiedSender}`,
      );
    }

    // 4. Check for duplicates
    const existing = await this.storage.getMessage(transportMessage.id);
    if (existing) {
      return {
        messageId: transportMessage.id,
        convoId: existing.convoId,
        isNew: false,
      };
    }

    // 5. Get or create conversation
    const participantIds = Array.from(
      new Set([validatedData.senderId, ...validatedData.recipientIds]),
    );

    let conversation: LocalConversation | null = null;
    let effectiveConvoId: string;

    // For 1:1 DMs, compute deterministic convoId
    if (participantIds.length === 2) {
      effectiveConvoId = await generateDMConvoId(
        participantIds[0],
        participantIds[1],
      );

      conversation = await this.storage.getConversation(effectiveConvoId);

      if (!conversation) {
        conversation = {
          id: effectiveConvoId,
          participantIds,
          createdAt: new Date(validatedData.createdAt),
          acceptedAt:
            validatedData.senderId === activeDid
              ? new Date(validatedData.createdAt)
              : undefined,
          lastMessageAt: new Date(validatedData.createdAt),
          unreadCount: validatedData.senderId !== activeDid ? 1 : 0,
        };

        await this.storage.saveConversation(conversation);
        this.conversationUpdatedSubject.next(effectiveConvoId);
      }
    } else {
      // Group chat: use the sender's convoId (existing behavior)
      effectiveConvoId = validatedData.convoId;
      conversation = await this.storage.getConversation(effectiveConvoId);

      if (!conversation) {
        conversation = {
          id: effectiveConvoId,
          participantIds,
          createdAt: new Date(validatedData.createdAt),
          acceptedAt:
            validatedData.senderId === activeDid
              ? new Date(validatedData.createdAt)
              : undefined,
          lastMessageAt: new Date(validatedData.createdAt),
          unreadCount: validatedData.senderId !== activeDid ? 1 : 0,
        };

        await this.storage.saveConversation(conversation);
        this.conversationUpdatedSubject.next(effectiveConvoId);
      }
    }

    // 6. Save message to database (using effective convoId, not sender's)
    const localMessage: LocalMessage = {
      id: transportMessage.id,
      convoId: effectiveConvoId,
      senderId: validatedData.senderId,
      recipientIds: validatedData.recipientIds,
      content: validatedData.content,
      contentType: validatedData.contentType,
      createdAt: new Date(validatedData.createdAt),
      isInvitation: false,
    };

    await this.storage.saveMessage(localMessage);

    // 7. Update conversation
    if (validatedData.senderId !== activeDid) {
      await this.storage.updateConversation(effectiveConvoId, {
        lastMessageAt: localMessage.createdAt,
        unreadCount: (conversation.unreadCount || 0) + 1,
      });
      this.conversationUpdatedSubject.next(effectiveConvoId);
    }

    // 8. Notify observers
    this.messageAddedSubject.next(localMessage);

    return {
      messageId: transportMessage.id,
      convoId: effectiveConvoId,
      isNew: true,
    };
  }

  /**
   * Sync messages from AT-SMS API (polling mode)
   * Uses processIncomingTransportMessage internally
   * Uses transport layer for intelligent HTTP/WebSocket selection
   */
  async syncMessages(endpointCert: ATSMSEndpointCertificate): Promise<{
    newMessages: number;
    totalMessages: number;
  }> {
    await this.ensureAuth(endpointCert);

    // Get last sync sequence
    const lastSyncSeq = await this.storage.getLastSyncRev();
    const afterSequence = lastSyncSeq ? parseInt(lastSyncSeq, 10) : undefined;

    // Fetch message list via transport layer (uses WebSocket if available, else HTTP)
    const messageListResponse = await this.getTransport().listMessages({
      after: afterSequence,
    });

    let highestSequence = messageListResponse.latestSeq || afterSequence || 0;
    const encryptedMessages = messageListResponse.messages || [];
    let newCount = 0;

    // Process each message through standard pipeline
    for (const msgHeader of encryptedMessages) {
      try {
        if (msgHeader.seq > highestSequence) {
          highestSequence = msgHeader.seq;
        }

        // Download full transport message via transport layer
        const transportMessage = await this.getTransport().getMessage(
          msgHeader.id,
        );

        if (!transportMessage?.encryptedContent) {
          continue;
        }

        // Process through standard pipeline
        const result = await this.processIncomingTransportMessage(
          transportMessage,
          endpointCert,
        );

        if (result.isNew) {
          newCount++;
        }
      } catch (error) {
        console.warn(`Failed to process message ${msgHeader.id}:`, error);
      }
    }

    // Update sync sequence
    if (highestSequence > 0) {
      await this.storage.setLastSyncRev(highestSequence.toString());
    }

    this.syncCompletedSubject.next();

    return {
      newMessages: newCount,
      totalMessages: encryptedMessages.length,
    };
  }

  /**
   * Create a WebSocket client that auto-processes messages
   * Returns configured client ready to connect
   * Also integrates with transport layer for unified API access
   */
  async createWebSocketClient(
    endpointCert: ATSMSEndpointCertificate,
    callbacks?: {
      onError?: (error: Error) => void;
      onConnect?: () => void;
      onDisconnect?: (code: number, reason: string) => void;
    },
  ): Promise<ATSMSWebSocketClient> {
    const wsApiUrl = this.httpClient.config.apiUrl;
    const activeDid = await this.getActiveDid();

    const deviceFingerprint = await endpointCert.getDeviceFingerprint();
    const wsClient = new ATSMSWebSocketClient({
      apiUrl: wsApiUrl,
      did: activeDid,
      deviceFingerprint,
      getToken: async () => {
        const privateKeyPEM = endpointCert.certificatePrivateKeyPEM;
        if (!privateKeyPEM) {
          throw new Error("No private key available for WebSocket auth");
        }
        return await generateJWT(privateKeyPEM, deviceFingerprint, activeDid);
      },
      onMessage: async (wsMessage) => {
        // Only process actual message notifications
        if (wsMessage.type === "new_message") {
          try {
            // Ensure auth is set
            await this.ensureAuth(endpointCert);

            // Download the full transport message via transport layer
            const transportMessage = await this.getTransport().getMessage(
              wsMessage.message.id,
            );

            // Process through standard pipeline
            await this.processIncomingTransportMessage(
              transportMessage,
              endpointCert,
            );
          } catch (error) {
            console.error("Failed to process WebSocket message:", error);
          }
        }
        // Ignore other message types (pong, auth_success, connected, etc.)
      },
      onConnect: async () => {
        // Update transport layer with connected WebSocket
        if (this.activeTransport) {
          this.activeTransport.setWebSocketClient(wsClient);
        }

        // Auto-sync messages on connect to catch up on any missed while offline
        // Note: onConnect only fires after authentication succeeds (see websocket-client.ts:268-276)
        // Guard check ensures WebSocket is authenticated before syncing
        if (wsClient.isConnected() && wsClient.isAuthenticated()) {
          try {
            await this.syncMessages(endpointCert);
          } catch (error) {
            // Log but don't throw - sync failure shouldn't block WebSocket connection
            console.warn("Auto-sync on WebSocket connect failed:", error);
          }
        }

        // Call user-provided callback if present
        if (callbacks?.onConnect) {
          callbacks.onConnect();
        }
      },
      onDisconnect: (code, reason) => {
        // Clear WebSocket from active transport
        if (this.activeTransport) {
          this.activeTransport.setWebSocketClient(null);
        }
        // Call user-provided callback if present
        if (callbacks?.onDisconnect) {
          callbacks.onDisconnect(code, reason);
        }
      },
      onError: (error) => {
        // Call user-provided callback if present, otherwise log to console
        if (callbacks?.onError) {
          callbacks.onError(error);
        } else {
          console.error("WebSocket error:", error);
        }
      },
    });

    // Update transport with this WebSocket client
    this.getTransport().setWebSocketClient(wsClient);

    return wsClient;
  }

  // Mark conversation as read
  async markConversationRead(convoId: string): Promise<void> {
    await this.storage.updateConversation(convoId, { unreadCount: 0 });
    this.conversationUpdatedSubject.next(convoId);
  }

  // Accept conversation
  async acceptConversation(convoId: string): Promise<void> {
    await this.storage.updateConversation(convoId, {
      acceptedAt: new Date(),
    });
    this.conversationUpdatedSubject.next(convoId);
  }

  // Delete message
  async deleteMessage(messageId: string): Promise<void> {
    const message = await this.storage.getMessage(messageId);
    if (message) {
      await this.storage.deleteMessage(messageId);
      // Note: We emit the message event even on delete so UI can update
      this.messageAddedSubject.next(message);
    }
  }

  // Clear all data
  async clearAll(): Promise<void> {
    await this.storage.clearAll();
  }


  // Certificate management
  private async getCachedOrFetchCertificatesForDID(
    did: string,
  ): Promise<CertificateCache> {
    // Check in-memory cache first (session-only cache)
    if (this.certificateCache.has(did)) {
      return this.certificateCache.get(did)!;
    }

    // TODO: Future enhancement - consider caching peer certificates in SQLite
    // This would enable:
    // - Offline messaging capability (queue messages for later delivery)
    // - Faster startup times by avoiding repeated PDS fetches
    // - Ability to show certificate status without network access
    //
    // Implementation considerations:
    // - Need expiration/TTL mechanism to ensure certificates are refreshed
    // - Should verify certificates are still valid when loading from cache
    // - May want to store only public certificates (no private keys for peers)
    // Example: const cachedPeerCert = await this.storage.getCertificate(did, 'peer')

    // Fetch from PDS (always gets latest certificates)
    const certs = await this.atsmsClient.getUserCertificates(did);

    // Handle specific error cases with clear messages
    if (certs.error) {
      switch (certs.error) {
        case "NOT_ATPROTO_USER":
          throw new Error(
            `${did} is not a valid AT Protocol user. ` +
              `Please verify the DID or handle is correct.`,
          );
        case "NO_ATSMS_CERTS":
          throw new Error(
            `${did} has not set up AT-SMS. ` + `No certificates found.`,
          );
        case "NO_ENDPOINT_CERTS":
          throw new Error(
            `${did} has incomplete AT-SMS setup. ` +
              `Missing endpoint certificates.`,
          );
        case "FETCH_ERROR":
          throw new Error(
            `Failed to fetch certificates for ${did}. ` +
              `The user's PDS may be unavailable or there was a network error.`,
          );
      }
    }

    const cache: CertificateCache = {
      did,
      endpointCerts: certs.endpointCerts,
    };

    // Store in memory cache for this session
    this.certificateCache.set(did, cache);
    return cache;
  }

  // Ensure AT-SMS API auth token is set
  private async ensureAuth(
    endpointCert: ATSMSEndpointCertificate,
  ): Promise<void> {
    const privateKeyPEM = endpointCert.certificatePrivateKeyPEM;
    if (!privateKeyPEM) {
      throw new Error("No private key available for authentication");
    }

    const activeDid = await this.getActiveDid();
    const jwt = await generateJWT(
      privateKeyPEM,
      await endpointCert.getDeviceFingerprint(),
      activeDid,
    );

    this.httpClient.setAuthToken(jwt);
  }
}
