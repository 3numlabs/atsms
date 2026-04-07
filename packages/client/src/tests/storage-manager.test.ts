/**
 * Tests for AT-SMS Storage Manager
 */

import { AtpAgent } from "@atproto/api";
import { beforeEach, describe, expect, test } from "bun:test";

import { ATSMSClient } from "../lib/atsms-client";
import { createTextContent } from "../lib/messages";
import type { StorageAdapter } from "../lib/storage/interface";
import { ATSMSStorageManager } from "../lib/storage/manager";
import type { LocalConversation, LocalMessage } from "../lib/storage/types";

// Mock storage adapter for testing
class MockStorageAdapter implements StorageAdapter {
  private messages = new Map<string, LocalMessage>();
  private conversations = new Map<string, LocalConversation>();
  private syncRev: string | null = null;
  private dids = new Map<string, any>();
  private certificates = new Map<string, any>();

  async saveMessage(message: LocalMessage): Promise<void> {
    this.messages.set(message.id, message);
  }

  async getMessage(id: string): Promise<LocalMessage | null> {
    return this.messages.get(id) || null;
  }

  async getMessages(convoId: string, limit?: number): Promise<LocalMessage[]> {
    const messages = Array.from(this.messages.values())
      .filter((m) => m.convoId === convoId)
      .sort((a, b) => b.createdAt.getTime() - a.createdAt.getTime());

    return limit ? messages.slice(0, limit) : messages;
  }

  async updateMessage(
    id: string,
    updates: Partial<LocalMessage>,
  ): Promise<void> {
    const message = this.messages.get(id);
    if (message) {
      this.messages.set(id, { ...message, ...updates });
    }
  }

  async deleteMessage(id: string): Promise<void> {
    this.messages.delete(id);
  }

  async saveConversation(conversation: LocalConversation): Promise<void> {
    this.conversations.set(conversation.id, conversation);
  }

  async getConversation(id: string): Promise<LocalConversation | null> {
    return this.conversations.get(id) || null;
  }

  async getConversations(limit?: number): Promise<LocalConversation[]> {
    const convos = Array.from(this.conversations.values()).sort(
      (a, b) => b.lastMessageAt.getTime() - a.lastMessageAt.getTime(),
    );

    return limit ? convos.slice(0, limit) : convos;
  }

  async findConversationByParticipants(
    participantDids: string[],
  ): Promise<LocalConversation | null> {
    const sorted = participantDids.slice().sort();
    for (const convo of this.conversations.values()) {
      const convoSorted = convo.participantIds.slice().sort();
      if (JSON.stringify(sorted) === JSON.stringify(convoSorted)) {
        return convo;
      }
    }
    return null;
  }

  async updateConversation(
    id: string,
    updates: Partial<LocalConversation>,
  ): Promise<void> {
    const conversation = this.conversations.get(id);
    if (conversation) {
      this.conversations.set(id, { ...conversation, ...updates });
    }
  }

  async deleteConversation(id: string): Promise<void> {
    this.conversations.delete(id);
  }

  async saveMessages(messages: LocalMessage[]): Promise<void> {
    for (const msg of messages) {
      await this.saveMessage(msg);
    }
  }

  async clearAll(): Promise<void> {
    this.messages.clear();
    this.conversations.clear();
    this.syncRev = null;
    this.dids.clear();
    this.certificates.clear();
  }

  async getLastSyncRev(): Promise<string | null> {
    return this.syncRev;
  }

  async setLastSyncRev(rev: string): Promise<void> {
    this.syncRev = rev;
  }

  observeConversations() {
    throw new Error("Not implemented for mock");
  }

  observeMessages() {
    throw new Error("Not implemented for mock");
  }

  observeConversation() {
    throw new Error("Not implemented for mock");
  }

  // DID management methods
  async getPrimaryDid(): Promise<any | null> {
    for (const did of this.dids.values()) {
      if (did.isPrimary) {
        return did;
      }
    }
    return null;
  }

  async getDid(did: string): Promise<any | null> {
    return this.dids.get(did) || null;
  }

  async saveDid(did: string, handle: string, endpointCert: any): Promise<void> {
    const now = new Date();
    const existing = this.dids.get(did);

    let isPrimary: boolean;
    let createdAt: Date;

    if (existing) {
      // DID exists - preserve isPrimary and createdAt
      isPrimary = existing.isPrimary;
      createdAt = existing.createdAt;
    } else {
      // New DID - first DID is primary
      isPrimary = this.dids.size === 0;
      createdAt = now;
    }

    this.dids.set(did, {
      did,
      handle,
      certSerial: endpointCert.serialNumber,
      isPrimary,
      createdAt,
      lastUsedAt: now,
    });

    // Also save certificate
    const certKey = `${did}:endpoint:${endpointCert.serialNumber}`;
    this.certificates.set(certKey, {
      certificatePEM: endpointCert.toString(),
      privateKeyPEM: endpointCert.certificatePrivateKeyPEM,
      isEncrypted: false,
    });
  }

  // Certificate methods
  async saveCertificate(
    did: string,
    type: string,
    serialNumber: string,
    certificatePEM: string,
    privateKeyPEM?: string,
    isEncrypted?: boolean,
    metadata?: Record<string, any>,
  ): Promise<void> {
    const key = `${did}:${type}:${serialNumber}`;
    this.certificates.set(key, {
      certificatePEM,
      privateKeyPEM,
      isEncrypted: isEncrypted || false,
      metadata,
    });
  }

  async getCertificate(
    did: string,
    type: string,
    serialNumber?: string,
  ): Promise<any | null> {
    if (serialNumber) {
      const key = `${did}:${type}:${serialNumber}`;
      return this.certificates.get(key) || null;
    }
    // Return first matching certificate
    for (const [key, cert] of this.certificates.entries()) {
      if (key.startsWith(`${did}:${type}:`)) {
        return cert;
      }
    }
    return null;
  }

  async listCertificates(did?: string): Promise<Array<any>> {
    const results: Array<any> = [];
    for (const [key, cert] of this.certificates.entries()) {
      if (!did || key.startsWith(`${did}:`)) {
        const [certDid, type, serialNumber] = key.split(":");
        results.push({
          did: certDid,
          type,
          serialNumber,
          notBefore: new Date(),
          notAfter: new Date(Date.now() + 365 * 24 * 60 * 60 * 1000),
          hasPrivateKey: !!cert.privateKeyPEM,
        });
      }
    }
    return results;
  }

  async deleteCertificate(
    did: string,
    type: string,
    serialNumber: string,
  ): Promise<void> {
    const key = `${did}:${type}:${serialNumber}`;
    this.certificates.delete(key);
  }
}

// Mock AT-SMS client
class MockATSMSClient extends ATSMSClient {
  constructor() {
    const agent = new AtpAgent({ service: "https://test.bsky.social" });
    super(agent, "did:plc:test123");
  }

  async getUserCertificates(did: string) {
    // Valid mock private key for testing (EC P-256)
    const mockPrivateKeyPEM = `-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgQKpLKKzVCPvYI5AH
cm/9HqRWGl0ug5JQPvR/OMDwD0WhRANCAAS0i+t8MqoJMDlJR4WO3Hvr7xNsQC3q
ywJtC5IxIDJRr4JSdBHBXBj6h+dKFhnoHEQQzcIASJYqiwnjz7FZvlCr
-----END PRIVATE KEY-----`;

    return {
      did,
      handle: "test.handle",
      clientCerts: [
        {
          serialNumber: "test-cert-001",
          certificate: new Uint8Array(),
          privateKey: null,
          raw: new Uint8Array(),
          certificatePrivateKeyPEM: mockPrivateKeyPEM,
        } as any,
      ],
    };
  }

  async resolveDIDToPDS(_did: string) {
    return "https://test.pds.example.com";
  }
}

describe("ATSMSStorageManager", () => {
  let storageAdapter: MockStorageAdapter;
  let atsmsClient: MockATSMSClient;
  let manager: ATSMSStorageManager;

  beforeEach(async () => {
    storageAdapter = new MockStorageAdapter();
    atsmsClient = new MockATSMSClient();

    manager = new ATSMSStorageManager({
      storage: storageAdapter,
      atsmsClient: atsmsClient as any,
      inboxUrl: "https://test.api.com",
    });

    // Setup a test DID with certificate
    const mockEndpointCert = {
      serialNumber: "test-cert-001",
      certificate: new Uint8Array(),
      privateKey: new Uint8Array(),
      raw: new Uint8Array(),
      toString: () =>
        "-----BEGIN CERTIFICATE-----\nMOCK\n-----END CERTIFICATE-----",
      certificatePrivateKeyPEM: `-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgQKpLKKzVCPvYI5AH
cm/9HqRWGl0ug5JQPvR/OMDwD0WhRANCAAS0i+t8MqoJMDlJR4WO3Hvr7xNsQC3q
ywJtC5IxIDJRr4JSdBHBXBj6h+dKFhnoHEQQzcIASJYqiwnjz7FZvlCr
-----END PRIVATE KEY-----`,
    } as any;

    await manager.saveDid("did:plc:user123", "user.test", mockEndpointCert);
    await manager.startTransport("did:plc:user123");
  });

  describe("DID Validation", () => {
    test("should validate correct DIDs", () => {
      // Access private method through any cast
      const m = manager as any;
      expect(m.isValidDID("did:plc:abc123")).toBe(true);
      expect(m.isValidDID("did:web:example.com")).toBe(true);
      expect(m.isValidDID("did:plc:abc-123_456.789")).toBe(true);
    });

    test("should reject invalid DIDs", () => {
      const m = manager as any;
      expect(m.isValidDID("not-a-did")).toBe(false);
      expect(m.isValidDID("did:invalid:abc")).toBe(false);
      expect(m.isValidDID("did:plc:")).toBe(false);
      expect(m.isValidDID("")).toBe(false);
    });
  });

  describe("Conversation Operations", () => {
    const testConversation: LocalConversation = {
      id: "convo-001",
      participantIds: ["did:plc:user123", "did:plc:user456"],
      createdAt: new Date("2024-01-01T10:00:00Z"),
      lastMessageAt: new Date("2024-01-01T12:00:00Z"),
      unreadCount: 0,
      metadata: {
        title: "Test Conversation",
        isGroup: false,
      },
    };

    test("should list conversations", async () => {
      await storageAdapter.saveConversation(testConversation);

      const conversations = await manager.listConversations();
      expect(conversations).toHaveLength(1);
      expect(conversations[0].id).toBe(testConversation.id);
    });

    test("should get a specific conversation", async () => {
      await storageAdapter.saveConversation(testConversation);

      const conversation = await manager.getConversation("convo-001");
      expect(conversation).toBeDefined();
      expect(conversation?.id).toBe(testConversation.id);
      expect(conversation?.metadata?.title).toBe("Test Conversation");
    });

    test("should return null for non-existent conversation", async () => {
      const conversation = await manager.getConversation("non-existent");
      expect(conversation).toBeNull();
    });

    test("should limit conversation retrieval", async () => {
      for (let i = 0; i < 10; i++) {
        await storageAdapter.saveConversation({
          ...testConversation,
          id: `convo-${i}`,
          lastMessageAt: new Date(Date.now() - i * 1000),
        });
      }

      const limited = await manager.listConversations(5);
      expect(limited).toHaveLength(5);
    });
  });

  describe("Message Operations", () => {
    const testMessage: LocalMessage = {
      id: "msg-001",
      convoId: "convo-001",
      senderId: "did:plc:user123",
      recipientIds: ["did:plc:user456"],
      content: createTextContent("Test message"),
      contentType: "atsms/text",
      createdAt: new Date("2024-01-01T12:00:00Z"),
    };

    test("should get messages for a conversation", async () => {
      await storageAdapter.saveMessage(testMessage);

      const messages = await manager.getMessages("convo-001");
      expect(messages).toHaveLength(1);
      expect(messages[0].id).toBe(testMessage.id);
      expect(messages[0].content).toBe(testMessage.content);
    });

    test("should limit message retrieval", async () => {
      for (let i = 0; i < 10; i++) {
        await storageAdapter.saveMessage({
          ...testMessage,
          id: `msg-${i}`,
          createdAt: new Date(Date.now() - i * 1000),
        });
      }

      const limited = await manager.getMessages("convo-001", 5);
      expect(limited).toHaveLength(5);
    });

    test("should return empty array for conversation with no messages", async () => {
      const messages = await manager.getMessages("empty-convo");
      expect(messages).toEqual([]);
    });
  });

  describe("Start Conversation", () => {
    test("should validate recipient DIDs", async () => {
      const freshStorage = new MockStorageAdapter();
      const freshAtsmsClient = new MockATSMSClient();
      const managerWithAPI = new ATSMSStorageManager({
        storage: freshStorage,
        atsmsClient: freshAtsmsClient as any,
        inboxUrl: "https://test.api.com",
      });

      const endpointCert = {
        serialNumber: "test-cert",
        certificate: new Uint8Array(),
        privateKey: new Uint8Array(),
        raw: new Uint8Array(),
        toString: () =>
          "-----BEGIN CERTIFICATE-----\nMOCK\n-----END CERTIFICATE-----",
        certificatePrivateKeyPEM: `-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgQKpLKKzVCPvYI5AH
cm/9HqRWGl0ug5JQPvR/OMDwD0WhRANCAAS0i+t8MqoJMDlJR4WO3Hvr7xNsQC3q
ywJtC5IxIDJRr4JSdBHBXBj6h+dKFhnoHEQQzcIASJYqiwnjz7FZvlCr
-----END PRIVATE KEY-----`,
      } as any;

      await managerWithAPI.saveDid(
        "did:plc:user123",
        "user.test",
        endpointCert,
      );
      await managerWithAPI.startTransport("did:plc:user123");

      await expect(
        managerWithAPI.startConversation(
          ["invalid-did"],
          "Hello",
          endpointCert,
        ),
      ).rejects.toThrow("Invalid DID: invalid-did");
    });

    // Skip tests that require mocking crypto functions to avoid affecting other tests
    test.skip("should create conversation and message records", async () => {
      // This test requires mocking crypto functions which affects other tests
      // Skipping to prevent test interference
    });

    test.skip("should handle group conversations", async () => {
      // This test requires mocking crypto functions which affects other tests
      // Skipping to prevent test interference
    });
  });

  describe("Send Message", () => {
    test("should throw error if conversation not found", async () => {
      const freshStorage = new MockStorageAdapter();
      const freshAtsmsClient = new MockATSMSClient();
      const managerWithAPI = new ATSMSStorageManager({
        storage: freshStorage,
        atsmsClient: freshAtsmsClient as any,
        inboxUrl: "https://test.api.com",
      });

      const endpointCert = {
        serialNumber: "test-cert",
        certificate: new Uint8Array(),
        privateKey: new Uint8Array(),
        raw: new Uint8Array(),
        toString: () =>
          "-----BEGIN CERTIFICATE-----\nMOCK\n-----END CERTIFICATE-----",
        certificatePrivateKeyPEM: `-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgQKpLKKzVCPvYI5AH
cm/9HqRWGl0ug5JQPvR/OMDwD0WhRANCAAS0i+t8MqoJMDlJR4WO3Hvr7xNsQC3q
ywJtC5IxIDJRr4JSdBHBXBj6h+dKFhnoHEQQzcIASJYqiwnjz7FZvlCr
-----END PRIVATE KEY-----`,
      } as any;

      await managerWithAPI.saveDid(
        "did:plc:user123",
        "user.test",
        endpointCert,
      );
      await managerWithAPI.startTransport("did:plc:user123");

      await expect(
        managerWithAPI.sendMessage("non-existent", "Hello", endpointCert),
      ).rejects.toThrow("Conversation non-existent not found");
    });

    // Skip tests that require mocking crypto functions to avoid affecting other tests
    test.skip("should send message in existing conversation", async () => {
      // This test requires mocking crypto functions which affects other tests
      // Skipping to prevent test interference
    });

    test.skip("should handle self-conversation", async () => {
      // This test requires mocking crypto functions which affects other tests
      // Skipping to prevent test interference
    });
  });

  describe("Event Emitters", () => {
    test("should emit sync completed event", async () => {
      let syncCompleted = false;

      const managerWithEvents = new ATSMSStorageManager({
        storage: storageAdapter,
        atsmsClient: atsmsClient as any,
        inboxUrl: "https://test.api.com",
        onSyncCompleted: () => {
          syncCompleted = true;
        },
      });

      // Trigger sync completed
      (managerWithEvents as any).syncCompletedSubject.next();

      // Wait a tick for the event to propagate
      await new Promise((resolve) => setTimeout(resolve, 0));

      expect(syncCompleted).toBe(true);
    });

    test("should emit message added event", async () => {
      let addedMessage: LocalMessage | null = null;

      const managerWithEvents = new ATSMSStorageManager({
        storage: storageAdapter,
        atsmsClient: atsmsClient as any,
        inboxUrl: "https://test.api.com",
        onMessageAdded: (message) => {
          addedMessage = message;
        },
      });

      const testMessage: LocalMessage = {
        id: "test-message",
        convoId: "test-convo",
        senderId: "did:plc:sender",
        recipientIds: ["did:plc:recipient"],
        content: createTextContent("test content"),
        contentType: "atsms/text",
        createdAt: new Date(),
        isInvitation: false,
      };

      // Trigger message added
      (managerWithEvents as any).messageAddedSubject.next(testMessage);

      await new Promise((resolve) => setTimeout(resolve, 0));

      expect(addedMessage).toEqual(testMessage);
      expect(addedMessage?.convoId).toBe("test-convo");
      expect(addedMessage?.id).toBe("test-message");
    });

    test("should emit conversation updated event", async () => {
      let updatedConvoId = "";

      const managerWithEvents = new ATSMSStorageManager({
        storage: storageAdapter,
        atsmsClient: atsmsClient as any,
        inboxUrl: "https://test.api.com",
        onConversationUpdated: (convoId) => {
          updatedConvoId = convoId;
        },
      });

      // Trigger conversation updated
      (managerWithEvents as any).conversationUpdatedSubject.next(
        "updated-convo",
      );

      await new Promise((resolve) => setTimeout(resolve, 0));

      expect(updatedConvoId).toBe("updated-convo");
    });

    test("should expose Observable accessors for event streams", async () => {
      const manager = new ATSMSStorageManager({
        storage: storageAdapter,
        atsmsClient: atsmsClient as any,
        inboxUrl: "https://test.api.com",
      });

      // Verify Observable accessors exist and have correct types
      expect(manager.messageAdded$).toBeDefined();
      expect(manager.conversationUpdated$).toBeDefined();
      expect(manager.syncCompleted$).toBeDefined();

      // Test messageAdded$ observable with full LocalMessage
      let receivedMessage: LocalMessage | null = null;
      const subscription = manager.messageAdded$.subscribe((message) => {
        receivedMessage = message;
      });

      const testMessage: LocalMessage = {
        id: "test-message",
        convoId: "test-convo",
        senderId: "did:plc:sender",
        recipientIds: ["did:plc:recipient"],
        content: createTextContent("test"),
        contentType: "atsms/text",
        createdAt: new Date(),
        isInvitation: false,
      };

      // Trigger event via private subject
      (manager as any).messageAddedSubject.next(testMessage);

      await new Promise((resolve) => setTimeout(resolve, 0));

      expect(receivedMessage).toEqual(testMessage);
      expect(receivedMessage?.convoId).toBe("test-convo");
      expect(receivedMessage?.id).toBe("test-message");
      expect(receivedMessage?.contentType).toBe("atsms/text");

      subscription.unsubscribe();
    });

    test("should allow filtering by contentType using RxJS operators", async () => {
      const manager = new ATSMSStorageManager({
        storage: storageAdapter,
        atsmsClient: atsmsClient as any,
        inboxUrl: "https://test.api.com",
      });

      const textMessages: string[] = [];
      const imageMessages: string[] = [];

      // Use RxJS filter operator
      const { filter } = await import("rxjs/operators");

      const textSub = manager.messageAdded$
        .pipe(filter((message) => message.contentType === "atsms/text"))
        .subscribe((message) => {
          textMessages.push(message.id);
        });

      const imageSub = manager.messageAdded$
        .pipe(filter((message) => message.contentType === "atsms/image"))
        .subscribe((message) => {
          imageMessages.push(message.id);
        });

      // Emit different content types
      const now = new Date();
      (manager as any).messageAddedSubject.next({
        id: "text-1",
        convoId: "test-convo",
        senderId: "did:plc:sender",
        recipientIds: ["did:plc:recipient"],
        content: createTextContent("text message 1"),
        contentType: "atsms/text",
        createdAt: now,
        isInvitation: false,
      } as LocalMessage);
      (manager as any).messageAddedSubject.next({
        id: "image-1",
        convoId: "test-convo",
        senderId: "did:plc:sender",
        recipientIds: ["did:plc:recipient"],
        content: '{"url":"https://example.com/image.jpg"}',
        contentType: "atsms/image",
        createdAt: now,
        isInvitation: false,
      } as LocalMessage);
      (manager as any).messageAddedSubject.next({
        id: "text-2",
        convoId: "test-convo",
        senderId: "did:plc:sender",
        recipientIds: ["did:plc:recipient"],
        content: createTextContent("text message 2"),
        contentType: "atsms/text",
        createdAt: now,
        isInvitation: false,
      } as LocalMessage);

      await new Promise((resolve) => setTimeout(resolve, 0));

      expect(textMessages).toEqual(["text-1", "text-2"]);
      expect(imageMessages).toEqual(["image-1"]);

      textSub.unsubscribe();
      imageSub.unsubscribe();
    });
  });

  describe("Certificate Caching", () => {
    test("should cache certificates after fetching", async () => {
      const managerWithAPI = new ATSMSStorageManager({
        storage: storageAdapter,
        atsmsClient: atsmsClient as any,
        inboxUrl: "https://test.api.com",
      });

      // First call should fetch from client
      const cache1 = await (
        managerWithAPI as any
      ).getCachedOrFetchCertificatesForDID("did:plc:test");
      expect(cache1.did).toBe("did:plc:test");

      // Second call should use cache
      const cache2 = await (
        managerWithAPI as any
      ).getCachedOrFetchCertificatesForDID("did:plc:test");
      expect(cache2).toBe(cache1); // Should be the same object reference
    });
  });

  describe("DID Management", () => {
    test("should save and retrieve primary DID", async () => {
      const freshStorage = new MockStorageAdapter();
      const freshManager = new ATSMSStorageManager({
        storage: freshStorage,
        atsmsClient: atsmsClient as any,
        inboxUrl: "https://test.api.com",
      });

      const mockEndpointCert = {
        serialNumber: "test-cert-001",
        certificate: new Uint8Array(),
        privateKey: new Uint8Array(),
        raw: new Uint8Array(),
        toString: () =>
          "-----BEGIN CERTIFICATE-----\nMOCK\n-----END CERTIFICATE-----",
        certificatePrivateKeyPEM: `-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgQKpLKKzVCPvYI5AH
cm/9HqRWGl0ug5JQPvR/OMDwD0WhRANCAAS0i+t8MqoJMDlJR4WO3Hvr7xNsQC3q
ywJtC5IxIDJRr4JSdBHBXBj6h+dKFhnoHEQQzcIASJYqiwnjz7FZvlCr
-----END PRIVATE KEY-----`,
      } as any;

      await freshManager.saveDid(
        "did:plc:alice123",
        "alice.test",
        mockEndpointCert,
      );

      const primaryDid = await freshManager.getPrimaryDid();
      expect(primaryDid).toBeDefined();
      expect(primaryDid?.did).toBe("did:plc:alice123");
      expect(primaryDid?.handle).toBe("alice.test");
      expect(primaryDid?.certSerial).toBe("test-cert-001");
      expect(primaryDid?.isPrimary).toBe(true);
    });

    test("should preserve isPrimary when updating DID with new certificate", async () => {
      const freshStorage = new MockStorageAdapter();
      const freshManager = new ATSMSStorageManager({
        storage: freshStorage,
        atsmsClient: atsmsClient as any,
        inboxUrl: "https://test.api.com",
      });

      const mockEndpointCert1 = {
        serialNumber: "test-cert-001",
        certificate: new Uint8Array(),
        privateKey: new Uint8Array(),
        raw: new Uint8Array(),
        toString: () =>
          "-----BEGIN CERTIFICATE-----\nMOCK1\n-----END CERTIFICATE-----",
        certificatePrivateKeyPEM: `-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgQKpLKKzVCPvYI5AH
cm/9HqRWGl0ug5JQPvR/OMDwD0WhRANCAAS0i+t8MqoJMDlJR4WO3Hvr7xNsQC3q
ywJtC5IxIDJRr4JSdBHBXBj6h+dKFhnoHEQQzcIASJYqiwnjz7FZvlCr
-----END PRIVATE KEY-----`,
      } as any;

      const mockEndpointCert2 = {
        serialNumber: "test-cert-002",
        certificate: new Uint8Array(),
        privateKey: new Uint8Array(),
        raw: new Uint8Array(),
        toString: () =>
          "-----BEGIN CERTIFICATE-----\nMOCK2\n-----END CERTIFICATE-----",
        certificatePrivateKeyPEM: `-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgQKpLKKzVCPvYI5AH
cm/9HqRWGl0ug5JQPvR/OMDwD0WhRANCAAS0i+t8MqoJMDlJR4WO3Hvr7xNsQC3q
ywJtC5IxIDJRr4JSdBHBXBj6h+dKFhnoHEQQzcIASJYqiwnjz7FZvlCr
-----END PRIVATE KEY-----`,
      } as any;

      // Save DID with first certificate
      await freshManager.saveDid(
        "did:plc:alice123",
        "alice.test",
        mockEndpointCert1,
      );

      const primaryDid1 = await freshManager.getPrimaryDid();
      expect(primaryDid1?.isPrimary).toBe(true);
      expect(primaryDid1?.certSerial).toBe("test-cert-001");

      // Save same DID with new certificate (simulating generating a new endpoint cert)
      await freshManager.saveDid(
        "did:plc:alice123",
        "alice.test",
        mockEndpointCert2,
      );

      // Should still be primary with updated certificate
      const primaryDid2 = await freshManager.getPrimaryDid();
      expect(primaryDid2).toBeDefined();
      expect(primaryDid2?.did).toBe("did:plc:alice123");
      expect(primaryDid2?.isPrimary).toBe(true);
      expect(primaryDid2?.certSerial).toBe("test-cert-002"); // Updated
      expect(primaryDid2?.createdAt).toEqual(primaryDid1?.createdAt); // Preserved
    });

    test("should retrieve specific DID", async () => {
      const didInfo = await manager.getDid("did:plc:user123");
      expect(didInfo).toBeDefined();
      expect(didInfo?.did).toBe("did:plc:user123");
      expect(didInfo?.handle).toBe("user.test");
    });

    test("should return null for non-existent DID", async () => {
      const didInfo = await manager.getDid("did:plc:nonexistent");
      expect(didInfo).toBeNull();
    });
  });

  describe("Transport Lifecycle", () => {
    test("should start transport for DID", async () => {
      const freshStorage = new MockStorageAdapter();
      const freshManager = new ATSMSStorageManager({
        storage: freshStorage,
        atsmsClient: atsmsClient as any,
        inboxUrl: "https://test.api.com",
      });

      const mockEndpointCert = {
        serialNumber: "test-cert-001",
        certificate: new Uint8Array(),
        privateKey: new Uint8Array(),
        raw: new Uint8Array(),
        toString: () =>
          "-----BEGIN CERTIFICATE-----\nMOCK\n-----END CERTIFICATE-----",
        certificatePrivateKeyPEM: `-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgQKpLKKzVCPvYI5AH
cm/9HqRWGl0ug5JQPvR/OMDwD0WhRANCAAS0i+t8MqoJMDlJR4WO3Hvr7xNsQC3q
ywJtC5IxIDJRr4JSdBHBXBj6h+dKFhnoHEQQzcIASJYqiwnjz7FZvlCr
-----END PRIVATE KEY-----`,
      } as any;

      await freshManager.saveDid(
        "did:plc:alice123",
        "alice.test",
        mockEndpointCert,
      );

      expect(freshManager.isTransportActive("did:plc:alice123")).toBe(false);

      await freshManager.startTransport("did:plc:alice123");

      expect(freshManager.isTransportActive("did:plc:alice123")).toBe(true);
    });

    test("should throw error starting transport for non-existent DID", async () => {
      await expect(
        manager.startTransport("did:plc:nonexistent"),
      ).rejects.toThrow(
        "Cannot start transport: DID did:plc:nonexistent not found",
      );
    });

    test("should stop transport for DID", async () => {
      expect(manager.isTransportActive("did:plc:user123")).toBe(true);

      await manager.stopTransport("did:plc:user123");

      expect(manager.isTransportActive("did:plc:user123")).toBe(false);
    });
  });
});
