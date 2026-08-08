/**
 * ATSMS IndexedDB Storage Adapter
 *
 * Browser-compatible storage adapter using IndexedDB
 * Provides the same interface as SQLiteAdapter for cross-platform compatibility
 */

import { X509Certificate } from "@peculiar/x509";
import { Observable, Subject } from "rxjs";

import type { ATSMSEndpointCertificate } from "../certificates/index.js";
import type { ATSMSCertificateType } from "../types";
import type { StorageAdapter } from "./interface";
import {
  type ATSMSDidInfo,
  contentFromStorage,
  contentToStorage,
  type ConversationFilter,
  type LocalConversation,
  type LocalMessage,
  reactionsFromStorage,
  reactionsToStorage,
} from "./types";

const DEFAULT_DB_NAME = "atsms";
const DB_VERSION = 3;

// Object store names
const STORES = {
  MESSAGES: "messages",
  CONVERSATIONS: "conversations",
  SYNC_METADATA: "sync_metadata",
  CERTIFICATES: "certificates",
  DIDS: "dids",
  ENGINE_STATE: "engine_state",
  DEVICE_STATE: "device_state",
};

export class IndexedDBAdapter implements StorageAdapter {
  private db: IDBDatabase | null = null;
  private conversationSubject = new Subject<LocalConversation[]>();
  private messageSubjects = new Map<string, Subject<LocalMessage[]>>();
  private conversationSubjects = new Map<
    string,
    Subject<LocalConversation | null>
  >();

  private readonly dbName: string;

  /** @param dbName one database per account/profile (default "atsms") — a
   *  browser origin hosting several identities needs separate stores. */
  constructor(dbName: string = DEFAULT_DB_NAME) {
    this.dbName = dbName;
    // Database will be initialized on first use
  }

  private async ensureDB(): Promise<IDBDatabase> {
    if (this.db) return this.db;

    return new Promise((resolve, reject) => {
      const request = indexedDB.open(this.dbName, DB_VERSION);

      request.onerror = () => reject(request.error);
      request.onsuccess = () => {
        this.db = request.result;
        resolve(this.db);
      };

      request.onupgradeneeded = (event) => {
        const db = (event.target as IDBOpenDBRequest).result;

        // Messages store
        if (!db.objectStoreNames.contains(STORES.MESSAGES)) {
          const messageStore = db.createObjectStore(STORES.MESSAGES, {
            keyPath: "id",
          });
          messageStore.createIndex("convoId", "convoId", { unique: false });
          messageStore.createIndex("createdAt", "createdAt", { unique: false });
        }

        // Conversations store
        if (!db.objectStoreNames.contains(STORES.CONVERSATIONS)) {
          const convoStore = db.createObjectStore(STORES.CONVERSATIONS, {
            keyPath: "id",
          });
          convoStore.createIndex("lastMessageAt", "lastMessageAt", {
            unique: false,
          });
        }

        // Sync metadata store
        if (!db.objectStoreNames.contains(STORES.SYNC_METADATA)) {
          db.createObjectStore(STORES.SYNC_METADATA, { keyPath: "key" });
        }

        // Certificates store
        if (!db.objectStoreNames.contains(STORES.CERTIFICATES)) {
          const certStore = db.createObjectStore(STORES.CERTIFICATES, {
            keyPath: "id",
          });
          certStore.createIndex("did", "did", { unique: false });
          certStore.createIndex("did_type", ["did", "type"], { unique: false });
          certStore.createIndex(
            "did_type_serial",
            ["did", "type", "serialNumber"],
            { unique: true },
          );
        }

        // DIDs store
        if (!db.objectStoreNames.contains(STORES.DIDS)) {
          const didStore = db.createObjectStore(STORES.DIDS, {
            keyPath: "did",
          });
          didStore.createIndex("isPrimary", "isPrimary", { unique: false });
        }

        if (!db.objectStoreNames.contains(STORES.ENGINE_STATE)) {
          db.createObjectStore(STORES.ENGINE_STATE, { keyPath: "convoId" });
        }

        if (!db.objectStoreNames.contains(STORES.DEVICE_STATE)) {
          db.createObjectStore(STORES.DEVICE_STATE, { keyPath: "key" });
        }
      };
    });
  }

  private async getTransaction(
    storeNames: string | string[],
    mode: IDBTransactionMode = "readonly",
  ): Promise<IDBTransaction> {
    const db = await this.ensureDB();
    return db.transaction(storeNames, mode);
  }

  private async getStore(
    storeName: string,
    mode: IDBTransactionMode = "readonly",
  ): Promise<IDBObjectStore> {
    const transaction = await this.getTransaction(storeName, mode);
    return transaction.objectStore(storeName);
  }

  private promisifyRequest<T>(request: IDBRequest<T>): Promise<T> {
    return new Promise((resolve, reject) => {
      request.onsuccess = () => resolve(request.result);
      request.onerror = () => reject(request.error);
    });
  }

  private promisifyTransaction(transaction: IDBTransaction): Promise<void> {
    return new Promise((resolve, reject) => {
      transaction.oncomplete = () => resolve();
      transaction.onerror = () => reject(transaction.error);
      transaction.onabort = () => reject(new Error("Transaction aborted"));
    });
  }

  // Message operations

  /** LocalMessage → stored record (plain JSON values; content as base64 CBOR). */
  private serializeMessage(message: LocalMessage) {
    return {
      id: message.id,
      convoId: message.convoId,
      senderId: message.senderId,
      createdAt: message.createdAt.getTime(),
      causalOrder: message.causalOrder ?? null,
      isInvitation: message.isInvitation ? 1 : 0,
      content: contentToStorage(message.content),
      reactions: reactionsToStorage(message.reactions),
      editedAt: message.editedAt ? message.editedAt.getTime() : null,
      deleted: message.deleted ? 1 : 0,
    };
  }

  async saveMessage(message: LocalMessage): Promise<void> {
    const transaction = await this.getTransaction(STORES.MESSAGES, "readwrite");
    const store = transaction.objectStore(STORES.MESSAGES);

    await this.promisifyRequest(store.put(this.serializeMessage(message)));

    // Notify observers
    const subject = this.messageSubjects.get(message.convoId);
    if (subject) {
      const messages = await this.getMessages(message.convoId);
      subject.next(messages);
    }
  }

  async getMessage(id: string): Promise<LocalMessage | null> {
    const store = await this.getStore(STORES.MESSAGES);
    const data = await this.promisifyRequest(store.get(id));

    if (!data) return null;

    return this.deserializeMessage(data);
  }

  async getMessages(
    convoId: string,
    limit = 50,
    cursor?: string,
  ): Promise<LocalMessage[]> {
    // Same contract as the SQLite adapter: the `limit` most-recent messages
    // (older than `cursor`, when given), returned in ASCENDING createdAt order
    // for the UI. The convoId index orders by primary key, not createdAt, so
    // sort explicitly (per-conversation sets are small client-side).
    const store = await this.getStore(STORES.MESSAGES);
    const index = store.index("convoId");
    const rows = await this.promisifyRequest<unknown[]>(index.getAll(IDBKeyRange.only(convoId)));
    const all = rows
      .map((r) => this.deserializeMessage(r))
      .sort(
        (a, b) =>
          (a.causalOrder ?? 0) - (b.causalOrder ?? 0) ||
          a.createdAt.getTime() - b.createdAt.getTime() ||
          a.id.localeCompare(b.id),
      );
    let end = all.length;
    if (cursor) {
      const at = all.findIndex((m) => m.id === cursor);
      if (at >= 0) end = at;
    }
    return all.slice(Math.max(0, end - limit), end);
  }

  async updateMessage(
    id: string,
    updates: Partial<LocalMessage>,
  ): Promise<void> {
    const existingMessage = await this.getMessage(id);
    if (!existingMessage) {
      throw new Error(`Message ${id} not found`);
    }

    const store = await this.getStore(STORES.MESSAGES, "readwrite");
    await this.promisifyRequest(store.put(this.serializeMessage({ ...existingMessage, ...updates })));

    // Notify observers
    const subject = this.messageSubjects.get(existingMessage.convoId);
    if (subject) {
      const messages = await this.getMessages(existingMessage.convoId);
      subject.next(messages);
    }
  }

  async deleteMessage(id: string): Promise<void> {
    const message = await this.getMessage(id);
    if (!message) return;

    const store = await this.getStore(STORES.MESSAGES, "readwrite");
    await this.promisifyRequest(store.delete(id));

    // Notify observers
    const subject = this.messageSubjects.get(message.convoId);
    if (subject) {
      const messages = await this.getMessages(message.convoId);
      subject.next(messages);
    }
  }

  // Conversation operations
  async saveConversation(conversation: LocalConversation): Promise<void> {
    const store = await this.getStore(STORES.CONVERSATIONS, "readwrite");

    const data = {
      ...conversation,
      participantIds: JSON.stringify(conversation.participantIds),
      createdAt: conversation.createdAt.getTime(),
      lastMessageAt: conversation.lastMessageAt.getTime(),
      acceptedAt: conversation.acceptedAt?.getTime() || null,
      mutedUntil: conversation.mutedUntil?.getTime() || null,
      metadata: conversation.metadata
        ? JSON.stringify(conversation.metadata)
        : null,
    };

    await this.promisifyRequest(store.put(data));

    // Notify observers
    this.conversationSubject.next(await this.getConversations());

    const subject = this.conversationSubjects.get(conversation.id);
    if (subject) {
      subject.next(conversation);
    }
  }

  async getConversation(id: string): Promise<LocalConversation | null> {
    const store = await this.getStore(STORES.CONVERSATIONS);
    const data = await this.promisifyRequest(store.get(id));

    if (!data) return null;

    return this.deserializeConversation(data);
  }

  async getConversations(
    limit?: number,
    cursor?: string,
  ): Promise<LocalConversation[]> {
    const store = await this.getStore(STORES.CONVERSATIONS);
    const index = store.index("lastMessageAt");
    const request = index.openCursor(null, "prev"); // Newest first

    const conversations: LocalConversation[] = [];
    let count = 0;
    let shouldSkip = !!cursor;

    return new Promise((resolve, reject) => {
      request.onsuccess = () => {
        const cursorResult = request.result;
        if (!cursorResult) {
          resolve(conversations);
          return;
        }

        if (shouldSkip && cursorResult.value.id === cursor) {
          shouldSkip = false;
          cursorResult.continue();
          return;
        }

        if (!shouldSkip) {
          conversations.push(this.deserializeConversation(cursorResult.value));
          count++;

          if (limit && count >= limit) {
            resolve(conversations);
            return;
          }
        }

        cursorResult.continue();
      };
      request.onerror = () => reject(request.error);
    });
  }

  async findConversationByParticipants(
    participantDids: string[],
  ): Promise<LocalConversation | null> {
    const allConversations = await this.getConversations();
    const sorted = participantDids.slice().sort();

    for (const convo of allConversations) {
      const convoSorted = convo.participantIds.slice().sort();
      if (
        sorted.length === convoSorted.length &&
        sorted.every((did, i) => did === convoSorted[i])
      ) {
        return convo;
      }
    }

    return null;
  }

  async updateConversation(
    id: string,
    updates: Partial<LocalConversation>,
  ): Promise<void> {
    const store = await this.getStore(STORES.CONVERSATIONS, "readwrite");
    const existing = await this.promisifyRequest(store.get(id));

    if (!existing) {
      throw new Error(`Conversation ${id} not found`);
    }

    const updated = {
      ...existing,
      ...updates,
      participantIds: updates.participantIds
        ? JSON.stringify(updates.participantIds)
        : existing.participantIds,
      lastMessageAt: updates.lastMessageAt?.getTime() || existing.lastMessageAt,
      acceptedAt: updates.acceptedAt?.getTime() || existing.acceptedAt,
      mutedUntil: updates.mutedUntil?.getTime() || existing.mutedUntil,
      metadata: updates.metadata
        ? JSON.stringify(updates.metadata)
        : existing.metadata,
    };

    await this.promisifyRequest(store.put(updated));

    // Notify observers
    this.conversationSubject.next(await this.getConversations());

    const subject = this.conversationSubjects.get(id);
    if (subject) {
      const updated = await this.getConversation(id);
      subject.next(updated);
    }
  }

  async deleteConversation(id: string): Promise<void> {
    const store = await this.getStore(STORES.CONVERSATIONS, "readwrite");
    await this.promisifyRequest(store.delete(id));

    // Notify observers
    this.conversationSubject.next(await this.getConversations());

    const subject = this.conversationSubjects.get(id);
    if (subject) {
      subject.next(null);
    }
  }

  // Bulk operations
  async saveMessages(messages: LocalMessage[]): Promise<void> {
    const store = await this.getStore(STORES.MESSAGES, "readwrite");

    for (const message of messages) {
      await this.promisifyRequest(store.put(this.serializeMessage(message)));
    }

    // Notify observers for affected conversations
    const convoIds = new Set(messages.map((m) => m.convoId));
    for (const convoId of convoIds) {
      const subject = this.messageSubjects.get(convoId);
      if (subject) {
        const messages = await this.getMessages(convoId);
        subject.next(messages);
      }
    }
  }

  // DCGKA engine state
  async saveEngineState(convoId: string, state: Uint8Array): Promise<void> {
    const store = await this.getStore(STORES.ENGINE_STATE, "readwrite");
    await this.promisifyRequest(store.put({ convoId, state, updatedAt: Date.now() }));
  }

  async loadEngineState(convoId: string): Promise<Uint8Array | null> {
    const store = await this.getStore(STORES.ENGINE_STATE);
    const row = await this.promisifyRequest<{ state: Uint8Array } | undefined>(store.get(convoId));
    return row ? new Uint8Array(row.state) : null;
  }

  async deleteEngineState(convoId: string): Promise<void> {
    const store = await this.getStore(STORES.ENGINE_STATE, "readwrite");
    await this.promisifyRequest(store.delete(convoId));
  }

  async listEngineStateIds(): Promise<string[]> {
    const store = await this.getStore(STORES.ENGINE_STATE);
    const keys = await this.promisifyRequest<IDBValidKey[]>(store.getAllKeys());
    return keys.map((k) => String(k));
  }

  // Device-local secret state
  async saveDeviceState(key: string, state: Uint8Array): Promise<void> {
    const store = await this.getStore(STORES.DEVICE_STATE, "readwrite");
    await this.promisifyRequest(store.put({ key, state, updatedAt: Date.now() }));
  }

  async loadDeviceState(key: string): Promise<Uint8Array | null> {
    const store = await this.getStore(STORES.DEVICE_STATE);
    const row = await this.promisifyRequest<{ state: Uint8Array } | undefined>(store.get(key));
    return row ? new Uint8Array(row.state) : null;
  }

  async deleteDeviceState(key: string): Promise<void> {
    const store = await this.getStore(STORES.DEVICE_STATE, "readwrite");
    await this.promisifyRequest(store.delete(key));
  }

  async clearAll(): Promise<void> {
    const db = await this.ensureDB();
    const storeNames = [
      STORES.MESSAGES,
      STORES.CONVERSATIONS,
      STORES.SYNC_METADATA,
      STORES.CERTIFICATES,
      STORES.DIDS,
      STORES.ENGINE_STATE,
      STORES.DEVICE_STATE,
    ];

    const transaction = db.transaction(storeNames, "readwrite");

    for (const storeName of storeNames) {
      const store = transaction.objectStore(storeName);
      await this.promisifyRequest(store.clear());
    }

    // Notify all observers
    this.conversationSubject.next([]);
    for (const subject of this.messageSubjects.values()) {
      subject.next([]);
    }
    for (const subject of this.conversationSubjects.values()) {
      subject.next(null);
    }
  }

  // Sync operations
  async getLastSyncRev(): Promise<string | null> {
    const store = await this.getStore(STORES.SYNC_METADATA);
    const data = await this.promisifyRequest(store.get("lastSyncRev"));
    return data?.value || null;
  }

  async setLastSyncRev(rev: string): Promise<void> {
    const store = await this.getStore(STORES.SYNC_METADATA, "readwrite");
    await this.promisifyRequest(store.put({ key: "lastSyncRev", value: rev }));
  }

  // Observable support
  // Observers emit the CURRENT data on subscribe (same contract as the SQLite
  // adapter), then re-emit on every change — a bare Subject would leave a
  // freshly-loaded page silent until the next write.
  observeConversations(
    _filter?: ConversationFilter,
  ): Observable<LocalConversation[]> {
    return new Observable((subscriber) => {
      void this.getConversations().then((convos) => subscriber.next(convos));
      const sub = this.conversationSubject.subscribe((convos) => subscriber.next(convos));
      return () => sub.unsubscribe();
    });
  }

  observeMessages(convoId: string): Observable<LocalMessage[]> {
    if (!this.messageSubjects.has(convoId)) {
      this.messageSubjects.set(convoId, new Subject<LocalMessage[]>());
    }
    const subject = this.messageSubjects.get(convoId)!;
    return new Observable((subscriber) => {
      void this.getMessages(convoId).then((msgs) => subscriber.next(msgs));
      const sub = subject.subscribe((msgs) => subscriber.next(msgs));
      return () => sub.unsubscribe();
    });
  }

  observeConversation(convoId: string): Observable<LocalConversation | null> {
    if (!this.conversationSubjects.has(convoId)) {
      this.conversationSubjects.set(
        convoId,
        new Subject<LocalConversation | null>(),
      );
    }
    const subject = this.conversationSubjects.get(convoId)!;
    return new Observable((subscriber) => {
      void this.getConversation(convoId).then((convo) => subscriber.next(convo));
      const sub = subject.subscribe((convo) => subscriber.next(convo));
      return () => sub.unsubscribe();
    });
  }

  // Certificate operations
  async saveCertificate(
    did: string,
    type: ATSMSCertificateType,
    serialNumber: string,
    certificatePEM: string,
    privateKeyPEM?: string,
    isEncrypted?: boolean,
    metadata?: Record<string, any>,
  ): Promise<void> {
    const store = await this.getStore(STORES.CERTIFICATES, "readwrite");

    // Parse certificate to get validity dates
    const cert = new X509Certificate(certificatePEM);
    const now = Date.now();

    const data = {
      id: `${did}:${type}:${serialNumber}`,
      did,
      type,
      serialNumber,
      certificatePEM,
      privateKeyPEM: privateKeyPEM || null,
      privateKeyEncrypted: isEncrypted ? 1 : 0,
      notBefore: cert.notBefore.getTime(),
      notAfter: cert.notAfter.getTime(),
      metadata: metadata ? JSON.stringify(metadata) : null,
      createdAt: now,
      updatedAt: now,
    };

    await this.promisifyRequest(store.put(data));
  }

  async getCertificate(
    did: string,
    type: ATSMSCertificateType,
    serialNumber?: string,
  ): Promise<{
    certificatePEM: string;
    privateKeyPEM?: string;
    isEncrypted: boolean;
    metadata?: Record<string, any>;
  } | null> {
    const store = await this.getStore(STORES.CERTIFICATES);

    if (serialNumber) {
      // Get specific certificate
      const id = `${did}:${type}:${serialNumber}`;
      const data = await this.promisifyRequest(store.get(id));

      if (!data) return null;

      return {
        certificatePEM: data.certificatePEM,
        privateKeyPEM: data.privateKeyPEM || undefined,
        isEncrypted: data.privateKeyEncrypted === 1,
        metadata: data.metadata ? JSON.parse(data.metadata) : undefined,
      };
    }

    // Get first matching certificate
    const index = store.index("did_type");
    const range = IDBKeyRange.only([did, type]);
    const data = await this.promisifyRequest(index.get(range));

    if (!data) return null;

    return {
      certificatePEM: data.certificatePEM,
      privateKeyPEM: data.privateKeyPEM || undefined,
      isEncrypted: data.privateKeyEncrypted === 1,
      metadata: data.metadata ? JSON.parse(data.metadata) : undefined,
    };
  }

  async listCertificates(did?: string): Promise<
    Array<{
      did: string;
      type: ATSMSCertificateType;
      serialNumber: string;
      notBefore: Date;
      notAfter: Date;
      hasPrivateKey: boolean;
    }>
  > {
    const store = await this.getStore(STORES.CERTIFICATES);

    let request: IDBRequest<
      Array<{
        did: string;
        type: string;
        serialNumber: string;
        notBefore: string | number;
        notAfter: string | number;
        privateKeyPEM?: string;
      }>
    >;
    if (did) {
      const index = store.index("did");
      request = index.getAll(IDBKeyRange.only(did));
    } else {
      request = store.getAll();
    }

    const results = await this.promisifyRequest(request);

    return results.map((cert) => ({
      did: cert.did,
      type: cert.type as ATSMSCertificateType,
      serialNumber: cert.serialNumber,
      notBefore: new Date(cert.notBefore),
      notAfter: new Date(cert.notAfter),
      hasPrivateKey: !!cert.privateKeyPEM,
    }));
  }

  async deleteCertificate(
    did: string,
    type: ATSMSCertificateType,
    serialNumber: string,
  ): Promise<void> {
    const store = await this.getStore(STORES.CERTIFICATES, "readwrite");
    const id = `${did}:${type}:${serialNumber}`;
    await this.promisifyRequest(store.delete(id));
  }

  // DID management operations
  async getPrimaryDid(): Promise<ATSMSDidInfo | null> {
    const store = await this.getStore(STORES.DIDS);
    const index = store.index("isPrimary");
    const data = await this.promisifyRequest(index.get(1));

    if (!data) return null;

    return {
      did: data.did,
      handle: data.handle,
      certSerial: data.certSerial,
      isPrimary: data.isPrimary === 1,
      createdAt: new Date(data.createdAt),
      lastUsedAt: new Date(data.lastUsedAt),
    };
  }

  async getDid(did: string): Promise<ATSMSDidInfo | null> {
    const store = await this.getStore(STORES.DIDS);
    const data = await this.promisifyRequest(store.get(did));

    if (!data) return null;

    return {
      did: data.did,
      handle: data.handle,
      certSerial: data.certSerial,
      isPrimary: data.isPrimary === 1,
      createdAt: new Date(data.createdAt),
      lastUsedAt: new Date(data.lastUsedAt),
    };
  }

  async saveDid(
    did: string,
    handle: string,
    endpointCert: ATSMSEndpointCertificate,
  ): Promise<void> {
    const now = Date.now();
    // Legacy column name; the VALUE is the device fingerprint (integration §8.5).
    const certSerial = await endpointCert.getDeviceFingerprint();

    // Check if DID already exists
    const existing = await this.getDid(did);

    let isPrimary: number;
    let createdAt: number;

    if (existing) {
      // DID exists - preserve isPrimary and createdAt
      isPrimary = existing.isPrimary ? 1 : 0;
      createdAt = existing.createdAt.getTime();
    } else {
      // New DID - check if this should be primary (first DID)
      const allDids = await this.getAllDids();
      isPrimary = allDids.length === 0 ? 1 : 0;
      createdAt = now;
    }

    // Save DID info
    const store = await this.getStore(STORES.DIDS, "readwrite");
    await this.promisifyRequest(
      store.put({
        did,
        handle,
        certSerial,
        isPrimary,
        createdAt,
        lastUsedAt: now,
      }),
    );

    // Save the endpoint certificate
    await this.saveCertificate(
      did,
      "endpoint",
      certSerial,
      endpointCert.toString(),
      endpointCert.certificatePrivateKeyPEM,
      false,
      {
        email: endpointCert.email,
        subject: endpointCert.subjectName,
      },
    );
  }

  private async getAllDids(): Promise<ATSMSDidInfo[]> {
    const store = await this.getStore(STORES.DIDS);
    const results = await this.promisifyRequest(store.getAll());

    return results.map((data) => ({
      did: data.did,
      handle: data.handle,
      certSerial: data.certSerial,
      isPrimary: data.isPrimary === 1,
      createdAt: new Date(data.createdAt),
      lastUsedAt: new Date(data.lastUsedAt),
    }));
  }

  // Helper methods to deserialize data
  private deserializeMessage(data: any): LocalMessage {
    return {
      id: data.id,
      convoId: data.convoId,
      senderId: data.senderId,
      createdAt: new Date(data.createdAt),
      causalOrder: data.causalOrder ?? undefined,
      isInvitation: data.isInvitation === 1,
      content: contentFromStorage(data.content),
      reactions: reactionsFromStorage(data.reactions),
      editedAt: data.editedAt ? new Date(data.editedAt) : undefined,
      deleted: data.deleted === 1 ? true : undefined,
    };
  }

  private deserializeConversation(data: any): LocalConversation {
    return {
      id: data.id,
      participantIds: JSON.parse(data.participantIds),
      createdAt: new Date(data.createdAt),
      lastMessageAt: new Date(data.lastMessageAt),
      acceptedAt: data.acceptedAt ? new Date(data.acceptedAt) : undefined,
      mutedUntil: data.mutedUntil ? new Date(data.mutedUntil) : undefined,
      unreadCount: data.unreadCount || 0,
      lastRev: data.lastRev || undefined,
      metadata: data.metadata ? JSON.parse(data.metadata) : undefined,
    };
  }
}
