/**
 * AT-SMS SQLite Storage Adapter
 *
 * Platform-agnostic SQLite adapter that works with any SQLite implementation
 * that conforms to the SQLiteDatabase interface
 */

import { X509Certificate } from "@peculiar/x509";
import { Observable, Subject } from "rxjs";

import type { ATSMSCertificateType } from "../types";
import { type SQLiteDatabase, type StorageAdapter } from "./interface";
import {
  type ConversationFilter,
  type LocalConversation,
  type LocalMessage,
} from "./types";

export class SQLiteAdapter implements StorageAdapter {
  private db: SQLiteDatabase;
  private conversationSubject = new Subject<LocalConversation[]>();
  private messageSubjects = new Map<string, Subject<LocalMessage[]>>();
  private conversationSubjects = new Map<
    string,
    Subject<LocalConversation | null>
  >();

  constructor(db: SQLiteDatabase) {
    this.db = db;
    this.initSchema();
  }

  private initSchema() {
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS messages (
        id TEXT PRIMARY KEY,
        convoId TEXT NOT NULL,
        senderId TEXT NOT NULL,
        recipientIds TEXT NOT NULL,
        content TEXT NOT NULL,
        contentType TEXT NOT NULL,
        createdAt INTEGER NOT NULL,
        isInvitation INTEGER DEFAULT 0,
        reactions TEXT,
        metadata TEXT,
        FOREIGN KEY(convoId) REFERENCES conversations(id)
      );

      CREATE TABLE IF NOT EXISTS conversations (
        id TEXT PRIMARY KEY,
        participantIds TEXT NOT NULL,
        createdAt INTEGER NOT NULL,
        lastMessageAt INTEGER NOT NULL,
        acceptedAt INTEGER,
        mutedUntil INTEGER,
        unreadCount INTEGER DEFAULT 0,
        lastRev TEXT,
        metadata TEXT
      );

      CREATE TABLE IF NOT EXISTS sync_metadata (
        key TEXT PRIMARY KEY,
        value TEXT
      );

      CREATE TABLE IF NOT EXISTS certificates (
        id TEXT PRIMARY KEY,
        did TEXT NOT NULL,
        type TEXT NOT NULL, -- 'endpoint'
        serialNumber TEXT NOT NULL,
        certificatePEM TEXT NOT NULL,
        privateKeyPEM TEXT, -- Encrypted private key in PEM format
        privateKeyEncrypted INTEGER DEFAULT 0, -- 1 if encrypted, 0 if not
        notBefore INTEGER NOT NULL,
        notAfter INTEGER NOT NULL,
        metadata TEXT, -- JSON metadata (issuer, subject, etc.)
        createdAt INTEGER NOT NULL,
        updatedAt INTEGER NOT NULL,
        UNIQUE(did, type, serialNumber)
      );

      CREATE TABLE IF NOT EXISTS dids (
        did TEXT PRIMARY KEY,
        handle TEXT NOT NULL,
        certSerial TEXT NOT NULL,
        isPrimary INTEGER DEFAULT 0, -- 1 = primary, 0 = not primary
        createdAt INTEGER NOT NULL,
        lastUsedAt INTEGER NOT NULL
      );

      CREATE INDEX IF NOT EXISTS idx_messages_convo ON messages(convoId);
      CREATE INDEX IF NOT EXISTS idx_messages_created ON messages(createdAt);
      CREATE INDEX IF NOT EXISTS idx_conversations_last ON conversations(lastMessageAt);
      CREATE INDEX IF NOT EXISTS idx_certificates_did ON certificates(did);
      CREATE INDEX IF NOT EXISTS idx_certificates_type ON certificates(did, type);
      CREATE UNIQUE INDEX IF NOT EXISTS idx_primary_did ON dids(isPrimary) WHERE isPrimary = 1;
    `);
  }

  // Message operations
  async saveMessage(message: LocalMessage): Promise<void> {
    const stmt = this.db.prepare(`
      INSERT OR REPLACE INTO messages (
        id, convoId, senderId, recipientIds, content, contentType,
        createdAt, isInvitation, reactions, metadata
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);

    stmt.run(
      message.id,
      message.convoId,
      message.senderId,
      JSON.stringify(message.recipientIds),
      message.content,
      message.contentType,
      message.createdAt.getTime(),
      message.isInvitation ? 1 : 0,
      message.reactions ? JSON.stringify(message.reactions) : null,
      message.metadata ? JSON.stringify(message.metadata) : null,
    );

    // Notify observers
    this.notifyMessageObservers(message.convoId);
  }

  async getMessage(id: string): Promise<LocalMessage | null> {
    const stmt = this.db.prepare("SELECT * FROM messages WHERE id = ?");
    const row = stmt.get(id);

    if (!row) return null;

    return this.rowToMessage(row);
  }

  async getMessages(
    convoId: string,
    limit = 50,
    cursor?: string,
  ): Promise<LocalMessage[]> {
    let query = "SELECT * FROM messages WHERE convoId = ?";
    const params: any[] = [convoId];

    if (cursor) {
      query += " AND createdAt < (SELECT createdAt FROM messages WHERE id = ?)";
      params.push(cursor);
    }

    query += " ORDER BY createdAt DESC LIMIT ?";
    params.push(limit);

    const stmt = this.db.prepare(query);
    const rows = stmt.all(...params);

    // Return in ascending order for UI
    return rows.map((row) => this.rowToMessage(row)).reverse();
  }

  async updateMessage(
    id: string,
    updates: Partial<LocalMessage>,
  ): Promise<void> {
    const existing = await this.getMessage(id);
    if (!existing) {
      throw new Error(`Message ${id} not found`);
    }

    const updated = { ...existing, ...updates };
    await this.saveMessage(updated);
  }

  async deleteMessage(id: string): Promise<void> {
    const message = await this.getMessage(id);
    if (message) {
      const stmt = this.db.prepare("DELETE FROM messages WHERE id = ?");
      stmt.run(id);
      this.notifyMessageObservers(message.convoId);
    }
  }

  // Conversation operations
  async saveConversation(conversation: LocalConversation): Promise<void> {
    const stmt = this.db.prepare(`
      INSERT OR REPLACE INTO conversations (
        id, participantIds, createdAt, lastMessageAt,
        acceptedAt, mutedUntil, unreadCount, lastRev, metadata
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);

    stmt.run(
      conversation.id,
      JSON.stringify(conversation.participantIds),
      conversation.createdAt.getTime(),
      conversation.lastMessageAt.getTime(),
      conversation.acceptedAt ? conversation.acceptedAt.getTime() : null,
      conversation.mutedUntil ? conversation.mutedUntil.getTime() : null,
      conversation.unreadCount,
      conversation.lastRev,
      conversation.metadata ? JSON.stringify(conversation.metadata) : null,
    );

    // Notify observers
    this.notifyConversationObservers();
    this.notifySingleConversationObservers(conversation.id);
  }

  async getConversation(id: string): Promise<LocalConversation | null> {
    const stmt = this.db.prepare("SELECT * FROM conversations WHERE id = ?");
    const row = stmt.get(id);

    if (!row) return null;

    return this.rowToConversation(row);
  }

  async getConversations(
    limit = 50,
    cursor?: string,
  ): Promise<LocalConversation[]> {
    let query = "SELECT * FROM conversations";
    const params: any[] = [];

    if (cursor) {
      query +=
        " WHERE lastMessageAt < (SELECT lastMessageAt FROM conversations WHERE id = ?)";
      params.push(cursor);
    }

    query += " ORDER BY lastMessageAt DESC LIMIT ?";
    params.push(limit);

    const stmt = this.db.prepare(query);
    const rows = stmt.all(...params);

    return rows.map((row) => this.rowToConversation(row));
  }

  async updateConversation(
    id: string,
    updates: Partial<LocalConversation>,
  ): Promise<void> {
    const existing = await this.getConversation(id);
    if (!existing) {
      throw new Error(`Conversation ${id} not found`);
    }

    const updated = { ...existing, ...updates };
    await this.saveConversation(updated);
  }

  async deleteConversation(id: string): Promise<void> {
    this.db.transaction(() => {
      // Delete all messages in the conversation
      const deleteMessages = this.db.prepare(
        "DELETE FROM messages WHERE convoId = ?",
      );
      deleteMessages.run(id);

      // Delete the conversation
      const deleteConvo = this.db.prepare(
        "DELETE FROM conversations WHERE id = ?",
      );
      deleteConvo.run(id);
    });

    this.notifyConversationObservers();
    this.notifyMessageObservers(id);
    this.notifySingleConversationObservers(id);
  }

  /**
   * Find conversation by exact participant set
   * Performs database query to find conversation with matching participants
   */
  async findConversationByParticipants(
    participantDids: string[],
  ): Promise<LocalConversation | null> {
    // Get all conversations (we need to parse JSON to compare participants)
    const query = "SELECT * FROM conversations";
    const stmt = this.db.prepare(query);
    const rows = stmt.all();

    // Sort query participants for comparison
    const sortedQuery = [...participantDids].sort();

    // Check each conversation for exact participant match
    for (const row of rows) {
      const conversation = this.rowToConversation(row);
      const sortedParticipants = [...conversation.participantIds].sort();

      // Check if participant sets match exactly
      if (
        sortedQuery.length === sortedParticipants.length &&
        sortedQuery.every((did, i) => did === sortedParticipants[i])
      ) {
        return conversation;
      }
    }

    return null;
  }

  // Bulk operations
  async saveMessages(messages: LocalMessage[]): Promise<void> {
    this.db.transaction(() => {
      for (const message of messages) {
        this.saveMessage(message);
      }
    });
  }

  async clearAll(): Promise<void> {
    this.db.transaction(() => {
      this.db.exec("DELETE FROM messages");
      this.db.exec("DELETE FROM conversations");
      this.db.exec("DELETE FROM sync_metadata");
    });

    // Notify all observers
    this.notifyAllObservers();
  }

  // Sync operations
  async getLastSyncRev(): Promise<string | null> {
    const stmt = this.db.prepare(
      "SELECT value FROM sync_metadata WHERE key = ?",
    );
    const row = stmt.get("lastSyncRev");
    return row ? row.value : null;
  }

  async setLastSyncRev(rev: string): Promise<void> {
    const stmt = this.db.prepare(
      "INSERT OR REPLACE INTO sync_metadata (key, value) VALUES (?, ?)",
    );
    stmt.run("lastSyncRev", rev);
  }

  // LiveQuery support
  observeConversations(
    filter?: ConversationFilter,
  ): Observable<LocalConversation[]> {
    return new Observable((subscriber) => {
      // Send initial data
      this.getFilteredConversations(filter).then((convos) => {
        subscriber.next(convos);
      });

      // Subscribe to updates
      const subscription = this.conversationSubject.subscribe(async () => {
        const convos = await this.getFilteredConversations(filter);
        subscriber.next(convos);
      });

      return () => subscription.unsubscribe();
    });
  }

  observeMessages(convoId: string): Observable<LocalMessage[]> {
    return new Observable((subscriber) => {
      // Create subject for this conversation if it doesn't exist
      if (!this.messageSubjects.has(convoId)) {
        this.messageSubjects.set(convoId, new Subject());
      }

      // Send initial data
      this.getMessages(convoId).then((messages) => {
        subscriber.next(messages);
      });

      // Subscribe to updates
      const subject = this.messageSubjects.get(convoId)!;
      const subscription = subject.subscribe(async () => {
        const messages = await this.getMessages(convoId);
        subscriber.next(messages);
      });

      return () => subscription.unsubscribe();
    });
  }

  observeConversation(convoId: string): Observable<LocalConversation | null> {
    return new Observable((subscriber) => {
      // Create subject for this conversation if it doesn't exist
      if (!this.conversationSubjects.has(convoId)) {
        this.conversationSubjects.set(convoId, new Subject());
      }

      // Send initial data
      this.getConversation(convoId).then((convo) => {
        subscriber.next(convo);
      });

      // Subscribe to updates
      const subject = this.conversationSubjects.get(convoId)!;
      const subscription = subject.subscribe(async () => {
        const convo = await this.getConversation(convoId);
        subscriber.next(convo);
      });

      return () => subscription.unsubscribe();
    });
  }

  // Helper methods
  private rowToMessage(row: any): LocalMessage {
    return {
      id: row.id,
      convoId: row.convoId,
      senderId: row.senderId,
      recipientIds: JSON.parse(row.recipientIds),
      content: row.content,
      contentType: row.contentType,
      createdAt: new Date(row.createdAt),
      isInvitation: row.isInvitation === 1,
      reactions: row.reactions ? JSON.parse(row.reactions) : undefined,
      metadata: row.metadata ? JSON.parse(row.metadata) : undefined,
    };
  }

  private rowToConversation(row: any): LocalConversation {
    return {
      id: row.id,
      participantIds: JSON.parse(row.participantIds),
      createdAt: new Date(row.createdAt),
      lastMessageAt: new Date(row.lastMessageAt),
      acceptedAt: row.acceptedAt ? new Date(row.acceptedAt) : undefined,
      mutedUntil: row.mutedUntil ? new Date(row.mutedUntil) : undefined,
      unreadCount: row.unreadCount,
      lastRev: row.lastRev,
      metadata: row.metadata ? JSON.parse(row.metadata) : undefined,
    };
  }

  private async getFilteredConversations(
    filter?: ConversationFilter,
  ): Promise<LocalConversation[]> {
    const allConvos = await this.getConversations(100);

    if (!filter) return allConvos;

    return allConvos.filter((convo) => {
      if (filter.status === "accepted" && !convo.acceptedAt) return false;
      if (filter.status === "request" && convo.acceptedAt) return false;
      if (filter.unreadOnly && convo.unreadCount === 0) return false;
      if (
        filter.participantDid &&
        !convo.participantIds.includes(filter.participantDid)
      ) {
        return false;
      }
      return true;
    });
  }

  private notifyMessageObservers(convoId: string) {
    const subject = this.messageSubjects.get(convoId);
    if (subject) {
      subject.next([]);
    }
  }

  private notifyConversationObservers() {
    this.conversationSubject.next([]);
  }

  private notifySingleConversationObservers(convoId: string) {
    const subject = this.conversationSubjects.get(convoId);
    if (subject) {
      subject.next(null);
    }
  }

  private notifyAllObservers() {
    this.conversationSubject.next([]);
    this.messageSubjects.forEach((subject) => subject.next([]));
    this.conversationSubjects.forEach((subject) => subject.next(null));
  }

  // Certificate operations
  async saveCertificate(
    did: string,
    type: ATSMSCertificateType,
    serialNumber: string,
    certificatePEM: string,
    privateKeyPEM?: string,
    isEncrypted = false,
    metadata?: Record<string, any>,
  ): Promise<void> {
    let notBefore: number;
    let notAfter: number;

    // Try to parse certificate for dates, but use defaults if it fails (for testing)
    try {
      const cert = new X509Certificate(certificatePEM);
      notBefore = cert.notBefore.getTime();
      notAfter = cert.notAfter.getTime();
    } catch {
      // Use default dates if certificate parsing fails (for test scenarios)
      const now = new Date();
      notBefore = now.getTime();
      notAfter = new Date(now.getTime() + 365 * 24 * 60 * 60 * 1000).getTime(); // 1 year later
    }

    const stmt = this.db.prepare(`
      INSERT OR REPLACE INTO certificates (
        id, did, type, serialNumber, certificatePEM, privateKeyPEM,
        privateKeyEncrypted, notBefore, notAfter, metadata,
        createdAt, updatedAt
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);

    const id = `${did}:${type}:${serialNumber}`;
    const now = Date.now();

    stmt.run(
      id,
      did,
      type,
      serialNumber,
      certificatePEM,
      privateKeyPEM || null,
      isEncrypted ? 1 : 0,
      notBefore,
      notAfter,
      metadata ? JSON.stringify(metadata) : null,
      now,
      now,
    );
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
    let query = "SELECT * FROM certificates WHERE did = ? AND type = ?";
    const params: any[] = [did, type];

    if (serialNumber) {
      query += " AND serialNumber = ?";
      params.push(serialNumber);
    } else {
      // Get the most recent certificate of this type
      query += " ORDER BY createdAt DESC LIMIT 1";
    }

    const stmt = this.db.prepare(query);
    const row = stmt.get(...params);

    if (!row) return null;

    return {
      certificatePEM: row.certificatePEM,
      privateKeyPEM: row.privateKeyPEM || undefined,
      isEncrypted: row.privateKeyEncrypted === 1,
      metadata: row.metadata ? JSON.parse(row.metadata) : undefined,
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
      privateKeyPEM?: string;
      isEncrypted?: boolean;
      certificatePEM?: string;
    }>
  > {
    let query = "SELECT * FROM certificates";
    const params: any[] = [];

    if (did) {
      query += " WHERE did = ?";
      params.push(did);
    }

    query += " ORDER BY createdAt DESC";

    const stmt = this.db.prepare(query);
    const rows = stmt.all(...params);

    return rows.map((row) => ({
      did: row.did,
      type: row.type,
      serialNumber: row.serialNumber,
      notBefore: new Date(row.notBefore),
      notAfter: new Date(row.notAfter),
      hasPrivateKey: !!row.privateKeyPEM,
      privateKeyPEM: row.privateKeyPEM || undefined,
      isEncrypted: row.privateKeyEncrypted === 1,
      certificatePEM: row.certificatePEM || undefined,
    }));
  }

  async deleteCertificate(
    did: string,
    type: ATSMSCertificateType,
    serialNumber: string,
  ): Promise<void> {
    const stmt = this.db.prepare(
      "DELETE FROM certificates WHERE did = ? AND type = ? AND serialNumber = ?",
    );
    stmt.run(did, type, serialNumber);
  }

  // DID management operations
  async getPrimaryDid(): Promise<import("./types").ATSMSDidInfo | null> {
    const stmt = this.db.prepare("SELECT * FROM dids WHERE isPrimary = 1");
    const row = stmt.get();

    if (!row) return null;

    return {
      did: row.did,
      handle: row.handle,
      certSerial: row.certSerial,
      isPrimary: row.isPrimary === 1,
      createdAt: new Date(row.createdAt),
      lastUsedAt: new Date(row.lastUsedAt),
    };
  }

  async getDid(did: string): Promise<import("./types").ATSMSDidInfo | null> {
    const stmt = this.db.prepare("SELECT * FROM dids WHERE did = ?");
    const row = stmt.get(did);

    if (!row) return null;

    return {
      did: row.did,
      handle: row.handle,
      certSerial: row.certSerial,
      isPrimary: row.isPrimary === 1,
      createdAt: new Date(row.createdAt),
      lastUsedAt: new Date(row.lastUsedAt),
    };
  }

  async saveDid(
    did: string,
    handle: string,
    endpointCert: import("../certificates/index.js").ATSMSEndpointCertificate,
  ): Promise<void> {
    const now = Date.now();
    const certSerial = endpointCert.serialNumber;

    // Check if DID already exists
    const existingStmt = this.db.prepare(
      "SELECT isPrimary, createdAt FROM dids WHERE did = ?",
    );
    const existing = existingStmt.get(did);

    let isPrimary: number;
    let createdAt: number;

    if (existing) {
      // DID exists - preserve isPrimary and createdAt, just update other fields
      isPrimary = existing.isPrimary;
      createdAt = existing.createdAt;
    } else {
      // New DID - check if this should be primary (first DID)
      const countStmt = this.db.prepare("SELECT COUNT(*) as count FROM dids");
      const countRow = countStmt.get();
      isPrimary = countRow.count === 0 ? 1 : 0;
      createdAt = now;
    }

    // Save DID info
    const stmt = this.db.prepare(`
      INSERT OR REPLACE INTO dids (did, handle, certSerial, isPrimary, createdAt, lastUsedAt)
      VALUES (?, ?, ?, ?, ?, ?)
    `);
    stmt.run(did, handle, certSerial, isPrimary, createdAt, now);

    // Save the endpoint certificate to certificates table
    await this.saveCertificate(
      did,
      "endpoint",
      certSerial,
      endpointCert.toString(),
      endpointCert.certificatePrivateKeyPEM,
      false, // Assume unencrypted for now (storage manager will handle encryption)
      {
        email: endpointCert.email,
        subject: endpointCert.subjectName,
      },
    );
  }
}
