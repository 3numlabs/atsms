/**
 * AT-SMS Storage Interface
 *
 * Abstract storage adapter interface that can be implemented
 * by different storage backends (SQLite, IndexedDB, etc.)
 */

import { Observable } from "rxjs";

import type { ATSMSEndpointCertificate } from "../certificates/index.js";
import type { ATSMSCertificateType } from "../types";
import {
  type ATSMSDidInfo,
  ConversationFilter,
  LocalConversation,
  LocalMessage,
} from "./types";

export interface StorageAdapter {
  // Message operations
  saveMessage(message: LocalMessage): Promise<void>;
  getMessage(id: string): Promise<LocalMessage | null>;
  getMessages(
    convoId: string,
    limit?: number,
    cursor?: string,
  ): Promise<LocalMessage[]>;
  updateMessage(id: string, updates: Partial<LocalMessage>): Promise<void>;
  deleteMessage(id: string): Promise<void>;

  // Conversation operations
  saveConversation(conversation: LocalConversation): Promise<void>;
  getConversation(id: string): Promise<LocalConversation | null>;
  getConversations(
    limit?: number,
    cursor?: string,
  ): Promise<LocalConversation[]>;
  findConversationByParticipants(
    participantDids: string[],
  ): Promise<LocalConversation | null>;
  updateConversation(
    id: string,
    updates: Partial<LocalConversation>,
  ): Promise<void>;
  deleteConversation(id: string): Promise<void>;

  // Bulk operations
  saveMessages(messages: LocalMessage[]): Promise<void>;
  clearAll(): Promise<void>;

  // Sync operations
  getLastSyncRev(): Promise<string | null>;
  setLastSyncRev(rev: string): Promise<void>;

  // DCGKA engine state (opaque, per-conversation snapshot from Session.serialize()).
  // This is the crypto engine's durable state — held in the SAME store as messages,
  // and MUST be encrypted at rest (it contains live group secrets; FS depends on it).
  saveEngineState(convoId: string, state: Uint8Array): Promise<void>;
  loadEngineState(convoId: string): Promise<Uint8Array | null>;
  deleteEngineState(convoId: string): Promise<void>;
  listEngineStateIds(): Promise<string[]>;

  // Device-local secret state (opaque blobs keyed by name — e.g. the prekey ring
  // from PrekeyManager.serialize()). Same encryption-at-rest obligation as
  // engine state: these are live admission secrets.
  saveDeviceState(key: string, state: Uint8Array): Promise<void>;
  loadDeviceState(key: string): Promise<Uint8Array | null>;
  deleteDeviceState(key: string): Promise<void>;

  // LiveQuery support (for reactive updates)
  observeConversations(
    filter?: ConversationFilter,
  ): Observable<LocalConversation[]>;
  observeMessages(convoId: string): Observable<LocalMessage[]>;
  observeConversation(convoId: string): Observable<LocalConversation | null>;

  // Certificate operations
  saveCertificate(
    did: string,
    type: ATSMSCertificateType,
    serialNumber: string,
    certificatePEM: string,
    privateKeyPEM?: string,
    isEncrypted?: boolean,
    metadata?: Record<string, any>,
  ): Promise<void>;

  getCertificate(
    did: string,
    type: ATSMSCertificateType,
    serialNumber?: string,
  ): Promise<{
    certificatePEM: string;
    privateKeyPEM?: string;
    isEncrypted: boolean;
    metadata?: Record<string, any>;
  } | null>;

  listCertificates(did?: string): Promise<
    Array<{
      did: string;
      type: ATSMSCertificateType;
      serialNumber: string;
      notBefore: Date;
      notAfter: Date;
      hasPrivateKey: boolean;
    }>
  >;

  deleteCertificate(
    did: string,
    type: ATSMSCertificateType,
    serialNumber: string,
  ): Promise<void>;

  // DID management operations
  getPrimaryDid(): Promise<ATSMSDidInfo | null>;
  getDid(did: string): Promise<ATSMSDidInfo | null>;
  saveDid(
    did: string,
    handle: string,
    endpointCert: ATSMSEndpointCertificate,
  ): Promise<void>;
}

// SQLite-specific interfaces for platform implementations
export interface SQLiteDatabase {
  exec(sql: string): void;
  prepare(sql: string): SQLiteStatement;
  transaction<T>(fn: () => T): T;
  close?(): void;
}

export interface SQLiteStatement {
  run(...params: any[]): void;
  get(...params: any[]): any;
  all(...params: any[]): any[];
  finalize?(): void;
}
