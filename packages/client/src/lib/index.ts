/**
 * @atsms/client - AT SMS Secure Messaging System Library
 *
 * This library provides cryptographic operations, message handling,
 * storage management, and API client functionality for the AT SMS secure messaging system.
 */

// Export all types
export * from "./types";

// Export storage types and interfaces
export { EncryptedStorageAdapter } from "./storage/encrypted-adapter";
export { IndexedDBAdapter } from "./storage/indexeddb-adapter";
export * from "./storage/interface";
export { SQLiteAdapter } from "./storage/sqlite-adapter";
export * from "./storage/types";

// Export certificate classes + factories
export {
  ATSMSCertificate,
  ATSMSEndpointCertificate,
  generateEndpointCertificate,
  loadEndpointCertificate,
  loadEndpointCertificateWithKey,
} from "./certificates/index";

// Re-export the AT Protocol agent so consumers share this package's instance
// (a file:-linked copy nests its own @atproto/api; a consumer-constructed
// AtpAgent from a second copy is nominally a different class).
export type { AtpSessionData } from "@atproto/api";
export { Agent, AtpAgent } from "@atproto/api";

// Export identity module (dcgka records/PDS/prekey bridge — sdk-shape.md Part A)
export * from "./identity/index";

// Export conversations module (stateful DCGKA sessions + persistence — sdk-shape.md Part A)
export * from "./conversations/index";

// Export send module (stateless X509-baseline one-shots — sdk-shape.md Part A)
export * from "./send/index";

// Export transport module (opaque envelope carriage — inbound-delivery.md bindings)
export * from "./transport/index";

// Export client module (the top-level ATSMS client — create() wiring + auto-routing)
export * from "./client/index";

// Export crypto operations
export {
  decryptAndVerifyMessageSignature,
  encryptMessage,
  signMessage,
} from "./crypto";

// Export crypto provider utilities
export { setCryptoProvider } from "./crypto-provider";

// Export message CMS composition + email extraction helpers
export { extractP7MFromEmail, prepareMessageForSending } from "./messages";

// Export the v2 message format (docs/message-format.md): CBOR content codec,
// derived IDs, part-kind registry, constructors, shared render model
export * from "./format/index";

// Export the shared inbound ingest + transcript helpers
export { ingestMessage, transcriptMessages } from "./storage/apply";

// Export WebSocket client (inbound push for the envelope transport)
export {
  ATSMSWebSocketClient,
  type ATSMSWebSocketClientConfig,
  type ATSMSWebSocketMessage,
} from "./websocket-client";

// Export JWT authentication
export { generateJWT, getTokenExpiration } from "./jwt-auth";


// Re-export commonly used types for convenience
export type {
  ATProtocolRecord,
  ATSMSCertificateType,
  ATSMSConfig,
  ATSMSDecryptedMessage,
  ATSMSDeleteMessageResponse,
  ATSMSGetMessageResponse,
  ATSMSListMessagesOptions,
  ATSMSListMessagesResponse,
  ATSMSMessageMetadata,
  ATSMSStatsResponse,
  ATSMSTransportMessage,
  ATSMSTransportReceipt,
} from "./types";
