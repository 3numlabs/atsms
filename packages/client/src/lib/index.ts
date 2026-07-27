/**
 * @atsms/sms - AT SMS Secure Messaging System Library
 *
 * This library provides cryptographic operations, message handling,
 * storage management, and API client functionality for the AT SMS secure messaging system.
 */

// Export all types
export * from "./types";

// Export storage types and interfaces
export { IndexedDBAdapter } from "./storage/indexeddb-adapter";
export * from "./storage/interface";
export {
  ATSMSStorageManager,
  type ATSMSStorageManagerConfig,
} from "./storage/manager";
export { SQLiteAdapter } from "./storage/sqlite-adapter";
export { payloadToLocalMessage } from "./storage/types";
export * from "./storage/types";

// Export certificate classes
export {
  ATSMSCertificate,
  ATSMSEndpointCertificate,
} from "./certificates/index";

// Export identity module (dcgka records/PDS/prekey bridge — sdk-shape.md Part A)
export * from "./identity/index";

// Export conversations module (stateful DCGKA sessions + persistence — sdk-shape.md Part A)
export * from "./conversations/index";

// Export transport module (opaque envelope carriage — inbound-delivery.md bindings)
export * from "./transport/index";

// Export client module (the ATSMS facade — create() wiring + auto-routing)
export * from "./client/index";

// Export crypto operations
export {
  decryptAndVerifyMessageSignature,
  encryptMessage,
  signMessage,
} from "./crypto";

// Export crypto provider utilities
export { setCryptoProvider } from "./crypto-provider";

// Export message handling functions
export {
  createMessagePayload,
  createTextContent,
  createWebRTCContent,
  extractP7MFromEmail,
  generateDMConvoId,
  isDMConvoId,
  parseTextContent,
  parseWebRTCContent,
  prepareMessageForSending,
} from "./messages";

// Export API client
export { ATSMSApiClient } from "./atsms-api";

// Export WebSocket client
export {
  ATSMSWebSocketClient,
  type ATSMSWebSocketClientConfig,
  type ATSMSWebSocketMessage,
} from "./websocket-client";

// Export Transport Layer
export { ATSMSTransportLayer } from "./transport-layer";

// Export JWT authentication
export { generateJWT, getTokenExpiration } from "./jwt-auth";

// Export the ATSMSClient (main client class)
export { ATSMSClient } from "./atsms-client";

// Re-export commonly used types for convenience
export type {
  ATProtocolRecord,
  ATProtoFacet,
  ATSMSCertificateType,
  ATSMSConfig,
  ATSMSDecryptedMessage,
  ATSMSDeleteMessageResponse,
  ATSMSGetMessageResponse,
  ATSMSListMessagesOptions,
  ATSMSListMessagesResponse,
  ATSMSMessageMetadata,
  ATSMSMessagePayload,
  ATSMSStatsResponse,
  ATSMSTextContent,
  ATSMSTransportLayerConfig,
  ATSMSTransportMessage,
  ATSMSTransportReceipt,
  ATSMSWebRTCContent,
} from "./types";
