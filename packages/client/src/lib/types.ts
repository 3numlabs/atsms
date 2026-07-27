/**
 * Shared types for AT-SMS Library
 */

import type { ATSMSEndpointCertificate } from "./certificates/index.js";

/**
 * AT-SMS Certificate Types
 * - 'endpoint': Self-signed endpoint certificate (one per device)
 */
export type ATSMSCertificateType = "endpoint";

/**
 * AT-SMS Message Types stored in per-certificate inboxes
 * - 'atsms': AT-SMS P7M encrypted payloads (opaque blob)
 * - 'atsms-email': S/MIME encrypted email (enveloped-data, opaque blob)
 * - 'email': Normal parsed email with subject, body, attachments
 */
export type ATSMSMessageType = "atsms" | "atsms-email" | "atsms-envelope" | "email";

/**
 * Result of decrypting and verifying an AT-SMS message signature
 */
export interface ATSMSDecryptedMessage {
  /** The certificate of the message signer */
  messageSigner: ATSMSEndpointCertificate;
  /** The decrypted content as raw bytes */
  decryptedContent: Uint8Array;
}

/**
 * Structured message payload (decrypted content)
 * This is the message format "on the wire" after decryption
 */
export interface ATSMSMessagePayload {
  version: string;
  contentType: string; // MIME type, e.g., "atsms/text"
  id: string;
  content: string; // JSON-serialized content
  senderId: string;
  recipientIds: string[];
  convoId: string;
  createdAt: string;
}

/**
 * Content structure for "atsms/text" messages
 * This is what's inside the JSON-serialized content field
 */
export interface ATSMSTextContent {
  text: string;
  facets?: ATProtoFacet[]; // Optional AT Protocol facets
}

/**
 * Content structure for "atsms/webrtc" messages
 * Used for WebRTC signaling (establishing audio/video calls)
 */
export interface ATSMSWebRTCContent {
  type: "offer" | "answer" | "ice-candidate" | "hangup";

  // SDP for offer/answer
  sdp?: string;

  // ICE candidate data
  candidate?: {
    candidate: string;
    sdpMid: string | null;
    sdpMLineIndex: number | null;
  };

  // Call metadata
  callId: string; // Unique identifier for this call session
  mediaTypes?: ("audio" | "video")[]; // What media tracks are offered

  // Optional metadata
  timestamp?: number; // When this signaling message was created
}

/**
 * AT Protocol facet (from @atproto/api)
 * For mentions, links, hashtags, etc.
 */
export interface ATProtoFacet {
  index: {
    byteStart: number;
    byteEnd: number;
  };
  features: Array<
    | { $type: "app.bsky.richtext.facet#mention"; did: string }
    | { $type: "app.bsky.richtext.facet#link"; uri: string }
    | { $type: "app.bsky.richtext.facet#tag"; tag: string }
  >;
}

// Transport receipt for tracking message origin and metadata
// The AT-SMS Inbox Provider adds this to messages for troubleshooting spam
export interface ATSMSTransportReceipt {
  source: "email" | "api"; // How the message was received
  timestamp?: string; // When received
  from?: string; // Sender info (for email)
  to?: string; // Recipient info (for email)
  subject?: string; // Subject (for email)
  envelopeFrom?: string; // Envelope from (for email)
  receivedAt?: string; // Receipt time
  headers?: Record<string, string>; // Email headers
  method?: string; // API method (for api)
  clientIp?: string; // Client IP (for api)
}

/**
 * Metadata for messages stored in the inbox service
 * Returned by list operations
 */
export interface ATSMSMessageMetadata {
  id: string; // Message ID (hash of encrypted content)
  messageType: ATSMSMessageType; // Message type (atsms, atsms-email, email)
  seq: number; // Sequence number for ordering
  length: number; // Content length in bytes
  storedAt: string; // ISO timestamp when stored
  transportSource?: string; // How message arrived (email, api, websocket)
  subject?: string; // Email subject (only for messageType: "email")
}

/**
 * Complete encrypted message with content
 * Returned by get/download operations
 */
export interface ATSMSTransportMessage extends ATSMSMessageMetadata {
  encryptedContent?: string; // Base64-encoded PKCS#7 content (atsms, atsms-email)
  // Email-specific fields (messageType: "email")
  from?: string; // Sender email/DID
  fromName?: string; // Sender display name
  to?: string; // Recipient email
  textBody?: string; // Plain text body
  htmlBody?: string; // HTML body
  attachments?: ATSMSEmailAttachment[];
  smimeVerification?: ATSMSSmimeVerification;
  read?: boolean; // Read flag
}

/**
 * Extended transport message with debugging info
 */
export interface ATSMSTransportMessageDebug extends ATSMSTransportMessage {
  transportReceipt: ATSMSTransportReceipt; // Transport metadata
}

/**
 * Email attachment
 */
export interface ATSMSEmailAttachment {
  filename: string;
  contentType: string;
  content: string; // Base64-encoded
  size: number;
}

/**
 * S/MIME verification result for email messages
 */
export interface ATSMSSmimeVerification {
  signed: boolean;
  signerEmail?: string;
  signerCertificate?: string;
  verified?: boolean;
  verificationError?: string;
  verifiedAt?: string;
}

export interface ATSMSConfig {
  apiUrl: string;
}

export interface ATProtocolRecord {
  rkey: string;
  value: any;
  cid?: string;
}

/**
 * Recipient information for multi-recipient message send
 * Groups all endpoints (devices) for a single DID
 */
export interface ATSMSSendRecipient {
  did: string; // Recipient's DID
  endpoints: Array<{
    certSerial: string; // Certificate serial number for this endpoint/device
    email: string; // Email address for routing (DO-to-DO vs SMTP)
  }>;
}

/**
 * Response from sending messages to multiple recipients
 * Contains per-endpoint delivery results
 */
export interface ATSMSSendMessageResponse {
  results: Array<{
    did: string; // Recipient DID
    certSerial?: string; // Recipient certificate serial (atsms/atsms-email)
    email?: string; // Recipient email (atsms/atsms-email)
    status: "sent" | "failed"; // Delivery status
    error?: string; // Error message (if failed)
    deliveredTo?: number; // Number of certs delivered to (email type)
  }>;
}

/**
 * Configuration for the transport layer
 * Used to initialize ATSMSTransportLayer with HTTP and WebSocket clients
 */
export interface ATSMSTransportLayerConfig {
  did: string;
  certSerial: string;
  httpClient: any; // ATSMSApiClient (avoiding circular dependency)
  wsClient?: any; // ATSMSWebSocketClient (avoiding circular dependency)
  preferWebSocket?: boolean;
}

/**
 * Options for listing messages from inbox
 */
export interface ATSMSListMessagesOptions {
  after?: number; // Sequence number to fetch messages after (pagination)
  limit?: number; // Maximum number of messages to return
}

/**
 * Response from listing messages
 * Used by both HTTP and WebSocket transports
 */
export interface ATSMSListMessagesResponse {
  messages: ATSMSMessageMetadata[];
  latestSeq: number;
  hasMore: boolean;
  totalCount: number;
}

/**
 * Response from getting a specific message
 * Used by WebSocket transport
 */
export interface ATSMSGetMessageResponse {
  message: ATSMSTransportMessage;
}

/**
 * Response from deleting a message
 * Used by WebSocket transport
 */
export interface ATSMSDeleteMessageResponse {
  success: boolean;
  messageId: string;
}

/**
 * Response from getting inbox statistics
 * Used by both HTTP and WebSocket transports
 */
export interface ATSMSStatsResponse {
  messageCount: number;
  latestSeq: number;
  connectedClients: number;
}
