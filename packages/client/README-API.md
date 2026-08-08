# @atsms/sms API Reference

> **STALE — documents the pre-v2 API.** Most of what follows no longer exists. The god-object clients
> (`ATSMSStorageManager`, `ATSMSClient`) were deleted at the v2 message-format cut-over, and
> `ATSMSTransportLayer` / `ATSMSApiClient` were deleted with the rest of that surface on 2026-08-05.
> For the current API — `ATSMS.create()`, `atsms.send()`, `atsms.conversations`, `atsms.peers` — see
> [`CLAUDE.md`](./CLAUDE.md) and the umbrella [`docs/sdk-shape.md`](../docs/sdk-shape.md). This file is
> kept only until it is rewritten against the current shape.

Complete API documentation for the ATSMS Secure Messaging System library.

**Browser & Node.js Support**: This library supports both environments with automatic platform detection and WebCrypto API usage.

## Table of Contents

- [Core Classes](#core-classes)
  - [ATSMSStorageManager](#atsmsstoragemanager)
  - [ATSMSClient](#atsmsclient)
  - [ATSMSTransportLayer](#atsmstransportlayer)
  - [ATSMSApiClient](#atsmsapiclient)
  - [ATSMSWebSocketClient](#atsmswebsocketclient)
- [Certificate Classes](#certificate-classes)
  - [RootCertificate](#rootcertificate)
  - [ClientCertificate](#clientcertificate)
  - [Certificate](#certificate)
- [Cryptographic Functions](#cryptographic-functions)
- [Message Functions](#message-functions)
- [JWT Authentication](#jwt-authentication)
- [Storage System](#storage-system)
- [Types Reference](#types-reference)

## Core Classes

### ATSMSStorageManager

High-level manager for messages, conversations, and certificate management. This is the primary class for application developers.

```typescript
import { ATSMSStorageManager, SQLiteAdapter, ATSMSClient } from '@atsms/sms'
import { AtpAgent } from '@atproto/api'

const agent = new AtpAgent({ service: 'https://bsky.social' })
await agent.login({ identifier: 'alice.bsky.social', password: 'app-password' })

const storage = new SQLiteAdapter('./messages.db')
await storage.initialize()

const manager = new ATSMSStorageManager({
  storage,
  atsmsClient: new ATSMSClient(agent),
  did: agent.session!.did,
  apiUrl: 'https://inbox.atsms.at'
})
```

#### Constructor

```typescript
constructor(config: ATSMSStorageManagerConfig)
```

**Config Parameters:**
- `storage: StorageAdapter` - Storage backend (e.g., SQLiteAdapter)
- `atsmsClient: ATSMSClient` - AT Protocol client for certificate operations
- `did: string` - User's DID
- `handle: string` - User's handle (e.g., "alice.bsky.social")
- `apiUrl: string` - ATSMS inbox service URL
- `certSerial: string` - Client certificate serial number for authentication
- `onSyncCompleted?: () => void` - Optional callback when sync completes
- `onMessageAdded?: (message: LocalMessage) => void` - Optional callback when message is added (full message object)
- `onConversationUpdated?: (convoId: string) => void` - Optional callback when conversation is updated

#### Certificate Methods

##### generateAndStoreCertificates()
```typescript
async generateAndStoreCertificates(
  email: string
): Promise<{
  rootCert: RootCertificate
  clientCert: ClientCertificate
}>
```
Generates root and client certificates, stores them locally and in PDS.

**Parameters:**
- `email: string` - Email address for certificate SAN (required for message routing)

**Returns:** Certificate pair with private keys

##### getCachedOrFetchCertificatesForDID()
```typescript
async getCachedOrFetchCertificatesForDID(
  did: string
): Promise<{
  rootCert: RootCertificate
  endpointCerts: ClientCertificate[]
}>
```
Retrieves certificates for a DID (cached or fetched from PDS).

#### Conversation Methods

##### startConversation()
```typescript
async startConversation(
  recipientDids: string[],
  senderCert: ClientCertificate
): Promise<string>
```
Creates a new conversation with recipients.

**Parameters:**
- `recipientDids: string[]` - Array of recipient DIDs
- `senderCert: ClientCertificate` - Sender's certificate with private key

**Returns:** Conversation ID (convoId)

##### listConversations()
```typescript
async listConversations(): Promise<Conversation[]>
```
Lists all conversations for the user.

##### getConversation()
```typescript
async getConversation(convoId: string): Promise<Conversation | null>
```
Gets a specific conversation by ID.

#### Message Methods

##### sendMessage()
```typescript
async sendMessage(
  convoId: string,
  text: string,
  senderCert: ATSMSEndpointCertificate
): Promise<void>
```
Sends an encrypted text message in a conversation. The text is automatically wrapped in the "atsms/text" content type format.

**Parameters:**
- `convoId: string` - Conversation ID
- `text: string` - Plain text message content (automatically serialized to JSON)
- `senderCert: ATSMSEndpointCertificate` - Sender's endpoint certificate with private key

**Note:** For advanced use cases with facets (mentions, links, hashtags), use the lower-level message creation functions from `src/lib/messages.ts`

##### getConversationMessages()
```typescript
async getConversationMessages(
  convoId: string,
  limit?: number
): Promise<ATSMSDecryptedMessage[]>
```
Gets all messages in a conversation (automatically decrypted).

##### syncMessages()
```typescript
async syncMessages(): Promise<void>
```
Syncs new messages from the inbox service.

#### Observable Accessors

The storage manager provides Observable accessors for reactive UI updates.

##### messageAdded$
```typescript
get messageAdded$(): Observable<LocalMessage>
```
Observable that emits the full `LocalMessage` object whenever a new message is added (sent or received).

**Usage:**
```typescript
import { filter } from 'rxjs/operators'
import { parseTextContent } from '@atsms/sms'

// Subscribe to all messages
manager.messageAdded$.subscribe((message) => {
  console.log(`New message: ${message.id}`)
  if (message.contentType === 'atsms/text') {
    const textContent = parseTextContent(message.content)
    console.log(`Text: ${textContent.text}`)
  }
})

// Filter by content type
manager.messageAdded$
  .pipe(filter(message => message.contentType === 'atsms/text'))
  .subscribe((message) => {
    const textContent = parseTextContent(message.content)
    showNotification(textContent.text)
  })
```

##### conversationUpdated$
```typescript
get conversationUpdated$(): Observable<string>
```
Observable that emits the conversation ID whenever a conversation's metadata changes.

##### syncCompleted$
```typescript
get syncCompleted$(): Observable<void>
```
Observable that emits when message synchronization completes.

---

### ATSMSClient

AT Protocol integration for certificate management. Handles storing and retrieving certificates from Personal Data Servers (PDS).

```typescript
import { ATSMSClient } from '@atsms/sms'
import { AtpAgent } from '@atproto/api'

const agent = new AtpAgent({ service: 'https://bsky.social' })
await agent.login({ identifier: 'alice.bsky.social', password: 'app-password' })

const client = new ATSMSClient(agent)
```

#### Constructor

```typescript
constructor(agent: AtpAgent)
```

**Parameters:**
- `agent: AtpAgent` - Authenticated AT Protocol agent

#### Methods

##### storeCertificate()
```typescript
async storeCertificate(
  cert: Certificate,
  type: 'root' | 'endpoint'
): Promise<{ uri: string; cid: string }>
```
Stores a certificate in the PDS (`at.atsms.x509` collection).

##### getCertificates()
```typescript
async getCertificates(
  did: string
): Promise<{
  rootCert: RootCertificate | null
  endpointCerts: ClientCertificate[]
}>
```
Retrieves all certificates for a DID from their PDS.

##### listCertificates()
```typescript
async listCertificates(did: string): Promise<string[]>
```
Lists certificate serial numbers for a DID.

##### resolveDIDtoPDS()
```typescript
async resolveDIDtoPDS(did: string): Promise<string>
```
Resolves a DID to its PDS URL via PLC directory.

---

### ATSMSTransportLayer

Unified transport layer with automatic WebSocket/HTTP fallback.

```typescript
import {
  ATSMSTransportLayer,
  ATSMSApiClient,
  ATSMSWebSocketClient
} from '@atsms/sms'

const httpClient = new ATSMSApiClient({ apiUrl: 'https://inbox.atsms.at' })
httpClient.setAuthToken(jwtToken)

const wsClient = new ATSMSWebSocketClient({
  apiUrl: 'https://inbox.atsms.at',
  did: 'did:plc:abc123',
  certSerial: 'xyz789',
  getToken: async () => jwtToken
})

const transport = new ATSMSTransportLayer({
  did: 'did:plc:abc123',
  certSerial: 'xyz789',
  httpClient,
  wsClient,
  preferWebSocket: true
})
```

#### Constructor

```typescript
constructor(config: ATSMSTransportLayerConfig)
```

**Config Parameters:**
- `did: string` - User's DID
- `certSerial: string` - Client certificate serial number
- `httpClient: ATSMSApiClient` - HTTP client
- `wsClient?: ATSMSWebSocketClient` - Optional WebSocket client
- `preferWebSocket?: boolean` - Prefer WebSocket when available (default: true)

#### Methods

##### listMessages()
```typescript
async listMessages(
  options?: ATSMSListMessagesOptions
): Promise<ATSMSListMessagesResponse>
```
Lists messages from inbox (WebSocket or HTTP).

**Options:**
- `after?: number` - Sequence number for pagination
- `limit?: number` - Max messages to return

**Returns:**
- `messages: ATSMSMessageMetadata[]` - Array of message metadata
- `latestSeq: number` - Latest sequence number
- `hasMore: boolean` - More messages available
- `totalCount: number` - Total message count

##### getMessage()
```typescript
async getMessage(messageId: string): Promise<ATSMSTransportMessage>
```
Gets a specific encrypted message.

##### deleteMessage()
```typescript
async deleteMessage(messageId: string): Promise<void>
```
Deletes a message from inbox.

##### getStats()
```typescript
async getStats(): Promise<ATSMSStatsResponse>
```
Gets inbox statistics.

**Returns:**
- `messageCount: number` - Total messages
- `latestSeq: number` - Latest sequence
- `connectedClients: number` - Connected WebSocket clients

##### sendMessage()
```typescript
async sendMessage(
  recipients: ATSMSSendRecipient[],
  encryptedContent: string
): Promise<ATSMSSendMessageResponse>
```
Sends encrypted message to multiple recipients (WebSocket or HTTP).

**Parameters:**
- `recipients: ATSMSSendRecipient[]` - Recipients grouped by DID with endpoints
- `encryptedContent: string` - Base64-encoded encrypted message

**Recipient Format:**
```typescript
interface ATSMSSendRecipient {
  did: string
  endpoints: Array<{
    certSerial: string  // Device certificate serial
    email: string       // Email for routing
  }>
}
```

**Returns:**
```typescript
interface ATSMSSendMessageResponse {
  results: Array<{
    did: string
    certSerial: string
    email: string
    status: 'sent' | 'failed'
    error?: string
  }>
}
```

---

### ATSMSApiClient

REST API client for ATSMS inbox service (HTTP only).

```typescript
import { ATSMSApiClient } from '@atsms/sms'

const client = new ATSMSApiClient({ apiUrl: 'https://inbox.atsms.at' })
client.setAuthToken(jwtToken)
```

#### Constructor

```typescript
constructor(config: ATSMSConfig)
```

**Config Parameters:**
- `apiUrl: string` - ATSMS inbox service URL

#### Methods

##### setAuthToken()
```typescript
setAuthToken(token: string): void
```
Sets the JWT authentication token.

##### listMessages()
```typescript
async listMessages(
  did: string,
  certSerial: string,
  afterSequence?: number,
  limit?: number
): Promise<ATSMSListMessagesResponse>
```
Lists messages for a DID and certificate.

##### downloadMessage()
```typescript
async downloadMessage(
  did: string,
  certSerial: string,
  messageId: string
): Promise<ATSMSTransportMessage>
```
Downloads a specific encrypted message.

##### deleteMessage()
```typescript
async deleteMessage(
  did: string,
  certSerial: string,
  messageId: string
): Promise<void>
```
Deletes a message from inbox.

##### getStats()
```typescript
async getStats(
  did: string,
  certSerial: string
): Promise<ATSMSStatsResponse>
```
Gets inbox statistics.

##### sendMessage()
```typescript
async sendMessage(
  recipients: ATSMSSendRecipient[],
  encryptedContent: string
): Promise<ATSMSSendMessageResponse>
```
**NOTE:** Currently throws error - HTTPS send not yet implemented on server. Use WebSocket send via `ATSMSTransportLayer` instead.

---

### ATSMSWebSocketClient

Real-time WebSocket client for ATSMS inbox service.

```typescript
import { ATSMSWebSocketClient } from '@atsms/sms'

const client = new ATSMSWebSocketClient({
  apiUrl: 'https://inbox.atsms.at',
  did: 'did:plc:abc123',
  certSerial: 'xyz789',
  getToken: async () => jwtToken,
  onMessage: (msg) => console.log('New message:', msg),
  onError: (err) => console.error('WebSocket error:', err)
})

await client.connect()
```

#### Constructor

```typescript
constructor(config: WebSocketClientConfig)
```

**Config Parameters:**
- `apiUrl: string` - ATSMS inbox service URL (wss:// protocol)
- `did: string` - User's DID
- `certSerial: string` - Client certificate serial
- `getToken: () => Promise<string>` - Function to get JWT token
- `onMessage?: (message: WebSocketMessage) => void` - Message callback
- `onError?: (error: Error) => void` - Error callback
- `reconnectDelay?: number` - Reconnect delay in ms (default: 1000)
- `maxReconnectAttempts?: number` - Max reconnect attempts (default: 10)

#### Methods

##### connect()
```typescript
async connect(): Promise<void>
```
Connects to WebSocket server with authentication.

**Authentication:**
- **Node.js**: JWT in `Authorization` header during connection
- **Browser**: JWT sent via `auth` message after connection

##### disconnect()
```typescript
disconnect(): void
```
Disconnects from WebSocket server.

##### isConnected()
```typescript
isConnected(): boolean
```
Checks if WebSocket is connected.

##### listMessages()
```typescript
async listMessages(
  after?: number,
  limit?: number
): Promise<ATSMSListMessagesResponse>
```
Lists messages via WebSocket request/response.

##### getMessage()
```typescript
async getMessage(messageId: string): Promise<ATSMSGetMessageResponse>
```
Gets a specific message via WebSocket.

##### deleteMessage()
```typescript
async deleteMessage(messageId: string): Promise<ATSMSDeleteMessageResponse>
```
Deletes a message via WebSocket.

##### getStats()
```typescript
async getStats(): Promise<ATSMSStatsResponse>
```
Gets inbox stats via WebSocket.

##### sendMessage()
```typescript
async sendMessage(
  recipients: ATSMSSendRecipient[],
  encryptedContent: string
): Promise<ATSMSSendMessageResponse>
```
Sends encrypted message to multiple recipients via WebSocket.

---

## Certificate Classes

### RootCertificate

Self-signed CA certificate using secp256k1 curve.

```typescript
import { RootCertificate } from '@atsms/sms'

const rootCert = await RootCertificate.generate({
  did: 'did:plc:abc123',
  validityDays: 3650
})

console.log(rootCert.certificatePEM)
console.log(rootCert.privateKeyPEM)
console.log(rootCert.did)
console.log(rootCert.serialNumber)
```

#### Static Methods

##### generate()
```typescript
static async generate(params: GenerateParams): Promise<RootCertificate>
```

**Params:**
- `did: string` - User's DID (stored in SAN)
- `validityDays?: number` - Certificate validity period (default: 3650)

##### fromPEM()
```typescript
static async fromPEM(
  certPEM: string,
  privateKeyPEM?: string
): Promise<RootCertificate>
```
Loads certificate from PEM strings.

#### Properties

- `certificatePEM: string` - PEM-encoded certificate
- `privateKeyPEM: string | undefined` - PEM-encoded private key
- `did: string | undefined` - DID extracted from SAN
- `serialNumber: string` - Certificate serial number (hex)
- `privateKey: CryptoKey | undefined` - CryptoKey for signing

---

### ClientCertificate

RSA 2048-bit certificate for message encryption and API authentication.

```typescript
import { ClientCertificate } from '@atsms/sms'

const clientCert = await ClientCertificate.generate({
  rootCert,
  email: 'alice@example.com',
  validityDays: 365
})

console.log(clientCert.certificatePEM)
console.log(clientCert.privateKeyPEM)
console.log(clientCert.did)
console.log(clientCert.email)  // From SAN
console.log(clientCert.serialNumber)
```

#### Static Methods

##### generate()
```typescript
static async generate(params: ClientCertParams): Promise<ClientCertificate>
```

**Params:**
- `rootCert: RootCertificate` - Root certificate for signing
- `email: string` - Email address (stored in SAN, required for routing)
- `validityDays?: number` - Certificate validity period (default: 365)

##### fromPEM()
```typescript
static async fromPEM(
  certPEM: string,
  privateKeyPEM?: string
): Promise<ClientCertificate>
```

##### fromPEMWithKey()
```typescript
static async fromPEMWithKey(
  certPEM: string,
  privateKeyPEM: string
): Promise<ClientCertificate>
```
Loads certificate with private key guaranteed.

#### Properties

- `certificatePEM: string` - PEM-encoded certificate
- `privateKeyPEM: string | undefined` - PEM-encoded private key
- `did: string | undefined` - DID extracted from SAN
- `email: string | undefined` - Email extracted from SAN (RFC822 name)
- `serialNumber: string` - Certificate serial number (hex)
- `privateKey: CryptoKey | undefined` - CryptoKey for decryption/signing

---

### Certificate

Base class for certificate operations (extended by RootCertificate and ClientCertificate).

#### Properties

- `certificatePEM: string` - PEM-encoded certificate
- `privateKeyPEM: string | undefined` - PEM-encoded private key
- `did: string | undefined` - DID from SAN extension
- `email: string | undefined` - Email from SAN extension
- `serialNumber: string` - Certificate serial number
- `privateKey: CryptoKey | undefined` - CryptoKey

---

## Cryptographic Functions

### encryptMessage()
```typescript
async function encryptMessage(
  content: Buffer,
  recipientCerts: string[]
): Promise<Buffer>
```
Encrypts message using S/MIME (PKCS#7) for multiple recipients.

**Encryption:**
- Algorithm: RSA-OAEP for key encryption
- Content encryption: AES-256-CBC
- Format: PKCS#7 enveloped-data

**Parameters:**
- `content: Buffer` - Message content (typically already signed)
- `recipientCerts: string[]` - Array of PEM-encoded recipient certificates

**Returns:** Encrypted message as Buffer

### signMessage()
```typescript
async function signMessage(
  content: Buffer,
  certificate: string,
  privateKey: CryptoKey
): Promise<Buffer>
```
Signs message using S/MIME (PKCS#7).

**Parameters:**
- `content: Buffer` - Message content to sign
- `certificate: string` - PEM-encoded certificate
- `privateKey: CryptoKey` - Private key for signing

**Returns:** Signed message as Buffer (PKCS#7 signed-data)

### decryptAndVerifyMessageSignature()
```typescript
async function decryptAndVerifyMessageSignature(
  encryptedContent: string | Buffer,
  recipientCert: string,
  recipientPrivateKey: CryptoKey,
  rootCert: string
): Promise<{
  content: string
  signatureVerified: boolean
  signerCertificate: any
}>
```
Decrypts and verifies message in one operation.

**Parameters:**
- `encryptedContent: string | Buffer` - Base64 string or Buffer
- `recipientCert: string` - Recipient's certificate PEM
- `recipientPrivateKey: CryptoKey` - Recipient's private key
- `rootCert: string` - Root certificate for signature verification

**Returns:**
- `content: string` - Decrypted message content (JSON string)
- `signatureVerified: boolean` - Signature valid
- `signerCertificate: any` - Signer's certificate

---

## Message Functions

### createTextContent()
```typescript
function createTextContent(
  text: string,
  facets?: ATProtoFacet[]
): string
```
Creates JSON-serialized content for "atsms/text" messages.

**Parameters:**
- `text: string` - Plain text message content
- `facets?: ATProtoFacet[]` - Optional AT Protocol facets for rich text (mentions, links, hashtags)

**Returns:** JSON string like `'{"text":"Hello","facets":[...]}'`

### parseTextContent()
```typescript
function parseTextContent(content: string): ATSMSTextContent
```
Parses "atsms/text" content from JSON string.

**Returns:**
```typescript
{
  text: string
  facets?: ATProtoFacet[]
}
```

### createMessagePayload()
```typescript
function createMessagePayload(
  senderId: string,
  recipientIds: string[],
  content: string,
  contentType?: string,
  conversationId?: string
): ATSMSMessagePayload
```
Creates a complete message payload structure.

**Parameters:**
- `senderId: string` - Sender's DID
- `recipientIds: string[]` - Recipient DIDs
- `content: string` - JSON-serialized content (use `createTextContent()` for text messages)
- `contentType?: string` - MIME type (default: "atsms/text")
- `conversationId?: string` - Conversation ID (auto-generated if not provided)

**Returns:**
```typescript
{
  version: '1.0',
  contentType: 'atsms/text',
  id: string,           // Auto-generated nanoid
  content: string,      // JSON-serialized content
  senderId: string,
  recipientIds: string[],
  convoId: string,
  createdAt: string     // ISO timestamp
}
```

**Example:**
```typescript
import { createTextContent, createMessagePayload } from '@atsms/sms'

const content = createTextContent('Hello world!')
const payload = createMessagePayload(
  'did:plc:sender123',
  ['did:plc:recipient456'],
  content
)
```

### prepareMessageForSending()
```typescript
async function prepareMessageForSending(
  payload: ATSMSMessagePayload,
  senderCert: ClientCertificate,
  recipientCerts: ClientCertificate[]
): Promise<string>
```
Signs and encrypts a message payload for sending.

**Steps:**
1. Serialize payload to JSON
2. Sign with sender's certificate
3. Encrypt for all recipient certificates

**Returns:** Base64-encoded encrypted message

### extractP7MFromEmail()
```typescript
function extractP7MFromEmail(emailContent: string): string | null
```
Extracts P7M attachment from MIME email content.

---

## JWT Authentication

### generateJWT()
```typescript
async function generateJWT(
  did: string,
  certSerial: string,
  email: string,
  privateKey: CryptoKey,
  expiresIn?: string
): Promise<string>
```
Generates ATSMS API JWT signed with client certificate.

**Parameters:**
- `did: string` - User's DID
- `certSerial: string` - Client certificate serial number
- `email: string` - Email from certificate
- `privateKey: CryptoKey` - Client certificate private key
- `expiresIn?: string` - Expiration time (default: '1h')

**Returns:** JWT token string

**Token Payload:**
```typescript
{
  did: string
  certSerial: string
  email: string
  iat: number  // Issued at
  exp: number  // Expiration
}
```

### getTokenExpiration()
```typescript
function getTokenExpiration(token: string): Date | null
```
Gets JWT expiration date.

### getValidCachedToken()
```typescript
function getValidCachedToken(cache: JWTCache): string | null
```
Retrieves cached JWT if still valid.

**Cache Structure:**
```typescript
interface JWTCache {
  token: string
  expiresAt: number  // Unix timestamp
}
```

---

## Storage System

### SQLiteAdapter

SQLite storage implementation (uses `bun:sqlite`).

```typescript
import { SQLiteAdapter } from '@atsms/sms'

const storage = new SQLiteAdapter('./messages.db')
await storage.initialize()
```

#### Methods

##### initialize()
```typescript
async initialize(): Promise<void>
```
Initializes database and creates tables.

##### storeMessage()
```typescript
async storeMessage(message: StoreMessageParams): Promise<void>
```

##### getMessage()
```typescript
async getMessage(messageId: string): Promise<StoredMessage | null>
```

##### listMessages()
```typescript
async listMessages(options?: ListOptions): Promise<StoredMessage[]>
```

##### deleteMessage()
```typescript
async deleteMessage(messageId: string): Promise<void>
```

##### storeCertificate()
```typescript
async storeCertificate(cert: StoreCertificateParams): Promise<void>
```

##### getCertificate()
```typescript
async getCertificate(
  did: string,
  type: 'root' | 'endpoint',
  serialNumber: string
): Promise<StoredCertificate | null>
```

##### storeConversation()
```typescript
async storeConversation(convo: Conversation): Promise<void>
```

##### getConversation()
```typescript
async getConversation(convoId: string): Promise<Conversation | null>
```

##### listConversations()
```typescript
async listConversations(): Promise<Conversation[]>
```

---

## Types Reference

### Message Types

```typescript
// Message payload (decrypted content)
interface ATSMSMessagePayload {
  version: '1.0'
  content: {
    text: string
  }
  senderId: string
  recipientIds: string[]
  convoId: string
  createdAt: string
}

// Decrypted message with metadata
interface ATSMSDecryptedMessage {
  id: string
  sequence: number
  encryptedContent: string
  receivedAt: string
  decryptedPayload: ATSMSMessagePayload
  signatureVerified: boolean
}

// Transport message (encrypted)
interface ATSMSTransportMessage extends ATSMSMessageMetadata {
  encryptedContent: string
}

// Message metadata (no content)
interface ATSMSMessageMetadata {
  id: string
  sequence: number
  receivedAt: string
}
```

### Send Types

```typescript
// Recipient with endpoints
interface ATSMSSendRecipient {
  did: string
  endpoints: Array<{
    certSerial: string
    email: string
  }>
}

// Send response
interface ATSMSSendMessageResponse {
  results: Array<{
    did: string
    certSerial: string
    email: string
    status: 'sent' | 'failed'
    error?: string
  }>
}
```

### Transport Types

```typescript
// Transport configuration
interface ATSMSTransportLayerConfig {
  did: string
  certSerial: string
  httpClient: any  // ATSMSApiClient
  wsClient?: any   // ATSMSWebSocketClient
  preferWebSocket?: boolean
}

// List messages options
interface ATSMSListMessagesOptions {
  after?: number
  limit?: number
}

// List messages response
interface ATSMSListMessagesResponse {
  messages: ATSMSMessageMetadata[]
  latestSeq: number
  hasMore: boolean
  totalCount: number
}

// Stats response
interface ATSMSStatsResponse {
  messageCount: number
  latestSeq: number
  connectedClients: number
}
```

### Configuration Types

```typescript
// API client config
interface ATSMSConfig {
  apiUrl: string
}

// Storage manager config
interface ATSMSStorageManagerConfig {
  storage: StorageAdapter
  atsmsClient: ATSMSClient
  did: string
  handle: string
  apiUrl: string
  certSerial: string
  onSyncCompleted?: () => void
  onMessageAdded?: (message: LocalMessage) => void
  onConversationUpdated?: (convoId: string) => void
}

// WebSocket client config
interface WebSocketClientConfig {
  apiUrl: string
  did: string
  certSerial: string
  getToken: () => Promise<string>
  onMessage?: (message: WebSocketMessage) => void
  onError?: (error: Error) => void
  reconnectDelay?: number
  maxReconnectAttempts?: number
}
```

### Conversation Types

```typescript
interface Conversation {
  id: string
  participantIds: string[]
  createdAt: string
  lastMessageAt?: string
}
```

---

## Error Handling

All async methods may throw errors. Always use try-catch:

```typescript
try {
  await manager.sendMessage(convoId, 'Hello', clientCert)
} catch (error) {
  console.error('Send failed:', error.message)
}
```

**Common Error Types:**
- Network errors (fetch failures)
- Certificate validation errors
- Decryption/encryption failures
- Missing certificates (recipient not found)
- Authentication errors (invalid JWT)
- WebSocket connection errors

---

## Complete Usage Example

```typescript
import {
  ATSMSStorageManager,
  SQLiteAdapter,
  ATSMSClient,
  RootCertificate,
  ClientCertificate
} from '@atsms/sms'
import { AtpAgent } from '@atproto/api'

// 1. Setup AT Protocol authentication
const agent = new AtpAgent({ service: 'https://bsky.social' })
await agent.login({
  identifier: 'alice.bsky.social',
  password: 'your-app-password'
})

// 2. Initialize storage
const storage = new SQLiteAdapter('./alice-messages.db')
await storage.initialize()

// 3. Create storage manager
const manager = new ATSMSStorageManager({
  storage,
  atsmsClient: new ATSMSClient(agent),
  did: agent.session!.did,
  apiUrl: 'https://inbox.atsms.at'
})

// 4. Generate certificates (first time)
const { rootCert, clientCert } = await manager.generateAndStoreCertificates(
  'alice@example.com'
)

// 5. Start conversation
const convoId = await manager.startConversation(
  ['did:plc:bob123'],
  clientCert
)

// 6. Send message
await manager.sendMessage(convoId, 'Hello Bob!', clientCert)

// 7. Sync and read messages
await manager.syncMessages()
const messages = await manager.getConversationMessages(convoId)

// Parse text content from message
import { parseTextContent } from '@atsms/sms'
const firstMessage = messages[0]
const textContent = parseTextContent(firstMessage.content)
console.log(textContent.text)

// 8. List all conversations
const conversations = await manager.listConversations()
conversations.forEach(c => {
  console.log(`Conversation: ${c.id}`)
  console.log(`Participants: ${c.participantIds.join(', ')}`)
})
```

---

## Browser vs Node.js

### Node.js (Bun)
```typescript
// No special setup needed
import { encryptMessage } from '@atsms/sms'
```

### Browser
```typescript
// Set crypto provider before operations
import { setCryptoProvider } from '@atsms/sms'
import { Crypto } from '@peculiar/webcrypto'

setCryptoProvider(new Crypto())
```

---

## Platform-Specific Notes

- **SQLite**: Uses `bun:sqlite` (Node.js/Bun only). For browser, implement custom `StorageAdapter` using IndexedDB.
- **WebSocket**: Browser uses native WebSocket, Node.js uses `ws` package (dynamically imported).
- **Crypto**: Browser uses native WebCrypto, Node.js uses `@peculiar/webcrypto` polyfill.

---

For more information, see:
- [Main README](README-NPM.md) - Quick start and overview
- [CLAUDE.md](CLAUDE.md) - Development guide and architecture details
