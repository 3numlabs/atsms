# @atsms/sms

End-to-end encrypted messaging library for AT Protocol (Bluesky) with X.509 certificate-based encryption.

> **STALE (2026-07-31):** this README predates the v2 message format (deterministic-CBOR content,
> derived message IDs, part registry — see the umbrella `docs/message-format.md`) and the removal of
> the legacy `ATSMSClient`/`ATSMSStorageManager` API it documents. Until it is rewritten, trust the
> repo `CLAUDE.md` and `src/lib/format/` over the examples below.

## Installation

```bash
npm install @atsms/sms
# or
bun add @atsms/sms
```

## Overview

`@atsms/sms` is a TypeScript library that provides secure, end-to-end encrypted messaging built on AT Protocol (Bluesky). Messages are encrypted using S/MIME (PKCS#7) with X.509 certificates, supporting both browser and Node.js environments.

## Features

- 🔐 **End-to-End Encryption**: S/MIME (PKCS#7) encryption with RSA-OAEP and AES-256-CBC
- 🔑 **Certificate Management**: secp256k1 root certificates and RSA client certificates with SAN extensions
- 📨 **Multi-Recipient Messaging**: Send encrypted messages to multiple recipients/devices in one call
- 🌐 **Dual Transport**: WebSocket (real-time) with HTTP fallback for all operations
- 💾 **Storage Layer**: Built-in SQLite storage with message decryption and conversation management
- 🔒 **JWT Authentication**: Certificate-signed JWTs for AT-SMS API authentication
- 📦 **TypeScript Support**: Full TypeScript types with ATSMS prefix convention
- 🖥️ **Cross-Platform**: Works in browser (WebCrypto) and Node.js (Bun)

## Quick Start

### Basic Usage with Storage Manager

```typescript
import {
  ATSMSStorageManager,
  SQLiteAdapter,
  ATSMSClient
} from '@atsms/sms'
import { AtpAgent } from '@atproto/api'

// 1. Initialize AT Protocol agent (for PDS authentication)
const agent = new AtpAgent({ service: 'https://bsky.social' })
await agent.login({
  identifier: 'alice.bsky.social',
  password: 'your-app-password'
})

// 2. Create AT-SMS client (for certificate management)
const atsmsClient = new ATSMSClient(agent)

// 3. Initialize storage with SQLite
const storage = new SQLiteAdapter('./messages.db')
await storage.initialize()

// 4. Create storage manager (handles encryption, transport, and storage)
const manager = new ATSMSStorageManager({
  storage,
  atsmsClient,
  did: agent.session!.did,
  apiUrl: 'https://inbox.atsms.at'
})

// 5. Generate certificates (first time only)
const { rootCert, clientCert } = await manager.generateAndStoreCertificates(
  'alice@example.com'  // Email for routing (required in SAN)
)

// 6. Start a conversation
const convoId = await manager.startConversation(
  ['did:plc:bob123'],  // Recipient DIDs
  clientCert  // Your client cert with private key
)

// 7. Send a message
await manager.sendMessage(
  convoId,
  'Hello Bob!',
  clientCert
)

// 8. List conversations
const conversations = await manager.listConversations()

// 9. Get messages in a conversation
const messages = await manager.getConversationMessages(convoId)

// Parse message content
import { parseTextContent } from '@atsms/sms'
const textContent = parseTextContent(messages[0].content)
console.log(textContent.text)
```

## Architecture

### Certificate System

The library uses a two-tier certificate hierarchy:

1. **Root Certificate** (secp256k1, self-signed CA)
   - One per user/DID
   - Stored in AT Protocol PDS (`at.atsms.x509` collection)
   - Signs client certificates

2. **Client Certificates** (RSA 2048)
   - One per device/endpoint
   - Signed by root certificate
   - Used for message encryption AND AT-SMS API authentication
   - Must include email in Subject Alternative Name (SAN)

```typescript
import { RootCertificate, ClientCertificate } from '@atsms/sms'

// Generate root certificate
const rootCert = await RootCertificate.generate({
  did: 'did:plc:alice123',
  validityDays: 3650
})

// Generate client certificate
const clientCert = await ClientCertificate.generate({
  rootCert,
  email: 'alice@example.com',  // Required in SAN
  validityDays: 365
})

// Extract information
console.log(clientCert.did)          // DID from SAN
console.log(clientCert.email)        // Email from SAN
console.log(clientCert.serialNumber) // Certificate serial
```

### Storage Layer

The storage layer handles message decryption, certificate caching, and conversation management:

```typescript
import { ATSMSStorageManager, SQLiteAdapter } from '@atsms/sms'

const storage = new SQLiteAdapter('./messages.db')
await storage.initialize()

const manager = new ATSMSStorageManager({
  storage,
  atsmsClient,
  did: 'did:plc:alice123',
  apiUrl: 'https://inbox.atsms.at'
})

// Messages are automatically decrypted when stored
// Certificates are cached for performance
// Conversations group messages by participants
```

### Transport Layer

The transport layer provides unified access to WebSocket and HTTP:

```typescript
import {
  ATSMSTransportLayer,
  ATSMSApiClient,
  ATSMSWebSocketClient
} from '@atsms/sms'

// HTTP client
const httpClient = new ATSMSApiClient({
  apiUrl: 'https://inbox.atsms.at'
})
httpClient.setAuthToken(jwtToken)

// WebSocket client (optional)
const wsClient = new ATSMSWebSocketClient({
  apiUrl: 'https://inbox.atsms.at',
  did: 'did:plc:alice123',
  certSerial: 'abc123',
  getToken: async () => jwtToken
})
await wsClient.connect()

// Transport layer (automatic fallback)
const transport = new ATSMSTransportLayer({
  did: 'did:plc:alice123',
  certSerial: 'abc123',
  httpClient,
  wsClient,
  preferWebSocket: true  // Try WebSocket first, fallback to HTTP
})

// List messages (uses WebSocket if connected, otherwise HTTP)
const response = await transport.listMessages({ after: 0, limit: 50 })
```

## Authentication

AT-SMS uses **two distinct JWT types**:

### 1. AT Protocol PDS JWTs (External to Library)
- **Purpose**: Authenticate with PDS to store/retrieve certificates
- **Generated by**: Your application using AT Protocol's `AtpAgent`
- **Used for**: Certificate management via `ATSMSClient`

### 2. AT-SMS API JWTs (Internal to Library)
- **Purpose**: Authenticate with AT-SMS inbox service
- **Generated by**: Library's `generateJWT()` function
- **Signed with**: Client certificate's private key
- **Used for**: Message operations (list/get/delete/send via WebSocket/HTTP)

```typescript
import { generateJWT } from '@atsms/sms'

// AT-SMS library generates these internally
const token = await generateJWT(
  did,
  certSerial,
  email,
  clientCert.privateKey  // CryptoKey from certificate
)

// Token contains: { did, certSerial, email, exp }
// Valid for 1 hour by default
```

## API Reference

### Core Types

All AT-SMS types use the `ATSMS` prefix:

```typescript
// Message types
ATSMSMessagePayload        // Decrypted message content
ATSMSDecryptedMessage      // Message with decrypted payload
ATSMSTransportMessage      // Encrypted message from transport
ATSMSMessageMetadata       // Message metadata (without content)

// Send types
ATSMSSendRecipient         // Recipient with endpoints array
ATSMSSendMessageResponse   // Send operation results

// Transport types
ATSMSTransportLayerConfig  // Transport layer configuration
ATSMSListMessagesOptions   // Options for listing messages
ATSMSListMessagesResponse  // List messages response
ATSMSGetMessageResponse    // Get message response
ATSMSDeleteMessageResponse // Delete message response
ATSMSStatsResponse         // Inbox statistics response

// Config
ATSMSConfig                // API client configuration
ATSMSTransportReceipt      // Transport metadata
```

### Key Classes

#### `ATSMSStorageManager`
High-level message and conversation management.

```typescript
class ATSMSStorageManager {
  // Certificate management
  generateAndStoreCertificates(email: string): Promise<CertificatePair>

  // Conversations
  startConversation(recipientDids: string[], senderCert: ClientCertificate): Promise<string>
  listConversations(): Promise<Conversation[]>
  getConversation(convoId: string): Promise<Conversation>

  // Messages
  sendMessage(convoId: string, text: string, senderCert: ATSMSEndpointCertificate): Promise<void>
  getConversationMessages(convoId: string): Promise<LocalMessage[]>

  // Sync
  syncMessages(): Promise<void>

  // Event Observables (for reactive UI updates)
  get messageAdded$(): Observable<LocalMessage>  // Full message with content included
  get conversationUpdated$(): Observable<string>
  get syncCompleted$(): Observable<void>
}
```

#### `ATSMSClient`
AT Protocol integration for certificate management.

```typescript
class ATSMSClient {
  constructor(agent: AtpAgent)

  // Certificate operations (interact with PDS)
  storeCertificate(cert: Certificate, type: 'root' | 'endpoint'): Promise<void>
  getCertificates(did: string): Promise<CertificateData>
  listCertificates(did: string): Promise<string[]>
}
```

#### `ATSMSTransportLayer`
Unified transport with WebSocket/HTTP fallback.

```typescript
class ATSMSTransportLayer {
  listMessages(options?: ATSMSListMessagesOptions): Promise<ATSMSListMessagesResponse>
  getMessage(messageId: string): Promise<ATSMSTransportMessage>
  deleteMessage(messageId: string): Promise<void>
  getStats(): Promise<ATSMSStatsResponse>
  sendMessage(recipients: ATSMSSendRecipient[], encryptedContent: string): Promise<ATSMSSendMessageResponse>
}
```

### Cryptographic Functions

```typescript
import {
  encryptMessage,
  signMessage,
  decryptAndVerifyMessageSignature
} from '@atsms/sms'

// Sign message
const signedContent = await signMessage(
  Buffer.from('message content'),
  senderCert.certificatePEM,
  senderCert.privateKey
)

// Encrypt for multiple recipients
const encryptedContent = await encryptMessage(
  signedContent,
  recipientCerts.map(c => c.certificatePEM)
)

// Decrypt and verify
const decrypted = await decryptAndVerifyMessageSignature(
  encryptedContent,
  recipientCert.certificatePEM,
  recipientCert.privateKey,
  senderRootCert.certificatePEM
)
```

### Message Format

```typescript
interface ATSMSMessagePayload {
  version: '1.0'
  contentType: string    // MIME type (e.g., "atsms/text")
  id: string             // Unique message ID
  content: string        // JSON-serialized content
  senderId: string       // Sender DID
  recipientIds: string[] // Recipient DIDs
  convoId: string        // Conversation ID
  createdAt: string      // ISO timestamp
}

// For "atsms/text" messages, content is JSON like:
interface ATSMSTextContent {
  text: string
  facets?: ATProtoFacet[]  // Optional rich text annotations
}

// Example content value: '{"text":"Hello world!"}'
```

## Browser vs Node.js

The library works in both environments with automatic platform detection:

```typescript
// Browser: Uses native WebCrypto
import { encryptMessage } from '@atsms/sms'

// Node.js: Uses @peculiar/webcrypto polyfill
import { setCryptoProvider } from '@atsms/sms'
import { Crypto } from '@peculiar/webcrypto'

// Set crypto provider for Node.js (required before crypto operations)
setCryptoProvider(new Crypto())
```

## Event Handling

The storage manager provides Observable accessors for reactive UI updates. You can subscribe to events and filter by content type using RxJS operators.

### Basic Event Subscription

```typescript
import { parseTextContent } from '@atsms/sms'

// Subscribe to all new messages (full message object included)
manager.messageAdded$.subscribe((message) => {
  console.log(`New message: ${message.id} with type ${message.contentType}`)

  // Access content directly without additional query
  if (message.contentType === 'atsms/text') {
    const textContent = parseTextContent(message.content)
    console.log(`Text: ${textContent.text}`)
  }
})

// Subscribe to conversation updates
manager.conversationUpdated$.subscribe((convoId) => {
  console.log(`Conversation ${convoId} updated`)
})

// Subscribe to sync completion
manager.syncCompleted$.subscribe(() => {
  console.log('Sync completed!')
})
```

### Filtering by Content Type

```typescript
import { filter } from 'rxjs/operators'
import { parseTextContent } from '@atsms/sms'

// Only handle text messages
manager.messageAdded$
  .pipe(filter(message => message.contentType === 'atsms/text'))
  .subscribe((message) => {
    const textContent = parseTextContent(message.content)
    console.log('New text message:', textContent.text)
    showNotification(message.convoId, textContent.text)
  })

// Handle image messages separately
manager.messageAdded$
  .pipe(filter(message => message.contentType === 'atsms/image'))
  .subscribe((message) => {
    console.log('New image message received')
    preloadImage(message.id, message.content)
  })
```

### Advanced RxJS Usage

```typescript
import { filter, debounceTime, distinctUntilChanged } from 'rxjs/operators'
import { combineLatest } from 'rxjs'

// Debounce conversation updates to avoid UI flicker
manager.conversationUpdated$
  .pipe(
    debounceTime(100),
    distinctUntilChanged()
  )
  .subscribe(convoId => {
    refreshConversationInUI(convoId)
  })

// Combine multiple event streams
combineLatest([
  manager.messageAdded$,
  manager.syncCompleted$
]).subscribe(([messageEvent, _]) => {
  // Handle new message after sync
})
```

## Multi-Recipient Messaging

Messages are sent to multiple recipients (DIDs), each with multiple endpoints (devices):

```typescript
// Recipients grouped by DID
const recipients: ATSMSSendRecipient[] = [
  {
    did: 'did:plc:bob123',
    endpoints: [
      { certSerial: 'abc123', email: 'bob-laptop@example.com' },
      { certSerial: 'def456', email: 'bob-phone@example.com' }
    ]
  },
  {
    did: 'did:plc:carol456',
    endpoints: [
      { certSerial: 'xyz789', email: 'carol@example.com' }
    ]
  }
]

// Send via transport (WebSocket or HTTP)
const response = await transport.sendMessage(recipients, encryptedContent)

// Check results
response.results.forEach(result => {
  console.log(`${result.email}: ${result.status}`)
  if (result.error) console.error(result.error)
})
```

## Requirements

- **Runtime**: Node.js 18+ or Bun
- **AT Protocol**: Bluesky account with app password
- **Certificates**: Generated by the library (X.509 with SAN extensions)
- **AT-SMS Service**: Access to AT-SMS inbox service endpoint

## Security Considerations

- ✅ Private keys stored locally only (never transmitted)
- ✅ End-to-end encryption using S/MIME (PKCS#7)
- ✅ RSA-OAEP for key encryption, AES-256-CBC for content
- ✅ Certificate chain validation for message authenticity
- ✅ JWT tokens expire after 1 hour (configurable)
- ✅ Email in certificate SAN required for message routing

## Development

```bash
# Install dependencies
bun install

# Build library
bun run build

# Run tests
bun test

# Local npm link
npm link
```

## TypeScript Configuration

The library is fully typed. Import types as needed:

```typescript
import type {
  ATSMSMessagePayload,
  ATSMSDecryptedMessage,
  ATSMSSendRecipient,
  ATSMSListMessagesResponse
} from '@atsms/sms'
```

## License

MIT License - see LICENSE file for details.

## Links

- **GitHub**: https://github.com/atsms/at-sms
- **Issues**: https://github.com/atsms/at-sms/issues
- **AT Protocol**: https://atproto.com
- **Bluesky**: https://bsky.app

## Related Projects

- [AT Protocol SDK](https://github.com/bluesky-social/atproto) - Official AT Protocol SDK
- [Bluesky](https://bsky.app) - Decentralized social network
