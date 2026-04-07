# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

AT-SMS (AT Protocol Secure Messaging Service) is a TypeScript library for end-to-end encrypted messaging on top of the AT Protocol (Bluesky). The library supports both Node.js and browser environments. The primary purpose of src/client/atsms-chat.ts and src/client/atsms.ts is to test the library via a command line utility, neither intended to be production client.

**Key technologies:**
- AT Protocol for decentralized identity (DIDs) and certificate storage in the PDS
- X.509 self-signed P-256 ECDSA certificates for per-device endpoint identity and key management
- S/MIME (PKCS#7) for message encryption/signing as a base level of encryption support
- WebCrypto API for cross-platform cryptography
- ECDSA with SHA-256 for certificate signing, ECDH for key agreement

## Common Commands

### Development
```bash
# Install dependencies
bun install

# Build library (browser + type definitions)
bun run build

# Build only the library bundle
bun run build-lib

# Build only type definitions
bun run build-types
```

### Testing
```bash
# Run all tests
bun test

# Run tests in watch mode
bun test:watch

# Run specific test file
bun test src/tests/certificates.test.ts
```

### Code Quality
```bash
# Lint code
bun run lint

# Lint and auto-fix
bun run lint:fix

# Format code
bun run format

# Check formatting
bun run format:check
```

### CLI Tools

The project includes three CLI tools for different purposes:

```bash
# 1. atsms.ts - Stateless testing & artifact generation
bun src/client/atsms.ts init --handle alice.bsky.social --endpoint-cert ./client.pem --endpoint-key ./client-key.pem --email-domain atsms.email
bun src/client/atsms.ts send --handle alice.bsky.social --sender-cert ./client.pem --sender-key ./client-key.pem --recipient bob.bsky.social --message "Hello"
bun src/client/atsms.ts send-email --handle alice.bsky.social --recipient bob.bsky.social --subject "Hello" --message "Hi Bob"
bun src/client/atsms.ts receive --handle alice.bsky.social --endpoint-cert ./client.pem --endpoint-key ./client-key.pem --type atsms
bun src/client/atsms.ts list --handle alice.bsky.social --endpoint-cert ./client.pem --endpoint-key ./client-key.pem --type all

# 2. api-client.ts - Lightweight API testing with cached credentials
bun src/client/api-client.ts list alice.bsky.social
bun src/client/api-client.ts watch alice.bsky.social  # WebSocket real-time monitoring
bun src/client/api-client.ts stats alice.bsky.social
bun src/client/api-client.ts send alice.bsky.social ./message.p7m did:plc:abc:4d18ac7f:user@example.com  # Send via WebSocket

# 3. atsms-chat.ts - Interactive chat with persistent storage
bun src/client/atsms-chat.ts alice.bsky.social
bun run chat
```

## Architecture

### Core Components

**Certificate System** (`src/lib/certificates/`):
- `ATSMSEndpointCertificate`: Self-signed P-256 ECDSA per-device endpoint identity, used for message encryption (ECDH) and API authentication (JWT signing)
  - Subject and Issuer: `CN=<did>` (self-signed)
  - Signature: ECDSA with SHA-256
  - Key Usage: digitalSignature, keyAgreement (for ECDH)
  - Extended Key Usage: serverAuth, clientAuth (future TLS), emailProtection (S/MIME)
  - Extensions: BasicConstraints (CA=false), SubjectAltName (DNS, URI, Email)
- `ATSMSCertificate`: Base abstract class with X.509 operations
  - `.did` getter: Extracts DID from Subject Alternative Name (SAN) URI field
  - `.email` getter: Extracts email from SAN extension (RFC822 name)
  - `.serialNumber` getter: Returns certificate serial number
- All certificates stored in AT Protocol records (`at.atsms.x509` collection)
- Private keys ONLY stored locally, never in PDS
- **Method signature**: `ATSMSEndpointCertificate.generate(did, domain, emailDomain, validityDays?)` - creates self-signed P-256 certificate
- **Factory functions**: `generateEndpointCertificate(did, domain, emailDomain, validityDays?)`, `loadEndpointCertificate(certPEM)`, `loadEndpointCertificateWithKey(certPEM, keyPEM)`

**Cryptographic Operations** (`src/lib/crypto.ts`, `src/lib/crypto-oaep.ts`):
- `encryptMessage()`: CMS EnvelopedData encryption using ECDH (KeyAgreeRecipientInfo) for multiple recipients
- `signMessage()`: PKCS#7 signed-data with P-256 ECDSA
- `decryptAndVerifyMessageSignature()`: Decrypt, verify PKCS#7 signature, and extract signer cert. Throws if signature is invalid.
- Uses ECDH with P-256 for key agreement, AES-256-CBC for content encryption
- Custom crypto provider system for browser/Node compatibility

**Storage System** (`src/lib/storage/`):
- `ATSMSStorageManager`: Business logic for message storage, sync, and conversation management
- `SQLiteAdapter`: Platform-specific SQLite implementation (uses bun:sqlite)
- `StorageAdapter` interface: Can be implemented for other storage backends
- Handles message decryption, certificate caching, and conversation threading

**API Client** (`src/lib/atsms-api.ts`):
- `ATSMSApiClient`: REST API client for AT-SMS inbox service
- Handles message transport, listing, and retrieval
- Supports three message types: `atsms`, `atsms-email`, `email`
- `sendMessage(did, encryptedContent, messageType?)`: Send atsms or atsms-email via HTTP
- `sendEmail({did, subject, textBody, ...})`: Send plain email via HTTP
- `listMessages(did, certSerial, after?, limit?, messageType?)`: List with type filter
- AT-SMS API JWT authentication (see "JWT Authentication" section)

**WebSocket Client** (`src/lib/websocket-client.ts`):
- Real-time message notifications
- AT-SMS API JWT authentication: post-connection auth message (browser compatible)
- Auto-reconnection with exponential backoff
- Request/response pattern for API operations (list, get, delete, stats, send)
- WebSocket send command for multi-recipient message delivery

**Message Handling** (`src/lib/messages.ts`):
- `createMessagePayload()`: Create structured message payload with `content` (JSON string) and `contentType` (MIME type)
- `createTextContent()`: Helper to create JSON content for "atsms/text" messages with optional facets
- `parseTextContent()`: Helper to parse JSON content from "atsms/text" messages
- `prepareMessageForSending()`: Sign + encrypt pipeline
- `extractP7MFromEmail()`: Parse S/MIME MIME messages

### Message Types

The inbox service supports three message types, all stored in per-certificate inboxes:

- **`atsms`** — AT-SMS P7M encrypted payloads (opaque blob). Default type.
- **`atsms-email`** — S/MIME encrypted email (enveloped-data, opaque blob — metadata inside encrypted payload)
- **`email`** — Normal parsed email with subject, body, attachments, and optional S/MIME verification

Types defined as `ATSMSMessageType = "atsms" | "atsms-email" | "email"` in `types.ts`.

### Data Flow

1. **Sending an atsms message:**
   - Create text content with `createTextContent(text, facets?)` → Create message payload with `contentType: "atsms/text"` and JSON `content`
   - Sign with sender cert (ECDSA) → Encrypt for recipients (ECDH) → Send via HTTP POST /send-message or WebSocket
   - Message payload stored as JSON, signed and encrypted as PKCS#7
   - Multi-recipient send in single call - server handles per-device delivery
   - Each recipient's devices receive via DO-to-DO (same service) or SMTP (external service)

2. **Sending an email:**
   - No encryption needed — send plain email via `sendEmail()` or WebSocket send with `messageType: "email"`
   - Server delivers to all active certificate inboxes for the recipient DID

3. **Receiving messages:**
   - API notification → Fetch message → For atsms/atsms-email: decrypt with endpoint cert → Parse content → Store in local DB
   - For email type: already decrypted by server, read fields directly
   - Messages stored with `content` (JSON string) and `contentType` (MIME type)
   - Use `parseTextContent(message.content)` to extract text from "atsms/text" messages
   - WebSocket used to inform the client apps of new inbound messages

4. **Certificate lookup for peers:**
   - DID → PLC directory → PDS URL → List records in `at.atsms.x509` → Parse certificates
   - Results cached in memory by `ATSMSStorageManager`

### Build Output

- `dist/index.js`: Node.js bundle
- `dist/index.browser.js`: Browser bundle
- `dist/index.native.js`: React Native bundle
- `dist/index.d.ts`: TypeScript type definitions
- Only `src/lib/**/*` files are included in the build (excludes `src/client`, `src/tests`)

### Command Line Tools for Testing AT-SMS

The project includes three CLI tools in `src/client/`, each serving different testing needs:

**1. atsms.ts** - Stateless Testing & Artifact Generation (`ATSMSCLITool`):
- **Purpose:** Comprehensive end-to-end testing tool with no persistent state
- **Architecture:** All file I/O controlled via explicit CLI arguments (no `.atsms` directory)
- **Commands:** init, send, send-email, receive, list, download, create-p7m, delete, stats
- **Use cases:**
  - Testing library functionality end-to-end
  - Generating certificates and P7M artifacts for testing
  - Sending plain email messages
  - CI/CD pipelines (stateless, reproducible)
  - When you need explicit control over file locations
- **Message type filter:** `list` and `receive` commands accept `--type atsms|atsms-email|email|all`
- **Authentication:** Uses both PDS JWTs (from AtpAgent) and AT-SMS API JWTs (generated on-demand from certificate files, not cached) - see "JWT Authentication" section
- **Dependencies:** Full AT Protocol integration (ATSMSClient, AtpAgent)

**2. api-client.ts** - Lightweight API Testing:
- **Purpose:** Simple Node.js tool for testing AT-SMS API endpoints
- **Architecture:** Uses cached credentials from `~/.atsms` directory
- **Commands:** list, get, delete, stats, watch (WebSocket), health
- **Use cases:**
  - Quick API testing after using chat client
  - Real-time WebSocket message monitoring (`watch` command)
  - Debugging API endpoints
  - When you already have cached credentials
- **Authentication:** AT-SMS API JWTs only (generated from cached certificates in `~/.atsms/messages.db`) - does NOT interact with PDS - see "JWT Authentication" section
- **Dependencies:** Minimal (Node.js `https`, `ws` package)
- **Data sources:**
  - `~/.atsms/auth-cache.json` - DIDs and authentication data
  - `~/.atsms/messages.db` - SQLite database with certificates

**3. atsms-chat.ts** - Interactive Chat Interface:
- **Purpose:** Full-featured interactive chat application
- **Architecture:** Persistent storage in `~/.atsms/<handle>/` directory
- **Features:** Conversations, contacts, real-time messaging, certificate management
- **Use cases:**
  - Interactive messaging and testing
  - End-user experience testing
  - Managing conversations and contacts
- **Authentication:** Uses both PDS JWTs (for certificate management via ATSMSClient) and AT-SMS API JWTs (handled internally by ATSMSStorageManager) - see "JWT Authentication" section
- **Storage:** Complete state in `~/.atsms/` directory

**Library Components (not CLI tools):**

**ATSMSClient** (`src/lib/atsms-client.ts`):
- Library class for AT Protocol operations (used by CLI tools)
- Handles certificate storage/retrieval from Personal Data Servers (PDS)
- Resolves DIDs to PDS URLs via PLC directory
- Does NOT handle encryption/decryption (that's in `crypto.ts`)

### Key Concepts

- **DID**: Decentralized identifier (e.g., `did:plc:xyz123`)
- **Handle**: Human-readable identifier (e.g., `alice.bsky.social`)
- **PDS**: Personal Data Server - each user's AT Protocol data store
- **Certificate Serial**: Unique identifier for client certificates, used as record key in PDS
- **Transport vs Payload**: Transport is the encrypted envelope; payload is the decrypted content
- **Conversation ID (convoId)**: Groups messages into threads. For 1:1 DMs, deterministically generated from sorted DID pair.
- **Message Type**: `atsms` (encrypted P7M), `atsms-email` (S/MIME encrypted email), `email` (plain email)

### Message Content Structure

AT-SMS uses a structured message format with separate `content` and `contentType` fields to support multiple content types while maintaining a consistent encryption and storage layer.

#### Message Fields

```typescript
interface ATSMSMessagePayload {
  version: '1.0'
  id: string              // Unique message ID
  contentType: string     // MIME type (e.g., "atsms/text")
  content: string         // JSON-serialized content
  senderId: string        // Sender DID
  recipientIds: string[]  // Recipient DIDs
  convoId: string         // Conversation ID
  createdAt: string       // ISO timestamp
}
```

#### Content Types

**1. "atsms/text" - Text Messages with Rich Formatting**

For text messages, the `content` field contains a JSON-serialized `ATSMSTextContent` object:

```typescript
interface ATSMSTextContent {
  text: string            // The actual message text
  facets?: ATProtoFacet[] // Optional rich text annotations (mentions, links, hashtags)
}
```

Example `content` value: `'{"text":"Hello @alice.bsky.social!","facets":[...]}'`

**Helper Functions:**
- `createTextContent(text: string, facets?: ATProtoFacet[]): string` - Creates JSON content string
- `parseTextContent(content: string): ATSMSTextContent` - Parses JSON content string

**2. Future Content Types**

The architecture supports extending to other content types in the future:
- "atsms/image" - Image messages with metadata
- "atsms/file" - File attachments
- "atsms/location" - Location sharing
- Custom application-specific types

Each content type should define its own JSON schema for the `content` field.

#### Storage Layer

Messages are stored in the local SQLite database with decrypted `content` and `contentType`:

```sql
CREATE TABLE messages (
  id TEXT PRIMARY KEY,
  convoId TEXT NOT NULL,
  senderId TEXT NOT NULL,
  recipientIds TEXT NOT NULL,
  content TEXT NOT NULL,      -- JSON-serialized content
  contentType TEXT NOT NULL,  -- MIME type
  createdAt INTEGER NOT NULL,
  isInvitation INTEGER DEFAULT 0,
  FOREIGN KEY (convoId) REFERENCES conversations(id)
);
```

#### Key Design Principles

1. **Content is always JSON-serialized**: Even simple text messages are stored as JSON objects
2. **ContentType determines parsing**: Applications check `contentType` before parsing `content`
3. **Extensibility**: New content types can be added without changing core library
4. **Storage agnostic**: Content stored as opaque JSON strings in database
5. **Type safety**: Helper functions enforce correct structure for each content type

### JWT Authentication

AT-SMS uses **two distinct JWT types** for different authentication purposes:

#### 1. AT Protocol PDS Authentication (Library External)
- **Purpose**: Authenticate with AT Protocol Personal Data Servers (PDS) to store/retrieve certificates
- **Used by**: `ATSMSClient` class when interacting with PDS
- **Generated by**: AT Protocol's `AtpAgent` using handle + app password
- **Token format**: Standard AT Protocol JWT (obtained via `com.atproto.server.createSession`)
- **Scope**: PDS operations only (certificate CRUD in `at.atsms.x509` collection)
- **Library note**: The AT-SMS library itself does NOT generate these JWTs - the calling application must provide an authenticated `AtpAgent`

#### 2. AT-SMS API Authentication (Library Internal)
- **Purpose**: Authenticate with AT-SMS API endpoints (inbox service) for message operations
- **Used by**: `ATSMSApiClient` and `ATSMSWebSocketClient`
- **Generated by**: `generateJWT()` in `src/lib/jwt-auth.ts`
- **Algorithm**: ES256 (P-256 ECDSA)
- **Token format**: Custom JWT signed with client certificate's private key
- **Scope**: AT-SMS API operations (list/get/delete messages, WebSocket connections, send messages)
- **Library note**: The AT-SMS library DOES generate these JWTs internally using client certificates

**JWT Generation in `jwt-auth.ts`:**
```typescript
// Creates JWT for AT-SMS API authentication
// Signed with ES256 (P-256 ECDSA) using certificate's private key
generateJWT(privateKeyPEM: string, endpointCertSerialNumber: string, did: string): Promise<string>
```

**JWT Claims:**
- `sub`: `at://[did]/at.atsms.x509/[serialNumber]` (AT Protocol URI)
- `iss`: DID
- `aud`: "atsms-api"
- `kid`: certificate serial number
- Expiration: 1 hour

**Usage in CLI Tools:**

- **atsms.ts** (stateless): Generates AT-SMS JWTs on-demand from certificate files (not cached)
- **api-client.ts** (lightweight): Generates AT-SMS JWTs from cached certificates in `~/.atsms/messages.db`
- **atsms-chat.ts** (interactive): Uses `ATSMSStorageManager` which internally handles AT-SMS JWT generation via transport layer

**Important Distinctions:**
- PDS JWTs are **external** to AT-SMS library - provided by application via `AtpAgent`
- AT-SMS API JWTs are **internal** to AT-SMS library - generated from client certificates
- Never confuse the two - they authenticate with completely different services
- Client certificates are used BOTH for message encryption AND AT-SMS API authentication (JWT signing)

## Testing Notes

- Tests use in-memory SQLite databases
- Test certificates generated in `src/tests/test-certificates.ts` using `generateTestEndpointCertificate(did, domain, emailDomain?)`
- Integration tests require actual AT Protocol credentials (set via env vars or skip)
- Sequential import test (`sequential-import.test.ts`) ensures proper module loading order

### Running Integration Tests

Integration tests connect to real AT Protocol and AT-SMS API servers. Set these environment variables:

```bash
export ATSMS_TEST_HANDLE=your.handle.bsky.social
export ATSMS_TEST_PASSWORD='your-app-password'
export ATSMS_API_URL=https://inbox.atsms.at

# Run specific integration test
bun test src/tests/websocket-client-integration.test.ts
bun test src/tests/atsms-client-integration.test.ts
```

**WebSocket Integration Test** (`websocket-client-integration.test.ts`):
- Tests real-time WebSocket connections to AT-SMS server
- Verifies AT-SMS API JWT authentication (ES256)
- Tests ping/pong keepalive mechanism
- Validates message broadcast reception
- Checks reconnection logic with exponential backoff
- Always generates fresh certificates with private keys (required for AT-SMS API JWT signing)

## Important Patterns

- **Crypto provider must be set early**: Call `setCryptoProvider()` before any crypto operations in browser environments
- **Certificate validation**: Endpoint certificates are self-signed; verify signature using the certificate's own public key
- **Signature verification**: `decryptAndVerifyMessageSignature()` verifies the PKCS#7 signature against the embedded signer certificate and throws if invalid. Note: this confirms the signature is mathematically valid but does NOT cross-check the certificate against the signer's PDS record — callers that need sender identity confirmation should compare fingerprints against `at.atsms.x509`.
- **Error handling**: Certificate operations return `null` for missing/invalid certs (not exceptions)
- **Platform detection**: Use `typeof window !== 'undefined'` for browser detection
- **Private key security**: Never serialize or transmit private keys; keep them in local storage only
- **Initial release**: This library has never been published and is often refactored to improve the data patterns. Never need backward compatibility with each refactor. (This line will be removed once we publish version 0.0.1)
- **Email in certificates**: All client certificates MUST include an email in the Subject Alternative Name (SAN) extension. The email is deterministically computed from the DID and email domain (e.g., `plc.[plc-id]@[emailDomain]`).

## Code Style Requirements

- **NO inline imports**: NEVER use `import()` statements inside function bodies. All imports must be at the top of the file.
  - If there is a compelling reason to break this rule (e.g., dynamic platform-specific imports), document it clearly at the top of the file with a comment explaining why.
  - Exception: CLI tools may use dynamic imports for optional dependencies, but this must be noted.
- **Type naming**: All AT-SMS specific types must use the `ATSMS` prefix for consistency and namespace clarity:
  - Certificate types: `ATSMSCertificate`, `ATSMSEndpointCertificate`
  - WebSocket types: `ATSMSWebSocketMessage`, `ATSMSWebSocketClientConfig`
  - Storage types: `ATSMSStorageManagerConfig`
  - Message types: All types in `types.ts` use `ATSMS` prefix
- **No duplicate types**: Types should be defined once in `src/lib/types.ts` and imported where needed
- **Single algorithm**: P-256 ECDSA only. No RSA support. No algorithm detection or type guards needed.
