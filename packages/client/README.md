# @atsms/sms

AT SMS (AT Protocol Secure Messaging System) - A TypeScript library for end-to-end encrypted messaging using AT Protocol.

## Features

- 🔐 **End-to-end encryption** using S/MIME standards
- 🆔 **Decentralized identity** via AT Protocol
- 🔑 **X.509 certificate management** for cryptographic operations

## Installation

```bash
bun add @atsms/sms
# or these *may* work
npm install @atsms/sms
# or
yarn add @atsms/sms
```
Has only been tested with bun.

## Quick Start

```typescript
import { ATSMSClient, ATSMSRootCertificate, ATSMSEndpointCertificate } from '@atsms/sms'
import { AtpAgent } from '@atproto/api'

// Initialize AT Protocol agent
const agent = new AtpAgent({
  service: 'https://bsky.social'
})

// Login to AT Protocol
await agent.login({
  identifier: 'your-handle.bsky.social',
  password: 'your-app-password'
})

// Create AT-SMS client
const client = new ATSMSClient(agent, agent.session!.did)

// Generate certificates (first time only)
const rootCert = await ATSMSRootCertificate.generate(
  agent.session!.did,
  'bsky.social',  // domain
  365  // valid for 1 year
)
await client.storeRootCertificate(rootCert)

// Generate endpoint certificate signed by root
// Note: did and domain are extracted from root cert automatically
const endpointCert = await rootCert.generateSignedEndpointCertificate(
  'user@example.com',  // Email address (validated)
  365  // validity days
)
await client.storeEndpointCertificate(endpointCert)

// Send encrypted message to a recipient
// First, get recipient's certificates
const recipientDid = 'did:plc:recipient123'
const { endpointCerts } = await client.getUserCertificates(recipientDid)
const recipientCert = endpointCerts[0]  // Use first available cert

// Encrypt and send
import { prepareMessageForSending } from '@atsms/sms'

const encrypted = await prepareMessageForSending(
  'Hello, secure world!',
  endpointCert,
  [recipientCert]
)

// Send via API (requires API client setup - see API documentation)
```

## Documentation

- [API Reference](./README-API.md) - Complete API documentation
- [NPM Package Guide](./README-NPM.md) - Package usage details
- [Browser Client Guide](./docs/BROWSER-CLIENT-GUIDE.md) - Building browser-based clients
- [IndexedDB Adapter](./docs/INDEXEDDB-ADAPTER.md) - Browser storage adapter reference
- [Architecture](./arch.md) - Technical architecture
- [Marketing Overview](./MARKETING-ARCH.md) - Non-technical overview

## CLI Tools

The package includes three command-line tools for different use cases:

### 1. **atsms.ts** - Stateless Testing & Artifact Generation

A comprehensive tool for end-to-end testing with explicit file paths (no persistent state).

```bash
# Generate certificates (no PDS publishing)
bun src/client/atsms.ts init --handle alice.bsky.social \
  --root-cert ./root.pem --root-key ./root-key.pem \
  --client-cert ./client.pem --client-key ./client-key.pem \
  --email alice@example.com

# Generate and publish to PDS
bun src/client/atsms.ts init --handle alice.bsky.social \
  --root-cert ./root.pem --root-key ./root-key.pem \
  --client-cert ./client.pem --client-key ./client-key.pem \
  --email alice@example.com --publish-to-pds

# Send encrypted message
bun src/client/atsms.ts send --handle alice.bsky.social \
  --sender-cert ./client.pem --sender-key ./client-key.pem \
  --recipient bob.bsky.social --message "Hello Bob!"

# Send with P7M artifact
bun src/client/atsms.ts send --handle alice.bsky.social \
  --sender-cert ./client.pem --sender-key ./client-key.pem \
  --recipient bob.bsky.social --message "Hello!" --save-p7m ./msg.p7m

# Receive and decrypt messages
bun src/client/atsms.ts receive --handle alice.bsky.social \
  --client-cert ./client.pem --client-key ./client-key.pem \
  --output-dir ./messages

# Create P7M file offline (testing)
bun src/client/atsms.ts create-p7m \
  --sender-cert ./alice-client.pem --sender-key ./alice-key.pem \
  --recipient-cert ./bob-client.pem --message "Test" --output ./test.p7m

# List, delete, stats
bun src/client/atsms.ts list --handle alice.bsky.social --client-cert ./client.pem --client-key ./client-key.pem
bun src/client/atsms.ts delete --handle alice.bsky.social --client-cert ./client.pem --client-key ./client-key.pem --message-id msg123
bun src/client/atsms.ts stats --handle alice.bsky.social --client-cert ./client.pem --client-key ./client-key.pem
```

**Use when:**
- Testing the library end-to-end
- Generating test certificates and artifacts
- CI/CD pipelines (stateless, reproducible)
- You need explicit control over file locations

### 2. **api-client.js** - Lightweight API Testing

Simple tool for testing AT-SMS API endpoints with cached credentials.

```bash
# List messages (uses cached credentials from chat client)
bun src/client/api-client.ts list alice.bsky.social

# Get specific message
bun src/client/api-client.ts get alice.bsky.social msg-123

# Delete message
bun src/client/api-client.ts delete alice.bsky.social msg-123

# Get inbox statistics
bun src/client/api-client.ts stats alice.bsky.social

# Real-time WebSocket monitoring
bun src/client/api-client.ts watch alice.bsky.social

# Check API health
bun src/client/api-client.ts health alice.bsky.social
```

**Use when:**
- Quick API testing after using chat client
- Real-time WebSocket message monitoring
- Debugging API endpoints
- You already have cached credentials in `~/.atsms`

**Note:** Reads certificates from `~/.atsms/messages.db` and DIDs from `~/.atsms/auth-cache.json`

### 3. **atsms-chat.ts** - Interactive Chat Interface

Full-featured chat application with persistent storage.

```bash
# Launch interactive chat
bun src/client/atsms-chat.ts alice.bsky.social

# Or use the npm script
bun run chat
```

**Use when:**
- Interactive messaging and testing
- You need persistent message storage
- Managing conversations and contacts
- End-user experience testing

**Storage:** Uses `~/.atsms/` directory for certificates, messages, and cache

## Browser Usage

```html
<script src="https://unpkg.com/@atsms/sms/dist/browser/index.js"></script>
<script>
  const { ATSMSClient } = window.ATSMS
  // Use the client
</script>
```

Or with ES modules:

```typescript
import { ATSMSClient } from '@atsms/sms'
```

## Core Components

### Certificate Management

```typescript
// Generate root certificate (one time)
const rootCert = await ATSMSRootCertificate.generate(
  did,
  domain,
  365  // valid for 1 year
)

// Generate endpoint certificate signed by root
// did and domain are automatically extracted from root certificate
const endpointCert = await rootCert.generateSignedEndpointCertificate(
  'user@example.com',  // Email address (validated - see below)
  365  // validity days
)

// For certificates loaded from PEM, you can optionally provide did/domain:
const endpointCertFromPEM = await rootCert.generateSignedEndpointCertificate(
  'user@example.com',
  365,
  did,     // optional - extracted from root cert if not provided
  domain   // optional - extracted from root cert if not provided
)

// Store in AT Protocol
await client.storeRootCertificate(rootCert)
await client.storeEndpointCertificate(endpointCert)
```

**Email Address Validation**: The `email` parameter in `generateSignedEndpointCertificate()` is validated to ensure it's a properly formatted email address. The validation checks:
- Must be a non-empty string
- Must contain exactly one `@` symbol
- Domain part (after `@`) must contain at least one `.` (e.g., `user@example.com`)

Invalid email addresses will throw an error: `Invalid email: must be a valid email address, got: <value>`

### Message Encryption

```typescript
import { encryptMessage, decryptAndVerifyMessageSignature } from '@atsms/sms'

// Encrypt
const encrypted = await encryptMessage(
  plaintext,
  senderCert,
  [recipientCert]
)

// Decrypt
const { content, verified } = await decryptAndVerifyMessageSignature(
  encryptedMessage,
  recipientCert,
  senderCert
)
```

## Testing

```bash
# Run all tests
bun test

# Run with watch mode
bun test:watch

# Lint code
bun run lint

# Format code
bun run format
```

## Development

```bash
# Clone repository
git clone https://github.com/atsms/at-sms.git
cd at-sms

# Install dependencies
bun install

# Build library
bun run build

# Run CLI chat locally
bun run chat
```

## Security

AT-SMS uses industry-standard cryptographic libraries:
- RSA-2048 or ECDSA (secp256k1) for key generation
- S/MIME (PKCS#7) for message format
- X.509 for certificate management
- SHA-256 for hashing

## License

MIT

## Contributing

Contributions are welcome! Please read our contributing guidelines and code of conduct.

## Support

- Issues: [GitHub Issues](https://github.com/atsms/at-sms/issues)
- Discussions: [GitHub Discussions](https://github.com/atsms/at-sms/discussions)

## Links

- [AT Protocol](https://atproto.com)
- [Bluesky](https://bsky.social)
- [Technical Architecture](./arch.md)