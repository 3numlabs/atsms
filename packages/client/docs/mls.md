# Plan: Dual-Protocol Support (S/MIME + MLS)

## Problem Statement

ATSMS currently requires X.509 certificates stored in a PDS for encryption. We want to:
1. Support users without a PDS
2. Preserve S/MIME for legacy infrastructure
3. Add modern encryption with forward secrecy

**Key Finding:** S/MIME fundamentally requires X.509 certificates. There's no way around this.

**Solution:** Add MLS (RFC 9420) as a second encryption protocol. MLS uses "basic" credentials (just DIDs) and doesn't require certificates.

---

## Approach: S/MIME + MLS Dual Protocol

| Feature | S/MIME (existing) | MLS (new) |
|---------|-------------------|-----------|
| X.509 Required | **Yes** | **No** |
| Forward Secrecy | No | Yes |
| Post-Compromise Security | No | Yes |
| PDS Required | Yes | No |
| State Model | Stateless | Stateful |
| Standard | PKCS#7 | RFC 9420 |

**Protocol Selection:**
- PDS users with X.509 certs → S/MIME
- PDS-less users with MLS key packages → MLS
- Protocol locked per conversation (no mixing)

---

## Implementation Plan: Encryption Protocol Abstraction + MLS

### Architecture Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                    APPLICATION LAYER                             │
│  (atsms-chat.ts, storage/manager.ts)                            │
└────────────────────────┬────────────────────────────────────────┘
                         │
┌────────────────────────▼────────────────────────────────────────┐
│              ENCRYPTION PROTOCOL ABSTRACTION                     │
│  interface EncryptionProtocol {                                 │
│    encrypt(payload, sender, recipients): EncryptedMessage       │
│    decrypt(encrypted, recipient): DecryptedMessage              │
│  }                                                              │
│  ├─ SMIMEProtocol (existing, refactored)                       │
│  └─ MLSProtocol (new, using ts-mls)                            │
└────────────────────────┬────────────────────────────────────────┘
                         │
┌────────────────────────▼────────────────────────────────────────┐
│              KEY MATERIAL ABSTRACTION                            │
│  interface KeyMaterial {                                        │
│    type: 'x509' | 'mls-keypackage'                             │
│    did: string                                                  │
│    // ... protocol-specific fields                              │
│  }                                                              │
└─────────────────────────────────────────────────────────────────┘
```

### Phase 1: Protocol Abstraction Layer

**Goal:** Refactor existing code to use an `EncryptionProtocol` interface, with S/MIME as the first implementation.

**New Files:**
```
src/lib/encryption/
├── protocol.ts          # EncryptionProtocol interface
├── smime-protocol.ts    # SMIMEProtocol implementation (from crypto.ts)
├── mls-protocol.ts      # MLSProtocol implementation (Phase 2)
└── index.ts             # Exports + protocol selection logic
```

**Key Interface:**
```typescript
// src/lib/encryption/protocol.ts
export interface EncryptionProtocol {
  readonly protocolId: 'smime' | 'mls'

  // Encrypt for multiple recipients
  encrypt(
    payload: ATSMSMessagePayload,
    senderKey: SenderKeyMaterial,
    recipientKeys: RecipientKeyMaterial[]
  ): Promise<EncryptedMessage>

  // Decrypt and verify
  decrypt(
    encrypted: EncryptedMessage,
    recipientKey: RecipientKeyMaterial
  ): Promise<DecryptedMessage>
}

export interface EncryptedMessage {
  protocolId: 'smime' | 'mls'
  data: Uint8Array
  // MLS-specific: group state updates
  mlsCommit?: Uint8Array
  mlsWelcome?: Uint8Array
}
```

**Modified Files:**
- `src/lib/storage/manager.ts` - Use injected protocol instead of direct crypto imports
- `src/lib/messages.ts` - Use protocol abstraction
- `src/lib/types.ts` - Add protocol-related types

### Phase 2: MLS Integration

**Goal:** Add MLS as a second encryption protocol using ts-mls.

**New Dependencies:**
```json
{
  "dependencies": {
    "ts-mls": "^0.x.x",
    "@hpke/core": "^1.x.x"
  }
}
```

**MLS Key Package Storage:**

For PDS users:
```typescript
// Collection: at.atsms.mls
// Record key: key package hash
{
  "$type": "at.atsms.mls",
  "keyPackage": "<base64-encoded-mls-keypackage>",
  "cipherSuite": "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519",
  "createdAt": "2024-01-01T00:00:00Z"
}
```

For PDS-less users:
- Stored at `{serviceEndpoint}/mls/{did}/keypackage`
- Same format, served via HTTP

**MLS State Management:**

MLS is stateful - group state evolves with each message. Storage approach:

```typescript
// New table in SQLite
CREATE TABLE mls_groups (
  groupId TEXT PRIMARY KEY,
  convoId TEXT NOT NULL,
  state BLOB NOT NULL,           -- Serialized MLS group state
  epoch INTEGER NOT NULL,        -- Current epoch
  updatedAt INTEGER NOT NULL,
  FOREIGN KEY (convoId) REFERENCES conversations(id)
);
```

**MLSProtocol Implementation:**
```typescript
// src/lib/encryption/mls-protocol.ts
export class MLSProtocol implements EncryptionProtocol {
  readonly protocolId = 'mls'

  constructor(
    private cipherSuite: CipherSuite,
    private stateStore: MLSStateStore
  ) {}

  async encrypt(payload, senderKey, recipientKeys): Promise<EncryptedMessage> {
    // 1. Get or create MLS group for this conversation
    // 2. Add recipients if not already in group
    // 3. Encrypt message with group key
    // 4. Return encrypted message + any welcome messages for new recipients
  }

  async decrypt(encrypted, recipientKey): Promise<DecryptedMessage> {
    // 1. Process any welcome message (if new to group)
    // 2. Decrypt message with group key
    // 3. Update local group state
  }
}
```

### Phase 3: Protocol Discovery & Selection

**DID Document Service Extension:**
```json
{
  "service": [{
    "id": "#atsms",
    "type": "ATSMSMessaging",
    "serviceEndpoint": "https://inbox.atsms.example",
    "encryptionProtocols": ["mls", "smime"]  // Preference order
  }]
}
```

**Protocol Selection Logic:**
```typescript
// src/lib/encryption/index.ts
export async function selectProtocol(
  senderProtocols: string[],
  recipientDid: string
): Promise<EncryptionProtocol> {
  // 1. Resolve recipient's DID document
  // 2. Find #atsms service
  // 3. Get recipient's supported protocols
  // 4. Find best common protocol (prefer MLS if both support)
  // 5. Return appropriate protocol instance
}
```

### Files to Create/Modify

**New Files:**
1. `src/lib/encryption/protocol.ts` - Interface definitions
2. `src/lib/encryption/smime-protocol.ts` - S/MIME implementation
3. `src/lib/encryption/mls-protocol.ts` - MLS implementation
4. `src/lib/encryption/mls-state-store.ts` - MLS state persistence
5. `src/lib/encryption/index.ts` - Protocol selection
6. `src/lib/did-resolver.ts` - DID document resolution

**Modified Files:**
1. `src/lib/storage/manager.ts` - Use protocol abstraction
2. `src/lib/storage/sqlite-adapter.ts` - Add MLS state tables
3. `src/lib/messages.ts` - Use protocol abstraction
4. `src/lib/types.ts` - Add protocol types
5. `src/lib/atsms-client.ts` - Add key package storage/retrieval

**Server-Side (separate repo):**
1. Add `/mls/{did}/keypackage` endpoint
2. Store/serve MLS key packages for PDS-less users

---

## Migration Strategy

1. **Phase 1** (Protocol Abstraction):
   - No user-facing changes
   - All existing messages continue to use S/MIME
   - Prepares codebase for MLS addition

2. **Phase 2** (MLS Addition):
   - MLS available for new conversations
   - Existing S/MIME conversations remain S/MIME
   - Users can opt-in to MLS

3. **Phase 3** (PDS-less Support):
   - PDS-less users register with MLS key packages
   - Can receive messages from any sender
   - S/MIME remains available for PDS users

---

## Design Decisions (Confirmed)

1. **Protocol per Conversation**: Lock to one protocol per conversation
   - Simpler state management
   - Cleaner security model
   - Protocol stored in `conversations` table

2. **Default Cipher Suite**: `MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519`
   - X25519 for key agreement
   - Ed25519 for signatures
   - AES-128-GCM for encryption
   - Fast, modern, widely supported

3. **MLS State**: Device-specific (no sync)
   - Each device has its own group membership
   - Similar to Signal's model
   - Simpler implementation
   - No PDS dependency for state

4. **Key Package Rotation**: Periodic (e.g., weekly or on-demand)
   - Old key packages remain valid until explicitly revoked
   - New conversations use latest key package

---

## References

- [RFC 9420 - MLS Protocol](https://datatracker.ietf.org/doc/rfc9420/)
- [ts-mls - TypeScript MLS Implementation](https://github.com/LukaJCB/ts-mls)
- [Signal Protocol X3DH](https://signal.org/docs/specifications/x3dh/)
