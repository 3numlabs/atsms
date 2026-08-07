# ATSMSStorageManager Architectural Refactor Proposal

## Executive Summary

This document proposes a major refactor of `ATSMSStorageManager` to separate initialization from user identity. The current design requires `did`, `handle`, and `certSerial` at construction time, which prevents the storage manager from being used before onboarding. The proposed design initializes the storage manager with infrastructure dependencies only, then adds user identity later via explicit APIs.

## Current Architecture Problems

### 1. Tight Coupling of Infrastructure and Identity

**Current constructor signature:**
```typescript
interface ATSMSStorageManagerConfig {
  did: string              // ❌ Required at construction
  handle: string           // ❌ Required at construction
  certSerial: string       // ❌ Required at construction
  storage: StorageAdapter
  atsmsClient: ATSMSClient
  apiUrl: string
  onSyncCompleted?: () => void
  onMessageAdded?: (message: LocalMessage) => void
  onConversationUpdated?: (convoId: string) => void
}
```

**Problems:**
- Cannot instantiate storage manager before user onboarding
- Application must know identity details before initializing storage
- No way to validate existing database before asking for credentials
- Transport layer created eagerly even if user hasn't onboarded
- Multi-identity scenarios (user switching) require recreating entire manager

### 2. Implicit Database State

**Current flow:**
```typescript
// Application must provide identity upfront
const manager = new ATSMSStorageManager({
  did: 'did:plc:abc123',    // Where did this come from?
  handle: 'alice.bsky.social',
  certSerial: '4d18ac7f',
  // ...
})

// No way to check if database is valid
// No way to check if user has onboarded
```

**Problems:**
- No API to query if user has completed onboarding
- No validation that database schema is correct
- Cannot distinguish between "new user" and "returning user" flows
- Application must track onboarding state separately

### 3. Transport Layer Initialization

**Current implementation:**
```typescript
constructor(config: ATSMSStorageManagerConfig) {
  this.did = config.did
  this.handle = config.handle

  // Transport layer created immediately
  this.transport = new ATSMSTransportLayer({
    did: config.did,          // ❌ Requires identity
    certSerial: config.certSerial,  // ❌ Requires certificate
    httpClient: this.httpClient,
    preferWebSocket: true
  })
}
```

**Problems:**
- Transport layer created even if user hasn't onboarded
- Cannot change identity without recreating manager
- WebSocket authentication requires certSerial at construction

## Proposed Architecture

### 1. Two-Phase Initialization

**Phase 1: Infrastructure Setup (No Identity Required)**
```typescript
interface ATSMSStorageManagerConfig {
  storage: StorageAdapter
  apiUrl: string
  atsmsClient: ATSMSClient  // Keep for PDS operations
  onSyncCompleted?: () => void
  onMessageAdded?: (message: LocalMessage) => void
  onConversationUpdated?: (convoId: string) => void
}

const manager = new ATSMSStorageManager({
  storage: sqliteAdapter,
  apiUrl: 'https://inbox.atsms.at',
  atsmsClient: atsmsClient,
  onMessageAdded: (msg) => console.log('New message!'),
})

// No explicit initialize() needed - happens automatically on first use
```

**Phase 2: Identity Activation (After Onboarding)**
```typescript
// Query current identity state
const primaryDid = await manager.getPrimaryDid()

if (!primaryDid) {
  // New user - perform onboarding
  const { did, handle, endpointCert } = await onboardUser()

  // Save DID with certificate (becomes primary DID automatically)
  await manager.saveDid(did, handle, endpointCert)

  // Start transport for this DID (authenticate, sync, listen for updates)
  await manager.startTransport(did)
} else {
  // Returning user - get the DID info
  const didInfo = await manager.getDid(primaryDid.did)

  if (!didInfo) {
    throw new Error('Primary DID data missing')
  }

  // Start transport for primary DID
  await manager.startTransport(didInfo.did)
}
```

### 2. New Interface Design

```typescript
export interface ATSMSStorageManagerConfig {
  // Infrastructure dependencies (required at construction)
  storage: StorageAdapter
  inboxUrl: string          // AT-SMS Inbox Provider URL only
  atsmsClient: ATSMSClient

  // Event handlers (optional)
  onSyncCompleted?: () => void
  onMessageAdded?: (message: LocalMessage) => void
  onConversationUpdated?: (convoId: string) => void
}

export interface ATSMSDidInfo {
  did: string
  handle: string
  certSerial: string
  isPrimary: boolean  // First DID saved is primary
  createdAt: Date
  lastUsedAt: Date
}

export class ATSMSStorageManager {
  // DID management
  async getPrimaryDid(): Promise<ATSMSDidInfo | null>
  async getDid(did: string): Promise<ATSMSDidInfo | null>
  async saveDid(
    did: string,
    handle: string,
    endpointCert: ATSMSEndpointCertificate
  ): Promise<void>

  // Transport lifecycle
  async startTransport(did: string): Promise<void>
  async stopTransport(did: string): Promise<void>
  isTransportActive(did: string): boolean

  // Existing methods (require transport to be started for a DID)
  async startConversation(...): Promise<string>
  async sendMessage(...): Promise<void>
  async sync(): Promise<void>
  // ... all other message operations
}
```

### 3. Database Schema Changes

**New `dids` table:**
```sql
CREATE TABLE dids (
  did TEXT PRIMARY KEY,
  handle TEXT NOT NULL,
  certSerial TEXT NOT NULL,
  isPrimary INTEGER DEFAULT 0,  -- Boolean: 1 = primary, 0 = not primary
  createdAt INTEGER NOT NULL,
  lastUsedAt INTEGER NOT NULL
);

-- Ensure only one primary DID
CREATE UNIQUE INDEX idx_primary_did ON dids(isPrimary)
  WHERE isPrimary = 1;
```

**Benefits:**
- Supports multiple DIDs per database (future-proof)
- First DID saved automatically becomes primary
- Clear distinction between "has onboarded" (rows exist) and "not onboarded" (empty table)
- Tracks when each DID was last used
- Schema ready for multi-DID support (just add APIs later)

### 4. Transport Layer Management

**Current (eager, single transport):**
```typescript
constructor(config: ATSMSStorageManagerConfig) {
  this.transport = new ATSMSTransportLayer({
    did: config.did,
    certSerial: config.certSerial,
    httpClient: this.httpClient,
    preferWebSocket: true
  })
}
```

**Proposed (explicit lifecycle, multi-transport ready):**
```typescript
export class ATSMSStorageManager {
  private transports = new Map<string, ATSMSTransportLayer>()  // did -> transport
  private activeTransport: ATSMSTransportLayer | null = null

  /**
   * Start transport for a DID - authenticates, syncs, and listens for updates
   */
  async startTransport(did: string): Promise<void> {
    // Get DID info from database
    const didInfo = await this.getDid(did)
    if (!didInfo) {
      throw new Error(`Cannot start transport: DID ${did} not found. Call saveDid() first.`)
    }

    // Create transport if doesn't exist
    if (!this.transports.has(did)) {
      const transport = new ATSMSTransportLayer({
        did: didInfo.did,
        certSerial: didInfo.certSerial,
        httpClient: this.httpClient,
        preferWebSocket: true
      })
      this.transports.set(did, transport)
    }

    // Set as active transport
    this.activeTransport = this.transports.get(did)!

    // Perform initial sync
    await this.sync()
  }

  /**
   * Stop transport for a DID - disconnects WebSocket and cleans up
   */
  async stopTransport(did: string): Promise<void> {
    const transport = this.transports.get(did)
    if (transport) {
      // Disconnect WebSocket if connected
      transport.setWebSocketClient(null)
      this.transports.delete(did)

      // Clear active if this was the active transport
      if (this.activeTransport === transport) {
        this.activeTransport = null
      }
    }
  }

  /**
   * Check if transport is active for a DID
   */
  isTransportActive(did: string): boolean {
    return this.transports.has(did)
  }

  private getTransport(): ATSMSTransportLayer {
    if (!this.activeTransport) {
      throw new Error('Cannot perform operations: No active transport. Call startTransport(did) first.')
    }
    return this.activeTransport
  }

  // All methods that need transport call getTransport()
  async listMessages(options?: ATSMSListMessagesOptions) {
    return this.getTransport().listMessages(options)
  }
}
```

**Benefits:**
- Transport only created when explicitly started
- Clear lifecycle: `saveDid()` → `startTransport()` → operations → `stopTransport()`
- Ready for multi-DID support (can have multiple transports)
- Clear error messages when operations attempted before transport started
- Explicit sync happens on transport start

### 5. Migration Path for Applications

**Before (atsms-chat.ts current code):**
```typescript
const storageManager = new ATSMSStorageManager({
  did,
  handle,
  storage,
  atsmsClient,
  apiUrl: `https://${ATSMS_API_DOMAIN}`,
  certSerial: endpointCert?.serialNumber || 'unknown',
  onMessageAdded: (message) => {
    this.handleNewMessage(message.convoId, message.id)
  },
})
```

**After (proposed new code):**
```typescript
// Phase 1: Initialize infrastructure (no await needed)
const storageManager = new ATSMSStorageManager({
  storage,
  atsmsClient,
  apiUrl: `https://${ATSMS_API_DOMAIN}`,
  onMessageAdded: (message) => {
    this.handleNewMessage(message.convoId, message.id)
  },
})

// Phase 2: Check if user has onboarded
const primaryDid = await storageManager.getPrimaryDid()

if (!primaryDid) {
  // New user flow
  console.log('No DID found. Starting onboarding...')

  // Perform certificate setup
  const { did, handle, endpointCert } = await setupCertificates()

  // Save DID with certificate (becomes primary automatically)
  await storageManager.saveDid(did, handle, endpointCert)

  console.log(`✓ Saved primary DID: ${handle}`)

  // Start transport (authenticate, sync, listen for updates)
  await storageManager.startTransport(did)

  console.log('✓ Transport started - ready to send/receive messages')
} else {
  // Returning user flow
  console.log(`Welcome back ${primaryDid.handle}!`)

  // Get full DID info
  const didInfo = await storageManager.getDid(primaryDid.did)

  if (!didInfo) {
    throw new Error('Primary DID data missing')
  }

  // Start transport for this DID (will throw if certificate invalid)
  await storageManager.startTransport(didInfo.did)

  console.log('✓ Transport started - ready to send/receive messages')
}
```

## Design Decisions Summary

### Q1: Should `atsmsClient` remain in constructor?

**Decision: Yes, keep it (Option A)**

- ✅ Storage manager can fetch certificates from PDS for peers
- ✅ Simpler API - one dependency injection point
- ✅ `atsmsClient` can be pre-authenticated by application
- ✅ Maintains clean separation: construction vs. DID activation

The `atsmsClient` is used for fetching peer certificates from PDS, which is independent of which DID the user has active. It should be authenticated by the application before passing to storage manager.

### Q2: How to handle multiple DIDs?

**Scenario:** User has multiple DIDs (e.g., work and personal accounts)

**Decision: Multi-DID schema, single-DID APIs (v1)**

```typescript
// v1: Only primary DID APIs
await manager.saveDid(did, handle, endpointCert)  // First call sets as primary
await manager.startTransport(did)

// Future v2: Multi-DID APIs (schema already supports this)
await manager.saveDid(workDid, workHandle, workCert)  // Already primary
await manager.saveDid(personalDid, personalHandle, personalCert)  // Not primary
await manager.setPrimaryDid(personalDid)  // Switch primary
await manager.startTransport(personalDid)  // Start transport for personal
await manager.listDids()  // Get all DIDs
```

**Benefits:**
- ✅ Simple v1 API (only primary DID)
- ✅ Schema ready for multi-DID (just add APIs later)
- ✅ No breaking changes when adding multi-DID support
- ✅ Database tracks isPrimary flag from day one

### Q3: Should transport layer be lazy or explicit lifecycle?

**Decision: Explicit lifecycle via `startTransport()` (proposed above)**

```typescript
// Explicit lifecycle management
await manager.saveDid(did, handle, endpointCert)  // Save DID data
await manager.startTransport(did)                  // Start transport explicitly
// ... perform operations ...
await manager.stopTransport(did)                   // Stop when done
```

**Benefits:**
- ✅ Clear when transport is active vs. inactive
- ✅ Application controls when authentication happens
- ✅ Application controls when sync happens
- ✅ Easy to stop/restart transport (e.g., on network change)
- ✅ Ready for multi-DID (can start multiple transports)
- ✅ `startTransport()` performs initial sync automatically

### Q4: How to handle certificate validation?

**Decision: No explicit validation - certificates self-validate on use**

```typescript
// saveDid() stores certificate in database
await manager.saveDid(did, handle, endpointCert)  // Cert stored automatically

// startTransport() uses certificate - will throw if invalid
await manager.startTransport(did)  // Certificate validated via library methods
```

**Benefits:**
- ✅ `saveDid()` stores full certificate (not just serial)
- ✅ Certificate available for future operations
- ✅ Certificate objects validate themselves when created/loaded
- ✅ No redundant validation logic - library handles it
- ✅ Clear errors thrown by certificate library if cert invalid

### Q5: Should `initialize()` be required?

**Decision: No explicit `initialize()` - automatic on first use (Option B)**

```typescript
const manager = new ATSMSStorageManager({ ... })
// Automatically initializes database schema on first method call
const primaryDid = await manager.getPrimaryDid()  // ✅ Triggers initialization internally
```

**Benefits:**
- ✅ Simpler API - one less method to remember
- ✅ No way to forget initialization
- ✅ Database schema created automatically when needed
- ✅ Idempotent - safe to call multiple times

**Implementation:**
```typescript
export class ATSMSStorageManager {
  private initialized = false

  private async ensureInitialized(): Promise<void> {
    if (!this.initialized) {
      // Create tables if they don't exist
      await this.storage.initialize()
      this.initialized = true
    }
  }

  async getPrimaryDid(): Promise<ATSMSDidInfo | null> {
    await this.ensureInitialized()  // Auto-initialize
    // ... rest of implementation
  }
}
```

### Q6: Error handling for operations before transport started?

**Decision: Throw from `getTransport()` with clear error message**

```typescript
private getTransport(): ATSMSTransportLayer {
  if (!this.activeTransport) {
    throw new Error(
      'Cannot perform operations: No active transport. ' +
      'Call startTransport(did) first after saving DID with saveDid().'
    )
  }
  return this.activeTransport
}

async sendMessage(...): Promise<void> {
  const transport = this.getTransport()  // ✅ Single check point
  // ... use transport
}
```

**Benefits:**
- ✅ Single enforcement point - easy to maintain
- ✅ Clear error message with actionable steps
- ✅ Consistent behavior across all operations
- ✅ Error message guides user to correct API usage

## Implementation Plan

### Phase 1: Database Schema (Non-Breaking)
1. Add `dids` table to database schema
2. Update `StorageAdapter` interface with new methods:
   - `getPrimaryDid()`
   - `getDid(did)`
   - `saveDid(did, handle, certSerial, endpointCert)`
3. Update `SQLiteAdapter` implementation
4. Add auto-initialization logic (ensureInitialized)
5. Test new schema with existing data

### Phase 2: Storage Manager Refactor (Breaking)
1. Update `ATSMSStorageManagerConfig` interface (remove did/handle/certSerial)
2. Remove explicit `initialize()` - make it automatic
3. Add `getPrimaryDid()`, `getDid()`, `saveDid()` methods
4. Add `startTransport()`, `stopTransport()`, `isTransportActive()` methods
5. Change transport management to explicit lifecycle with Map<did, transport>
6. Update all methods to use `getTransport()`
7. Remove certificate validation methods (not needed)
8. Ensure `saveDid()` stores full certificate in database
9. Create httpClient internally from inboxUrl (not passed in config)

### Phase 3: Application Updates (No Backward Compatibility Needed)
1. Update `src/client/atsms-chat.ts`:
   - Remove did/handle/certSerial from constructor
   - Change `apiUrl` to `inboxUrl`
   - Call `getPrimaryDid()` to check onboarding
   - Call `saveDid()` for new users with full endpointCert
   - Call `startTransport()` before operations
2. Update `src/client/api-client.ts`:
   - Adapt to new storage manager API
   - Update to use `inboxUrl` parameter
3. Update `src/client/atsms.ts`:
   - Keep stateless behavior (no storage manager)
   - May need minor tweaks for consistency
4. Update all unit tests in `src/tests/`:
   - Update storage manager construction
   - Update test flows for new DID management
   - Test transport lifecycle
5. Add examples and documentation

### Phase 4: Testing
1. Unit tests for new DID management methods
2. Unit tests for transport lifecycle
3. Integration tests for onboarding flows
4. Migration tests for existing databases
5. Test auto-initialization behavior

## Breaking Changes Summary

### API Changes
- ✅ **Breaking:** `ATSMSStorageManagerConfig` no longer accepts `did`, `handle`, `certSerial`
- ✅ **Breaking:** `ATSMSStorageManagerConfig.apiUrl` renamed to `inboxUrl`
- ✅ **Breaking:** Must call `saveDid()` before using message operations
- ✅ **Breaking:** Must call `startTransport()` before sending/receiving messages
- ✅ **New:** `getPrimaryDid()` - query primary DID (returns null if not onboarded)
- ✅ **New:** `getDid(did)` - get specific DID info
- ✅ **New:** `saveDid(did, handle, endpointCert)` - save DID with certificate
- ✅ **New:** `startTransport(did)` - start transport (auth, sync, listen)
- ✅ **New:** `stopTransport(did)` - stop transport
- ✅ **New:** `isTransportActive(did)` - check transport status
- ✅ **Removed:** `validateCertificate()` - certificates self-validate

### Database Changes
- ✅ **Non-breaking:** New `dids` table (auto-created on first run)
- ✅ **Non-breaking:** Existing data remains intact

### Behavior Changes
- ✅ **Breaking:** Operations throw error if called before `startTransport()`
- ✅ **Breaking:** Transport created explicitly via `startTransport()`
- ✅ **Breaking:** First DID saved automatically becomes primary
- ✅ **New:** `startTransport()` performs initial sync automatically

## Benefits Summary

1. **Cleaner Separation of Concerns**
   - Infrastructure setup separate from user identity
   - Storage manager can exist before onboarding

2. **Better Error Messages**
   - Clear errors when operations attempted before identity set
   - Explicit certificate validation with detailed reasons

3. **Improved Application Flow**
   - Applications can check onboarding status via `getPrimaryIdentity()`
   - Clear distinction between new vs. returning user flows

4. **Future-Proof Architecture**
   - Easy to add multi-identity support later
   - Simple to add identity switching
   - Room for advanced features (backup/restore, identity verification)

5. **Better Testing**
   - Can test storage manager without mocking identity
   - Easier to test error cases
   - Clear initialization lifecycle

## Timeline Estimate

- **Phase 1 (Database):** 2-3 hours
- **Phase 2 (Storage Manager):** 4-6 hours
- **Phase 3 (Applications):** 2-3 hours
- **Phase 4 (Testing):** 3-4 hours
- **Total:** ~15 hours of development time

## Next Steps

1. **Review and approve this proposal** - Discuss open questions and make decisions
2. **Create GitHub issue** - Track implementation work
3. **Begin Phase 1** - Database schema changes
4. **Iterate on feedback** - Adjust design based on implementation learnings

---

## Summary of User Decisions

Based on user feedback, the design has been updated with these decisions:

1. ✅ **No `initialize()`** - Automatic initialization on first use
2. ✅ **Rename Identity → Did** - `getPrimaryDid()`, `getDid()`, `saveDid()`
3. ✅ **Use "save" not "set"** - `saveDid()` instead of `setIdentity()`
4. ✅ **Save full certificate** - `saveDid(did, handle, endpointCert)` stores complete cert
5. ✅ **First DID is primary** - Automatic on first `saveDid()` call
6. ✅ **Multi-DID schema, single-DID APIs** - v1 only has primary DID APIs, schema ready for v2
7. ✅ **Explicit transport lifecycle** - `startTransport(did)` / `stopTransport(did)` methods
8. ✅ **Transport authenticates and syncs** - `startTransport()` handles initial sync

All open questions have been resolved and incorporated into the design above.
