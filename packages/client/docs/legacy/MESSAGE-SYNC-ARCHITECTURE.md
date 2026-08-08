# ATSMS Message Synchronization Architecture

The ATSMS library syncs messages with the ATSMS Inbox Provider through a sophisticated multi-layer architecture with three transport mechanisms and a unified processing pipeline.

## Architecture Layers

### 1. Transport Layer (`ATSMSTransportLayer`) - Intelligent Transport Abstraction
- **Location**: `src/lib/transport-layer.ts`
- **Purpose**: Unified API that abstracts HTTP and WebSocket transports
- **Strategy**: Prefers WebSocket when available (more efficient), automatically falls back to HTTP
- **Key methods**:
  - `listMessages(options)`: Fetch message list with optional pagination
  - `getMessage(messageId)`: Download full encrypted message by ID
  - `deleteMessage(messageId)`: Delete message from inbox
  - `getStats()`: Get inbox statistics
  - `sendMessage(recipients, encryptedContent)`: Send messages to multiple recipients

### 2. HTTP Client (`ATSMSApiClient`) - REST API Communication
- **Location**: `src/lib/atsms-api.ts`
- **Purpose**: Direct HTTP communication with ATSMS API server
- **Authentication**: JWT token in `Authorization: Bearer <token>` header
- **Endpoints**:
  - `GET /messages/{did}/{certSerial}/list?after={seq}&limit={n}`: List messages
  - `GET /messages/{did}/{certSerial}/{messageId}`: Download specific message
  - `DELETE /messages/{did}/{certSerial}/{messageId}`: Delete message
  - `GET /messages/{did}/{certSerial}/stats`: Get inbox stats
  - `POST /send-message`: Send message (WebSocket-only currently)

### 3. WebSocket Client (`ATSMSWebSocketClient`) - Real-time Communication
- **Location**: `src/lib/websocket-client.ts`
- **Purpose**: Real-time bidirectional messaging with the server
- **Features**:
  - Real-time `new_message` notifications
  - Request/response pattern for all operations
  - Auto-reconnection with exponential backoff
  - Dual authentication: headers (Node.js) or post-connection (browser)

### 4. Storage Manager (`ATSMSStorageManager`) - Business Logic & Orchestration
- **Location**: `src/lib/storage/manager.ts`
- **Purpose**: Coordinates sync, decryption, storage, and conversation management
- **Key responsibilities**:
  - Orchestrate sync operations
  - Decrypt and verify incoming messages
  - Manage local SQLite database
  - Handle conversation threading
  - Emit events for UI updates

## Synchronization Flow

### Sync Process (`syncMessages` method at `manager.ts:556`)

**Step 1: Retrieve Last Sync Position**
```typescript
const lastSyncSeq = await this.storage.getLastSyncRev()
const afterSequence = lastSyncSeq ? parseInt(lastSyncSeq, 10) : undefined
```
- Reads the last sequence number from local database
- Uses this for incremental sync (only fetch new messages since last sync)
- If no previous sync, fetches all messages

**Step 2: Fetch Message List**
```typescript
const messageListResponse = await this.transport.listMessages({
  after: afterSequence
})
```
- Transport layer decides: WebSocket if connected, else HTTP
- Returns array of message headers with metadata (ID, sender, timestamp, sequence)
- Also includes `latestSeq` - the highest sequence number on the server

**Step 3: Download Full Messages**
```typescript
for (const msgHeader of encryptedMessages) {
  const transportMessage = await this.transport.getMessage(msgHeader.id)
  // Process each message...
}
```
- Message list only contains metadata, not encrypted content
- Each message downloaded individually by ID
- Transport layer auto-selects WebSocket or HTTP for each fetch

**Step 4: Process Through Standard Pipeline**
```typescript
const result = await this.processIncomingTransportMessage(
  transportMessage,
  endpointCert
)
```
- All messages go through the same processing pipeline (detailed below)
- Returns `isNew` flag (true if not duplicate)

**Step 5: Update Sync Position**
```typescript
if (highestSequence > 0) {
  await this.storage.setLastSyncRev(highestSequence.toString())
}
```
- Stores highest sequence number seen
- Next sync will start from this position
- Ensures no messages are missed or duplicated

**Step 6: Emit Completion Event**
```typescript
this.syncCompletedSubject.next()
```
- Observable pattern for UI updates
- Clients can listen to know when sync finishes

## Message Processing Pipeline

### processIncomingTransportMessage (`manager.ts:445`)

This is the **single entry point** for all incoming messages, regardless of source (sync, WebSocket notification, direct fetch).

**Step 1: Decrypt Message**
```typescript
const encryptedContent = Uint8Array.from(
  atob(transportMessage.encryptedContent),
  c => c.charCodeAt(0)
)

const decrypted = await decryptAndVerifyMessageSignature(
  encryptedContent,
  endpointCert
)
```
- Base64 decode the encrypted content
- Uses S/MIME (PKCS#7) to decrypt with local endpoint certificate's private key
- Simultaneously verifies sender's signature

**Step 2: Extract and Verify Sender**
```typescript
const verifiedSender = decrypted.messageSigner.issuer.replace(/^CN=/, '')
const contentText = new TextDecoder().decode(decrypted.decryptedContent)
const messageData = JSON.parse(contentText)
```
- Extracts sender DID from certificate signature
- Decodes decrypted payload as UTF-8
- Parses JSON message structure

**Step 3: Validate Schema**
```typescript
const validatedData = MessageDataSchema.parse(messageData)

if (validatedData.senderId !== verifiedSender) {
  throw new Error('Sender mismatch...')
}
```
- Validates message structure with Zod schema
- Cross-checks payload sender vs signature sender
- Prevents impersonation attacks

**Step 4: Check for Duplicates**
```typescript
const existing = await this.storage.getMessage(transportMessage.id)
if (existing) {
  return { messageId, convoId, isNew: false }
}
```
- Queries local database for message ID
- Returns early if already processed
- Prevents duplicate messages in UI

**Step 5: Get or Create Conversation**
```typescript
let conversation = await this.storage.getConversation(validatedData.convoId)

if (!conversation) {
  conversation = {
    id: validatedData.convoId,
    participantIds: [...],
    unreadCount: validatedData.senderId !== this.did ? 1 : 0,
    // ...
  }
  await this.storage.saveConversation(conversation)
}
```
- Looks up conversation by ID
- Creates new conversation if first message in thread
- Initializes unread counter for incoming messages

**Step 6: Save to Database**
```typescript
const localMessage: LocalMessage = {
  id: transportMessage.id,
  convoId: validatedData.convoId,
  senderId: validatedData.senderId,
  recipientIds: validatedData.recipientIds,
  content: validatedData.content,        // JSON-serialized content
  contentType: validatedData.contentType, // MIME type (e.g., "atsms/text")
  createdAt: new Date(validatedData.createdAt),
  isInvitation: false,
}

await this.storage.saveMessage(localMessage)
```
- Stores decrypted message in local SQLite database
- Content is JSON-serialized (for "atsms/text": `{"text":"...", "facets":[...]}`)
- Only plaintext stored locally (encrypted content discarded after decryption)

**Step 7: Update Conversation Metadata**
```typescript
if (validatedData.senderId !== this.did) {
  await this.storage.updateConversation(validatedData.convoId, {
    lastMessageAt: localMessage.createdAt,
    unreadCount: (conversation.unreadCount || 0) + 1,
  })
}
```
- Updates conversation's last message timestamp
- Increments unread counter for incoming messages only
- Keeps conversation list sorted and annotated

**Step 8: Emit Events**
```typescript
this.messageAddedSubject.next({ convoId, messageId, contentType: validatedData.contentType })
this.conversationUpdatedSubject.next(convoId)
```
- Notifies UI observers of new message with content type
- Triggers conversation list refresh
- Observable pattern for reactive UI updates

## Real-Time WebSocket Integration

### WebSocket Message Handler (`manager.ts:648-662`)

When a WebSocket `new_message` notification arrives:

```typescript
onMessage: async (wsMessage) => {
  if (wsMessage.type === 'new_message') {
    await this.ensureAuth(endpointCert)

    // Download the full transport message
    const transportMessage = await this.transport.getMessage(wsMessage.id)

    // Process through standard pipeline
    await this.processIncomingTransportMessage(transportMessage, endpointCert)

    this.messageReceivedSubject.next()
  }
}
```

**Key Design**:
- WebSocket only sends notification with message ID (not full encrypted content)
- Client fetches full message via transport layer
- Same `processIncomingTransportMessage` pipeline ensures consistency
- No code duplication between sync and real-time paths

## Authentication Flow

### JWT Token Generation (`ensureAuth` method)
```typescript
async ensureAuth(endpointCert: ATSMSEndpointCertificate) {
  if (!endpointCert.certificatePrivateKeyPEM) {
    throw new Error('No private key available')
  }

  const token = await generateJWT(
    endpointCert.certificatePrivateKeyPEM,
    endpointCert.serialNumber,
    this.did
  )

  this.httpClient.setAuthToken(token)
}
```

- JWT signed with endpoint certificate's private key
- Contains DID and certificate serial number
- Set on HTTP client before any API operations
- Server validates signature against certificate stored in PDS

## Key Design Principles

1. **Unified Processing Pipeline**: All messages go through `processIncomingTransportMessage` regardless of source
2. **Transport Abstraction**: WebSocket preferred, HTTP fallback, client code doesn't care
3. **Incremental Sync**: Sequence-based pagination avoids re-fetching old messages
4. **Duplicate Prevention**: Message ID checked against local database
5. **Cryptographic Verification**: Signature verification prevents impersonation
6. **Observable Pattern**: Events emitted for reactive UI updates
7. **Conversation Threading**: Messages grouped by `convoId` for chat-like UX
8. **Fail-Open on Network Errors**: Sync failures don't block the application

## Storage Manager Events

The `ATSMSStorageManager` emits three types of events using RxJS Subjects for reactive UI updates:

### 1. `syncCompleted` Event
**Emitted when:** Message synchronization completes (successful or failed)

**Payload:** `void` (no data)

**Usage (via Observable accessor):**
```typescript
storageManager.syncCompleted$.subscribe(() => {
  console.log('Sync completed - UI can refresh')
})
```

**Emitted from:**
- `syncMessages()` - After all messages are synced (line 606)

**Purpose:** Notify UI that sync is done, refresh indicators/badges can be updated

---

### 2. `messageAdded` Event
**Emitted when:** A new message is added to the local database

**Payload:** Full `LocalMessage` object
```typescript
interface LocalMessage {
  id: string              // Unique message ID
  convoId: string         // Conversation ID
  senderId: string        // Sender DID
  recipientIds: string[]  // Recipient DIDs
  content: string         // JSON-serialized content
  contentType: string     // MIME type (e.g., "atsms/text")
  createdAt: Date         // Message timestamp
  isInvitation: boolean   // Whether this is a conversation invitation
}
```

**Usage (via Observable accessor):**
```typescript
import { parseTextContent } from '@atsms/sms'

// Subscribe to all message events
storageManager.messageAdded$.subscribe((message) => {
  console.log(`New message ${message.id} in conversation ${message.convoId}`)
  console.log(`Content type: ${message.contentType}`)

  // Access message content directly without additional query
  if (message.contentType === 'atsms/text') {
    const textContent = parseTextContent(message.content)
    console.log(`Text: ${textContent.text}`)
  }
})

// Filter by content type using RxJS operators
import { filter } from 'rxjs/operators'

storageManager.messageAdded$
  .pipe(filter(message => message.contentType === 'atsms/text'))
  .subscribe((message) => {
    const textContent = parseTextContent(message.content)
    console.log('New text message:', textContent.text)
  })

storageManager.messageAdded$
  .pipe(filter(message => message.contentType === 'atsms/image'))
  .subscribe((message) => {
    console.log('New image message received')
    // message.content contains image metadata
  })
```

**Emitted from:**
- `sendMessage()` - After sending your own message (line 316, 430)
- `processIncomingTransportMessage()` - After receiving a message (line 536)
- `acceptConversation()` - When accepting a conversation invitation (line 735)

**Purpose:** Real-time UI updates when messages arrive or are sent

---

### 3. `conversationUpdated` Event
**Emitted when:** A conversation's metadata changes (last message time, unread count, etc.)

**Payload:** `string` (conversation ID)

**Usage (via Observable accessor):**
```typescript
storageManager.conversationUpdated$.subscribe((convoId) => {
  console.log(`Conversation ${convoId} was updated`)
  // Refresh conversation list, update badges, re-sort conversations
})
```

**Emitted from:**
- `createOrUpdateConversation()` - When conversation metadata changes (line 235)
- `sendMessage()` - After sending a message (line 431)
- `processIncomingTransportMessage()` - After receiving a message (line 510, 532)
- `markConversationAsRead()` - When marking conversation as read (line 719)
- `muteConversation()` - When muting/unmuting (line 727)

**Purpose:** Keep conversation list UI in sync with database changes

---

### Event Configuration

**Method 1: Callbacks (Simple)**

Events can be configured via callbacks in the `ATSMSStorageManagerConfig`:

```typescript
const storageManager = new ATSMSStorageManager({
  did: 'did:plc:...',
  handle: 'user.bsky.social',
  storage: sqliteAdapter,
  atsmsClient: client,
  apiUrl: 'https://atsms-api.example.com',
  certSerial: 'abc123',

  // Optional event callbacks
  onSyncCompleted: () => {
    console.log('Sync done!')
  },
  onMessageAdded: (message) => {
    console.log(`New message: ${message.id} (${message.contentType})`)
    // Access full message content without additional query
    if (message.contentType === 'atsms/text') {
      const textContent = parseTextContent(message.content)
      showNotification(message.convoId, textContent.text)
    }
  },
  onConversationUpdated: (convoId) => {
    console.log(`Conversation updated: ${convoId}`)
    refreshConversationList()
  }
})
```

**Method 2: Observable Accessors (Advanced)**

For more control and filtering capabilities, use the Observable accessors with RxJS operators:

```typescript
import { filter, debounceTime, distinctUntilChanged } from 'rxjs/operators'

// Subscribe to specific content types only
storageManager.messageAdded$
  .pipe(filter(event => event.contentType === 'atsms/text'))
  .subscribe(({ convoId, messageId }) => {
    console.log('Text message added')
  })

// Debounce conversation updates to avoid UI flicker
storageManager.conversationUpdated$
  .pipe(
    debounceTime(100),
    distinctUntilChanged()
  )
  .subscribe(convoId => {
    refreshConversationInUI(convoId)
  })

// Combine multiple observables
import { combineLatest } from 'rxjs'

combineLatest([
  storageManager.messageAdded$,
  storageManager.conversationUpdated$
]).subscribe(([messageEvent, convoId]) => {
  // Handle both events together
})
```

**Available Observable Accessors:**
- `messageAdded$` - Observable of full `LocalMessage` objects (includes content, no additional query needed)
- `conversationUpdated$` - Observable of conversation ID strings
- `syncCompleted$` - Observable of sync completion events (void)

### Observable Queries

In addition to events, the storage manager provides observable queries for reactive data binding:

```typescript
// Observe all conversations with optional filter
const conversations$ = storageManager.observeConversations({
  status: 'accepted',
  unreadOnly: true
})

// Observe messages in a specific conversation
const messages$ = storageManager.observeMessages('convo-123')

// Observe a single conversation
const conversation$ = storageManager.observeConversation('convo-123')
```

These return RxJS `Observable` streams that emit whenever the underlying data changes.

## Sequence Diagram

```
Client                Storage Manager         Transport Layer         API/WebSocket
  |                        |                        |                      |
  |--syncMessages()------->|                        |                      |
  |                        |--getLastSyncRev()-->   |                      |
  |                        |<--(returns seq 42)--   |                      |
  |                        |--listMessages({after:42})------------------->|
  |                        |                        |<--(msg headers, seq 50)
  |                        |<--(headers, latestSeq 50)                    |
  |                        |                        |                      |
  |                        |--for each header------>|                      |
  |                        |  getMessage(id)        |-------------------->|
  |                        |                        |<-(encrypted message)-|
  |                        |<-(transport message)---|                      |
  |                        |                        |                      |
  |                        |--processIncoming()---->|                      |
  |                        |  (decrypt, verify)     |                      |
  |                        |  (save to DB)          |                      |
  |                        |  (emit events)         |                      |
  |                        |<-(messageId,isNew)-----|                      |
  |                        |                        |                      |
  |                        |--setLastSyncRev(50)--->|                      |
  |<-(newCount, total)-----|                        |                      |
```

This architecture ensures reliable, efficient, and secure message delivery while providing a clean separation of concerns between transport, cryptography, and storage.
