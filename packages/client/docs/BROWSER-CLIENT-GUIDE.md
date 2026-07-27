# Building Browser Clients with AT-SMS

This guide explains how to build browser-based AT-SMS clients using the new IndexedDB storage adapter.

## Quick Start

### Installation

```bash
npm install @atsms/sms @atproto/api
```

### Minimal Example

```typescript
import { AtpAgent } from '@atproto/api'
import {
  IndexedDBAdapter,
  ATSMSStorageManager,
  ATSMSClient,
  ATSMSRootCertificate,
  ATSMSEndpointCertificate
} from '@atsms/sms'

async function initializeClient(identifier: string, password: string) {
  // 1. Create storage adapter
  const storage = new IndexedDBAdapter()

  // 2. Login to AT Protocol
  const agent = new AtpAgent({ service: 'https://bsky.social' })
  await agent.login({ identifier, password })

  // 3. Create AT-SMS client
  const atsmsClient = new ATSMSClient(agent, agent.session.did)

  // 4. Create storage manager
  const storageManager = new ATSMSStorageManager({
    storage,
    atsmsClient,
    inboxUrl: 'https://inbox.atsms.at',
    onMessageAdded: (message) => {
      console.log('New message:', message)
      // Update your UI here
    }
  })

  // 5. Check for existing certificates
  const primaryDid = await storageManager.getPrimaryDid()

  if (!primaryDid) {
    // First time setup - generate certificates
    await setupCertificates(agent, atsmsClient, storageManager)
  } else {
    // Existing user - start transport
    await storageManager.startTransport(primaryDid.did)
  }

  return { agent, atsmsClient, storageManager }
}

async function setupCertificates(agent, atsmsClient, storageManager) {
  // Generate root certificate
  const rootCert = await ATSMSRootCertificate.generate(
    agent.session.did,
    'bsky.social'
  )
  await atsmsClient.storeRootCertificate(rootCert)

  // Generate endpoint certificate
  const email = `${agent.session.did.split(':').pop()}@inbox.atsms.at`
  const endpointCert = await ATSMSEndpointCertificate.generateWithRoot(
    rootCert,
    agent.session.did,
    agent.session.handle,
    email
  )
  await atsmsClient.storeEndpointCertificate(endpointCert)

  // Save DID and start transport
  await storageManager.saveDid(
    agent.session.did,
    agent.session.handle,
    endpointCert
  )
  await storageManager.startTransport(agent.session.did)
}
```

## Key Differences from Node.js

### 1. Storage Adapter

**Node.js:**
```typescript
import Database from 'bun:sqlite'
import { SQLiteAdapter } from '@atsms/sms'

const db = new Database('messages.db')
const storage = new SQLiteAdapter(db)
```

**Browser:**
```typescript
import { IndexedDBAdapter } from '@atsms/sms'

const storage = new IndexedDBAdapter()
// Database created automatically in browser
```

### 2. No File System Access

Browsers don't have file system access, so all data is stored in IndexedDB:

- **Messages**: Stored in `atsms` database, `messages` object store
- **Conversations**: `conversations` object store
- **Certificates**: `certificates` object store
- **DIDs**: `dids` object store

### 3. Crypto Provider

The library automatically uses WebCrypto API in browsers - no configuration needed.

## Complete React Example

```typescript
import React, { useEffect, useState } from 'react'
import { AtpAgent } from '@atproto/api'
import {
  IndexedDBAdapter,
  ATSMSStorageManager,
  ATSMSClient,
  ATSMSRootCertificate,
  ATSMSEndpointCertificate,
  createTextContent,
  parseTextContent
} from '@atsms/sms'

interface Message {
  id: string
  senderId: string
  content: string
  createdAt: Date
}

export function ATSMSChat() {
  const [storageManager, setStorageManager] = useState<ATSMSStorageManager | null>(null)
  const [conversations, setConversations] = useState<any[]>([])
  const [messages, setMessages] = useState<Message[]>([])
  const [currentConvo, setCurrentConvo] = useState<string | null>(null)
  const [isInitialized, setIsInitialized] = useState(false)

  // Initialize AT-SMS
  useEffect(() => {
    async function init() {
      const storage = new IndexedDBAdapter()
      const agent = new AtpAgent({ service: 'https://bsky.social' })

      // Restore session from localStorage or login
      const savedSession = localStorage.getItem('atproto-session')
      if (savedSession) {
        await agent.resumeSession(JSON.parse(savedSession))
      } else {
        // Show login UI
        return
      }

      const atsmsClient = new ATSMSClient(agent, agent.session.did)

      const manager = new ATSMSStorageManager({
        storage,
        atsmsClient,
        inboxUrl: 'https://inbox.atsms.at',
        onMessageAdded: (msg) => {
          // Update UI when new message arrives
          if (msg.convoId === currentConvo) {
            setMessages(prev => [...prev, {
              id: msg.id,
              senderId: msg.senderId,
              content: parseTextContent(msg.content).text,
              createdAt: msg.createdAt
            }])
          }
        }
      })

      // Check if user has certificates
      const primaryDid = await manager.getPrimaryDid()

      if (!primaryDid) {
        // Setup certificates for first time
        const rootCert = await ATSMSRootCertificate.generate(
          agent.session.did,
          'bsky.social'
        )
        await atsmsClient.storeRootCertificate(rootCert)

        const email = `${agent.session.did.split(':').pop()}@inbox.atsms.at`
        const endpointCert = await ATSMSEndpointCertificate.generateWithRoot(
          rootCert,
          agent.session.did,
          agent.session.handle,
          email
        )
        await atsmsClient.storeEndpointCertificate(endpointCert)

        await manager.saveDid(agent.session.did, agent.session.handle, endpointCert)
        await manager.startTransport(agent.session.did)
      } else {
        // Start transport for existing user
        await manager.startTransport(primaryDid.did)
      }

      setStorageManager(manager)
      setIsInitialized(true)
    }

    init().catch(console.error)
  }, [])

  // Load conversations
  useEffect(() => {
    if (!storageManager) return

    const sub = storageManager.observeConversations().subscribe(convos => {
      setConversations(convos)
    })

    return () => sub.unsubscribe()
  }, [storageManager])

  // Load messages for current conversation
  useEffect(() => {
    if (!storageManager || !currentConvo) return

    const sub = storageManager.observeMessages(currentConvo).subscribe(msgs => {
      setMessages(msgs.map(m => ({
        id: m.id,
        senderId: m.senderId,
        content: parseTextContent(m.content).text,
        createdAt: m.createdAt
      })))
    })

    return () => sub.unsubscribe()
  }, [storageManager, currentConvo])

  // Send message
  async function sendMessage(recipient: string, text: string) {
    if (!storageManager) return

    const primaryDid = await storageManager.getPrimaryDid()
    if (!primaryDid) throw new Error('No primary DID')

    const endpointCert = await storageManager.getEndpointCertificate(primaryDid.did)
    if (!endpointCert) throw new Error('No endpoint certificate')

    await storageManager.startConversation(
      [recipient],
      text,
      endpointCert
    )
  }

  if (!isInitialized) {
    return <div>Initializing AT-SMS...</div>
  }

  return (
    <div className="chat-container">
      <div className="conversations">
        <h2>Conversations</h2>
        {conversations.map(convo => (
          <div
            key={convo.id}
            onClick={() => setCurrentConvo(convo.id)}
            className={currentConvo === convo.id ? 'active' : ''}
          >
            {convo.participantIds.join(', ')}
          </div>
        ))}
      </div>

      <div className="messages">
        <h2>Messages</h2>
        {messages.map(msg => (
          <div key={msg.id} className="message">
            <strong>{msg.senderId}</strong>
            <p>{msg.content}</p>
            <small>{msg.createdAt.toLocaleString()}</small>
          </div>
        ))}
      </div>
    </div>
  )
}
```

## Observables for Real-time Updates

The IndexedDB adapter supports RxJS Observables for reactive UI updates:

```typescript
// Watch all conversations
storageManager.observeConversations().subscribe(conversations => {
  updateConversationList(conversations)
})

// Watch messages in a specific conversation
storageManager.observeMessages('convo-123').subscribe(messages => {
  updateMessageList(messages)
})

// Watch a single conversation
storageManager.observeConversation('convo-123').subscribe(conversation => {
  if (conversation) {
    updateConversationHeader(conversation)
  }
})
```

## Message Content Types

AT-SMS uses structured message content with `contentType` and `content` fields:

### Text Messages

```typescript
import { createTextContent, parseTextContent } from '@atsms/sms'

// Creating a message
const content = createTextContent('Hello @alice.bsky.social!')

// Parsing received message
const message = await storageManager.getMessage('msg-123')
if (message.contentType === 'atsms/text') {
  const parsed = parseTextContent(message.content)
  console.log(parsed.text) // "Hello @alice.bsky.social!"
  console.log(parsed.facets) // Rich text annotations
}
```

### Future Content Types

The architecture supports extending to other types:
- `atsms/image` - Image messages
- `atsms/file` - File attachments
- `atsms/location` - Location sharing

## Storage Limits

IndexedDB storage limits vary by browser:

- **Chrome**: ~60% of available disk space
- **Firefox**: ~50% of available disk space
- **Safari**: 1GB (with user permission for more)

### Requesting Persistent Storage

```typescript
if (navigator.storage && navigator.storage.persist) {
  const isPersisted = await navigator.storage.persist()
  console.log(`Persistent storage: ${isPersisted}`)
}
```

### Monitoring Storage Usage

```typescript
if (navigator.storage && navigator.storage.estimate) {
  const estimate = await navigator.storage.estimate()
  const percentUsed = (estimate.usage / estimate.quota) * 100
  console.log(`Storage: ${percentUsed.toFixed(2)}% used`)
}
```

## Error Handling

### Quota Exceeded

```typescript
try {
  await storageManager.startConversation(recipients, message, endpointCert)
} catch (error) {
  if (error.name === 'QuotaExceededError') {
    alert('Storage quota exceeded. Please delete old messages.')
    // Optionally clear old data
    // await storage.clearAll()
  }
}
```

### Private Browsing Mode

```typescript
try {
  const storage = new IndexedDBAdapter()
  await storage.getLastSyncRev() // Trigger DB initialization
} catch (error) {
  console.error('IndexedDB not available (private browsing?)')
  // Fallback to in-memory storage or show error
}
```

## Best Practices

### 1. Session Management

Store AT Protocol session in localStorage for persistence:

```typescript
const agent = new AtpAgent({ service: 'https://bsky.social' })
await agent.login({ identifier, password })

// Save session
localStorage.setItem('atproto-session', JSON.stringify(agent.session))

// Restore session
const savedSession = localStorage.getItem('atproto-session')
if (savedSession) {
  await agent.resumeSession(JSON.parse(savedSession))
}
```

### 2. Certificate Caching

The storage manager caches certificates in memory. Don't create multiple instances:

```typescript
// ✓ Good - Single instance
const storageManager = new ATSMSStorageManager({ storage, atsmsClient, inboxUrl })

// ✗ Bad - Multiple instances
const manager1 = new ATSMSStorageManager({ storage, atsmsClient, inboxUrl })
const manager2 = new ATSMSStorageManager({ storage, atsmsClient, inboxUrl })
```

### 3. Cleanup on Logout

```typescript
async function logout(storageManager: ATSMSStorageManager) {
  // Stop all transports
  const primaryDid = await storageManager.getPrimaryDid()
  if (primaryDid) {
    await storageManager.stopTransport(primaryDid.did)
  }

  // Clear storage (optional)
  // await storage.clearAll()

  // Clear session
  localStorage.removeItem('atproto-session')
}
```

### 4. Debounce UI Updates

For high-frequency updates, debounce Observable notifications:

```typescript
import { debounceTime } from 'rxjs/operators'

storageManager.observeMessages(convoId)
  .pipe(debounceTime(100)) // Wait 100ms between updates
  .subscribe(messages => {
    updateUI(messages)
  })
```

## Browser Compatibility

Minimum browser versions:

- Chrome 87+
- Firefox 82+
- Safari 14.1+
- Edge 88+

All modern browsers support:
- IndexedDB
- WebCrypto API
- ES2020+ JavaScript

## Debugging

### View IndexedDB in DevTools

1. Open Browser DevTools (F12)
2. Go to "Application" tab (Chrome) or "Storage" tab (Firefox)
3. Expand "IndexedDB"
4. Open "atsms" database

### Enable Debug Logging

```typescript
const storageManager = new ATSMSStorageManager({
  storage,
  atsmsClient,
  inboxUrl: 'https://inbox.atsms.at',
  onMessageAdded: (message) => {
    console.log('[DEBUG] New message:', message)
  }
})
```

## Migration from Node.js Client

If you have a Node.js client using SQLiteAdapter, migrating to browser is straightforward:

```typescript
// Node.js
import Database from 'bun:sqlite'
import { SQLiteAdapter } from '@atsms/sms'
const db = new Database('messages.db')
const storage = new SQLiteAdapter(db)

// Browser
import { IndexedDBAdapter } from '@atsms/sms'
const storage = new IndexedDBAdapter()
```

Everything else remains the same - same API, same methods, same behavior.

## Common Issues

### Issue: "IndexedDB not available"

**Cause**: Private browsing mode or browser doesn't support IndexedDB

**Solution**: Check for IndexedDB support and show appropriate error:

```typescript
if (!('indexedDB' in window)) {
  alert('Your browser does not support IndexedDB')
}
```

### Issue: Transport fails with 403 Forbidden

**Cause**: Certificate mismatch or expired JWT

**Solution**: Regenerate endpoint certificate:

```typescript
const primaryDid = await storageManager.getPrimaryDid()
const rootCert = await storageManager.getRootCertificate(primaryDid.did)

const newEndpointCert = await ATSMSEndpointCertificate.generateWithRoot(
  rootCert,
  primaryDid.did,
  primaryDid.handle,
  email
)
await atsmsClient.storeEndpointCertificate(newEndpointCert)

// Update DID and restart transport
await storageManager.stopTransport(primaryDid.did)
await storageManager.saveDid(primaryDid.did, primaryDid.handle, newEndpointCert)
await storageManager.startTransport(primaryDid.did)
```

### Issue: Messages not appearing

**Cause**: Transport not started or sync not running

**Solution**: Ensure transport is active and sync is running:

```typescript
const primaryDid = await storageManager.getPrimaryDid()
if (!storageManager.isTransportActive(primaryDid.did)) {
  await storageManager.startTransport(primaryDid.did)
}

// Manually trigger sync
await storageManager.syncMessages()
```

## See Also

- [IndexedDB Adapter API Reference](./INDEXEDDB-ADAPTER.md)
- [AT-SMS Library Documentation](../README.md)
- [Message Content Structure](./CLAUDE.md#message-content-structure)
- [MDN IndexedDB API](https://developer.mozilla.org/en-US/docs/Web/API/IndexedDB_API)
