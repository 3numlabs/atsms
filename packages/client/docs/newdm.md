# Deterministic DM Conversation IDs

This document describes the changes made to prevent duplicate 1:1 DM conversations in ATSMS. Use this to implement the same fix in the Flutter port.

## Problem

When two users message each other, duplicate conversations were being created because:

1. **Sender side**: `startConversation()` generated a random `convoId = nanoid(13)` without checking for existing conversations with the same participants
2. **Receiver side**: `processIncomingTransportMessage()` looked up conversations by ID only. If the sender's random convoId didn't exist locally, it created a new conversation

Result: Alice and Bob could each have their own separate conversation records for what should be a single DM thread.

## Solution

For 1:1 direct messages (exactly 2 participants), use a **deterministic conversation ID** based on both participants' DIDs:

```
dm_[sha256(sorted_dids).substring(0, 16)]
```

Example:
- Participants: `did:plc:alice123`, `did:plc:bob456`
- Sorted & joined: `did:plc:alice123,did:plc:bob456`
- SHA-256 hash: `a1b2c3d4e5f6789...`
- Final convoId: `dm_a1b2c3d4e5f6789a`

This ensures:
- Both parties compute the **same** convoId independently
- DMs always map to a single conversation
- Group chats (3+ participants) continue using random IDs

---

## Implementation Details

### 1. Add Helper Functions

Create two helper functions for generating and detecting DM conversation IDs:

```typescript
/**
 * Generate deterministic conversation ID for 1:1 DMs.
 * Both parties will compute the same ID given the same DIDs.
 */
async function generateDMConvoId(did1: string, did2: string): Promise<string> {
  // 1. Sort DIDs alphabetically to ensure consistent ordering
  const sortedDids = [did1, did2].sort().join(",");

  // 2. Hash with SHA-256
  const encoder = new TextEncoder();
  const data = encoder.encode(sortedDids);
  const hashBuffer = await crypto.subtle.digest("SHA-256", data);

  // 3. Convert to hex and take first 16 characters
  const hashArray = new Uint8Array(hashBuffer);
  const hashHex = Array.from(hashArray)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");

  return `dm_${hashHex.substring(0, 16)}`;
}

/**
 * Check if a conversation ID is a deterministic DM ID
 */
function isDMConvoId(convoId: string): boolean {
  return convoId.startsWith("dm_");
}
```

**Flutter/Dart equivalent:**

```dart
import 'dart:convert';
import 'package:crypto/crypto.dart';

Future<String> generateDMConvoId(String did1, String did2) async {
  // Sort DIDs alphabetically
  final sortedDids = [did1, did2]..sort();
  final joined = sortedDids.join(',');

  // SHA-256 hash
  final bytes = utf8.encode(joined);
  final digest = sha256.convert(bytes);

  // Take first 16 hex characters
  final hashHex = digest.toString().substring(0, 16);
  return 'dm_$hashHex';
}

bool isDMConvoId(String convoId) {
  return convoId.startsWith('dm_');
}
```

---

### 2. Update `startConversation()`

When starting a new conversation, check if it's a 1:1 DM and use deterministic ID:

```typescript
async startConversation(
  recipientDIDs: string[],
  content: string,
  endpointCert: ATSMSEndpointCertificate,
  metadata?: { title?: string },
): Promise<string> {
  const activeDid = await this.getActiveDid();

  // For 1:1 DMs, use deterministic convoId to prevent duplicates
  let convoId: string;
  if (recipientDIDs.length === 1) {
    convoId = await generateDMConvoId(activeDid, recipientDIDs[0]);

    // Check if conversation already exists — send message there instead
    const existing = await this.storage.getConversation(convoId);
    if (existing) {
      await this.sendMessage(convoId, content, endpointCert);
      return convoId;
    }
  } else {
    // Group chat: use random ID
    convoId = nanoid(13);
  }

  // ... rest of method continues with new conversation creation
}
```

**Key points:**
- Single recipient (1:1 DM) → compute deterministic ID
- If conversation with that ID exists → just send a message to it, don't create duplicate
- Multiple recipients (group) → use random ID as before

---

### 3. Update `processIncomingTransportMessage()`

When receiving a message, compute the deterministic ID for DMs instead of using the sender's convoId:

```typescript
async processIncomingTransportMessage(
  transportMessage: ATSMSTransportMessage,
  endpointCert: ATSMSEndpointCertificate,
): Promise<{ messageId: string; convoId: string; isNew: boolean }> {

  // ... decrypt and validate message ...

  // Get participant list
  const participantIds = Array.from(
    new Set([validatedData.senderId, ...validatedData.recipientIds]),
  );

  let conversation: LocalConversation | null = null;
  let effectiveConvoId: string;

  // For 1:1 DMs, compute deterministic convoId
  if (participantIds.length === 2) {
    effectiveConvoId = await generateDMConvoId(
      participantIds[0],
      participantIds[1],
    );

    conversation = await this.storage.getConversation(effectiveConvoId);

    if (!conversation) {
      conversation = {
        id: effectiveConvoId,  // Use deterministic ID, NOT sender's convoId
        participantIds,
        createdAt: new Date(validatedData.createdAt),
        // ... other fields
      };
      await this.storage.saveConversation(conversation);
    }
  } else {
    // Group chat: use the sender's convoId (existing behavior)
    effectiveConvoId = validatedData.convoId;
    conversation = await this.storage.getConversation(effectiveConvoId);

    if (!conversation) {
      conversation = {
        id: effectiveConvoId,
        participantIds,
        // ... other fields
      };
      await this.storage.saveConversation(conversation);
    }
  }

  // Save message with the EFFECTIVE convoId (not sender's original)
  const localMessage: LocalMessage = {
    id: transportMessage.id,
    convoId: effectiveConvoId,  // Important: use computed ID for DMs
    // ... other fields
  };

  await this.storage.saveMessage(localMessage);

  return {
    messageId: transportMessage.id,
    convoId: effectiveConvoId,
    isNew: true,
  };
}
```

**Key points:**
- 2 participants → compute deterministic ID, ignore sender's convoId
- 3+ participants (group) → use sender's convoId as before
- Always save the message with `effectiveConvoId`, not the original `validatedData.convoId`

---

### 4. Update `getOrCreateConversation()` (if applicable)

If you have a helper that gets or creates a conversation by participants, update it too:

```typescript
async getOrCreateConversation(
  participantDids: string[],
): Promise<LocalConversation> {
  // Look for existing conversation first
  let conversation = await this.storage.findConversationByParticipants(participantDids);

  if (conversation) {
    return conversation;
  }

  // For 1:1 DMs, use deterministic convoId; random for groups
  const convoId =
    participantDids.length === 2
      ? await generateDMConvoId(participantDids[0], participantDids[1])
      : generateRandomId(13);

  conversation = {
    id: convoId,
    participantIds: participantDids,
    createdAt: new Date(),
    lastMessageAt: new Date(),
    unreadCount: 0,
  };

  await this.storage.saveConversation(conversation);
  return conversation;
}
```

---

### 5. Migration for Existing Duplicates (Optional)

Add a one-time migration to merge existing duplicate DM conversations:

```typescript
async migrateDuplicateDMConversations(): Promise<number> {
  const allConversations = await this.storage.getConversations(1000);
  let migratedCount = 0;

  // Group conversations by sorted participant pair
  const dmGroups = new Map<string, LocalConversation[]>();

  for (const convo of allConversations) {
    if (convo.participantIds.length === 2) {
      const key = [...convo.participantIds].sort().join(",");
      const group = dmGroups.get(key) || [];
      group.push(convo);
      dmGroups.set(key, group);
    }
  }

  // Merge duplicates into canonical conversation
  for (const [key, convos] of dmGroups) {
    if (convos.length > 1) {
      const [did1, did2] = key.split(",");
      const canonicalId = await generateDMConvoId(did1, did2);

      // Ensure canonical conversation exists
      let canonical = await this.storage.getConversation(canonicalId);
      if (!canonical) {
        const earliest = convos.reduce((a, b) =>
          a.createdAt < b.createdAt ? a : b
        );
        canonical = { ...earliest, id: canonicalId };
        await this.storage.saveConversation(canonical);
      }

      // Migrate messages from all non-canonical conversations
      for (const convo of convos) {
        if (convo.id !== canonicalId) {
          await this.storage.migrateMessagesToConversation(convo.id, canonicalId);
          await this.storage.deleteConversation(convo.id);
          migratedCount++;
        }
      }
    }
  }

  return migratedCount;
}
```

**Storage adapter method needed:**

```typescript
// In StorageAdapter interface
migrateMessagesToConversation(fromConvoId: string, toConvoId: string): Promise<number>;

// SQLite implementation
async migrateMessagesToConversation(fromConvoId: string, toConvoId: string): Promise<number> {
  const result = db.run(
    "UPDATE messages SET convoId = ? WHERE convoId = ?",
    [toConvoId, fromConvoId]
  );
  return result.changes;
}
```

---

## Summary of Changes

| Location | Change |
|----------|--------|
| Helper functions | Add `generateDMConvoId()` and `isDMConvoId()` |
| `startConversation()` | Use deterministic ID for 1:1 DMs; check for existing before creating |
| `processIncomingTransportMessage()` | Compute deterministic ID for 2-participant conversations |
| `getOrCreateConversation()` | Use deterministic ID when creating new 1:1 conversations |
| Storage adapter | Add `migrateMessagesToConversation()` for migration support |
| Manager | Add `migrateDuplicateDMConversations()` for one-time cleanup |

## Testing

Verify:
1. `generateDMConvoId("did:plc:a", "did:plc:b")` equals `generateDMConvoId("did:plc:b", "did:plc:a")`
2. Starting a conversation with the same recipient twice returns the same convoId
3. Receiving a message from someone you've messaged goes into the existing conversation
4. Group chats (3+ participants) still use random IDs
