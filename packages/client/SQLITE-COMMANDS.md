# SQLite Commands for AT-SMS Development

This document contains helpful SQLite commands for inspecting and debugging the AT-SMS local database.

## Database Location

The default database location is `~/.atsms/messages.db` (set in `atsms-chat.ts`).

For development/testing, you may also have databases in:
- `./messages.db` (current directory)
- Custom paths specified in tests

## Quick Start

### Interactive Session

```bash
sqlite3 ~/.atsms/messages.db
```

Inside the SQLite prompt, enable better formatting:
```sql
.mode column
.headers on
```

Exit with `.quit` or `Ctrl+D`.

### One-Line Commands

Run a single query and exit:
```bash
sqlite3 ~/.atsms/messages.db "SELECT * FROM conversations"
```

## Schema Inspection

### List All Tables

```bash
sqlite3 ~/.atsms/messages.db ".tables"
```

### View Table Schema

```bash
# View conversations table schema
sqlite3 ~/.atsms/messages.db ".schema conversations"

# View messages table schema
sqlite3 ~/.atsms/messages.db ".schema messages"

# View certificates table schema
sqlite3 ~/.atsms/messages.db ".schema certificates"

# View all schemas
sqlite3 ~/.atsms/messages.db ".schema"
```

### Table Information

```bash
# Show table structure with data types
sqlite3 ~/.atsms/messages.db "PRAGMA table_info(conversations);"
sqlite3 ~/.atsms/messages.db "PRAGMA table_info(messages);"
sqlite3 ~/.atsms/messages.db "PRAGMA table_info(certificates);"
```

## Conversations

### List All Conversations

```bash
sqlite3 ~/.atsms/messages.db "
SELECT * FROM conversations
"
```

### List Conversations (Formatted)

```bash
sqlite3 ~/.atsms/messages.db "
SELECT
  id,
  participantIds,
  datetime(lastMessageAt) as last_message,
  unreadCount,
  datetime(createdAt) as created
FROM conversations
ORDER BY lastMessageAt DESC
"
```

### Count Conversations

```bash
sqlite3 ~/.atsms/messages.db "SELECT COUNT(*) as total FROM conversations"
```

### Find Conversation by ID

```bash
sqlite3 ~/.atsms/messages.db "
SELECT * FROM conversations
WHERE id = 'your-convo-id'
"
```

### Find Conversations by Participant DID

```bash
sqlite3 ~/.atsms/messages.db "
SELECT * FROM conversations
WHERE participantIds LIKE '%did:plc:xyz123%'
"
```

### Unread Conversations

```bash
sqlite3 ~/.atsms/messages.db "
SELECT
  id,
  participantIds,
  unreadCount,
  datetime(lastMessageAt) as last_message
FROM conversations
WHERE unreadCount > 0
ORDER BY lastMessageAt DESC
"
```

## Messages

### List All Messages

```bash
sqlite3 ~/.atsms/messages.db "SELECT * FROM messages"
```

### List Recent Messages (Formatted)

```bash
sqlite3 ~/.atsms/messages.db "
SELECT
  id,
  convoId,
  senderId,
  substr(content, 1, 50) as content_preview,
  contentType,
  datetime(createdAt) as created
FROM messages
ORDER BY createdAt DESC
LIMIT 20
"
```

### Count Messages

```bash
sqlite3 ~/.atsms/messages.db "SELECT COUNT(*) as total FROM messages"
```

### Messages in a Specific Conversation

```bash
sqlite3 ~/.atsms/messages.db "
SELECT
  id,
  senderId,
  substr(content, 1, 100) as content_preview,
  contentType,
  datetime(createdAt) as sent_at
FROM messages
WHERE convoId = 'your-convo-id'
ORDER BY createdAt ASC
"
```

### Messages from a Specific Sender

```bash
sqlite3 ~/.atsms/messages.db "
SELECT
  id,
  convoId,
  substr(content, 1, 100) as content_preview,
  contentType,
  datetime(createdAt) as sent_at
FROM messages
WHERE senderId = 'did:plc:xyz123'
ORDER BY createdAt DESC
"
```

### Search Messages by Text Content

```bash
sqlite3 ~/.atsms/messages.db "
SELECT
  id,
  convoId,
  senderId,
  substr(content, 1, 100) as content_preview,
  contentType,
  datetime(createdAt) as sent_at
FROM messages
WHERE content LIKE '%search term%'
ORDER BY createdAt DESC
"
```

**Note:** For "atsms/text" messages, content is JSON like `{"text":"..."}`. To search the actual text, you can use:
```bash
sqlite3 ~/.atsms/messages.db "
SELECT
  id,
  convoId,
  json_extract(content, '$.text') as message_text,
  datetime(createdAt) as sent_at
FROM messages
WHERE contentType = 'atsms/text'
  AND json_extract(content, '$.text') LIKE '%search term%'
ORDER BY createdAt DESC
"
```

### Message Count by Conversation

```bash
sqlite3 ~/.atsms/messages.db "
SELECT
  convoId,
  COUNT(*) as message_count
FROM messages
GROUP BY convoId
ORDER BY message_count DESC
"
```

## Certificates

### List All Certificates

```bash
sqlite3 ~/.atsms/messages.db "SELECT * FROM certificates"
```

### List Certificates (Formatted)

```bash
sqlite3 ~/.atsms/messages.db "
SELECT
  did,
  type,
  serialNumber,
  hasPrivateKey,
  isEncrypted,
  datetime(createdAt) as created
FROM certificates
ORDER BY createdAt DESC
"
```

### Find Certificates by DID

```bash
sqlite3 ~/.atsms/messages.db "
SELECT
  type,
  serialNumber,
  hasPrivateKey,
  isEncrypted
FROM certificates
WHERE did = 'did:plc:xyz123'
"
```

### Find Root Certificates

```bash
sqlite3 ~/.atsms/messages.db "
SELECT
  did,
  serialNumber,
  hasPrivateKey,
  isEncrypted
FROM certificates
WHERE type = 'root'
"
```

### Find Client Certificates

```bash
sqlite3 ~/.atsms/messages.db "
SELECT
  did,
  serialNumber,
  hasPrivateKey,
  isEncrypted
FROM certificates
WHERE type = 'endpoint'
"
```

### Certificates with Private Keys

```bash
sqlite3 ~/.atsms/messages.db "
SELECT
  did,
  type,
  serialNumber,
  isEncrypted
FROM certificates
WHERE hasPrivateKey = 1
"
```

### Check Certificate PEM (truncated)

```bash
sqlite3 ~/.atsms/messages.db "
SELECT
  did,
  type,
  serialNumber,
  substr(certificatePEM, 1, 50) || '...' as cert_preview
FROM certificates
"
```

## Combined Queries

### Conversations with Message Counts

```bash
sqlite3 ~/.atsms/messages.db "
SELECT
  c.id,
  c.participantIds,
  COUNT(m.id) as message_count,
  datetime(c.lastMessageAt) as last_message,
  c.unreadCount
FROM conversations c
LEFT JOIN messages m ON c.id = m.convoId
GROUP BY c.id
ORDER BY c.lastMessageAt DESC
"
```

### Latest Message in Each Conversation

```bash
sqlite3 ~/.atsms/messages.db "
SELECT
  c.id as convo_id,
  c.participantIds,
  substr(m.content, 1, 50) as last_message_preview,
  m.contentType,
  datetime(m.createdAt) as sent_at
FROM conversations c
LEFT JOIN messages m ON c.id = m.convoId
WHERE m.createdAt = (
  SELECT MAX(createdAt)
  FROM messages
  WHERE convoId = c.id
)
ORDER BY m.createdAt DESC
"
```

## Maintenance & Debugging

### Database Statistics

```bash
sqlite3 ~/.atsms/messages.db "
SELECT
  (SELECT COUNT(*) FROM conversations) as conversations,
  (SELECT COUNT(*) FROM messages) as messages,
  (SELECT COUNT(*) FROM certificates) as certificates
"
```

### Check for Orphaned Messages

```bash
sqlite3 ~/.atsms/messages.db "
SELECT
  m.id,
  m.convoId,
  substr(m.content, 1, 50) as content_preview,
  m.contentType
FROM messages m
LEFT JOIN conversations c ON m.convoId = c.id
WHERE c.id IS NULL
"
```

### Vacuum Database (Reclaim Space)

```bash
sqlite3 ~/.atsms/messages.db "VACUUM;"
```

### Check Database Integrity

```bash
sqlite3 ~/.atsms/messages.db "PRAGMA integrity_check;"
```

### Database File Size

```bash
ls -lh ~/.atsms/messages.db
```

## Cleanup Operations

### Delete All Messages in a Conversation

```bash
sqlite3 ~/.atsms/messages.db "
DELETE FROM messages
WHERE convoId = 'your-convo-id'
"
```

### Delete a Conversation (and its messages)

```bash
sqlite3 ~/.atsms/messages.db "
BEGIN TRANSACTION;
DELETE FROM messages WHERE convoId = 'your-convo-id';
DELETE FROM conversations WHERE id = 'your-convo-id';
COMMIT;
"
```

### Delete All Data (Reset Database)

```bash
sqlite3 ~/.atsms/messages.db "
DELETE FROM messages;
DELETE FROM conversations;
DELETE FROM certificates;
VACUUM;
"
```

### Delete Specific Certificate

```bash
sqlite3 ~/.atsms/messages.db "
DELETE FROM certificates
WHERE did = 'did:plc:xyz123' AND serialNumber = 'abc123'
"
```

## Export Data

### Export Conversations to CSV

```bash
sqlite3 ~/.atsms/messages.db <<EOF
.mode csv
.output conversations.csv
SELECT * FROM conversations;
.quit
EOF
```

### Export Messages to CSV

```bash
sqlite3 ~/.atsms/messages.db <<EOF
.mode csv
.output messages.csv
SELECT * FROM messages;
.quit
EOF
```

### Export to JSON (requires json1 extension)

```bash
sqlite3 ~/.atsms/messages.db "
SELECT json_group_array(
  json_object(
    'id', id,
    'participantIds', participantIds,
    'lastMessageAt', lastMessageAt,
    'unreadCount', unreadCount
  )
)
FROM conversations
"
```

## Advanced Queries

### Messages per Day

```bash
sqlite3 ~/.atsms/messages.db "
SELECT
  date(createdAt) as day,
  COUNT(*) as message_count
FROM messages
GROUP BY date(createdAt)
ORDER BY day DESC
"
```

### Most Active Conversations (by message count)

```bash
sqlite3 ~/.atsms/messages.db "
SELECT
  c.participantIds,
  COUNT(m.id) as message_count,
  datetime(MAX(m.createdAt)) as last_message
FROM conversations c
JOIN messages m ON c.id = m.convoId
GROUP BY c.id
ORDER BY message_count DESC
LIMIT 10
"
```

### Average Messages per Conversation

```bash
sqlite3 ~/.atsms/messages.db "
SELECT
  AVG(msg_count) as avg_messages_per_convo
FROM (
  SELECT COUNT(*) as msg_count
  FROM messages
  GROUP BY convoId
)
"
```

## Tips

1. **Always use transactions** for multiple related operations:
   ```sql
   BEGIN TRANSACTION;
   -- your queries here
   COMMIT;
   ```

2. **Use EXPLAIN QUERY PLAN** to optimize slow queries:
   ```sql
   EXPLAIN QUERY PLAN SELECT * FROM messages WHERE convoId = 'xyz';
   ```

3. **Create indexes** for frequently queried columns:
   ```sql
   CREATE INDEX idx_messages_convoId ON messages(convoId);
   CREATE INDEX idx_messages_createdAt ON messages(createdAt);
   ```

4. **Check if an index exists**:
   ```bash
   sqlite3 ~/.atsms/messages.db "PRAGMA index_list(messages);"
   ```

5. **Backup before cleanup operations**:
   ```bash
   cp ~/.atsms/messages.db ~/.atsms/messages.db.backup
   ```

## Common Issues

### Database Locked

If you see "database is locked", close all applications using the database, including:
- Running chat clients
- SQLite sessions
- Running tests

### Corrupted Database

```bash
# Check integrity
sqlite3 ~/.atsms/messages.db "PRAGMA integrity_check;"

# If corrupted, try to recover
sqlite3 ~/.atsms/messages.db ".recover" > recovered.sql
sqlite3 new_messages.db < recovered.sql
```

### Performance Issues

```bash
# Analyze database for query optimization
sqlite3 ~/.atsms/messages.db "ANALYZE;"

# Check query performance
sqlite3 ~/.atsms/messages.db "EXPLAIN QUERY PLAN SELECT * FROM messages WHERE convoId = 'xyz';"
```
