/**
 * Tests for SQLite Storage Adapter
 */

import { Database } from 'bun:sqlite'
import { afterAll, beforeEach, describe, expect, test } from 'bun:test'
import { firstValueFrom, skip, take } from 'rxjs'

import { createTextContent } from '../lib/messages'
import { SQLiteAdapter } from '../lib/storage/sqlite-adapter'
import type { LocalConversation, LocalMessage } from '../lib/storage/types'

// Create a mock SQLite database interface that matches our requirements
class BunSQLiteWrapper {
  private db: Database

  constructor() {
    this.db = new Database(':memory:')
  }

  exec(sql: string): void {
    this.db.exec(sql)
  }

  prepare(sql: string) {
    const stmt = this.db.prepare(sql)
    return {
      run: (...params: any[]) => stmt.run(...params),
      get: (...params: any[]) => stmt.get(...params),
      all: (...params: any[]) => stmt.all(...params),
    }
  }

  transaction<T>(fn: () => T): T {
    return this.db.transaction(fn)()
  }

  close() {
    this.db.close()
  }
}

describe('SQLiteAdapter', () => {
  let db: BunSQLiteWrapper
  let adapter: SQLiteAdapter

  beforeEach(() => {
    db = new BunSQLiteWrapper()
    adapter = new SQLiteAdapter(db as any)
  })

  afterAll(() => {
    db?.close()
  })

  describe('Message Operations', () => {
    const testMessage: LocalMessage = {
      id: 'msg-001',
      convoId: 'convo-001',
      senderId: 'did:plc:sender123',
      recipientIds: ['did:plc:recipient123'],
      content: createTextContent('Hello, world!'),
      contentType: 'atsms/text',
      createdAt: new Date('2024-01-01T12:00:00Z'),
      isInvitation: false,
    }

    test('should save and retrieve a message', async () => {
      await adapter.saveMessage(testMessage)
      const retrieved = await adapter.getMessage(testMessage.id)

      expect(retrieved).toBeDefined()
      expect(retrieved?.id).toBe(testMessage.id)
      expect(retrieved?.content).toBe(testMessage.content)
      expect(retrieved?.contentType).toBe(testMessage.contentType)
      expect(retrieved?.senderId).toBe(testMessage.senderId)
      expect(retrieved?.recipientIds).toEqual(testMessage.recipientIds)
    })

    test('should return null for non-existent message', async () => {
      const message = await adapter.getMessage('non-existent')
      expect(message).toBeNull()
    })

    test('should update a message', async () => {
      await adapter.saveMessage(testMessage)

      const updates = {
        content: createTextContent('Updated message'),
        contentType: 'atsms/text',
        metadata: { edited: true }
      }

      await adapter.updateMessage(testMessage.id, updates)
      const updated = await adapter.getMessage(testMessage.id)

      expect(updated?.content).toBe(updates.content)
      expect(updated?.metadata).toEqual(updates.metadata)
    })

    test('should delete a message', async () => {
      await adapter.saveMessage(testMessage)
      await adapter.deleteMessage(testMessage.id)

      const deleted = await adapter.getMessage(testMessage.id)
      expect(deleted).toBeNull()
    })

    test('should get messages by conversation', async () => {
      const messages: LocalMessage[] = [
        { ...testMessage, id: 'msg-001', createdAt: new Date('2024-01-01T10:00:00Z') },
        { ...testMessage, id: 'msg-002', createdAt: new Date('2024-01-01T11:00:00Z') },
        { ...testMessage, id: 'msg-003', createdAt: new Date('2024-01-01T12:00:00Z') },
      ]

      for (const msg of messages) {
        await adapter.saveMessage(msg)
      }

      const retrieved = await adapter.getMessages('convo-001')
      expect(retrieved).toHaveLength(3)
      // Messages are returned in ascending order (oldest first) after being reversed
      expect(retrieved[0].id).toBe('msg-001') // Oldest first
      expect(retrieved[1].id).toBe('msg-002')
      expect(retrieved[2].id).toBe('msg-003') // Most recent last
    })

    test('should limit message retrieval', async () => {
      const messages: LocalMessage[] = Array.from({ length: 10 }, (_, i) => ({
        ...testMessage,
        id: `msg-${i.toString().padStart(3, '0')}`,
        createdAt: new Date(Date.now() - i * 1000),
      }))

      for (const msg of messages) {
        await adapter.saveMessage(msg)
      }

      const limited = await adapter.getMessages('convo-001', 5)
      expect(limited).toHaveLength(5)
    })

    test('should save multiple messages at once', async () => {
      const messages: LocalMessage[] = [
        { ...testMessage, id: 'bulk-001' },
        { ...testMessage, id: 'bulk-002' },
        { ...testMessage, id: 'bulk-003' },
      ]

      await adapter.saveMessages(messages)

      for (const msg of messages) {
        const saved = await adapter.getMessage(msg.id)
        expect(saved).toBeDefined()
        expect(saved?.id).toBe(msg.id)
      }
    })
  })

  describe('Conversation Operations', () => {
    const testConversation: LocalConversation = {
      id: 'convo-001',
      participantIds: ['did:plc:user1', 'did:plc:user2'],
      createdAt: new Date('2024-01-01T10:00:00Z'),
      lastMessageAt: new Date('2024-01-01T12:00:00Z'),
      unreadCount: 0,
      metadata: {
        title: 'Test Conversation',
        isGroup: false,
      },
    }

    test('should save and retrieve a conversation', async () => {
      await adapter.saveConversation(testConversation)
      const retrieved = await adapter.getConversation(testConversation.id)

      expect(retrieved).toBeDefined()
      expect(retrieved?.id).toBe(testConversation.id)
      expect(retrieved?.participantIds).toEqual(testConversation.participantIds)
      expect(retrieved?.metadata?.title).toBe('Test Conversation')
    })

    test('should return null for non-existent conversation', async () => {
      const conversation = await adapter.getConversation('non-existent')
      expect(conversation).toBeNull()
    })

    test('should update a conversation', async () => {
      await adapter.saveConversation(testConversation)

      const updates = {
        unreadCount: 5,
        lastMessageAt: new Date('2024-01-02T00:00:00Z'),
        metadata: { title: 'Updated Title', isGroup: true }
      }

      await adapter.updateConversation(testConversation.id, updates)
      const updated = await adapter.getConversation(testConversation.id)

      expect(updated?.unreadCount).toBe(5)
      expect(updated?.metadata?.title).toBe('Updated Title')
      expect(updated?.metadata?.isGroup).toBe(true)
    })

    test('should delete a conversation', async () => {
      await adapter.saveConversation(testConversation)
      await adapter.deleteConversation(testConversation.id)

      const deleted = await adapter.getConversation(testConversation.id)
      expect(deleted).toBeNull()
    })

    test('should get conversations sorted by lastMessageAt', async () => {
      const conversations: LocalConversation[] = [
        { ...testConversation, id: 'convo-001', lastMessageAt: new Date('2024-01-01T10:00:00Z') },
        { ...testConversation, id: 'convo-002', lastMessageAt: new Date('2024-01-01T12:00:00Z') },
        { ...testConversation, id: 'convo-003', lastMessageAt: new Date('2024-01-01T11:00:00Z') },
      ]

      for (const convo of conversations) {
        await adapter.saveConversation(convo)
      }

      const retrieved = await adapter.getConversations()
      expect(retrieved).toHaveLength(3)
      expect(retrieved[0].id).toBe('convo-002') // Most recent first
      expect(retrieved[1].id).toBe('convo-003')
      expect(retrieved[2].id).toBe('convo-001') // Oldest last
    })

    test('should limit conversation retrieval', async () => {
      const conversations: LocalConversation[] = Array.from({ length: 10 }, (_, i) => ({
        ...testConversation,
        id: `convo-${i.toString().padStart(3, '0')}`,
        lastMessageAt: new Date(Date.now() - i * 1000),
      }))

      for (const convo of conversations) {
        await adapter.saveConversation(convo)
      }

      const limited = await adapter.getConversations(5)
      expect(limited).toHaveLength(5)
    })
  })

  describe('Sync Operations', () => {
    test('should save and retrieve sync revision', async () => {
      const rev = 'rev-123456789'
      await adapter.setLastSyncRev(rev)
      const retrieved = await adapter.getLastSyncRev()
      expect(retrieved).toBe(rev)
    })

    test('should return null for unset sync revision', async () => {
      const rev = await adapter.getLastSyncRev()
      expect(rev).toBeNull()
    })

    test('should update sync revision', async () => {
      await adapter.setLastSyncRev('rev-001')
      await adapter.setLastSyncRev('rev-002')
      const retrieved = await adapter.getLastSyncRev()
      expect(retrieved).toBe('rev-002')
    })
  })

  describe('Bulk Operations', () => {
    test('should clear all data', async () => {
      // Add some data
      const message: LocalMessage = {
        id: 'msg-clear',
        convoId: 'convo-clear',
        senderId: 'did:plc:sender',
        recipientIds: ['did:plc:recipient'],
        content: createTextContent('To be cleared'),
        contentType: 'atsms/text',
        createdAt: new Date(),
      }

      const conversation: LocalConversation = {
        id: 'convo-clear',
        participantIds: ['did:plc:user1'],
        createdAt: new Date(),
        lastMessageAt: new Date(),
        unreadCount: 0,
      }

      await adapter.saveMessage(message)
      await adapter.saveConversation(conversation)
      await adapter.setLastSyncRev('rev-clear')

      // Clear all
      await adapter.clearAll()

      // Verify everything is gone
      const msg = await adapter.getMessage('msg-clear')
      const convo = await adapter.getConversation('convo-clear')
      const rev = await adapter.getLastSyncRev()

      expect(msg).toBeNull()
      expect(convo).toBeNull()
      expect(rev).toBeNull()
    })
  })

  describe('LiveQuery Support', () => {
    test('should observe conversations', async () => {
      const conversation: LocalConversation = {
        id: 'convo-live',
        participantIds: ['did:plc:user1'],
        createdAt: new Date(),
        lastMessageAt: new Date(),
        unreadCount: 0,
      }

      const observable = adapter.observeConversations()

      // Skip initial emission and take next
      const promise = firstValueFrom(observable.pipe(skip(1), take(1)))

      await adapter.saveConversation(conversation)

      const result = await promise
      expect(result).toHaveLength(1)
      expect(result[0].id).toBe('convo-live')
    })

    test('should observe messages for a conversation', async () => {
      const message: LocalMessage = {
        id: 'msg-live',
        convoId: 'convo-observe',
        senderId: 'did:plc:sender',
        recipientIds: ['did:plc:recipient'],
        content: createTextContent('Observable message'),
        contentType: 'atsms/text',
        createdAt: new Date(),
      }

      const observable = adapter.observeMessages('convo-observe')

      // Skip initial emission and take next
      const promise = firstValueFrom(observable.pipe(skip(1), take(1)))

      await adapter.saveMessage(message)

      const result = await promise
      expect(result).toHaveLength(1)
      expect(result[0].id).toBe('msg-live')
    })

    test('should observe a specific conversation', async () => {
      const conversation: LocalConversation = {
        id: 'convo-specific',
        participantIds: ['did:plc:user1'],
        createdAt: new Date(),
        lastMessageAt: new Date(),
        unreadCount: 2,
      }

      const observable = adapter.observeConversation('convo-specific')

      // Skip initial emission and take next
      const promise = firstValueFrom(observable.pipe(skip(1), take(1)))

      await adapter.saveConversation(conversation)

      const result = await promise
      expect(result).toBeDefined()
      expect(result?.id).toBe('convo-specific')
      expect(result?.unreadCount).toBe(2)
    })

    test('should emit updates when conversation is updated', async () => {
      const conversation: LocalConversation = {
        id: 'convo-update-obs',
        participantIds: ['did:plc:user1'],
        createdAt: new Date(),
        lastMessageAt: new Date(),
        unreadCount: 0,
      }

      await adapter.saveConversation(conversation)

      const observable = adapter.observeConversation('convo-update-obs')

      // Skip initial emission and take next
      const promise = firstValueFrom(observable.pipe(skip(1), take(1)))

      await adapter.updateConversation('convo-update-obs', { unreadCount: 5 })

      const result = await promise
      expect(result?.unreadCount).toBe(5)
    })
  })

  describe('Edge Cases', () => {
    test('should handle empty recipientIds array', async () => {
      const message: LocalMessage = {
        id: 'msg-empty-recipients',
        convoId: 'convo-001',
        senderId: 'did:plc:sender',
        recipientIds: [],
        content: createTextContent('No recipients'),
        contentType: 'atsms/text',
        createdAt: new Date(),
      }

      await adapter.saveMessage(message)
      const retrieved = await adapter.getMessage(message.id)

      expect(retrieved).toBeDefined()
      expect(retrieved?.recipientIds).toEqual([])
    })

    test('should handle special characters in text', async () => {
      const message: LocalMessage = {
        id: 'msg-special',
        convoId: 'convo-001',
        senderId: 'did:plc:sender',
        recipientIds: ['did:plc:recipient'],
        content: createTextContent('Special chars: "\'<>&\n\t\\'),
        contentType: 'atsms/text',
        createdAt: new Date(),
        isInvitation: false,
      }

      await adapter.saveMessage(message)
      const retrieved = await adapter.getMessage(message.id)

      expect(retrieved?.content).toBe(message.content)
    })

    test('should handle null metadata gracefully', async () => {
      const conversation: LocalConversation = {
        id: 'convo-null-meta',
        participantIds: ['did:plc:user1'],
        createdAt: new Date(),
        lastMessageAt: new Date(),
        unreadCount: 0,
        metadata: undefined,
      }

      await adapter.saveConversation(conversation)
      const retrieved = await adapter.getConversation(conversation.id)

      expect(retrieved).toBeDefined()
      expect(retrieved?.metadata).toBeUndefined()
    })

    test('should handle pagination with cursor', async () => {
      const messages: LocalMessage[] = Array.from({ length: 20 }, (_, i) => ({
        id: `msg-${i.toString().padStart(3, '0')}`,
        convoId: 'convo-paginated',
        senderId: 'did:plc:sender',
        recipientIds: ['did:plc:recipient'],
        content: createTextContent(`Message ${i}`),
        contentType: 'atsms/text',
        createdAt: new Date(Date.now() - i * 1000),
      }))

      for (const msg of messages) {
        await adapter.saveMessage(msg)
      }

      // Get first page
      const firstPage = await adapter.getMessages('convo-paginated', 5)
      expect(firstPage).toHaveLength(5)

      // Use last message ID as cursor for next page
      const cursor = firstPage[4].id
      const secondPage = await adapter.getMessages('convo-paginated', 5, cursor)
      expect(secondPage).toHaveLength(5)
      expect(secondPage[0].id).not.toBe(firstPage[0].id)
    })
  })
})