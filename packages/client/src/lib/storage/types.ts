/**
 * AT-SMS Storage Types
 *
 * Core types for local encrypted message storage
 */

import type { ATSMSMessagePayload } from '../types'

export interface LocalMessage {
  id: string // Unique message ID
  convoId: string // Explicit conversation ID
  senderId: string // DID of sender
  recipientIds: string[] // DIDs of all recipients
  content: string // JSON-serialized content (same as wire format)
  contentType: string // MIME type, e.g., "atsms/text"
  createdAt: Date // When message was sent (Date object, not string)
  isInvitation: boolean // True if this starts a new conversation
  reactions?: Reaction[] // Decrypted reactions
  metadata?: MessageMetadata
}

export interface LocalConversation {
  id: string // Conversation ID
  participantIds: string[] // All participant DIDs
  createdAt: Date
  lastMessageAt: Date
  acceptedAt?: Date // When user accepted the conversation
  mutedUntil?: Date
  unreadCount: number
  lastRev?: string // Last sync revision
  metadata?: ConversationMetadata
}

export interface Reaction {
  senderId: string
  emoji: string
  createdAt: Date
}

export interface MessageMetadata {
  embeds?: any[]
  facets?: any[]
  edited?: boolean
  editedAt?: Date
}

export interface ConversationMetadata {
  title?: string
  isGroup?: boolean
  pinnedAt?: Date
}

export interface ConversationFilter {
  status?: 'accepted' | 'request' | 'all'
  unreadOnly?: boolean
  participantDid?: string
}

/**
 * DID information stored in local database
 */
export interface ATSMSDidInfo {
  did: string
  handle: string
  certSerial: string
  isPrimary: boolean  // First DID saved is primary
  createdAt: Date
  lastUsedAt: Date
}

/**
 * Helper to convert ATSMSMessagePayload to LocalMessage
 */
export function payloadToLocalMessage(
  payload: ATSMSMessagePayload,
  isInvitation: boolean = false
): LocalMessage {
  return {
    id: payload.id,
    convoId: payload.convoId,
    senderId: payload.senderId,
    recipientIds: payload.recipientIds,
    content: payload.content,
    contentType: payload.contentType,
    createdAt: new Date(payload.createdAt),
    isInvitation,
  }
}