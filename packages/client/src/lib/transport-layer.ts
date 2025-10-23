/**
 * AT-SMS Transport Layer
 *
 * Unified abstraction for HTTP and WebSocket transports.
 * Intelligently chooses the best transport method for each operation.
 *
 * Features:
 * - Automatic fallback from WebSocket to HTTP
 * - Preference for WebSocket when available (more efficient)
 * - Consistent API regardless of underlying transport
 * - Connection state management
 */

import type { ATSMSApiClient } from './atsms-api'
import type {
  ATSMSListMessagesOptions,
  ATSMSListMessagesResponse,
  ATSMSSendMessageResponse,
  ATSMSSendRecipient,
  ATSMSStatsResponse,
  ATSMSTransportLayerConfig,
  ATSMSTransportMessage} from './types'
import type { ATSMSWebSocketClient } from './websocket-client'

/**
 * Unified transport layer that abstracts HTTP and WebSocket
 */
export class ATSMSTransportLayer {
  private config: ATSMSTransportLayerConfig
  private preferWebSocket: boolean

  constructor(config: ATSMSTransportLayerConfig) {
    this.config = config
    this.preferWebSocket = config.preferWebSocket ?? true
  }

  /**
   * Check if WebSocket is available and connected
   */
  private get canUseWebSocket(): boolean {
    return !!this.config.wsClient && this.config.wsClient.isConnected()
  }

  /**
   * List messages from the inbox
   * Uses WebSocket if available, falls back to HTTP
   */
  async listMessages(options: ATSMSListMessagesOptions = {}): Promise<ATSMSListMessagesResponse> {
    if (this.preferWebSocket && this.canUseWebSocket) {
      try {
        return await this.config.wsClient!.listMessages(options.after, options.limit)
      } catch (error) {
        // Fallback to HTTP on WebSocket error
        console.warn('WebSocket listMessages failed, falling back to HTTP:', error)
      }
    }

    // Use HTTP
    return await this.config.httpClient.listMessages(
      this.config.did,
      this.config.certSerial,
      options.after,
      options.limit
    )
  }

  /**
   * Get a specific message by ID
   * Uses WebSocket if available, falls back to HTTP
   */
  async getMessage(messageId: string): Promise<ATSMSTransportMessage> {
    if (this.preferWebSocket && this.canUseWebSocket) {
      try {
        const response = await this.config.wsClient!.getMessage(messageId)
        return response.message
      } catch (error) {
        // Fallback to HTTP on WebSocket error
        console.warn('WebSocket getMessage failed, falling back to HTTP:', error)
      }
    }

    // Use HTTP
    return await this.config.httpClient.downloadMessage(
      this.config.did,
      this.config.certSerial,
      messageId
    )
  }

  /**
   * Delete a message from the inbox
   * Uses WebSocket if available, falls back to HTTP
   */
  async deleteMessage(messageId: string): Promise<void> {
    if (this.preferWebSocket && this.canUseWebSocket) {
      try {
        await this.config.wsClient!.deleteMessage(messageId)
        return
      } catch (error) {
        // Fallback to HTTP on WebSocket error
        console.warn('WebSocket deleteMessage failed, falling back to HTTP:', error)
      }
    }

    // Use HTTP
    await this.config.httpClient.deleteMessage(
      this.config.did,
      this.config.certSerial,
      messageId
    )
  }

  /**
   * Get inbox statistics
   * Uses WebSocket if available, falls back to HTTP
   */
  async getStats(): Promise<ATSMSStatsResponse> {
    if (this.preferWebSocket && this.canUseWebSocket) {
      try {
        return await this.config.wsClient!.getStats()
      } catch (error) {
        // Fallback to HTTP on WebSocket error
        console.warn('WebSocket getStats failed, falling back to HTTP:', error)
      }
    }

    // Use HTTP
    return await this.config.httpClient.getStats(
      this.config.did,
      this.config.certSerial
    )
  }

  /**
   * Send a message to multiple recipients
   * Uses WebSocket if available and preferred, falls back to HTTP (stub)
   *
   * @param recipients - Array of recipient objects with DID, certSerial, and email
   * @param encryptedContent - Base64-encoded encrypted message content
   * @returns Send results for each recipient
   */
  async sendMessage(recipients: ATSMSSendRecipient[], encryptedContent: string): Promise<ATSMSSendMessageResponse> {
    if (this.preferWebSocket && this.canUseWebSocket) {
      try {
        return await this.config.wsClient!.sendMessage(recipients, encryptedContent)
      } catch (error) {
        // Fallback to HTTP on WebSocket error
        console.warn('WebSocket sendMessage failed, falling back to HTTP:', error)
      }
    }

    // Use HTTP (currently a stub that throws error)
    return await this.config.httpClient.sendMessage(recipients, encryptedContent)
  }

  /**
   * Update the WebSocket client
   * Useful when WebSocket connection state changes
   */
  setWebSocketClient(wsClient: ATSMSWebSocketClient | null): void {
    this.config.wsClient = wsClient || undefined
  }

  /**
   * Update preference for WebSocket transport
   */
  setPreferWebSocket(prefer: boolean): void {
    this.preferWebSocket = prefer
  }

  /**
   * Check if currently using WebSocket for operations
   */
  isUsingWebSocket(): boolean {
    return this.preferWebSocket && this.canUseWebSocket
  }

  /**
   * Get the underlying HTTP client (for advanced use cases)
   */
  get httpClient(): ATSMSApiClient {
    return this.config.httpClient
  }

  /**
   * Get the underlying WebSocket client (for advanced use cases)
   */
  get wsClient(): ATSMSWebSocketClient | undefined {
    return this.config.wsClient
  }
}
