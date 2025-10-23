/**
 * AT-SMS API Client
 * Handles all communication with the AT-SMS API over HTTP
 * This module is browser-compatible and only handles API interactions
 */

// Mailgun imports - commented out but preserved for reference
// import FormData from 'form-data'
// import Mailgun from 'mailgun.js'

import {
  type ATSMSConfig,
  type ATSMSListMessagesResponse,
  type ATSMSSendMessageResponse,
  type ATSMSSendRecipient,
  type ATSMSStatsResponse,
  type ATSMSTransportMessage,
} from './types'

export class ATSMSApiClient {
  public config: ATSMSConfig
  private authToken?: string
  // private mailgun: any

  constructor(config: ATSMSConfig) {
    this.config = config

    // Initialize Mailgun client - commented out but preserved
    /*
    const mg = new Mailgun(FormData)
    this.mailgun = mg.client({
      username: 'api',
      key: this.config.mailgunApiKey,
    })
    */
  }

  /**
   * Set the JWT authentication token
   */
  setAuthToken(token: string): void {
    this.authToken = token
  }

  /**
   * Get authorization headers
   */
  private getAuthHeaders(): Record<string, string> {
    if (!this.authToken) {
      return {}
    }
    return {
      'Authorization': `Bearer ${this.authToken}`
    }
  }

  /**
   * List messages for a specific DID and certificate
   * @param did - The DID of the user
   * @param certSerial - The certificate serial number
   * @param afterSequence - Optional sequence number to fetch messages after (for pagination)
   * @param limit - Maximum number of messages to return (default: 50, max: 100)
   */
  async listMessages(
    did: string,
    certSerial: string,
    afterSequence?: number,
    limit?: number
  ): Promise<ATSMSListMessagesResponse> {
    try {
      const url = new URL(`${this.config.apiUrl}/messages/${did}/${certSerial}/list`)
      if (afterSequence !== undefined) {
        url.searchParams.set('after', afterSequence.toString())
      }
      if (limit !== undefined) {
        url.searchParams.set('limit', limit.toString())
      }

      const response = await fetch(
        url.toString(),
        {
          headers: this.getAuthHeaders()
        }
      )

      if (!response.ok) {
        throw new Error(`API error: ${response.status} ${response.statusText}`)
      }

      return await response.json() as ATSMSListMessagesResponse
    } catch (error) {
      throw new Error(`Failed to list messages: ${error}`)
    }
  }

  /**
   * Download raw message (without decryption)
   */
  async downloadMessage(did: string, certSerial: string, messageId: string): Promise<ATSMSTransportMessage> {
    try {
      const response = await fetch(
        `${this.config.apiUrl}/messages/${did}/${certSerial}/${messageId}`,
        {
          headers: this.getAuthHeaders()
        }
      )

      if (!response.ok) {
        throw new Error(`API error: ${response.status} ${response.statusText}`)
      }

      // TODO: Fix this to use an API interface
      const downloadedMessage = await response.json() as { message: ATSMSTransportMessage }
      return downloadedMessage.message as ATSMSTransportMessage
    } catch (error) {
      throw new Error(`Failed to download message: ${error}`)
    }
  }

  /**
   * Get inbox statistics
   */
  async getStats(did: string, certSerial: string): Promise<ATSMSStatsResponse> {
    try {
      const response = await fetch(
        `${this.config.apiUrl}/messages/${did}/${certSerial}/stats`,
        {
          method: 'GET',
          headers: this.getAuthHeaders()
        }
      )

      if (!response.ok) {
        const errorText = await response.text()
        throw new Error(`Failed to get stats: ${response.status} ${response.statusText} - ${errorText}`)
      }

      return await response.json() as ATSMSStatsResponse
    } catch (error) {
      throw new Error(`Failed to get stats: ${error}`)
    }
  }

  /**
   * Delete a message
   */
  async deleteMessage(did: string, certSerial: string, messageId: string): Promise<void> {
    try {
      const response = await fetch(
        `${this.config.apiUrl}/messages/${did}/${certSerial}/${messageId}`,
        {
          method: 'DELETE',
          headers: this.getAuthHeaders()
        }
      )

      if (!response.ok) {
        const errorText = await response.text()
        throw new Error(`Failed to delete message: ${response.status} ${response.statusText} - ${errorText}`)
      }
    } catch (error) {
      throw new Error(`Failed to delete message: ${error}`)
    }
  }

  /**
   * Send encrypted message via ATSMS API (HTTPS)
   *
   * NOTE: This is a stub implementation for the new multi-recipient send API.
   * The HTTPS version is not yet implemented on the server.
   * Use WebSocket send instead (via transport layer).
   *
   * @param recipients - Array of recipient objects with DID, certSerial, and email
   * @param encryptedContent - The encrypted message content (base64 encoded)
   * @throws Error indicating HTTPS send is not yet implemented
   */
  async sendMessage(
    _recipients: ATSMSSendRecipient[],
    _encryptedContent: string
  ): Promise<ATSMSSendMessageResponse> {
    // Stub: HTTPS send endpoint not yet implemented on server
    // When implemented, it should POST to /send-message with the new format
    throw new Error(
      'HTTPS send-message endpoint not yet implemented. ' +
      'Use WebSocket send instead (transport layer will handle this automatically).'
    )

    // Future implementation (when server supports it):
    /*
    try {
      const url = `${this.config.apiUrl}/send-message`

      const response = await fetch(url, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          ...this.getAuthHeaders()
        },
        body: JSON.stringify({
          to: recipients,
          encryptedContent: encryptedContent
        }),
      })

      if (!response.ok) {
        const errorText = await response.text()
        throw new Error(`API error: ${response.status} ${response.statusText} ${errorText}`)
      }

      return await response.json()
    } catch (error) {
      throw new Error(`Failed to send message: ${error}`)
    }
    */
  }

  /**
   * Legacy send message method (single recipient)
   * Kept for backward compatibility during transition
   * @deprecated Use sendMessage with recipients array instead
   */
  async sendMessageLegacy(
    recipientDID: string,
    encryptedContent: string
  ): Promise<void> {
    try {
      // Use the old /send-message endpoint (if still supported)
      const url = `${this.config.apiUrl}/send-message`

      const response = await fetch(url, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          ...this.getAuthHeaders()
        },
        body: JSON.stringify({
          did: recipientDID,
          encryptedContent: encryptedContent
        }),
      })

      if (!response.ok) {
        const errorText = await response.text()
        console.error(`API error response: ${response.status} ${response.statusText} ${errorText}`)
        throw new Error(`API error: ${response.status} ${response.statusText} ${errorText}`)
      }
    } catch (error) {
      throw new Error(`Failed to send message: ${error}`)
    }
  }

}