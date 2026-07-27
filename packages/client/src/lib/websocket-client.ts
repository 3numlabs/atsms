/**
 * WebSocket client for real-time message notifications and API operations
 * Supports both browser and Node.js environments with dual authentication paths
 * Now includes request/response pattern for WebSocket-based API calls
 *
 * NOTE: This file contains a dynamic import for the 'ws' package (Node.js WebSocket).
 * This is necessary because:
 * - Browser environments have native WebSocket support
 * - Node.js requires the 'ws' package
 * - The import must be conditional based on runtime environment
 * - Static imports would break browser builds
 */

// Declare minimal global types we need for browser detection
// This avoids requiring DOM lib in tsconfig while still supporting browser builds
declare const window: { WebSocket?: typeof WebSocket } | undefined;

import type {
  ATSMSDeleteMessageResponse,
  ATSMSGetMessageResponse,
  ATSMSListMessagesResponse,
  ATSMSSendMessageResponse,
  ATSMSSendRecipient,
  ATSMSStatsResponse,
} from "./types";

export interface ATSMSWebSocketMessage {
  type: string;
  [key: string]: any;
}

export interface ATSMSWebSocketClientConfig {
  apiUrl: string;
  did: string;
  /** Device fingerprint (lowercase hex) — the per-device inbox key. */
  deviceFingerprint: string;
  getToken: () => Promise<string> | string;
  onMessage?: (message: ATSMSWebSocketMessage) => void;
  onConnect?: () => void;
  onDisconnect?: (code: number, reason: string) => void;
  onError?: (error: Error) => void;
  reconnectDelay?: number;
  maxReconnectAttempts?: number;
  logger?: {
    log: (message: string) => void;
    error: (message: string, error?: any) => void;
  };
}

interface PendingRequest {
  resolve: (value: any) => void;
  reject: (error: Error) => void;
  timeout: any;
}

export class ATSMSWebSocketClient {
  private config: ATSMSWebSocketClientConfig;
  private ws: (WebSocket | any) | null = null;
  private authenticated = false;
  private messageQueue: ATSMSWebSocketMessage[] = [];
  private reconnectAttempts = 0;
  private reconnectTimer: any = null;
  private pingInterval: any = null;
  private isBrowser: boolean;
  private logger: {
    log: (msg: string) => void;
    error: (msg: string, err?: any) => void;
  };

  // Request/response tracking for WebSocket API calls
  private pendingRequests = new Map<string, PendingRequest>();
  private requestIdCounter = 0;
  private readonly REQUEST_TIMEOUT = 30000; // 30 seconds

  constructor(config: ATSMSWebSocketClientConfig) {
    this.config = {
      reconnectDelay: 5000,
      maxReconnectAttempts: 5,
      ...config,
    };

    // Use provided logger or default to console
    this.logger = config.logger || {
      log: (msg: string) => console.log(msg),
      error: (msg: string, err?: any) => console.error(msg, err),
    };

    // Detect environment
    this.isBrowser =
      typeof window !== "undefined" && typeof window.WebSocket !== "undefined";
  }

  /**
   * Connect to the WebSocket server
   */
  async connect(): Promise<void> {
    try {
      // URL encode the DID and cert serial (DIDs contain colons which need encoding)
      const encodedDid = encodeURIComponent(this.config.did);
      const encodedDeviceFingerprint = encodeURIComponent(this.config.deviceFingerprint);
      const wsUrl = `${this.config.apiUrl.replace("https://", "wss://").replace("http://", "ws://")}/ws/${encodedDid}/${encodedDeviceFingerprint}`;

      if (this.isBrowser) {
        // Browser: Use post-connection authentication
        this.ws = new WebSocket(wsUrl);
        this.setupBrowserHandlers();
      } else {
        // Node.js: Use post-connection authentication (same as browser)
        // Dynamic import for Node.js WebSocket
        const WebSocketModule = await import("ws");
        const NodeWebSocket =
          WebSocketModule.default || WebSocketModule.WebSocket;

        this.ws = new NodeWebSocket(wsUrl) as any;
        this.setupNodeHandlers();
      }
    } catch (error) {
      this.handleError(new Error(`Failed to connect: ${error}`));
      this.scheduleReconnect();
    }
  }

  /**
   * Setup event handlers for browser WebSocket
   */
  private setupBrowserHandlers(): void {
    if (!this.ws) return;

    this.ws.onopen = async () => {
      this.logger.log("WebSocket connected, authenticating...");

      // Send authentication immediately
      try {
        const token = await this.getToken();
        this.send({
          type: "auth",
          token: token,
        });
      } catch (error) {
        this.logger.error("Failed to get auth token:", error);
        this.ws?.close();
      }
    };

    this.ws.onmessage = (event: MessageEvent) => {
      this.handleMessage(event.data);
    };

    this.ws.onclose = (event: CloseEvent) => {
      this.handleClose(event.code, event.reason);
    };

    this.ws.onerror = (_event: Event) => {
      this.handleError(new Error("WebSocket error"));
    };
  }

  /**
   * Setup event handlers for Node.js WebSocket
   */
  private setupNodeHandlers(): void {
    if (!this.ws) return;

    this.ws.on("open", async () => {
      // Send authentication immediately
      try {
        const token = await this.getToken();
        this.send({
          type: "auth",
          token: token,
        });
      } catch (error) {
        this.logger.error("Failed to get auth token:", error);
        this.ws?.close();
      }
    });

    this.ws.on("message", (data: any) => {
      this.handleMessage(data.toString());
    });

    this.ws.on("close", (code: number, reason: Buffer) => {
      this.handleClose(code, reason?.toString() || "");
    });

    this.ws.on("error", (error: Error) => {
      this.handleError(error);
    });
  }

  /**
   * Handle incoming messages
   */
  private async handleMessage(data: string): Promise<void> {
    try {
      const message = JSON.parse(data) as ATSMSWebSocketMessage;

      // Handle authentication responses
      if (message.type === "auth_required") {
        // Respond with auth token (for both browser and Node.js)
        if (!this.authenticated) {
          try {
            const token = await this.getToken();
            this.send({
              type: "auth",
              token: token,
            });
          } catch (error) {
            this.logger.error("Failed to get auth token:", error);
            this.ws?.close();
          }
        }
        return;
      }

      if (message.type === "auth_success") {
        this.authenticated = true;
        this.onConnected();
        return;
      }

      if (message.type === "connected") {
        if (message.authenticated) {
          this.authenticated = true;
          this.onConnected();
        } else {
          // Server says we're not authenticated yet - send auth message
          if (!this.authenticated) {
            try {
              const token = await this.getToken();
              this.send({
                type: "auth",
                token: token,
              });
            } catch (error) {
              this.logger.error("Failed to get auth token:", error);
              this.ws?.close();
            }
          }
        }
        return;
      }

      // Handle pong responses
      if (message.type === "pong") {
        // Pong received, connection is alive
        return;
      }

      // Handle API responses (list_response, get_response, delete_response, stats_response, error)
      if (message.requestId && this.pendingRequests.has(message.requestId)) {
        const pending = this.pendingRequests.get(message.requestId)!;
        this.pendingRequests.delete(message.requestId);
        clearTimeout(pending.timeout);

        if (message.type === "error") {
          pending.reject(new Error(message.error || "Unknown error"));
        } else {
          pending.resolve(message);
        }
        return;
      }

      // Pass other messages to the handler (new_message notifications, etc.)
      if (this.authenticated && this.config.onMessage) {
        this.config.onMessage(message);
      }
    } catch (error) {
      this.logger.error("Error parsing WebSocket message:", error);
    }
  }

  /**
   * Handle connection established and authenticated
   */
  private onConnected(): void {
    this.reconnectAttempts = 0;
    this.flushMessageQueue();
    this.startPingInterval();

    if (this.config.onConnect) {
      this.config.onConnect();
    }
  }

  /**
   * Handle connection close
   */
  private handleClose(code: number, reason: string): void {
    this.logger.log(`WebSocket closed: ${code} - ${reason}`);

    this.authenticated = false;
    this.ws = null;
    this.stopPingInterval();

    // Reject all pending requests
    const error = new Error(`WebSocket closed: ${code} - ${reason}`);
    for (const [_requestId, pending] of this.pendingRequests.entries()) {
      clearTimeout(pending.timeout);
      pending.reject(error);
    }
    this.pendingRequests.clear();

    if (this.config.onDisconnect) {
      this.config.onDisconnect(code, reason);
    }

    // Don't reconnect for intentional disconnects or auth failures
    if (code === 1000 || code === 1008) {
      // 1000 = Normal Closure (intentional disconnect)
      // 1008 = Policy Violation (authentication failure)
      return;
    }

    // Schedule reconnection for other close codes (unexpected disconnects)
    this.scheduleReconnect();
  }

  /**
   * Handle errors
   */
  private handleError(error: Error): void {
    this.logger.error("WebSocket error:", error);

    if (this.config.onError) {
      this.config.onError(error);
    }
  }

  /**
   * Send a message
   */
  send(message: ATSMSWebSocketMessage): void {
    if (!this.ws) {
      this.logger.error("WebSocket not connected");
      return;
    }

    // Queue messages if not authenticated (except auth messages)
    if (!this.authenticated && message.type !== "auth") {
      this.messageQueue.push(message);
      return;
    }

    try {
      this.ws.send(JSON.stringify(message));
    } catch (error) {
      this.logger.error("Failed to send message:", error);
      this.messageQueue.push(message);
    }
  }

  /**
   * Flush queued messages
   */
  private flushMessageQueue(): void {
    while (this.messageQueue.length > 0) {
      const message = this.messageQueue.shift();
      if (message) {
        this.send(message);
      }
    }
  }

  /**
   * Start ping interval for keepalive
   */
  private startPingInterval(): void {
    this.stopPingInterval();

    this.pingInterval = setInterval(() => {
      if (this.authenticated) {
        // NOTE: This application layer ping must only contain '{"type":"ping"}' in order for it to be handled
        // by the the Cloudlare WabSocket Hibernation API
        // this.state.setWebSocketAutoResponse(
        //   new WebSocketRequestResponsePair('{"type":"ping"}', '{"type":"pong"}')
        // );

        this.send({ type: "ping" });
      }
    }, 30000); // Ping every 30 seconds
  }

  /**
   * Stop ping interval
   */
  private stopPingInterval(): void {
    if (this.pingInterval) {
      clearInterval(this.pingInterval);
      this.pingInterval = null;
    }
  }

  /**
   * Schedule reconnection
   */
  private scheduleReconnect(): void {
    if (this.reconnectAttempts >= this.config.maxReconnectAttempts!) {
      this.logger.error("Max reconnection attempts reached");
      return;
    }

    if (this.reconnectTimer) {
      clearTimeout(this.reconnectTimer);
    }

    this.reconnectAttempts++;
    const delay =
      this.config.reconnectDelay! * Math.pow(2, this.reconnectAttempts - 1);

    this.logger.log(
      `Reconnecting in ${delay}ms (attempt ${this.reconnectAttempts}/${this.config.maxReconnectAttempts})`,
    );

    this.reconnectTimer = setTimeout(() => {
      this.connect();
    }, delay);
  }

  /**
   * Get authentication token
   */
  private async getToken(): Promise<string> {
    const token = await this.config.getToken();
    if (!token) {
      throw new Error("No authentication token available");
    }
    return token;
  }

  /**
   * Disconnect from the server
   */
  disconnect(): void {
    if (this.reconnectTimer) {
      clearTimeout(this.reconnectTimer);
      this.reconnectTimer = null;
    }

    this.stopPingInterval();
    this.reconnectAttempts = this.config.maxReconnectAttempts!; // Prevent auto-reconnect

    // Reject all pending requests
    const error = new Error("WebSocket disconnected by client");
    for (const [_requestId, pending] of this.pendingRequests.entries()) {
      clearTimeout(pending.timeout);
      pending.reject(error);
    }
    this.pendingRequests.clear();

    if (this.ws) {
      this.ws.close(1000, "Client disconnect");
      this.ws = null;
    }

    this.authenticated = false;
    this.messageQueue = [];
  }

  /**
   * Check if connected and authenticated
   */
  isConnected(): boolean {
    return this.ws !== null && this.authenticated;
  }

  /**
   * Check if WebSocket is authenticated
   * Note: isConnected() already includes authentication check
   */
  isAuthenticated(): boolean {
    return this.authenticated;
  }

  /**
   * Helper method to send a request and wait for response
   */
  private sendRequest<T>(
    type: string,
    data: Record<string, any> = {},
  ): Promise<T> {
    return new Promise((resolve, reject) => {
      if (!this.isConnected()) {
        reject(new Error("WebSocket not connected or authenticated"));
        return;
      }

      const requestId = `req_${++this.requestIdCounter}_${Date.now()}`;

      const timeout = setTimeout(() => {
        this.pendingRequests.delete(requestId);
        reject(new Error(`Request timeout: ${type}`));
      }, this.REQUEST_TIMEOUT);

      this.pendingRequests.set(requestId, { resolve, reject, timeout });

      this.send({
        type,
        requestId,
        ...data,
      });
    });
  }

  /**
   * List messages via WebSocket
   */
  async listMessages(
    after?: number,
    limit?: number,
  ): Promise<ATSMSListMessagesResponse> {
    const response = await this.sendRequest<any>("list", { after, limit });
    return {
      messages: response.messages || [],
      latestSeq: response.latestSeq || 0,
      hasMore: response.hasMore || false,
      totalCount: response.totalCount || 0,
    };
  }

  /**
   * Get a specific message via WebSocket
   */
  async getMessage(messageId: string): Promise<ATSMSGetMessageResponse> {
    const response = await this.sendRequest<any>("get", { messageId });
    return {
      message: response.message,
    };
  }

  /**
   * Delete a message via WebSocket
   */
  async deleteMessage(messageId: string): Promise<ATSMSDeleteMessageResponse> {
    const response = await this.sendRequest<any>("delete", { messageId });
    return {
      success: response.success || false,
      messageId: response.messageId || messageId,
    };
  }

  /**
   * Get inbox statistics via WebSocket
   */
  async getStats(): Promise<ATSMSStatsResponse> {
    const response = await this.sendRequest<any>("stats");
    return {
      messageCount: response.messageCount || 0,
      latestSeq: response.latestSeq || 0,
      connectedClients: response.connectedClients || 0,
    };
  }

  /**
   * Send a message via WebSocket
   * @param recipients - Array of recipient objects with DID, certSerial, and email
   * @param encryptedContent - Base64-encoded encrypted message content
   */
  async sendMessage(
    recipients: ATSMSSendRecipient[],
    encryptedContent: string,
  ): Promise<ATSMSSendMessageResponse> {
    const response = await this.sendRequest<any>("send", {
      to: recipients,
      encryptedContent,
    });
    return {
      results: response.results || [],
    };
  }
}
