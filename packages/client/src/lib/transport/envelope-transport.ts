/**
 * Envelope transport (sdk-shape.md "shared plumbing"; inbound-delivery.md) —
 * carries opaque `SealedEnvelope`s to and from DIDs. Two directions:
 *
 * - **outbound**: anonymous `POST { envelope: base64 }` — to a DID's public
 *   `at.atsms.inbox` `https:` endpoint (welcome channel / first contact) or to
 *   an in-band advertised URL (non-welcome, sealed-sender §12). The transport
 *   never learns what an envelope is; it addresses *destinations*.
 * - **inbound**: this device's per-certificate worker inbox — JWT-authed
 *   `?type=atsms-envelope` backfill plus WebSocket push; each envelope is
 *   handed to the dispatcher and deleted from the inbox once the handler
 *   returns (a failed handler leaves it for the next drain).
 */

import { generateJWT } from "../jwt-auth.js";
import { ATSMSWebSocketClient } from "../websocket-client.js";

/** Carries sealed envelopes; implementations: worker HTTP/WS, loopback (tests). */
export interface EnvelopeTransport {
  /** This device's own ingress URL — what conversations advertise in-band
   *  (sealed-sender §12), or null if the transport has no HTTPS ingress. */
  readonly ingressUrl: string | null;
  /** Deliver to an explicit `https:` ingress URL (in-band advert). */
  deliverToUrl(url: string, envelope: Uint8Array): Promise<void>;
  /** Deliver to a DID's public inbox (resolves its `at.atsms.inbox` record). */
  deliverToDid(did: string, envelope: Uint8Array): Promise<void>;
  /** Begin receiving: every inbound envelope is passed to `onEnvelope`
   *  (serially); the envelope is acknowledged when the handler resolves. */
  start(onEnvelope: (envelope: Uint8Array) => Promise<void>): Promise<void>;
  stop(): Promise<void>;
}

export interface ATSMSWorkerTransportConfig {
  /** Worker base URL, e.g. `https://inbox.atsms.at`. */
  apiUrl: string;
  did: string;
  /** This device's endpoint-cert serial (the worker inbox key, pre-§8.5). */
  certSerial: string;
  /** Endpoint-cert private key (PEM) — signs the worker API JWTs. */
  privateKeyPEM: string;
  /** Resolve a DID's public inbox to an `https:` POST target (the facade backs
   *  this with `resolveInbox` + `pickEndpoint(record, ["https"])`). */
  resolveInboxUrl: (did: string) => Promise<string | null>;
  /** Poll interval for the backfill drain (ms); WS push also triggers drains.
   *  Undefined ⇒ no timer (drain on start + on push only). */
  pollIntervalMs?: number;
  /** Called when a background drain fails (list/fetch errors); the drain
   *  retries on the next trigger either way. Default: silent. */
  onError?: (error: Error) => void;
  /** Injectable for tests. */
  fetchFn?: typeof fetch;
  webSocket?: boolean; // default true
}

interface InboxMessage {
  id: string;
  seq: number;
  messageType?: string;
  encryptedContent?: string;
}

const JWT_REFRESH_MS = 45 * 60 * 1000; // tokens live 1 h; refresh well before

/** The reference transport: the atsms-worker Relay Node's HTTP/WS binding. */
export class ATSMSWorkerEnvelopeTransport implements EnvelopeTransport {
  readonly ingressUrl: string;
  private readonly fetchFn: typeof fetch;
  private handler: ((envelope: Uint8Array) => Promise<void>) | null = null;
  private ws: ATSMSWebSocketClient | null = null;
  private pollTimer: ReturnType<typeof setInterval> | null = null;
  private draining: Promise<void> = Promise.resolve();
  private jwt: { token: string; mintedAt: number } | null = null;

  constructor(private readonly config: ATSMSWorkerTransportConfig) {
    this.ingressUrl = `${config.apiUrl}/inbox/${encodeURIComponent(config.did)}`;
    this.fetchFn = config.fetchFn ?? fetch;
  }

  async deliverToUrl(url: string, envelope: Uint8Array): Promise<void> {
    const res = await this.fetchFn(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ envelope: toBase64(envelope) }),
    });
    if (!res.ok) throw new Error(`envelope delivery failed: ${res.status} ${url}`);
  }

  async deliverToDid(did: string, envelope: Uint8Array): Promise<void> {
    const url = await this.config.resolveInboxUrl(did);
    if (url === null) throw new Error(`no https inbox endpoint for ${did} (mailto-only floor not carried by this transport)`);
    await this.deliverToUrl(url, envelope);
  }

  async start(onEnvelope: (envelope: Uint8Array) => Promise<void>): Promise<void> {
    this.handler = onEnvelope;
    if (this.config.webSocket !== false) {
      this.ws = new ATSMSWebSocketClient({
        apiUrl: this.config.apiUrl,
        did: this.config.did,
        certSerial: this.config.certSerial,
        getToken: () => this.token(),
        onMessage: (m) => {
          if ((m as { type?: string }).type === "new_message") this.scheduleDrain();
        },
        logger: { log: () => {}, error: () => {} },
      });
      // Push is an optimization — never fail start() on a WS hiccup.
      await this.ws.connect().catch(() => {});
    }
    if (this.config.pollIntervalMs !== undefined) {
      this.pollTimer = setInterval(() => this.scheduleDrain(), this.config.pollIntervalMs);
    }
    await this.scheduleDrain();
  }

  async stop(): Promise<void> {
    this.handler = null;
    if (this.pollTimer !== null) clearInterval(this.pollTimer);
    this.pollTimer = null;
    this.ws?.disconnect();
    this.ws = null;
    await this.draining;
  }

  // ── internals ─────────────────────────────────────────────────────────────

  /** Serialize drains (WS bursts + timer must not interleave inbox reads). */
  private scheduleDrain(): Promise<void> {
    this.draining = this.draining
      .then(() => this.drain())
      .catch((err) => this.config.onError?.(err instanceof Error ? err : new Error(String(err))));
    return this.draining;
  }

  /** List undelivered envelopes (metadata), fetch each body, hand it to the
   *  dispatcher, and delete on success. The list endpoint returns metadata
   *  only — `encryptedContent` requires the per-message GET. */
  private async drain(): Promise<void> {
    if (this.handler === null) return;
    const base = `${this.config.apiUrl}/messages/${encodeURIComponent(this.config.did)}/${encodeURIComponent(this.config.certSerial)}`;
    const res = await this.fetchFn(`${base}/list?type=atsms-envelope&limit=100`, {
      headers: { Authorization: `Bearer ${await this.token()}` },
    });
    if (!res.ok) throw new Error(`inbox list failed: ${res.status}`);
    const { messages } = (await res.json()) as { messages: InboxMessage[] };
    for (const m of messages) {
      if (this.handler === null) return;
      const got = await this.fetchFn(`${base}/${encodeURIComponent(m.id)}`, {
        headers: { Authorization: `Bearer ${await this.token()}` },
      });
      if (!got.ok) throw new Error(`inbox get ${m.id} failed: ${got.status}`);
      // The API worker wraps the message: { message: {...} }.
      const raw = (await got.json()) as { message?: InboxMessage } & InboxMessage;
      const body = raw.message ?? raw;
      if (typeof body.encryptedContent !== "string") {
        throw new Error(`inbox get ${m.id}: no encryptedContent in response`);
      }
      await this.handler(fromBase64(body.encryptedContent));
      await this.fetchFn(`${base}/${encodeURIComponent(m.id)}`, {
        method: "DELETE",
        headers: { Authorization: `Bearer ${await this.token()}` },
      });
    }
  }

  private async token(): Promise<string> {
    if (this.jwt === null || Date.now() - this.jwt.mintedAt > JWT_REFRESH_MS) {
      const token = await generateJWT(this.config.privateKeyPEM, this.config.certSerial, this.config.did);
      this.jwt = { token, mintedAt: Date.now() };
    }
    return this.jwt.token;
  }
}

function toBase64(bytes: Uint8Array): string {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin);
}

function fromBase64(s: string): Uint8Array {
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}
