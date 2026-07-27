/**
 * `ATSMS` — the top-level client (sdk-shape.md Part A): wires identity + storage +
 * transport + PDS into the two surfaces, and owns **auto-routing** in both
 * directions:
 *
 * - outbound: every op's sealed envelopes are delivered via the transport —
 *   to the in-band advertised URL when known (sealed-sender §12), else to the
 *   recipient DID's public `at.atsms.inbox` (inbound-delivery §3/§5);
 * - inbound: the transport's envelope stream is dispatched — `sealed-asym`
 *   envelopes are trial-opened with the device's prekey secrets and either
 *   bootstrap a conversation (create/welcome) or route to one by GroupID;
 *   `sealed-sym` envelopes are offered to every open conversation (only tag
 *   tables can tell whose they are — sealed-sender §11.3).
 *
 * A dispatch that throws leaves the envelope unacknowledged in the inbox (the
 * transport redelivers on the next drain).
 */

import {
  bytesToHex,
  CLS_CONTROL,
  CLS_WELCOME,
  type Csprng,
  envelopeMode,
  hexToBytes,
  MODE_ASYM,
  MODE_SYM,
  parseFrame,
  payloadFromCbor,
  type PdsClient,
  pickEndpoint,
  resolveInbox,
  SealLayer,
} from "@atsms/dcgka";
import { x25519 } from "@noble/curves/ed25519";
import { type Observable,Subject } from "rxjs";

import {
  admissionKeysFor,
  Conversation,
  type ConversationContext,
  type MemberDescriptor,
  type Outbound,
} from "../conversations/index.js";
import { capableDevices } from "../identity/capability.js";
import { ATSMSDeviceIdentity } from "../identity/device-identity.js";
import { createMessagePayload, createTextContent } from "../messages.js";
import {
  oneShotConvoId,
  oneShotSenderProblem,
  openOneShot,
  resolveRecipientCerts,
  sealOneShot,
} from "../send/index.js";
import type { StorageAdapter } from "../storage/interface.js";
import type { LocalConversation, LocalMessage } from "../storage/types.js";
import { payloadToLocalMessage } from "../storage/types.js";
import type { EnvelopeTransport } from "../transport/envelope-transport.js";

export interface ATSMSConfig {
  identity: ATSMSDeviceIdentity;
  storage: StorageAdapter;
  transport: EnvelopeTransport;
  pds: PdsClient;
  rng: Csprng;
  /** Publish the `at.atsms.inbox` record on create: the transport's ingress URL
   *  plus this `mailto:` fallback address — the universally supported delivery
   *  route the record must always include (skipped when undefined — e.g. in tests). */
  mailtoAddress?: string;
  /** Dispatcher diagnostics (envelope drops, bootstraps, joins). Default: silent. */
  onEvent?: (kind: string, detail: string) => void;
}

/** App-facing handle for one conversation: subscribe + send, no crypto. */
export class ATSMSConversation {
  constructor(
    private readonly convo: Conversation,
    private readonly router: (outbound: Outbound[], convo: Conversation) => Promise<void>,
  ) {}

  get id(): string {
    return this.convo.groupId;
  }

  /** Fully-processed messages (decrypted, verified, deduped, persisted). */
  get messages$(): Observable<LocalMessage[]> {
    return this.convo.messages$;
  }

  /** Member DIDs (deduped across devices), including self. */
  get members(): string[] {
    return this.convo.members;
  }

  /** Send a text message; sealing + delivery are automatic. */
  async send(text: string): Promise<void> {
    await this.router(await this.convo.send(text), this.convo);
  }

  /** Rotate keys (post-compromise healing). */
  async update(): Promise<void> {
    await this.router(await this.convo.update(), this.convo);
  }

  /** @internal the wrapped conversation (dispatcher use). */
  get inner(): Conversation {
    return this.convo;
  }
}

export class ATSMS {
  /** Open conversations by GroupID (hex) — the sym-envelope offer set. */
  private readonly openConvos = new Map<string, ATSMSConversation>();
  /** Inbound one-shots (verified + persisted), as they arrive. */
  private readonly oneShots = new Subject<LocalMessage>();

  private constructor(
    readonly identity: ATSMSDeviceIdentity,
    private readonly storage: StorageAdapter,
    private readonly transport: EnvelopeTransport,
    private readonly pds: PdsClient,
    private readonly rng: Csprng,
    private readonly onEvent: (kind: string, detail: string) => void,
  ) {}

  /**
   * Wire up a client: publish this device's prekey bundle (rotating if due) and
   * the DID's inbox record (when a mailto address is configured), reopen every
   * persisted conversation, and start receiving.
   */
  static async create(config: ATSMSConfig): Promise<ATSMS> {
    const atsms = new ATSMS(
      config.identity,
      config.storage,
      config.transport,
      config.pds,
      config.rng,
      config.onEvent ?? (() => {}),
    );

    await config.identity.ensurePrekeyPublished(config.pds);
    if (config.mailtoAddress !== undefined) {
      const endpoints = [
        ...(config.transport.ingressUrl !== null ? [{ uri: config.transport.ingressUrl }] : []),
        { uri: config.mailtoAddress },
      ];
      await config.identity.publishInbox(config.pds, endpoints);
    }

    for (const groupId of await config.storage.listEngineStateIds()) {
      const convo = await Conversation.restore(atsms.context(), groupId);
      if (convo !== null) atsms.register(convo);
    }

    await config.transport.start((envelope) => atsms.dispatch(envelope));
    return atsms;
  }

  async close(): Promise<void> {
    await this.transport.stop();
  }

  /** All conversations, reactively (metadata level). */
  get conversations$(): Observable<LocalConversation[]> {
    return this.storage.observeConversations();
  }

  /** Inbound one-shots (X509 baseline), fully processed: decrypted, signature
   *  verified, sender resolved against their published records, persisted. */
  get received$(): Observable<LocalMessage> {
    return this.oneShots.asObservable();
  }

  // ── the stateless surface ──────────────────────────────────────────────────

  /**
   * Send a stateless one-shot (sdk-shape.md Part A): X509 sign-then-encrypt to
   * every valid endpoint cert of every recipient — no session, no stored
   * crypto state. Works for any recipient with published certs (DCGKA
   * capability not required); recipients with none are named in the error.
   */
  async send(params: { to: string[]; text: string }): Promise<void> {
    const recipients = [...new Set(params.to.filter((d) => d !== this.identity.did))];
    if (recipients.length === 0) throw new Error("send: no recipients");

    const recipientCerts = [];
    const unreachable: string[] = [];
    for (const did of recipients) {
      const certs = await resolveRecipientCerts(this.pds, did);
      if (certs.length === 0) unreachable.push(did);
      else recipientCerts.push(...certs);
    }
    if (unreachable.length > 0) {
      throw new Error(`no published endpoint certificates: ${unreachable.join(", ")}`);
    }

    const convoId = await oneShotConvoId([this.identity.did, ...recipients]);
    const payload = createMessagePayload(
      this.identity.did,
      recipients,
      createTextContent(params.text),
      "atsms/text",
      convoId,
    );
    const bytes = await sealOneShot(payload, await this.identity.endpointCertificate(), recipientCerts);

    await this.saveOneShotConversation(convoId, [this.identity.did, ...recipients]);
    await this.storage.saveMessage(payloadToLocalMessage(payload));
    for (const did of recipients) {
      await this.transport.deliverToDid(did, bytes);
    }
  }

  // ── the stateful surface ───────────────────────────────────────────────────

  /**
   * Open (or reuse) the conversation with `members` (DIDs; self implied). Every
   * member must be DCGKA-capable — the incapable ones are named in the error,
   * never silently downgraded (capability §3); one-shots to them can use the
   * stateless X509 baseline instead.
   */
  async open(params: { members: string[]; admins?: string[] }): Promise<ATSMSConversation> {
    const others = [...new Set(params.members.filter((d) => d !== this.identity.did))];
    const participants = [this.identity.did, ...others];

    const existing = await this.storage.findConversationByParticipants(participants);
    if (existing !== null) {
      const reopened = await this.get(existing.id);
      if (reopened !== null) return reopened;
    }

    const descriptors: MemberDescriptor[] = [this.identity.descriptor];
    const incapable: string[] = [];
    for (const did of others) {
      const devices = await capableDevices(this.pds, did);
      if (devices.length === 0) {
        incapable.push(did);
        continue;
      }
      for (const d of devices) {
        descriptors.push({
          device: { did, fingerprint: hexToBytes(d.fingerprint) },
          leafPk: d.prekey.signedPrekey,
          signingPk: d.prekey.signingPk,
        });
      }
    }
    if (incapable.length > 0) {
      throw new Error(`not DCGKA-capable (no verified prekey): ${incapable.join(", ")}`);
    }

    const { conversation, outbound } = await Conversation.open(this.context(), {
      keys: this.identity.localKeys,
      members: descriptors,
      admins: params.admins ?? [this.identity.did],
    });
    const handle = this.register(conversation);
    await this.route(outbound, conversation);

    // Advertise our ingress in-band, then the creator's mandatory first update
    // (healing rule) carries the advert and establishes the first epoch.
    if (this.transport.ingressUrl !== null) await conversation.advertiseEndpoint(this.transport.ingressUrl);
    await this.route(await conversation.update(), conversation);
    return handle;
  }

  /** A conversation by GroupID — open handle, or restored from storage. Null if unknown. */
  async get(groupId: string): Promise<ATSMSConversation | null> {
    const open = this.openConvos.get(groupId);
    if (open !== undefined) return open;
    const convo = await Conversation.restore(this.context(), groupId);
    return convo === null ? null : this.register(convo);
  }

  /** Add a DID to a conversation (every capable device of it). */
  async addMember(groupId: string, did: string): Promise<void> {
    const handle = await this.get(groupId);
    if (handle === null) throw new Error(`unknown conversation ${groupId}`);
    const devices = await capableDevices(this.pds, did);
    if (devices.length === 0) throw new Error(`not DCGKA-capable (no verified prekey): ${did}`);
    for (const d of devices) {
      const outbound = await handle.inner.addMember({
        device: { did, fingerprint: hexToBytes(d.fingerprint) },
        leafPk: d.prekey.signedPrekey,
        signingPk: d.prekey.signingPk,
      });
      await this.route(outbound, handle.inner);
    }
  }

  // ── auto-routing ───────────────────────────────────────────────────────────

  /** Outbound: in-band advertised URL first, else the DID's public inbox. */
  private async route(outbound: Outbound[], convo: Conversation): Promise<void> {
    const devices = convo.memberDevices;
    for (const o of outbound) {
      if (o.url !== null) {
        await this.transport.deliverToUrl(o.url, o.envelope);
        continue;
      }
      const did = devices.get(o.to);
      if (did === undefined || did === this.identity.did) continue; // not routable / self
      await this.transport.deliverToDid(did, o.envelope);
    }
  }

  /** Inbound: one opaque delivery from the transport (throw ⇒ no ack ⇒
   *  redelivery). Sealed envelopes are strict-CBOR; anything else is offered
   *  to the X509 one-shot opener (the delivery contract is payload-agnostic,
   *  inbound-delivery §1). */
  private async dispatch(envelope: Uint8Array): Promise<void> {
    const mode = sealedMode(envelope);
    if (mode === MODE_ASYM) return this.dispatchBootstrap(envelope);
    if (mode === MODE_SYM) {
      // Only a conversation's tag table can recognize it — offer to all; the
      // seal layer dedups (EnvelopeID) and buffers unknown tags briefly.
      for (const handle of this.openConvos.values()) {
        const repairs = await handle.inner.deliverEnvelope(envelope);
        await this.route(repairs, handle.inner);
      }
      return;
    }
    return this.dispatchOneShot(envelope);
  }

  private async dispatchOneShot(bytes: Uint8Array): Promise<void> {
    let opened;
    try {
      opened = await openOneShot(bytes, await this.identity.endpointCertificate());
    } catch (err) {
      // Not addressed to this device / bad signature / not a one-shot at all.
      this.onEvent("drop-unopenable", err instanceof Error ? err.message : String(err));
      return;
    }
    const problem = await oneShotSenderProblem(this.pds, opened);
    if (problem !== null) {
      this.onEvent("drop-unverified-sender", problem);
      return;
    }
    // The convoId must be the deterministic id for the payload's participant
    // set — a verified sender still cannot inject into an arbitrary thread.
    const participants = [opened.payload.senderId, ...opened.payload.recipientIds];
    if (opened.payload.convoId !== (await oneShotConvoId(participants))) {
      this.onEvent("drop-forged-thread", opened.payload.convoId);
      return;
    }
    await this.saveOneShotConversation(opened.payload.convoId, participants);
    const message = payloadToLocalMessage(opened.payload);
    await this.storage.saveMessage(message);
    this.oneShots.next(message);
    this.onEvent("one-shot", `${opened.payload.senderId} → ${opened.payload.convoId.slice(0, 8)}…`);
  }

  private async saveOneShotConversation(convoId: string, participants: string[]): Promise<void> {
    const existing = await this.storage.getConversation(convoId);
    const now = new Date();
    await this.storage.saveConversation({
      id: convoId,
      participantIds: [...new Set(participants)].sort(),
      createdAt: existing?.createdAt ?? now,
      lastMessageAt: now,
      unreadCount: existing?.unreadCount ?? 0,
      metadata: { protocol: "x509" },
    });
  }

  private async dispatchBootstrap(envelope: Uint8Array): Promise<void> {
    let frame: Uint8Array;
    try {
      frame = SealLayer.openBootstrap(envelope, this.identity.prekeySecrets);
    } catch (err) {
      // Not addressed to us (or a rotated-out generation) — drop + ack.
      this.onEvent("drop-unopenable", err instanceof Error ? err.message : String(err));
      return;
    }
    const parsed = parseFrame(frame);
    // A create frame carries a zero groupId placeholder (the GroupID *is* the
    // create frame's id) — normalize so the known-group check works for both.
    const isCreate =
      parsed.body.cls === CLS_CONTROL &&
      payloadFromCbor(parsed.body.payload, parsed.body.sender.device.fingerprint).type === "create";
    const groupId = bytesToHex(isCreate ? parsed.id : parsed.body.groupId);
    if (this.openConvos.has(groupId)) {
      // Known group (e.g. a redelivered welcome, or an asym-sealed frame from
      // the pre-epoch window) — hand the frame to its session.
      const handle = this.openConvos.get(groupId)!;
      if (parsed.body.cls !== CLS_WELCOME) {
        await this.route(await handle.inner.ingestFrame(frame), handle.inner);
      }
      return;
    }

    if (parsed.body.cls === CLS_WELCOME) {
      const keys = this.admissionKeys(frame);
      if (keys === null) {
        // The pinned generation is no longer held — undecryptable-by-design.
        this.onEvent("drop-admission-keys", `welcome for group ${groupId}`);
        return;
      }
      const { conversation, outbound } = await Conversation.join(this.context(), { keys, welcomeFrame: frame });
      this.register(conversation);
      this.onEvent("joined", groupId);
      if (this.transport.ingressUrl !== null) await conversation.advertiseEndpoint(this.transport.ingressUrl);
      await this.route(outbound, conversation);
      return;
    }

    if (isCreate) {
      const keys = this.admissionKeys(frame);
      if (keys === null) {
        this.onEvent("drop-admission-keys", `create for group ${groupId}`);
        return;
      }
      const conversation = await Conversation.bootstrap(this.context(), { keys, createFrame: frame });
      this.register(conversation);
      this.onEvent("bootstrapped", groupId);
      if (this.transport.ingressUrl !== null) await conversation.advertiseEndpoint(this.transport.ingressUrl);
      return;
    }
    // A non-bootstrap frame for a group we don't hold — nothing to attach it to.
    this.onEvent("drop-unknown-group", groupId);
  }

  // ── internals ──────────────────────────────────────────────────────────────

  private context(): ConversationContext {
    return {
      storage: this.storage,
      rng: this.rng,
      device: this.identity.device,
      did: this.identity.did,
      prekeySecrets: this.identity.prekeySecrets,
    };
  }

  private admissionKeys(frame: Uint8Array) {
    return admissionKeysFor(
      frame,
      this.identity.device,
      this.identity.prekeySecrets,
      this.identity.signingKeys,
      (sk) => x25519.getPublicKey(sk),
    );
  }

  private register(convo: Conversation): ATSMSConversation {
    const handle = new ATSMSConversation(convo, (out, c) => this.route(out, c));
    this.openConvos.set(convo.groupId, handle);
    return handle;
  }
}

/** The sealed-envelope mode of an opaque delivery, or null when the bytes are
 *  not a sealed envelope at all (e.g. an X509 one-shot: DER, not strict CBOR). */
function sealedMode(bytes: Uint8Array): number | null {
  try {
    const mode = envelopeMode(bytes);
    return mode === MODE_ASYM || mode === MODE_SYM ? mode : null;
  } catch {
    return null;
  }
}

/** Back an `EnvelopeTransport`'s inbox resolution with the PDS record
 *  (inbound-delivery §3): the highest-preference `https:` endpoint, or null. */
export function inboxUrlResolver(pds: PdsClient): (did: string) => Promise<string | null> {
  return async (did) => {
    const r = await resolveInbox(pds, did);
    if (!r.ok) return null;
    return pickEndpoint(r.record, ["https"])?.uri ?? null;
  };
}
