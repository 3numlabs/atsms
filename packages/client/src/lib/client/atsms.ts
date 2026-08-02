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
  CONTENT_CMS,
  CONTENT_FRAME,
  type Csprng,
  envelopeMode,
  hexToBytes,
  MODE_ASYM,
  MODE_SYM,
  openAsym,
  parseFrame,
  payloadFromCbor,
  type PdsClient,
  pickEndpoint,
  resolveInbox,
  sealAsymTo,
} from "@atsms/dcgka";
import { x25519 } from "@noble/curves/ed25519";
import { type Observable,Subject } from "rxjs";

import {
  admissionKeysFor,
  Conversation,
  type ConversationContext,
  type MemberDescriptor,
  type Outbound,
  type SendInput,
} from "../conversations/index.js";
import {
  convoIdFromHex,
  convoIdToHex,
  createContent,
  deriveMessageId,
  encodeContent,
  EXT_RECIPIENTS,
  groupIdOfConvoId,
  type MessageContent,
  messageIdToHex,
  oneShotConvoIdV2,
  type Part,
  recipientsExtension,
  textPart,
} from "../format/index.js";
import { capableDevices } from "../identity/capability.js";
import { ATSMSDeviceIdentity } from "../identity/device-identity.js";
import { oneShotSenderProblem, openOneShot, resolveRecipientCerts, sealOneShot } from "../send/index.js";
import { ingestMessage } from "../storage/apply.js";
import type { StorageAdapter } from "../storage/interface.js";
import type { LocalConversation, LocalMessage } from "../storage/types.js";
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
  /** Ephemeral (signal-class) messages — call signaling, typing — from any
   *  conversation (format §8). Never persisted; identify the conversation via
   *  `content.convoId`. Default: dropped. */
  onSignal?: (content: MessageContent, senderDid: string) => void;
  /** Genesis-wait window in ms (concurrent-update-partition §4.2): a joiner with
   *  no epoch waits this long for the creator's first update before self-healing.
   *  Default 4000. Set 0 for a synchronous transport (tests) that has already
   *  delivered the update by send time. */
  genesisWaitMs?: number;
}

/** Genesis wait (concurrent-update-partition §4.2): how long a joiner with no
 *  epoch waits for the creator's mandatory first update before self-healing,
 *  and how often it re-checks. The exact values are not load-bearing — §4.1
 *  makes the self-heal fallback converge either way; the wait only prefers the
 *  clean shared-epoch path in the common genesis case. Zero disables the wait
 *  (tests with synchronous transports never need it). */
const GENESIS_EPOCH_WAIT_MS = 4000;
const GENESIS_EPOCH_POLL_MS = 250;

/** App-facing handle for one conversation: subscribe + send, no crypto. */
export class ATSMSConversation {
  constructor(
    private readonly convo: Conversation,
    private readonly router: (outbound: Outbound[], convo: Conversation) => Promise<void>,
    private readonly genesisWaitMs: number = GENESIS_EPOCH_WAIT_MS,
  ) {}

  /** The conversation ID: hex of the 33-byte v2 ConvoId (format §8). */
  get id(): string {
    return this.convo.convoId;
  }

  /** Fully-processed messages (decrypted, verified, deduped, persisted). */
  get messages$(): Observable<LocalMessage[]> {
    return this.convo.messages$;
  }

  /** Member DIDs (deduped across devices), including self. */
  get members(): string[] {
    return this.convo.members;
  }

  /** Send a message — plain text or structured v2 content (replies, reactions,
   *  edits, signaling); sealing + delivery are automatic.
   *
   *  If the engine has no usable epoch (`NoRootKey`): at GENESIS — a joiner
   *  bootstrapped from `create` that has never held an epoch — the creator's
   *  mandatory first update is in flight, so wait briefly for the transport to
   *  deliver it (deriving the shared epoch) rather than self-heal into a
   *  concurrent update that would need repair (concurrent-update-partition §4.2).
   *  Self-heal only if it never arrives, or immediately for an already-
   *  established group that is momentarily rootless (§4.1 converges that path). */
  async send(input: string | SendInput): Promise<void> {
    try {
      await this.router(await this.convo.send(input), this.convo);
    } catch (err) {
      if (!(err instanceof Error) || !err.message.includes("NoRootKey")) throw err;
      if (this.convo.awaitingFirstEpoch && this.genesisWaitMs > 0) {
        await this.awaitFirstEpoch();
      }
      if (!this.convo.hasSendableEpoch) {
        await this.router(await this.convo.update(), this.convo);
      }
      await this.router(await this.convo.send(input), this.convo);
    }
  }

  /** Poll (letting the transport's inbound dispatch run) until the creator's
   *  update lands or the bounded genesis window elapses. */
  private async awaitFirstEpoch(): Promise<void> {
    const deadline = Date.now() + this.genesisWaitMs;
    while (Date.now() < deadline && this.convo.awaitingFirstEpoch) {
      await new Promise((resolve) => setTimeout(resolve, GENESIS_EPOCH_POLL_MS));
    }
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
    private readonly onSignal?: (content: MessageContent, senderDid: string) => void,
    private readonly genesisWaitMs: number = GENESIS_EPOCH_WAIT_MS,
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
      config.onSignal,
      config.genesisWaitMs ?? GENESIS_EPOCH_WAIT_MS,
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

  /**
   * How a recipient can be reached — the input to the app's DELIBERATE mode
   * choice (sdk-shape.md Part A: mode selection is deliberate; capability §3:
   * no silent downgrade). The two surfaces are different products with
   * different guarantees, so the app picks one, visibly, at thread creation —
   * never per message, and never as a fallback:
   *
   * - `"conversation"` — ≥1 device has a verified prekey: the stateful DCGKA
   *   surface (forward secrecy, sealed sender, calls) via `open()`.
   * - `"one-shot"` — published endpoint certs only: the stateless X509
   *   surface via `send()` (certified-mail-style notices / notifications).
   * - `"unreachable"` — no published certs; nothing can be delivered.
   */
  async reachability(did: string): Promise<"conversation" | "one-shot" | "unreachable"> {
    if ((await capableDevices(this.pds, did)).length > 0) return "conversation";
    if ((await resolveRecipientCerts(this.pds, did)).length > 0) return "one-shot";
    return "unreachable";
  }

  // ── the stateless surface ──────────────────────────────────────────────────

  /**
   * Send a stateless one-shot (sdk-shape.md Part A): X509 sign-then-encrypt to
   * every valid endpoint cert of every recipient — no session, no stored
   * crypto state. Works for any recipient with published certs (DCGKA
   * capability not required); recipients with none are named in the error.
   *
   * Transport privacy (format §8): the CMS is sealed into a sealed-sender
   * envelope (`CONTENT_CMS`) per recipient device that published a prekey;
   * devices with only an X509 cert receive the bare CMS — the explicit
   * legacy form, not a sniffed special case.
   */
  async send(params: { to: string[]; text?: string; parts?: Part[]; fallback?: string }): Promise<void> {
    const recipients = [...new Set(params.to.filter((d) => d !== this.identity.did))];
    if (recipients.length === 0) throw new Error("send: no recipients");
    const parts = params.parts ?? (params.text !== undefined ? [textPart(params.text)] : null);
    if (parts === null) throw new Error("send: no content");

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

    const participants = [this.identity.did, ...recipients];
    const convoId = oneShotConvoIdV2(participants);
    const content = createContent({
      convoId,
      salt: this.rng(16),
      body: parts,
      fallback: params.fallback,
      extensions: new Map([[EXT_RECIPIENTS, recipients]]),
    });
    const contentBytes = encodeContent(content);
    const cms = await sealOneShot(contentBytes, await this.identity.endpointCertificate(), recipientCerts);

    const convoIdHex = convoIdToHex(convoId);
    await this.saveOneShotConversation(convoIdHex, participants);
    await ingestMessage({
      storage: this.storage,
      id: messageIdToHex(deriveMessageId(this.identity.did, content, contentBytes)),
      convoId: convoIdHex,
      senderId: this.identity.did,
      content,
    });

    for (const did of recipients) {
      // Sealed-sender whenever the recipient has devices we can seal to; the
      // worker fans every envelope to all of the DID's device inboxes, and
      // non-target devices fail the AEAD open and drop (multi-device model).
      const devices = await capableDevices(this.pds, did);
      if (devices.length > 0) {
        for (const d of devices) {
          await this.transport.deliverToDid(did, sealAsymTo(d.prekey.signedPrekey, CONTENT_CMS, cms, this.rng));
        }
      } else {
        await this.transport.deliverToDid(did, cms); // X509-only recipient: bare CMS (legacy form)
      }
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
    // The record's id is the v2 ConvoId hex; only a conversation-context id
    // (0x02 prefix) maps back to a DCGKA GroupID — a one-shot record with the
    // same participant set is a different conversation (format §8).
    const existingGroupId = existing === null ? null : groupIdOfConvoId(convoIdFromHex(existing.id));
    if (existingGroupId !== null) {
      const reopened = await this.get(existingGroupId);
      if (reopened !== null) {
        // Reconcile membership with the members' CURRENT device lists: a DID
        // may have published a new device (or re-keyed one) since the group was
        // founded — admit anything missing so it can participate. Its welcome
        // carries the log; traffic before admission stays unreadable to it (FS).
        await this.reconcileDevices(reopened);
        return reopened;
      }
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

  /** A conversation by ID (v2 ConvoId hex, or a bare DCGKA GroupID) — open
   *  handle, or restored from storage. Null if unknown. */
  async get(id: string): Promise<ATSMSConversation | null> {
    const groupId = toGroupId(id);
    const open = this.openConvos.get(groupId);
    if (open !== undefined) return open;
    const convo = await Conversation.restore(this.context(), groupId);
    return convo === null ? null : this.register(convo);
  }

  /** Admit every capable device of the conversation's member DIDs that is not
   *  yet in the group (device enrollment / re-key catch-up). */
  private async reconcileDevices(handle: ATSMSConversation): Promise<void> {
    const present = handle.inner.memberDevices;
    for (const did of handle.members.filter((d) => d !== this.identity.did)) {
      for (const d of await capableDevices(this.pds, did)) {
        if (present.has(d.fingerprint)) continue;
        this.onEvent("device-added", `${did} device ${d.fingerprint.slice(0, 12)}… → ${handle.id.slice(0, 8)}…`);
        const outbound = await handle.inner.addMember({
          device: { did, fingerprint: hexToBytes(d.fingerprint) },
          leafPk: d.prekey.signedPrekey,
          signingPk: d.prekey.signingPk,
        });
        await this.route(outbound, handle.inner);
      }
    }
  }

  /** Add a DID to a conversation (every capable device of it). */
  async addMember(groupId: string, did: string): Promise<void> {
    const handle = await this.get(groupId);
    if (handle === null) throw new Error(`unknown conversation ${groupId}`);
    const devices = await capableDevices(this.pds, did);
    if (devices.length === 0) throw new Error(`not DCGKA-capable (no verified prekey): ${did}`);
    const present = handle.inner.memberDevices;
    for (const d of devices) {
      if (present.has(d.fingerprint)) continue; // already a member
      const outbound = await handle.inner.addMember({
        device: { did, fingerprint: hexToBytes(d.fingerprint) },
        leafPk: d.prekey.signedPrekey,
        signingPk: d.prekey.signingPk,
      });
      await this.route(outbound, handle.inner);
    }
  }

  // ── auto-routing ───────────────────────────────────────────────────────────

  /** Outbound: in-band advertised URL first, else the DID's public inbox. The
   *  seal layer already excludes THIS device from recipients, so each envelope
   *  targets another device — routed by that device's DID, never skipped just
   *  because it shares our DID (multi-device: our other devices are real
   *  recipients; the worker fans a copy to our own inbox, which we drop). */
  private async route(outbound: Outbound[], convo: Conversation): Promise<void> {
    const devices = convo.memberDevices;
    for (const o of outbound) {
      if (o.url !== null) {
        await this.transport.deliverToUrl(o.url, o.envelope);
        continue;
      }
      const did = devices.get(o.to);
      if (did === undefined) continue; // not a known member device — unroutable
      await this.transport.deliverToDid(did, o.envelope);
    }
  }

  /** Inbound: one opaque delivery from the transport (throw ⇒ no ack ⇒
   *  redelivery). Sealed envelopes are strict-CBOR and declare their content
   *  type once opened (frame vs CMS — format §8); bare DER is the X509-only
   *  legacy form of a one-shot (the delivery contract is payload-agnostic,
   *  inbound-delivery §1). */
  private async dispatch(envelope: Uint8Array): Promise<void> {
    const mode = sealedMode(envelope);
    if (mode === MODE_ASYM) return this.dispatchAsym(envelope);
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

  /** Trial-open a sealed-asym envelope with this device's prekey secrets and
   *  route by the DECLARED content type: a frame bootstraps/joins a
   *  conversation; a CMS body is a sealed one-shot (format §8). */
  private async dispatchAsym(envelope: Uint8Array): Promise<void> {
    for (const sk of this.identity.prekeySecrets) {
      let opened;
      try {
        opened = openAsym(sk, envelope);
      } catch {
        continue; // not this secret (or not for us) — try the next
      }
      if (opened.contentType === CONTENT_FRAME) return this.dispatchBootstrap(opened.body);
      if (opened.contentType === CONTENT_CMS) return this.dispatchOneShot(opened.body);
      this.onEvent("drop-unknown-sealed-type", String(opened.contentType));
      return;
    }
    // Not addressed to us (or a rotated-out generation) — drop + ack.
    this.onEvent("drop-unopenable", "no prekey secret opens this sealed-asym envelope");
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
    const senderDid = opened.signer.did;
    if (senderDid === undefined) {
      this.onEvent("drop-unverified-sender", "signer certificate carries no DID");
      return;
    }
    const problem = await oneShotSenderProblem(this.pds, opened.signer);
    if (problem !== null) {
      this.onEvent("drop-unverified-sender", problem);
      return;
    }
    let recipients: string[] | null;
    try {
      recipients = recipientsExtension(opened.content, EXT_RECIPIENTS);
    } catch {
      this.onEvent("drop-bad-recipients", senderDid);
      return;
    }
    if (recipients === null) {
      this.onEvent("drop-bad-recipients", senderDid);
      return;
    }
    // The convoId must be the deterministic id for the participant set — a
    // verified sender still cannot inject into an arbitrary thread (format §8).
    const participants = [senderDid, ...recipients];
    const convoIdHex = convoIdToHex(opened.content.convoId);
    if (convoIdHex !== convoIdToHex(oneShotConvoIdV2(participants))) {
      this.onEvent("drop-forged-thread", convoIdHex);
      return;
    }
    if (opened.content.ephemeral) return; // one-shots have no signaling surface

    await this.saveOneShotConversation(convoIdHex, participants);
    const message = await ingestMessage({
      storage: this.storage,
      id: messageIdToHex(deriveMessageId(senderDid, opened.content, opened.contentBytes)),
      convoId: convoIdHex,
      senderId: senderDid,
      content: opened.content,
    });
    this.oneShots.next(message);
    this.onEvent("one-shot", `${senderDid} → ${convoIdHex.slice(0, 8)}…`);
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

  /** An unsealed bootstrap-class frame (create/welcome/pre-epoch traffic). */
  private async dispatchBootstrap(frame: Uint8Array): Promise<void> {
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
      onEvent: (kind, detail) => this.onEvent(kind, detail),
      onEngineEvent: (kind, detail) => this.onEvent(kind, detail),
      onSignal: this.onSignal,
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
    const handle = new ATSMSConversation(convo, (out, c) => this.route(out, c), this.genesisWaitMs);
    this.openConvos.set(convo.groupId, handle);
    return handle;
  }
}

/** Accept either conversation-id currency: a 66-hex v2 ConvoId (0x02 context
 *  byte) maps to its DCGKA GroupID; anything else is already a GroupID. */
function toGroupId(id: string): string {
  if (id.length === 66 && id.startsWith("02")) return id.slice(2);
  return id;
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
