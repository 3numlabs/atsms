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
import { loadEndpointCertificate, type ATSMSEndpointCertificate } from "../certificates/index.js";
import { instrumentPds, instrumentTransport, span, type ATSMSMetric, type MetricSink } from "./metrics.js";
import { ATSMSDeviceIdentity } from "../identity/device-identity.js";
import { ATSMSPeers, capableFromSnapshot, peerKeyBytes, type PeerSnapshot } from "../identity/peers.js";
import { oneShotSenderProblem, openOneShot, sealOneShot } from "../send/index.js";
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
  /** §8 repair trigger (ordering-auth §8, T_REPAIR): when a conversation's
   *  ordering buffer has held frames for this long — we are missing causal
   *  ancestors a lossy relay never delivered — send a sealed repair request to
   *  the members; any member re-serves the signed frames it retains. Default
   *  60000. Set 0 to disable (e.g. single-shot tools or tests that drive
   *  repair manually). */
  repairAfterMs?: number;
  /** Peer-directory freshness window (sdk-shape.md `peers`): operations serve
   *  the local snapshot when younger than this, else revalidate. Default
   *  15 min. 0 = revalidate on every operation read (the pre-directory
   *  semantics — useful for tests that mutate records and expect immediate
   *  visibility). Explicit `peers.refresh()` always bypasses the window. */
  peerMaxAgeMs?: number;
  /** Structured timing samples (profiling): PDS reads/writes, transport
   *  posts, and operation spans with phase breakdowns. On-device only — the
   *  sink decides where samples go (the reference CLI appends JSONL under
   *  its profile dir). Default: none collected. */
  onMetric?: (m: ATSMSMetric) => void;
}

/** Genesis wait (concurrent-update-partition §4.2): how long a joiner with no
 *  epoch waits for the creator's mandatory first update before self-healing,
 *  and how often it re-checks. The exact values are not load-bearing — §4.1
 *  makes the self-heal fallback converge either way; the wait only prefers the
 *  clean shared-epoch path in the common genesis case. Zero disables the wait
 *  (tests with synchronous transports never need it). */
const GENESIS_EPOCH_WAIT_MS = 4000;
const GENESIS_EPOCH_POLL_MS = 250;

/** §8 T_REPAIR (ordering-auth §8): how long an ordering gap may persist before
 *  the client asks the members to re-serve the missing frames. */
const REPAIR_AFTER_MS = 60_000;

/** C-fallback threshold: unopenable envelopes on a conversation we still
 *  believe we belong to, before surfacing a soft "possibly removed". */
const UNOPENABLE_SUSPECT_REMOVED = 3;

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

  /** Am I still a member? False once my own removal is processed — clients
   *  render the conversation read-only and say why. */
  get amMember(): boolean {
    return this.convo.amMember;
  }

  /** Who admitted/removed whom, in causal order (for a system-message view). */
  membershipLog(): ReturnType<Conversation["membershipLog"]> {
    return this.convo.membershipLog();
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
    // Removed members must not send: their epoch is gone, so send() throws
    // NoRootKey — indistinguishable from the transient case the catch below
    // heals by updating, which for a non-member mints a fork nobody accepts.
    // Check membership first and say so plainly.
    if (!this.convo.amMember) {
      throw new Error("removed-from-conversation: you are no longer a member of this conversation");
    }
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
  /** §8 repair trigger state: groupId → when its ordering buffer first went
   *  (and stayed) non-empty. Cleared the moment the buffer drains. */
  private readonly gapSince = new Map<string, number>();
  /** Conversations already flagged as possibly-removed (report once). */
  private readonly suspected = new Set<string>();
  private repairTimer: ReturnType<typeof setInterval> | null = null;
  /** The local peer directory (sdk-shape.md: the third noun) — operations
   *  read it; refreshes happen off the user's critical path. */
  readonly peers: ATSMSPeers;

  private constructor(
    readonly identity: ATSMSDeviceIdentity,
    private readonly storage: StorageAdapter,
    private readonly transport: EnvelopeTransport,
    private readonly pds: PdsClient,
    private readonly rng: Csprng,
    private readonly onEvent: (kind: string, detail: string) => void,
    private readonly onSignal?: (content: MessageContent, senderDid: string) => void,
    private readonly genesisWaitMs: number = GENESIS_EPOCH_WAIT_MS,
    private readonly repairAfterMs: number = REPAIR_AFTER_MS,
    peerMaxAgeMs?: number,
    private readonly onMetric: MetricSink = () => {},
  ) {
    this.peers = new ATSMSPeers(pds, storage, onEvent, peerMaxAgeMs);
  }

  /**
   * Wire up a client: publish this device's prekey bundle (rotating if due) and
   * the DID's inbox record (when a mailto address is configured), reopen every
   * persisted conversation, and start receiving.
   */
  static async create(config: ATSMSConfig): Promise<ATSMS> {
    // With a metric sink configured, both network seams are timed — every
    // client gets measurement without wiring anything but the sink.
    const pds = config.onMetric ? instrumentPds(config.pds, config.onMetric) : config.pds;
    const transport = config.onMetric ? instrumentTransport(config.transport, config.onMetric) : config.transport;
    const atsms = new ATSMS(
      config.identity,
      config.storage,
      transport,
      pds,
      config.rng,
      config.onEvent ?? (() => {}),
      config.onSignal,
      config.genesisWaitMs ?? GENESIS_EPOCH_WAIT_MS,
      config.repairAfterMs ?? REPAIR_AFTER_MS,
      config.peerMaxAgeMs,
      config.onMetric,
    );

    await config.identity.ensurePrekeyPublished(pds);
    if (config.mailtoAddress !== undefined) {
      const endpoints = [
        ...(config.transport.ingressUrl !== null ? [{ uri: config.transport.ingressUrl }] : []),
        { uri: config.mailtoAddress },
      ];
      await config.identity.publishInbox(pds, endpoints);
    }

    for (const groupId of await config.storage.listEngineStateIds()) {
      const convo = await Conversation.restore(atsms.context(), groupId);
      if (convo !== null) atsms.register(convo);
    }

    await transport.start((envelope) => atsms.dispatch(envelope));
    atsms.startRepairTimer();
    return atsms;
  }

  async close(): Promise<void> {
    if (this.repairTimer !== null) clearInterval(this.repairTimer);
    this.repairTimer = null;
    await this.transport.stop();
  }

  // ── §8 gap repair (ordering-auth §8: the session computes, the host schedules) ──

  /** Poll every open conversation's ordering buffer; a gap that persists past
   *  `repairAfterMs` (T_REPAIR) triggers a sealed repair request to the members
   *  — any member re-serves the signed frames it retains, and the buffered
   *  frames drain when the holes fill. Re-fires every window while a gap
   *  persists (responses are A5-deduped, so retries are harmless). */
  private startRepairTimer(): void {
    if (this.repairAfterMs <= 0) return;
    this.repairTimer = setInterval(
      () => void this.repairTick().catch((e) => this.onEvent("repair-error", e instanceof Error ? e.message : String(e))),
      Math.max(1, Math.floor(this.repairAfterMs / 2)),
    );
    // Never keep a process alive just to poll for gaps (CLI-friendliness).
    (this.repairTimer as { unref?: () => void }).unref?.();
  }

  private async repairTick(): Promise<void> {
    const now = Date.now();
    for (const [groupId, handle] of this.openConvos) {
      // C-fallback (A+C): the removal notice is one best-effort envelope. A
      // device that missed it (offline past mailbox retention) still believes
      // it is a member while nothing it receives opens — surface that as a
      // soft "you may have been removed", never as fact. Members' self-healing
      // re-notice usually resolves it into the authoritative event above.
      if (handle.inner.amMember && handle.inner.unopenableCount >= UNOPENABLE_SUSPECT_REMOVED && !this.suspected.has(groupId)) {
        this.suspected.add(groupId);
        this.onEvent("possibly-removed-from-conversation", `${handle.id} (nothing opening)`);
      }
      const buffered = handle.inner.bufferedFrames;
      if (buffered === 0) {
        this.gapSince.delete(groupId);
        continue;
      }
      const since = this.gapSince.get(groupId);
      if (since === undefined) {
        this.gapSince.set(groupId, now);
        continue;
      }
      if (now - since < this.repairAfterMs) continue;
      this.gapSince.set(groupId, now); // rearm: retry next window if still gapped
      const outbound = await handle.inner.requestRepair();
      if (outbound.length > 0) {
        this.onEvent("repair-requested", `${groupId.slice(0, 10)} buffered=${buffered}`);
        await this.route(outbound, handle.inner);
      }
    }
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
    return (await this.peers.ensureFresh(did)).reachability;
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
    const trace = span(this.onMetric, "send.oneShot", recipients.join(","));

    // Directory read-through (parallel across recipients): certs parse from
    // the snapshot's PEMs — no per-send listRecords pass.
    const snapshots = new Map<string, PeerSnapshot>(
      await Promise.all(
        recipients.map(async (did): Promise<[string, PeerSnapshot]> => [did, await this.peers.ensureFresh(did)]),
      ),
    );
    const recipientCerts: ATSMSEndpointCertificate[] = [];
    const unreachable: string[] = [];
    for (const did of recipients) {
      const certs = validCertsOf(snapshots.get(did)!);
      if (certs.length === 0) unreachable.push(did);
      else recipientCerts.push(...certs);
    }
    if (unreachable.length > 0) {
      throw new Error(`no published endpoint certificates: ${unreachable.join(", ")}`);
    }
    trace.mark("discovery");

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
    trace.mark("seal");

    // Recipients are independent — deliver concurrently, FIFO per recipient.
    await Promise.all(
      recipients.map(async (did) => {
        // Sealed-sender whenever the recipient has devices we can seal to; the
        // worker fans every envelope to all of the DID's device inboxes, and
        // non-target devices fail the AEAD open and drop (multi-device model).
        const sealable = snapshots
          .get(did)!
          .devices.filter((d) => d.capable && d.signedPrekeyB64 !== undefined);
        if (sealable.length > 0) {
          for (const d of sealable) {
            await this.deliverByDid(did, sealAsymTo(peerKeyBytes(d.signedPrekeyB64!), CONTENT_CMS, cms, this.rng));
          }
        } else {
          await this.deliverByDid(did, cms); // X509-only recipient: bare CMS (legacy form)
        }
      }),
    );
    trace.mark("deliver");
    trace.end({ recipients: recipients.length, certs: recipientCerts.length });
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
        // Repair a half-built conversation: an open() interrupted by a delivery
        // failure can leave a persisted group with no epoch, which every later
        // open() would otherwise reuse forever (permanently unusable). If we
        // hold no epoch and never have, establish one now.
        if (reopened.inner.awaitingFirstEpoch) {
          this.onEvent("repair-missing-epoch", reopened.id);
          await this.route(await reopened.inner.update(), reopened.inner);
        }
        return reopened;
      }
    }

    const trace = span(this.onMetric, "open", others.join(","));
    const descriptors: MemberDescriptor[] = [this.identity.descriptor];
    const incapable: string[] = [];
    // Directory read-through, parallel across members — a warm open does no
    // discovery fetches at all.
    const capabilities = await Promise.all(
      others.map(async (did) => [did, capableFromSnapshot(await this.peers.ensureFresh(did))] as const),
    );
    for (const [did, devices] of capabilities) {
      if (devices.length === 0) {
        incapable.push(did);
        continue;
      }
      for (const d of devices) {
        descriptors.push({
          device: { did, fingerprint: hexToBytes(d.fingerprint) },
          leafPk: d.leafPk,
          signingPk: d.signingPk,
        });
      }
    }
    if (incapable.length > 0) {
      throw new Error(`not DCGKA-capable (no verified prekey): ${incapable.join(", ")}`);
    }
    trace.mark("discovery");

    const { conversation, outbound } = await Conversation.open(this.context(), {
      keys: this.identity.localKeys,
      members: descriptors,
      admins: params.admins ?? [this.identity.did],
    });
    const handle = this.register(conversation);
    this.onEvent("open-created", handle.id.slice(0, 10));

    // Build the group's LOCAL state completely before any delivery: advertise
    // our ingress in-band, then mint the creator's mandatory first update (the
    // healing rule) which establishes the first epoch. Delivery is retryable;
    // local state must never be half-built — a transient relay/network error
    // between the create and the update used to leave a persisted, registered,
    // epoch-less conversation that every later open() reused forever.
    if (this.transport.ingressUrl !== null) await conversation.advertiseEndpoint(this.transport.ingressUrl);
    this.onEvent("open-advertised", handle.id.slice(0, 10));
    const firstUpdate = await conversation.update();
    this.onEvent("open-epoch-established", `${handle.id.slice(0, 10)} envelopes=${firstUpdate.length}`);
    trace.mark("seal");

    // Now deliver — create first (recipients bootstrap from it), then the update.
    await this.route(outbound, conversation);
    this.onEvent("open-create-delivered", String(outbound.length));
    await this.route(firstUpdate, conversation);
    this.onEvent("open-update-delivered", String(firstUpdate.length));
    trace.mark("deliver");
    trace.end({ members: others.length, devices: descriptors.length - 1, envelopes: outbound.length + firstUpdate.length });
    return handle;
  }

  /** A conversation by ID (v2 ConvoId hex, or a bare DCGKA GroupID) — open
   *  handle, or restored from storage. Null if unknown. */
  async get(id: string): Promise<ATSMSConversation | null> {
    const groupId = toGroupId(id);
    const open = this.openConvos.get(groupId);
    if (open !== undefined) return open;
    const convo = await Conversation.restore(this.context(), groupId);
    // Re-check after the await: open()/join may have registered the live
    // session while we restored (storage observers fire on the create's
    // persist, BEFORE open() registers — a subscriber calling get() lands
    // exactly here). Registering our snapshot would shadow the live session
    // with a stale, possibly epochless copy that then eats inbound envelopes
    // and clobbers the persisted state. The map entry, not the restore, wins.
    const raced = this.openConvos.get(groupId);
    if (raced !== undefined) return raced;
    return convo === null ? null : this.register(convo);
  }

  /** Admit every capable device of the conversation's member DIDs that is not
   *  yet in the group (device enrollment / re-key catch-up). */
  private async reconcileDevices(handle: ATSMSConversation): Promise<void> {
    const present = handle.inner.memberDevices;
    const others = handle.members.filter((d) => d !== this.identity.did);
    const capabilities = await Promise.all(
      others.map(async (did) => [did, capableFromSnapshot(await this.peers.ensureFresh(did))] as const),
    );
    // Every missing device across every member DID joins in ONE batched round.
    const missing: MemberDescriptor[] = [];
    for (const [did, devices] of capabilities) {
      for (const d of devices) {
        if (present.has(d.fingerprint)) continue;
        this.onEvent("device-added", `${did} device ${d.fingerprint.slice(0, 12)}… → ${handle.id.slice(0, 8)}…`);
        missing.push({
          device: { did, fingerprint: hexToBytes(d.fingerprint) },
          leafPk: d.leafPk,
          signingPk: d.signingPk,
        });
      }
    }
    if (missing.length === 0) return;
    await this.route(await handle.inner.addMembers(missing), handle.inner);
  }

  /** Add a DID to a conversation (every capable device of it). */
  async addMember(groupId: string, did: string): Promise<void> {
    const handle = await this.get(groupId);
    if (handle === null) throw new Error(`unknown conversation ${groupId}`);
    const trace = span(this.onMetric, "addMember", did);
    const devices = capableFromSnapshot(await this.peers.ensureFresh(did));
    if (devices.length === 0) throw new Error(`not DCGKA-capable (no verified prekey): ${did}`);
    trace.mark("discovery");
    const present = handle.inner.memberDevices;
    // ONE batched round for every missing device (add-member-flow §6): K adds
    // → one post-add epoch → K welcomes, sealed and routed together.
    const missing = devices.filter((d) => !present.has(d.fingerprint));
    const outbound = await handle.inner.addMembers(
      missing.map((d) => ({
        device: { did, fingerprint: hexToBytes(d.fingerprint) },
        leafPk: d.leafPk,
        signingPk: d.signingPk,
      })),
    );
    trace.mark("seal");
    await this.route(outbound, handle.inner);
    trace.mark("deliver");
    trace.end({ devices: devices.length, added: missing.length, rounds: missing.length > 0 ? 1 : 0, envelopes: outbound.length });
  }

  /**
   * Remove a DID from a conversation — every device of it, in ONE batched
   * round (K removes + the healing update; strong remove, dgm §4: the engine
   * rejects a non-admin cross-DID removal). The removed devices receive
   * nothing and simply stop decrypting; a removal notification for their UX
   * is a later, deliberate feature. This is also the cure for the stale-
   * device PCS hole (ordering-auth §9 / dgm §7 eviction) and the lost-state
   * device recovery flow ("remove + re-add me").
   */
  async removeMember(groupId: string, did: string): Promise<void> {
    if (did === this.identity.did) {
      throw new Error("removeMember: cannot remove self — leave() is a separate (not yet built) flow");
    }
    const handle = await this.get(groupId);
    if (handle === null) throw new Error(`unknown conversation ${groupId}`);
    const memberships = handle.inner.membershipsOf(did);
    if (memberships.length === 0) throw new Error(`${did} is not a member of this conversation`);
    const trace = span(this.onMetric, "removeMember", did);
    const outbound = await handle.inner.removeMembers(memberships);
    trace.mark("seal");
    await this.route(outbound, handle.inner);
    trace.mark("deliver");
    trace.end({ devices: memberships.length, envelopes: outbound.length });
    this.onEvent("member-removed", `${did} (${memberships.length} devices) from ${handle.id.slice(0, 10)}`);
  }

  // ── auto-routing ───────────────────────────────────────────────────────────

  /** Outbound: in-band advertised URL first, else the DID's public inbox. The
   *  seal layer already excludes THIS device from recipients, so each envelope
   *  targets another device — routed by that device's DID, never skipped just
   *  because it shares our DID (multi-device: our other devices are real
   *  recipients; the worker fans a copy to our own inbox, which we drop). */
  private async route(outbound: Outbound[], convo: Conversation): Promise<void> {
    const devices = convo.memberDevices;
    // Different recipients are independent — deliver concurrently. Envelopes
    // to the SAME recipient device keep their order (FIFO per lane; the
    // ordering buffer + §8 repair absorb violations, but in-order is free).
    const lanes = new Map<string, Outbound[]>();
    for (const o of outbound) {
      let lane = lanes.get(o.to);
      if (lane === undefined) lanes.set(o.to, (lane = []));
      lane.push(o);
    }
    await Promise.all(
      [...lanes.values()].map(async (lane) => {
        for (const o of lane) {
          if (o.url !== null) {
            await this.transport.deliverToUrl(o.url, o.envelope);
            continue;
          }
          // Members, plus devices we removed: a removal notice is addressed to
          // a device that is (by then) no longer a member.
          const did = devices.get(o.to) ?? convo.didOfDevice(o.to);
          if (did === undefined) continue; // unknown device — unroutable
          await this.deliverByDid(did, o.envelope);
        }
      }),
    );
  }

  /** DID-addressed delivery through the peer directory: the snapshot's https
   *  ingress when it has one (a failure invalidates the snapshot and retries
   *  once on fresh data — the self-healing contract), else the transport's own
   *  resolver (which owns the mailto-only error). */
  private async deliverByDid(did: string, envelope: Uint8Array): Promise<void> {
    const url = await this.peers.inboxUrl(did).catch(() => null);
    if (url === null) {
      await this.transport.deliverToDid(did, envelope);
      return;
    }
    try {
      await this.transport.deliverToUrl(url, envelope);
    } catch {
      await this.peers.invalidate(did);
      const fresh = await this.peers.inboxUrl(did).catch(() => null);
      if (fresh === null) {
        await this.transport.deliverToDid(did, envelope);
        return;
      }
      await this.transport.deliverToUrl(fresh, envelope);
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
        const wasMember = handle.inner.amMember;
        const repairs = await handle.inner.deliverEnvelope(envelope);
        await this.route(repairs, handle.inner);
        // The removal op is sealed to the device it removes, so this is how a
        // removed device finds out — immediately, on the delivery that carries
        // it (the conversation record's `removed` flag is written by the same
        // delivery, so a reloading client sees it too).
        if (wasMember && !handle.inner.amMember) {
          this.onEvent("removed-from-conversation", handle.id);
        }
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
/** Parse the snapshot's cert PEMs into valid endpoint certs — local, no network. */
function validCertsOf(snap: PeerSnapshot): ATSMSEndpointCertificate[] {
  const certs: ATSMSEndpointCertificate[] = [];
  for (const d of snap.devices) {
    try {
      const cert = loadEndpointCertificate(d.certificatePEM);
      if (cert.isValid()) certs.push(cert);
    } catch {
      // unparseable snapshot entry — not a device
    }
  }
  return certs;
}

export function inboxUrlResolver(pds: PdsClient): (did: string) => Promise<string | null> {
  return async (did) => {
    const r = await resolveInbox(pds, did);
    if (!r.ok) return null;
    return pickEndpoint(r.record, ["https"])?.uri ?? null;
  };
}
