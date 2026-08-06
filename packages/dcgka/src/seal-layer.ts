/**
 * Sealed-sender delivery layer (sealed-sender.md §1/§11; the "engine emits
 * (sealed message, recipient list); delivery does the fan-out" boundary). Wraps
 * a {@link Session}: outbound frames are sealed **per recipient** and inbound
 * envelopes are unsealed back into frames, so the whole protocol runs over
 * `SealedEnvelope`s and an observer sees only opaque, uncorrelatable blobs.
 *
 * Mode selection (sealed-sender §1/§11.1):
 * - **sealed-sym** for in-conversation traffic once the sender has an
 *   established epoch — one `envKey` per sender-epoch, a distinct per-recipient
 *   tag/nonce/ciphertext (unlinkable fan-out).
 * - **sealed-asym** (HPKE to the recipient's signed prekey) for bootstrap: the
 *   `create`, the first `update` (no prior epoch), and `welcome`s (the joiner
 *   has no group state). Recipient prekeys ride in the `create`/`add` ops
 *   themselves (the leaf key IS the signed prekey, D10), so no PDS lookup is
 *   needed for the protocol's own bootstrap.
 *
 * Transport is out of scope: this yields `{ to, envelope }` pairs and consumes
 * envelopes; who carries them (relay push, gossip, …) is a separate concern.
 */

import { bytesToHex } from './bytes.js';
import {
  CLS_CONTROL,
  CLS_WELCOME,
  parseFrame,
} from './frames.js';
import { encodeMembership, membershipKey, type DeviceID, type Membership } from './ids.js';
import type { Csprng } from './keyhive.js';
import {
  CONTENT_FRAME,
  MODE_ASYM,
  MODE_SYM,
  TagTable,
  envelopeId,
  envelopeMode,
  openAsym,
  parseSymEnvelope,
  sealAsymTo,
  sealSymTo,
  openSym,
  type SealedPlaintext,
} from './envelope.js';
import { payloadFromCbor } from './ops.js';
import type { Session } from './ordering.js';

/** A sealed envelope addressed to one recipient device (by fingerprint hex). */
export interface Outbound {
  to: string; // recipient device fingerprint (hex)
  /**
   * Non-welcome delivery endpoint learned in-band (sealed-sender §12), or null
   * when not yet known (welcome frames — routed via the joiner's public
   * `at.atsms.welcome.*` record — or a recipient whose advert hasn't landed; the
   * transport resolves/retries those). The literal `POST url` is the transport's job.
   */
  url: string | null;
  envelope: Uint8Array;
}

export class SealLayer {
  private tags = new TagTable();
  /**
   * Identification-only tags for devices we have REMOVED. Kept separate from
   * `tags` on purpose: a hit here never yields content to the session — it
   * only tells us "a device that does not know it was removed is still
   * talking", so we can re-send its removal notice (the notice is one
   * best-effort envelope; a device offline past mailbox retention misses it).
   * Removing this table costs nothing but that self-healing.
   */
  private removedTags = new TagTable();
  /** device fingerprint hex → signed-prekey pub (from create/add leaf keys). */
  private prekeys = new Map<string, Uint8Array>();
  /** add-op id hex → the joiner's device fingerprint (for welcome routing). */
  private addToJoiner = new Map<string, string>();
  /** frame id hex → the one device a re-invitation is meant for (§8.2). */
  private reinviteTargets = new Map<string, string>();
  /** sym envelopes whose tag isn't known yet (epoch not derived) — retried on
   *  refresh, FIFO-dropped past the bound (sealed-sender §11.4, "buffer briefly …
   *  else drop"; also sheds the unopenable sym add-copy a joiner receives of its
   *  own add). Each carries a retry counter: an envelope that stays unopenable
   *  across many refreshes is a divergence signal, not a transient (§4.3). */
  private pending: Array<{ envelope: Uint8Array; tries: number }> = [];
  private static readonly MAX_PENDING = 256;
  /** Retries after which a still-unopenable sym envelope is reported as a likely
   *  epoch divergence (concurrent-update-partition §4.3) and dropped — instead
   *  of the old silent FIFO drop that hid the live partition bug. */
  private static readonly UNOPENABLE_REPORT_AT = 8;
  private seen = new Set<string>(); // EnvelopeID dedup (§3)
  private encMe: Uint8Array;

  constructor(
    readonly session: Session,
    /** This device's live signed-prekey secrets (current + grace) for opening asym (D10). */
    private prekeySecrets: Uint8Array[],
    private rng: Csprng,
    /** Diagnostics sink — surfaced, never fatal. Persistently-unopenable sym
     *  traffic reports here (kind `unopenable-envelope`). Default: silent. */
    private onEvent: (kind: string, detail: string) => void = () => {},
  ) {
    this.encMe = encodeMembership(session.engine.me);
    // Learn prekeys from the create the session already holds.
    // Replay the whole op log, not just the create: prekeys and add→joiner
    // routing are learned by observing ops, and a restored session has already
    // processed its adds, so a fresh seal layer would know nothing about them.
    // Re-welcoming an earlier joiner (§8.2) needs exactly that routing.
    for (const op of session.engine.opsList()) this.observeOp(op.id, op.payload as never);
    this.refresh();
  }

  /**
   * The prekey this conversation ADMITTED a device with — the leaf key named in
   * its `create`/`add` op, which is also what everything asym-sealed to it uses.
   * A device that has since re-keyed (rotated past its grace window, or lost the
   * ring with its local state while keeping its identity key) no longer holds
   * the matching secret, and nothing sealed to it will ever open. Comparing this
   * against what the device publishes today is how a host tells "their
   * invitation went missing" (re-invite works) from "their keys have moved on"
   * (only a fresh add works).
   */
  admittedPrekey(fingerprintHex: string): Uint8Array | null {
    return this.prekeys.get(fingerprintHex) ?? null;
  }

  /**
   * §8.2: queue a member's admission material again — the recovery for a lost
   * `create` or `welcome`. Addressing is this layer's job, so the target is
   * recorded here; `drainSealed()` seals it to that device alone, sealed to its
   * prekey and routed to its public inbox, exactly as first contact was.
   */
  reinvite(device: DeviceID): boolean {
    const raw = this.session.reinvite(device);
    if (raw === null) return false;
    this.reinviteTargets.set(bytesToHex(parseFrame(raw).id), bytesToHex(device.fingerprint));
    return true;
  }

  /**
   * Seal everything the session has queued. Returns per-recipient envelopes for
   * the transport. Call after any local op / after `deliver`.
   */
  drainSealed(): Outbound[] {
    const out: Outbound[] = [];
    // (the table is rebuilt at the end — a local op may have changed membership)
    const outbox = this.session.takeOutbox();
    // Removals in one batch form a dependency CHAIN (remove#2 depends on
    // remove#1). A device that could only open its own removal would buffer it
    // forever on the missing earlier op and never learn — so every removal in
    // the batch is addressed to every device the batch removes. They were all
    // members when it happened; a removal is a fact they are party to.
    const batchRemoved: Membership[] = [];
    for (const raw of outbox) {
      for (const m of removedBy(parseFrame(raw))) {
        if (!batchRemoved.some((x) => sameFp(x, m))) batchRemoved.push(m);
      }
    }
    for (const raw of outbox) {
      const frame = parseFrame(raw);
      if (frame.body.cls === CLS_CONTROL) {
        // Learn prekeys before routing (an add precedes its welcome in the outbox).
        const payload = payloadFromCbor(frame.body.payload, frame.body.sender.device.fingerprint);
        this.observeOp(frame.id, payload);
      }
      // §8.2 re-invitation: a re-queued `create` is addressed to the one member
      // that never received it, not fanned to the group — everyone else already
      // holds it and would only dedup a copy. (A rebuilt welcome routes itself
      // below, by the joiner named in its add op.)
      const reinviteFp = this.reinviteTargets.get(bytesToHex(frame.id));
      if (reinviteFp !== undefined) {
        this.reinviteTargets.delete(bytesToHex(frame.id));
        const pk = this.prekeys.get(reinviteFp);
        if (pk !== undefined) {
          out.push({
            to: reinviteFp,
            url: null, // first contact again: the public inbox record
            envelope: sealAsymTo(pk, CONTENT_FRAME, raw, this.rng),
          });
        }
        continue;
      }
      if (frame.body.cls === CLS_WELCOME) {
        // Point-to-point, asym to the joiner's prekey.
        const [addOpId] = frame.body.payload as [Uint8Array];
        const joinerFp = this.addToJoiner.get(bytesToHex(addOpId));
        const pk = joinerFp === undefined ? undefined : this.prekeys.get(joinerFp);
        if (joinerFp !== undefined && pk !== undefined) {
          // url null: a welcome is routed via the joiner's public welcome record.
          out.push({ to: joinerFp, url: null, envelope: sealAsymTo(pk, CONTENT_FRAME, raw, this.rng) });
        }
        continue;
      }
      // Seal under the epoch the frame's causal ancestors establish (sealed-sender
      // §11.4): app content rides the current epoch; an epoch-advancing control op
      // resolves to its parent epoch (receivers hold it, then derive the new one
      // by processing this frame). Null ⇒ no epoch precedes it (first update after
      // create) ⇒ fall to asym (bootstrap-class, §1) to each recipient's prekey.
      const recipients = this.session.engine.members().filter((m) => !sameFp(m, this.session.engine.me));
      // A removed device is no longer a member, so the fan-out above excludes
      // it — meaning it would never learn it was removed and would go on
      // talking into a group that ignores it (live UX complaint 2026-08-03).
      // Deliberate decision: the removal op IS sealed to the devices it
      // removes, under the PARENT epoch they still hold. It tells them nothing
      // they did not already know (they were members; the op names them), and
      // it is what every mainstream messenger does. They cannot derive the
      // post-remove epoch, so this is their last readable frame.
      if (removedBy(frame).length > 0) {
        for (const removed of batchRemoved) {
          // Never to ourselves: on leave() the batch removes our own device too.
          if (sameFp(removed, this.session.engine.me)) continue;
          if (!recipients.some((m) => sameFp(m, removed))) recipients.push(removed);
        }
      }
      const epochId = this.session.engine.sealEpochFor(frame.body.deps);
      const envKey = epochId === null ? null : this.session.engine.epochEnvKey(epochId, this.encMe);
      for (const r of recipients) {
        const fp = bytesToHex(r.device.fingerprint);
        // Non-welcome routing: the endpoint the recipient advertised in-band (§12).
        const url = this.session.endpointOf(r.device.fingerprint);
        if (envKey !== null) {
          out.push({ to: fp, url, envelope: sealSymTo(envKey, encodeMembership(r), CONTENT_FRAME, raw, this.rng) });
        } else {
          const pk = this.prekeys.get(fp);
          if (pk !== undefined) out.push({ to: fp, url, envelope: sealAsymTo(pk, CONTENT_FRAME, raw, this.rng) });
        }
      }
    }
    // Local ops change what we should ACCEPT: after a remove, the removed
    // member's receive tags must go immediately. Previously only `deliver()`
    // refreshed, so the REMOVER kept a stale table and went on accepting the
    // removed member's traffic while everyone else (who learned by delivery)
    // correctly ignored it — the live asymmetry seen 2026-08-03.
    this.refresh();
    return out;
  }

  /** Unseal an incoming envelope and feed the frame to the session. */
  deliver(envelope: Uint8Array): void {
    const id = bytesToHex(envelopeId(envelope));
    if (this.seen.has(id)) return; // §3 dedup, pre-decryption
    this.seen.add(id);
    if (!this.tryOpen(envelope)) {
      this.pending.push({ envelope, tries: 0 });
      if (this.pending.length > SealLayer.MAX_PENDING) this.pending.shift(); // FIFO drop
    }
    this.refresh(); // an ingest may have derived a new epoch → new tags, retry buffered
  }

  /** Bootstrap: unseal an asym `create`/`welcome` envelope to raw frame bytes. */
  static openBootstrap(envelope: Uint8Array, prekeySecrets: Uint8Array[]): Uint8Array {
    for (const sk of prekeySecrets) {
      try {
        const { contentType, body } = openAsym(sk, envelope);
        if (contentType === CONTENT_FRAME) return body;
      } catch {
        /* try the next (grace) secret */
      }
    }
    throw new Error('openBootstrap: no prekey secret opens this envelope');
  }

  // ── internals ─────────────────────────────────────────────────────────────

  private tryOpen(envelope: Uint8Array): boolean {
    const mode = envelopeMode(envelope);
    if (mode === MODE_SYM) {
      parseSymEnvelope(envelope); // validate shape
      const opened = this.tags.open(envelope);
      if (opened === null) {
        // Not addressed to US by tag — but that is the COMMON case in a
        // multi-device DID: the relay cannot tell which device an envelope is
        // for (sealed sender), so it fans every copy to every device of the
        // recipient DID, and we see one copy per sibling.
        //
        // Those copies are ours to open anyway: the sym key is per
        // (epoch, sender) — only the tag and nonce are per-recipient (§11.3,
        // where the tag is called a routing HINT, not a secret). Opening them
        // turns fan-out into redundancy (a sibling's copy still delivers the
        // frame if ours was lost) and, just as usefully, keeps the
        // unopenable-envelope warning meaningful instead of firing on ordinary
        // multi-device traffic.
        const sibling = this.openAsSiblingCopy(envelope);
        if (sibling !== null) {
          if (sibling.contentType === CONTENT_FRAME) this.ingest(sibling.body); // A5 dedups
          return true;
        }
        // Is it a device we removed that never learned? Then consume it —
        // content discarded, never ingested — and re-send its removal notice.
        const fromRemoved = this.removedTags.open(envelope);
        if (fromRemoved !== null) {
          const meta = fromRemoved.meta as { device: DeviceID };
          this.onEvent('traffic-from-removed-device', bytesToHex(meta.device.fingerprint).slice(0, 12));
          this.session.renotifyRemovedDevice(meta.device);
          return true;
        }
        return false; // genuinely unknown: an epoch we do not hold
      }
      if (opened.plaintext.contentType === CONTENT_FRAME) this.ingest(opened.plaintext.body);
      return true;
    }
    if (mode === MODE_ASYM) {
      for (const sk of this.prekeySecrets) {
        try {
          const { contentType, body } = openAsym(sk, envelope);
          if (contentType === CONTENT_FRAME) this.ingest(body);
          return true;
        } catch {
          /* next secret */
        }
      }
      return false; // not addressed to us
    }
    return false;
  }

  /**
   * Try every (live epoch, member-sender) key we hold. A hit means the
   * envelope is a fan-out copy addressed to one of our sibling devices —
   * same plaintext, different tag/nonce. Bounded by epochs × members, and
   * only reached when the tag lookup missed.
   */
  private openAsSiblingCopy(envelope: Uint8Array): SealedPlaintext | null {
    const eng = this.session.engine;
    // Only while we are IN the group. A device that left or was removed can
    // still decrypt fan-out copies for a while (it holds the old epoch), and
    // picking group state out of them would let it walk itself back in: it
    // would ingest the add op that re-admits it from someone else's copy,
    // believe it is a member again, and never process the welcome that
    // carries the material it actually needs — so its next message is sealed
    // under state no one shares (live-shaped regression, caught by the
    // leave → re-add churn scenario). The way back in is the welcome.
    if (!this.session.amMember()) return null;
    for (const epochId of eng.liveEpochs()) {
      for (const sender of eng.members()) {
        const envKey = eng.epochEnvKey(epochId, encodeMembership(sender));
        if (envKey === null) continue;
        try {
          return openSym(envKey, envelope);
        } catch {
          /* not this key — keep looking */
        }
      }
    }
    return null;
  }

  private ingest(frameBytes: Uint8Array): void {
    const frame = parseFrame(frameBytes);
    if (frame.body.cls === CLS_CONTROL) {
      const payload = payloadFromCbor(frame.body.payload, frame.body.sender.device.fingerprint);
      this.observeOp(frame.id, payload);
    }
    this.session.ingestFrame(frameBytes);
  }

  /** Rebuild the receive tag table from live epochs × members, then retry buffered. */
  private refresh(): void {
    const eng = this.session.engine;
    this.tags = new TagTable();
    this.removedTags = new TagTable();
    for (const epochId of eng.liveEpochs()) {
      for (const gone of this.session.removedMemberships()) {
        const envKey = eng.epochEnvKey(epochId, encodeMembership(gone));
        if (envKey !== null) this.removedTags.install(envKey, this.encMe, { device: gone.device });
      }
    }
    const meFp = eng.me.device.fingerprint;
    for (const epochId of eng.liveEpochs()) {
      for (const s of eng.members()) {
        if (bytesToHex(s.device.fingerprint) === bytesToHex(meFp)) continue;
        const envKey = eng.epochEnvKey(epochId, encodeMembership(s));
        if (envKey !== null) this.tags.install(envKey, this.encMe, { epochId, sender: membershipKey(s) });
      }
    }
    if (this.pending.length > 0) {
      const still: Array<{ envelope: Uint8Array; tries: number }> = [];
      for (const p of this.pending) {
        if (this.tryOpen(p.envelope)) continue; // opened — done
        p.tries++;
        if (p.tries >= SealLayer.UNOPENABLE_REPORT_AT) {
          // Persistently unopenable: the sender sealed under an epoch we never
          // derived — the concurrent-update partition signature (§4.3). Report
          // and drop, rather than the old silent buffer-forever/FIFO drop.
          this.onEvent(
            'unopenable-envelope',
            `sym envelope unopened after ${p.tries} refreshes (unknown epoch tag: traffic sealed under an epoch ` +
              `we do not hold — a peer mid-heal, an envelope left over from earlier churn, or genuine divergence)`,
          );
          continue;
        }
        still.push(p);
      }
      // Only recurse-refresh if we actually drained/dropped something (avoid loops).
      const drained = still.length < this.pending.length;
      this.pending = still;
      if (drained) this.refresh();
    }
  }

  private observeOp(opId: Uint8Array, payload: { type: string } & Record<string, unknown>): void {
    if (payload.type === 'create') {
      const devices = (payload as unknown as { initialDevices: Array<{ device: { fingerprint: Uint8Array }; leafPk: Uint8Array }> }).initialDevices;
      for (const d of devices) this.prekeys.set(bytesToHex(d.device.fingerprint), d.leafPk);
    } else if (payload.type === 'add') {
      const p = payload as unknown as { device: { fingerprint: Uint8Array }; leafPk: Uint8Array };
      const fp = bytesToHex(p.device.fingerprint);
      this.prekeys.set(fp, p.leafPk);
      this.addToJoiner.set(bytesToHex(opId), fp);
    }
  }
}

function sameFp(a: Membership, b: Membership): boolean {
  return bytesToHex(a.device.fingerprint) === bytesToHex(b.device.fingerprint);
}

/** The memberships a control frame removes (empty for every other frame). */
function removedBy(frame: ReturnType<typeof parseFrame>): Membership[] {
  if (frame.body.cls !== CLS_CONTROL) return [];
  try {
    const payload = payloadFromCbor(frame.body.payload, frame.body.sender.device.fingerprint);
    return payload.type === 'remove' ? [payload.membership] : [];
  } catch {
    return [];
  }
}
