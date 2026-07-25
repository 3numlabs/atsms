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
import { encodeMembership, membershipKey, type Membership } from './ids.js';
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
  /** device fingerprint hex → signed-prekey pub (from create/add leaf keys). */
  private prekeys = new Map<string, Uint8Array>();
  /** add-op id hex → the joiner's device fingerprint (for welcome routing). */
  private addToJoiner = new Map<string, string>();
  /** sym envelopes whose tag isn't known yet (epoch not derived) — retried on
   *  refresh, FIFO-dropped past the bound (sealed-sender §11.4, "buffer briefly …
   *  else drop"; also sheds the unopenable sym add-copy a joiner receives of its
   *  own add). */
  private pending: Uint8Array[] = [];
  private static readonly MAX_PENDING = 256;
  private seen = new Set<string>(); // EnvelopeID dedup (§3)
  private encMe: Uint8Array;

  constructor(
    readonly session: Session,
    /** This device's live signed-prekey secrets (current + grace) for opening asym (D10). */
    private prekeySecrets: Uint8Array[],
    private rng: Csprng,
  ) {
    this.encMe = encodeMembership(session.engine.me);
    // Learn prekeys from the create the session already holds.
    this.observeOp(session.engine.bootstrapOp().id, session.engine.bootstrapOp().payload as never);
    this.refresh();
  }

  /**
   * Seal everything the session has queued. Returns per-recipient envelopes for
   * the transport. Call after any local op / after `deliver`.
   */
  drainSealed(): Outbound[] {
    const out: Outbound[] = [];
    for (const raw of this.session.takeOutbox()) {
      const frame = parseFrame(raw);
      if (frame.body.cls === CLS_CONTROL) {
        // Learn prekeys before routing (an add precedes its welcome in the outbox).
        const payload = payloadFromCbor(frame.body.payload, frame.body.sender.device.fingerprint);
        this.observeOp(frame.id, payload);
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
    return out;
  }

  /** Unseal an incoming envelope and feed the frame to the session. */
  deliver(envelope: Uint8Array): void {
    const id = bytesToHex(envelopeId(envelope));
    if (this.seen.has(id)) return; // §3 dedup, pre-decryption
    this.seen.add(id);
    if (!this.tryOpen(envelope)) {
      this.pending.push(envelope);
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
      if (opened === null) return false; // unknown tag — epoch not derived yet
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
    const meFp = eng.me.device.fingerprint;
    for (const epochId of eng.liveEpochs()) {
      for (const s of eng.members()) {
        if (bytesToHex(s.device.fingerprint) === bytesToHex(meFp)) continue;
        const envKey = eng.epochEnvKey(epochId, encodeMembership(s));
        if (envKey !== null) this.tags.install(envKey, this.encMe, { epochId, sender: membershipKey(s) });
      }
    }
    if (this.pending.length > 0) {
      const still: Uint8Array[] = [];
      for (const env of this.pending) if (!this.tryOpen(env)) still.push(env);
      // Only recurse-refresh if we actually drained something (avoid loops).
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
