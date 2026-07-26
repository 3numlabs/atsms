/**
 * Identity / PDS lifecycle (identity-devices.md §4, inbound-delivery.md §3).
 *
 * The crypto package stays free of `@atproto/api` (RN-safe): PDS access is a
 * thin injected {@link PdsClient} seam, and the publish/rotate/revoke logic +
 * {@link PrekeyManager} are pure over it. The real `@atproto/api` adapter lives
 * at the integration edge (Phase 5, reusing atsms-lib's `ATSMSClient` plumbing);
 * an adapter MUST preserve `bytes` ⇄ `Uint8Array` round-trips (dag-cbor byte
 * strings), so `signedPrekey`/`bundleSig` survive a fetch.
 */

import { x25519 } from '@noble/curves/ed25519';
import type { Csprng } from './keyhive.js';
import {
  buildInboxRecord,
  buildPrekeyRecord,
  inboxRecordError,
  verifyPrekeyRecord,
  type InboxEndpoint,
  type InboxRecord,
  type PrekeyRecord,
} from './records.js';

export const COLLECTION_PREKEY = 'at.atsms.prekey';
export const COLLECTION_INBOX = 'at.atsms.inbox';
export const INBOX_RKEY = 'self';

/** One record as returned from a PDS read. `value` decodes with `bytes` as `Uint8Array`. */
export interface PdsRecordView {
  uri: string; // at://<did>/<collection>/<rkey>
  cid?: string;
  value: unknown;
}
export interface PutResult {
  uri: string;
  cid?: string;
}

/**
 * The minimal PDS surface this package needs. Writes target the authenticated
 * user's **own** repo; reads take an explicit `repo` (any DID).
 */
export interface PdsClient {
  putRecord(collection: string, rkey: string, value: unknown): Promise<PutResult>;
  deleteRecord(collection: string, rkey: string): Promise<void>;
  getRecord(repo: string, collection: string, rkey: string): Promise<PdsRecordView | null>;
  listRecords(repo: string, collection: string): Promise<PdsRecordView[]>;
}

export type ResolveResult<T> = { ok: true; record: T } | { ok: false; reason: string };

// ── at.atsms.prekey lifecycle ────────────────────────────────────────────────

/** Publish/replace this device's prekey record (rkey = device fingerprint). */
export function publishPrekey(pds: PdsClient, fingerprint: string, record: PrekeyRecord): Promise<PutResult> {
  return pds.putRecord(COLLECTION_PREKEY, fingerprint, record);
}

/** Revoke (delete) this device's prekey record — part of lost-device teardown (§4). */
export function revokePrekey(pds: PdsClient, fingerprint: string): Promise<void> {
  return pds.deleteRecord(COLLECTION_PREKEY, fingerprint);
}

/**
 * Fetch and **verify** another device's prekey (§4.2 step 2–3): getRecord, then
 * check `bundleSig` against that device's identity (P-256) key — the key from its
 * `at.atsms.x509` endpoint cert, resolved separately (cert parsing lives in the
 * integration edge). `now` (ms) enables the expiry check. Trust nothing until
 * verified.
 */
export async function resolvePrekey(
  pds: PdsClient,
  did: string,
  fingerprint: string,
  identityPub: Uint8Array,
  now?: number,
): Promise<ResolveResult<PrekeyRecord>> {
  const view = await pds.getRecord(did, COLLECTION_PREKEY, fingerprint);
  if (view === null) return { ok: false, reason: 'not-found' };
  const record = view.value as PrekeyRecord;
  const v = verifyPrekeyRecord(record, identityPub, now);
  return v.ok ? { ok: true, record } : { ok: false, reason: v.reason };
}

// ── at.atsms.inbox lifecycle ─────────────────────────────────────────────────

/** Publish/replace the per-DID inbox singleton (rkey = `self`). */
export function publishInbox(pds: PdsClient, record: InboxRecord): Promise<PutResult> {
  const err = inboxRecordError(record);
  if (err !== null) return Promise.reject(new Error(`invalid inbox record: ${err}`));
  return pds.putRecord(COLLECTION_INBOX, INBOX_RKEY, record);
}

/** Build + publish an inbox record from an ordered endpoint list (mailto: floor enforced).
 *  `async` so an invalid list surfaces as a rejected promise, not a sync throw. */
export async function publishInboxEndpoints(pds: PdsClient, endpoints: InboxEndpoint[]): Promise<PutResult> {
  return publishInbox(pds, buildInboxRecord(endpoints));
}

/** Fetch + validate a DID's inbox record. */
export async function resolveInbox(pds: PdsClient, did: string): Promise<ResolveResult<InboxRecord>> {
  const view = await pds.getRecord(did, COLLECTION_INBOX, INBOX_RKEY);
  if (view === null) return { ok: false, reason: 'not-found' };
  const record = view.value as InboxRecord;
  const err = inboxRecordError(record);
  return err === null ? { ok: true, record } : { ok: false, reason: err };
}

// ── prekey rotation (device-local key management, §4.2 / D4) ──────────────────

/**
 * Device-local signed-prekey state: holds **two** live X25519 secrets (current +
 * previous, D4), signs each generation's record with the device identity (P-256)
 * key, and rolls the ring on rotation. Pure — no ambient clock or RNG (both
 * injected); the caller publishes the returned record via {@link publishPrekey}.
 */
export class PrekeyManager {
  private currentSk: Uint8Array | null = null;
  private previousSk: Uint8Array | null = null;
  private current: PrekeyRecord | null = null;

  /** @param ttlMs signed-prekey lifetime (one rotation period; parameters.md). */
  constructor(
    private readonly identitySk: Uint8Array,
    private readonly rng: Csprng,
    private readonly ttlMs: number,
  ) {}

  /**
   * Generate a fresh signed prekey, roll current → previous, sign the record, and
   * return it for publishing. The old current secret is retained as the grace
   * secret (one period); any older secret is dropped.
   */
  rotate(now: number): PrekeyRecord {
    this.previousSk = this.currentSk; // may be null on first rotation
    const sk = this.rng(32);
    this.currentSk = sk;
    const record = buildPrekeyRecord(
      {
        signedPrekey: x25519.getPublicKey(sk),
        createdAt: new Date(now).toISOString(),
        expiresAt: new Date(now + this.ttlMs).toISOString(),
      },
      this.identitySk,
    );
    this.current = record;
    return record;
  }

  /** The live secrets for sealed-asym trial-decryption (current, then grace) — the
   *  array {@link SealLayer} consumes. Empty until the first `rotate`. */
  liveSecrets(): Uint8Array[] {
    return [this.currentSk, this.previousSk].filter((s): s is Uint8Array => s !== null);
  }

  /** The current published record, or null before the first rotation. */
  currentRecord(): PrekeyRecord | null {
    return this.current;
  }

  /** True if there is no prekey yet, or the current one expires within `marginMs`. */
  needsRotation(now: number, marginMs = 0): boolean {
    if (this.current === null) return true;
    return Date.parse(this.current.expiresAt) - now <= marginMs;
  }
}
