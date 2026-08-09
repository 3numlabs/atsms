/**
 * Identity / PDS lifecycle (identity-devices.md §4, inbound-delivery.md §3).
 *
 * The crypto package stays free of `@atproto/api` (RN-safe): PDS access is a
 * thin injected {@link PdsClient} seam, and the publish/rotate/revoke logic +
 * {@link PrekeyManager} are pure over it. The real `@atproto/api` adapter lives
 * at the integration edge (Phase 5, reusing packages/client's `ATSMSClient` plumbing);
 * an adapter MUST preserve `bytes` ⇄ `Uint8Array` round-trips (dag-cbor byte
 * strings), so `signedPrekey`/`bundleSig` survive a fetch.
 */

import { x25519 } from '@noble/curves/ed25519';
import { cborDecode, cborEncode, type CborValue } from './cbor.js';
import { generateSigningKeypair } from './frames.js';
import type { Csprng } from './keyhive.js';
import {
  buildInboxRecord,
  buildPrekeyRecord,
  inboxRecordError,
  inboxRecordNonConformance,
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
  const err = inboxRecordNonConformance(record);
  if (err !== null) return Promise.reject(new Error(`invalid inbox record: ${err}`));
  return pds.putRecord(COLLECTION_INBOX, INBOX_RKEY, record);
}

/** Build + publish an inbox record from an ordered endpoint list (https: requirement enforced).
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

/** One prekey generation's secret halves: the X25519 signed-prekey secret and
 *  the Ed25519 initial-protocol-signing secret published alongside it. */
interface PrekeyGeneration {
  prekeySk: Uint8Array;
  signingSk: Uint8Array;
  signingPk: Uint8Array;
}

/**
 * Device-local signed-prekey state: holds **two** live generations (current +
 * previous, D4) — each an X25519 signed-prekey secret plus the Ed25519 initial
 * protocol signing keypair the bundle declares — signs each generation's record
 * with the device identity (P-256) key, and rolls the ring on rotation. Pure —
 * no ambient clock or RNG (both injected); the caller publishes the returned
 * record via {@link publishPrekey} and persists {@link serialize} (encrypted —
 * these are live admission secrets).
 */
export class PrekeyManager {
  private currentGen: PrekeyGeneration | null = null;
  private previousGen: PrekeyGeneration | null = null;
  private current: PrekeyRecord | null = null;

  /** @param ttlMs signed-prekey lifetime (one rotation period; parameters.md). */
  constructor(
    private readonly identitySk: Uint8Array,
    private readonly rng: Csprng,
    private readonly ttlMs: number,
  ) {}

  /**
   * Generate a fresh generation (signed prekey + initial signing keypair), roll
   * current → previous, sign the record, and return it for publishing. The old
   * current generation is retained as the grace generation (one period); any
   * older one is dropped.
   */
  rotate(now: number): PrekeyRecord {
    this.previousGen = this.currentGen; // may be null on first rotation
    const prekeySk = this.rng(32);
    const signing = generateSigningKeypair(this.rng);
    this.currentGen = { prekeySk, signingSk: signing.sk, signingPk: signing.pk };
    const record = buildPrekeyRecord(
      {
        signedPrekey: x25519.getPublicKey(prekeySk),
        signingPk: signing.pk,
        createdAt: new Date(now).toISOString(),
        expiresAt: new Date(now + this.ttlMs).toISOString(),
      },
      this.identitySk,
    );
    this.current = record;
    return record;
  }

  /** The live signed-prekey secrets for sealed-asym trial-decryption (current,
   *  then grace) — the array {@link SealLayer} consumes. Empty until the first
   *  `rotate`. */
  liveSecrets(): Uint8Array[] {
    return this.liveGenerations().map((g) => g.prekeySk);
  }

  /** The live initial-protocol-signing keypairs (current, then grace). A device
   *  being founded into / added to a group finds the keypair whose `pk` the
   *  create/add op declared (the adder may have resolved either live bundle). */
  liveSigningKeys(): Array<{ sk: Uint8Array; pk: Uint8Array }> {
    return this.liveGenerations().map((g) => ({ sk: g.signingSk, pk: g.signingPk }));
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

  // ── host persistence (atsms-integration §2: the host persists, encrypted) ──

  /** Serialize the ring + current record to an opaque blob. */
  serialize(): Uint8Array {
    const gen = (g: PrekeyGeneration | null): CborValue => (g === null ? null : [g.prekeySk, g.signingSk, g.signingPk]);
    const rec: CborValue =
      this.current === null
        ? null
        : [this.current.signedPrekey, this.current.signingPk, this.current.createdAt, this.current.expiresAt, this.current.bundleSig];
    return cborEncode([1, gen(this.currentGen), gen(this.previousGen), rec]);
  }

  /** Restore from `serialize()` output. `identitySk`/`rng` are injected (behavior,
   *  not persisted state). */
  static restore(bytes: Uint8Array, ctx: { identitySk: Uint8Array; rng: Csprng; ttlMs: number }): PrekeyManager {
    const arr = cborDecode(bytes) as CborValue[];
    if (arr[0] !== 1) throw new Error(`unknown prekey snapshot version ${String(arr[0])}`);
    const gen = (v: CborValue): PrekeyGeneration | null => {
      if (v === null) return null;
      const [prekeySk, signingSk, signingPk] = v as [Uint8Array, Uint8Array, Uint8Array];
      return { prekeySk, signingSk, signingPk };
    };
    const mgr = new PrekeyManager(ctx.identitySk, ctx.rng, ctx.ttlMs);
    mgr.currentGen = gen(arr[1] as CborValue);
    mgr.previousGen = gen(arr[2] as CborValue);
    if (arr[3] !== null) {
      const [signedPrekey, signingPk, createdAt, expiresAt, bundleSig] = arr[3] as [
        Uint8Array, Uint8Array, string, string, Uint8Array,
      ];
      mgr.current = { $type: 'at.atsms.prekey', signedPrekey, signingPk, createdAt, expiresAt, bundleSig };
    }
    return mgr;
  }

  private liveGenerations(): PrekeyGeneration[] {
    return [this.currentGen, this.previousGen].filter((g): g is PrekeyGeneration => g !== null);
  }
}
