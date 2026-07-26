/**
 * PDS record codec + validation (identity-devices.md §4, inbound-delivery.md §3).
 * Pure and RN-safe: building/signing/validating records has no network. The PDS
 * I/O (publish/rotate/revoke via `@atproto/api`) is a separate adapter that
 * consumes these.
 *
 * - `at.atsms.prekey` — the device's always-available bootstrap key; `bundleSig`
 *   is ECDSA-P256 (device identity key) over the strict CBOR of the generation.
 * - `at.atsms.inbox` — the per-DID inbound-delivery record; transport is the URI
 *   scheme (`mailto:` floor + optional upgrades).
 */

import { p256 } from '@noble/curves/p256';
import { sha256 } from '@noble/hashes/sha2';
import { cborEncode } from './cbor.js';

// ── at.atsms.prekey (identity-devices §4.2) ──────────────────────────────────

export interface PrekeyRecord {
  $type: 'at.atsms.prekey';
  signedPrekey: Uint8Array; // X25519 pub, 32 bytes
  createdAt: string; // ISO 8601
  expiresAt: string; // ISO 8601
  bundleSig: Uint8Array; // ECDSA-P256, 64 bytes (compact r‖s)
}

/**
 * The exact bytes `bundleSig` signs (identity-devices §4.2): SHA-256 of the
 * deterministic CBOR **positional array** of the preceding fields, in
 * declaration order. Positional (not a map) per the map-free DRISL base wire
 * (wire-format §1) — the encoding is bijective, so the signature is unambiguous.
 */
export function prekeyBundleSigInput(fields: {
  signedPrekey: Uint8Array;
  createdAt: string;
  expiresAt: string;
}): Uint8Array {
  return sha256(cborEncode([fields.signedPrekey, fields.createdAt, fields.expiresAt]));
}

/** Build + sign a prekey record with the device identity (P-256) private key. */
export function buildPrekeyRecord(
  fields: { signedPrekey: Uint8Array; createdAt: string; expiresAt: string },
  identitySk: Uint8Array,
): PrekeyRecord {
  if (fields.signedPrekey.length !== 32) throw new Error('signedPrekey must be 32 bytes (X25519 pub)');
  const bundleSig = p256.sign(prekeyBundleSigInput(fields), identitySk).toCompactRawBytes();
  return { $type: 'at.atsms.prekey', ...fields, bundleSig };
}

export type PrekeyVerifyResult =
  | { ok: true }
  | { ok: false; reason: 'bad-shape' | 'bad-signature' | 'expired' };

/**
 * Verify a prekey record against the device identity (P-256) public key — the
 * key extracted from that device's `at.atsms.x509` endpoint cert (§4.2 step 3).
 * `now` (ms, injected — the engine forbids ambient clocks) enables the expiry
 * check; omit to skip it.
 */
export function verifyPrekeyRecord(
  record: PrekeyRecord,
  identityPub: Uint8Array,
  now?: number,
): PrekeyVerifyResult {
  if (
    record.$type !== 'at.atsms.prekey' ||
    !(record.signedPrekey instanceof Uint8Array) ||
    record.signedPrekey.length !== 32 ||
    typeof record.createdAt !== 'string' ||
    typeof record.expiresAt !== 'string' ||
    !(record.bundleSig instanceof Uint8Array) ||
    record.bundleSig.length !== 64
  ) {
    return { ok: false, reason: 'bad-shape' };
  }
  const input = prekeyBundleSigInput(record);
  if (!p256.verify(record.bundleSig, input, identityPub)) return { ok: false, reason: 'bad-signature' };
  if (now !== undefined && Date.parse(record.expiresAt) <= now) return { ok: false, reason: 'expired' };
  return { ok: true };
}

// ── at.atsms.inbox (inbound-delivery §3) ─────────────────────────────────────

export interface InboxEndpoint {
  uri: string;
}
export interface InboxRecord {
  $type: 'at.atsms.inbox';
  endpoints: InboxEndpoint[];
}

/** The scheme of a URI (lowercased), or null if it has none. */
export function uriScheme(uri: string): string | null {
  const m = /^([a-zA-Z][a-zA-Z0-9+.-]*):/.exec(uri);
  return m === null ? null : m[1]!.toLowerCase();
}

/**
 * Build a validated inbox record. `endpoints` are kept in the given preference
 * order (most-preferred first). Requires at least one `mailto:` endpoint — the
 * SMTP interop floor (inbound-delivery §3).
 */
export function buildInboxRecord(endpoints: InboxEndpoint[]): InboxRecord {
  const err = inboxRecordError({ $type: 'at.atsms.inbox', endpoints });
  if (err !== null) throw new Error(`invalid inbox record: ${err}`);
  return { $type: 'at.atsms.inbox', endpoints: endpoints.map((e) => ({ uri: e.uri })) };
}

/** Validate a decoded inbox record; returns a reason string, or null if valid. */
export function inboxRecordError(record: InboxRecord): string | null {
  if (record.$type !== 'at.atsms.inbox') return 'wrong $type';
  if (!Array.isArray(record.endpoints) || record.endpoints.length === 0) return 'endpoints must be a non-empty array';
  let hasMailto = false;
  for (const e of record.endpoints) {
    if (e === null || typeof e !== 'object' || typeof e.uri !== 'string') return 'endpoint must be { uri: string }';
    const scheme = uriScheme(e.uri);
    if (scheme === null) return `endpoint uri has no scheme: ${e.uri}`;
    if (scheme === 'mailto') hasMailto = true;
  }
  if (!hasMailto) return 'at least one mailto: endpoint required (SMTP floor)';
  return null;
}

/**
 * Pick the highest-preference endpoint whose scheme the caller supports
 * (inbound-delivery §3 selection). `supported` defaults to `['mailto']` — the
 * floor every implementation can hit. Returns null if none match.
 */
export function pickEndpoint(record: InboxRecord, supported: string[] = ['mailto']): InboxEndpoint | null {
  const set = new Set(supported.map((s) => s.toLowerCase()));
  for (const e of record.endpoints) {
    const scheme = uriScheme(e.uri);
    if (scheme !== null && set.has(scheme)) return e;
  }
  return null;
}
