/**
 * at.atsms.prekey + at.atsms.inbox record codec/validation
 * (identity-devices §4.2 / §4.3, inbound-delivery §3).
 */

import { p256 } from '@noble/curves/p256';
import { ed25519, x25519 } from '@noble/curves/ed25519';
import { blake3 } from '@noble/hashes/blake3';
import { describe, expect, it } from 'vitest';
import {
  buildInboxRecord,
  buildPrekeyRecord,
  inboxRecordError,
  inboxRecordNonConformance,
  pickEndpoint,
  prekeyBundleSigInput,
  uriScheme,
  verifyPrekeyRecord,
  type PrekeyRecord,
} from '../src/records.js';

// Deterministic keys (no ambient randomness).
const identitySk = blake3(new TextEncoder().encode('records:identity-sk'), { dkLen: 32 });
const identityPub = p256.getPublicKey(identitySk); // device identity (P-256) pub, from the x509 cert
const signedPrekey = x25519.getPublicKey(blake3(new TextEncoder().encode('records:prekey-sk'), { dkLen: 32 }));
const signingPk = ed25519.getPublicKey(blake3(new TextEncoder().encode('records:signing-sk'), { dkLen: 32 }));
const createdAt = '2026-07-26T00:00:00.000Z';
const expiresAt = '2026-08-02T00:00:00.000Z';

describe('at.atsms.prekey', () => {
  it('builds a record whose bundleSig verifies against the identity key', () => {
    const rec = buildPrekeyRecord({ signedPrekey, signingPk, createdAt, expiresAt }, identitySk);
    expect(rec.$type).toBe('at.atsms.prekey');
    expect(rec.bundleSig.length).toBe(64);
    expect(verifyPrekeyRecord(rec, identityPub)).toEqual({ ok: true });
  });

  it('rejects a bundleSig that signed reordered fields (§4.3 — cross-generation mix-and-match)', () => {
    // Sign createdAt/expiresAt swapped, then present the record in declared order.
    const bad = p256
      .sign(prekeyBundleSigInput({ signedPrekey, signingPk, createdAt: expiresAt, expiresAt: createdAt }), identitySk)
      .toCompactRawBytes();
    const rec: PrekeyRecord = { $type: 'at.atsms.prekey', signedPrekey, signingPk, createdAt, expiresAt, bundleSig: bad };
    expect(verifyPrekeyRecord(rec, identityPub)).toEqual({ ok: false, reason: 'bad-signature' });
  });

  it('rejects a tampered signedPrekey', () => {
    const rec = buildPrekeyRecord({ signedPrekey, signingPk, createdAt, expiresAt }, identitySk);
    const tampered = { ...rec, signedPrekey: x25519.getPublicKey(blake3(new TextEncoder().encode('other'), { dkLen: 32 })) };
    expect(verifyPrekeyRecord(tampered, identityPub).ok).toBe(false);
  });

  it('rejects a tampered signingPk (initial protocol signing key is bundle-bound)', () => {
    const rec = buildPrekeyRecord({ signedPrekey, signingPk, createdAt, expiresAt }, identitySk);
    const tampered = { ...rec, signingPk: ed25519.getPublicKey(blake3(new TextEncoder().encode('evil'), { dkLen: 32 })) };
    expect(verifyPrekeyRecord(tampered, identityPub)).toEqual({ ok: false, reason: 'bad-signature' });
  });

  it('rejects the wrong identity key', () => {
    const rec = buildPrekeyRecord({ signedPrekey, signingPk, createdAt, expiresAt }, identitySk);
    const otherPub = p256.getPublicKey(blake3(new TextEncoder().encode('records:other-identity'), { dkLen: 32 }));
    expect(verifyPrekeyRecord(rec, otherPub)).toEqual({ ok: false, reason: 'bad-signature' });
  });

  it('enforces expiry only when a clock is supplied', () => {
    const rec = buildPrekeyRecord({ signedPrekey, signingPk, createdAt, expiresAt }, identitySk);
    expect(verifyPrekeyRecord(rec, identityPub, Date.parse('2026-07-27T00:00:00.000Z'))).toEqual({ ok: true });
    expect(verifyPrekeyRecord(rec, identityPub, Date.parse('2026-09-01T00:00:00.000Z'))).toEqual({
      ok: false,
      reason: 'expired',
    });
    expect(verifyPrekeyRecord(rec, identityPub)).toEqual({ ok: true }); // no clock → skip
  });

  it('rejects a malformed record shape', () => {
    const rec = buildPrekeyRecord({ signedPrekey, signingPk, createdAt, expiresAt }, identitySk);
    expect(verifyPrekeyRecord({ ...rec, bundleSig: rec.bundleSig.slice(0, 32) }, identityPub)).toEqual({
      ok: false,
      reason: 'bad-shape',
    });
  });
});

describe('at.atsms.inbox', () => {
  const mailto = { uri: 'mailto:did!plc!abc123@haiven.mobile' };
  const https = { uri: 'https://relay.haiven.mobile/atsms/in/9d2e' };

  it('uriScheme extracts the (lowercased) transport', () => {
    expect(uriScheme('mailto:x@y')).toBe('mailto');
    expect(uriScheme('HTTPS://h/p')).toBe('https');
    expect(uriScheme('no-scheme')).toBeNull();
  });

  it('builds a record and keeps preference order', () => {
    const rec = buildInboxRecord([https, mailto]);
    expect(rec.$type).toBe('at.atsms.inbox');
    expect(rec.endpoints.map((e) => e.uri)).toEqual([https.uri, mailto.uri]);
    expect(inboxRecordError(rec)).toBeNull();
  });

  it('publishing requires at least one https: endpoint (D15)', () => {
    expect(() => buildInboxRecord([mailto])).toThrow(/https/);
    expect(inboxRecordNonConformance({ $type: 'at.atsms.inbox', endpoints: [mailto] })).toMatch(/https/);
  });

  it('reading is lenient — a mailto-only record is unreachable, not malformed', () => {
    expect(inboxRecordError({ $type: 'at.atsms.inbox', endpoints: [mailto] })).toBeNull();
  });

  it('accepts an https-only record — mailto: is recommended, not required (D15)', () => {
    const rec = buildInboxRecord([https]);
    expect(rec.endpoints.map((e) => e.uri)).toEqual([https.uri]);
    expect(inboxRecordError(rec)).toBeNull();
  });

  it('rejects an empty endpoints list and schemeless URIs', () => {
    expect(inboxRecordError({ $type: 'at.atsms.inbox', endpoints: [] })).toMatch(/non-empty/);
    expect(inboxRecordError({ $type: 'at.atsms.inbox', endpoints: [{ uri: 'nope' }] })).toMatch(/scheme/);
  });

  it('pickEndpoint honors preference and supported schemes', () => {
    const rec = buildInboxRecord([https, mailto]);
    expect(pickEndpoint(rec, ['https', 'mailto'])?.uri).toBe(https.uri); // https preferred
    expect(pickEndpoint(rec, ['mailto'])?.uri).toBe(mailto.uri); // mail-only sender
    expect(pickEndpoint(rec, ['sip'])).toBeNull();
    expect(pickEndpoint(rec)?.uri).toBe(https.uri); // default = https (D15)
  });
});
