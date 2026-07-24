/**
 * HPKE Base mode (RFC 9180, DHKEM(X25519)/HKDF-SHA256/ChaCha20-Poly1305) and
 * the sealed-asym envelope (sealed-sender §4).
 */

import { blake3 } from '@noble/hashes/blake3';
import { x25519 } from '@noble/curves/ed25519';
import { describe, expect, it } from 'vitest';
import { openBase, sealBase } from '../src/hpke.js';
import {
  CONTENT_FRAME,
  openAsym,
  padToBucket,
  parseAsymEnvelope,
  sealAsymTo,
} from '../src/envelope.js';
import { bytesToHex } from '../src/bytes.js';
import type { Csprng } from '../src/keyhive.js';

function rngOf(label: string): Csprng {
  let c = 0;
  return (n) => blake3(new TextEncoder().encode(`${label}:${c++}`), { dkLen: n });
}
const ascii = (s: string) => new TextEncoder().encode(s);

describe('HPKE Base (RFC 9180)', () => {
  const skR = rngOf('recipient')(32);
  const pkR = x25519.getPublicKey(skR);

  it('SealBase → OpenBase round-trips', () => {
    const info = ascii('atsms-seal:v1');
    const aad = ascii('header');
    const pt = ascii('secret payload');
    const { enc, ct } = sealBase(pkR, info, aad, pt, rngOf('e'));
    expect(enc.length).toBe(32);
    const got = openBase(enc, skR, info, aad, ct);
    expect(new TextDecoder().decode(got)).toBe('secret payload');
  });

  it('wrong recipient key fails to open', () => {
    const info = ascii('atsms-seal:v1');
    const { enc, ct } = sealBase(pkR, info, ascii(''), ascii('x'), rngOf('e'));
    const wrong = rngOf('other')(32);
    expect(() => openBase(enc, wrong, info, ascii(''), ct)).toThrow();
  });

  it('info / aad are bound (mismatch fails)', () => {
    const { enc, ct } = sealBase(pkR, ascii('info-A'), ascii('aad-A'), ascii('m'), rngOf('e'));
    expect(() => openBase(enc, skR, ascii('info-B'), ascii('aad-A'), ct)).toThrow();
    expect(() => openBase(enc, skR, ascii('info-A'), ascii('aad-B'), ct)).toThrow();
  });

  it('each seal uses a fresh ephemeral (distinct enc)', () => {
    const info = ascii('atsms-seal:v1');
    const a = sealBase(pkR, info, ascii(''), ascii('m'), rngOf('e1'));
    const b = sealBase(pkR, info, ascii(''), ascii('m'), rngOf('e2'));
    expect(bytesToHex(a.enc)).not.toBe(bytesToHex(b.enc));
  });
});

describe('sealed-asym envelope (§4)', () => {
  const skR = rngOf('prekey')(32);
  const pkR = x25519.getPublicKey(skR);

  it('seals a frame to a signed prekey and opens it; padded to a bucket', () => {
    const body = ascii('welcome payload — bootstrap class');
    const env = sealAsymTo(pkR, CONTENT_FRAME, body, rngOf('a'));
    const parsed = parseAsymEnvelope(env);
    expect(parsed.suite).toBe(1);
    expect(parsed.enc.length).toBe(32);
    const { contentType, body: got } = openAsym(skR, env);
    expect(contentType).toBe(CONTENT_FRAME);
    expect(new TextDecoder().decode(got)).toBe('welcome payload — bootstrap class');
    // Envelope size = a bucket + HPKE/CBOR overhead (padded plaintext is a bucket).
    expect(env.length).toBeGreaterThanOrEqual(1024);
    expect(env.length).toBeLessThan(1024 + 200);
  });

  it('the wrong prekey secret (grace trial) fails, the right one succeeds', () => {
    const env = sealAsymTo(pkR, CONTENT_FRAME, ascii('m'), rngOf('a'));
    const graceSk = rngOf('grace')(32);
    expect(() => openAsym(graceSk, env)).toThrow(); // trial with the wrong (grace) secret
    expect(openAsym(skR, env).contentType).toBe(CONTENT_FRAME); // current secret opens
  });

  it('padding hides the body size (two different bodies → same envelope size within a bucket)', () => {
    const e1 = sealAsymTo(pkR, CONTENT_FRAME, padTrim(100), rngOf('a'));
    const e2 = sealAsymTo(pkR, CONTENT_FRAME, padTrim(500), rngOf('a'));
    expect(e1.length).toBe(e2.length); // both in the 1 KiB bucket
  });
});

function padTrim(n: number): Uint8Array {
  void padToBucket; // (padding is exercised inside sealAsymTo)
  return new Uint8Array(n).fill(0x41);
}
