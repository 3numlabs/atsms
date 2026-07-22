import { describe, expect, it } from 'vitest';
import {
  deriveFromBytes,
  deriveSymmetricKey,
  ratchetForward,
  ratchetNForward,
  shareKeyOf,
  sivNew,
  tryDecrypt,
  tryEncrypt,
} from '../src/keyhive.js';
import { bytesToHex } from '../src/bytes.js';

describe('keyhive_crypto parity', () => {
  it('Separable::derive_from_bytes matches the upstream doctest vector', () => {
    // keyhive_crypto/src/separable.rs doctest: derive_from_bytes(&[0; 32])
    const expected =
      '21d6ef218970ea57fcd46b43e1f8d7e9b102e5e4d6645bd24883ea70b8b393fe';
    expect(bytesToHex(deriveFromBytes(new Uint8Array(32)))).toBe(expected);
  });

  it('ratchet_forward is derive_from_bytes over raw secret bytes', () => {
    const sk = new Uint8Array(32).fill(7);
    expect(bytesToHex(ratchetForward(sk))).toBe(bytesToHex(deriveFromBytes(sk)));
    expect(bytesToHex(ratchetNForward(sk, 3))).toBe(
      bytesToHex(ratchetForward(ratchetForward(ratchetForward(sk)))),
    );
  });

  it('derive_symmetric_key is symmetric across the DH pair', () => {
    const a = new Uint8Array(32).fill(1);
    const b = new Uint8Array(32).fill(2);
    const kab = deriveSymmetricKey(a, shareKeyOf(b));
    const kba = deriveSymmetricKey(b, shareKeyOf(a));
    expect(bytesToHex(kab)).toBe(bytesToHex(kba));
  });

  it('Siv + XChaCha20-Poly1305 round-trips with the keyhive AAD', () => {
    // Mirrors the symmetric_key.rs doctest shape.
    const plaintext = new TextEncoder().encode('hello world');
    const docId = new TextEncoder().encode('some-document-id');
    const key = new Uint8Array(32).fill(9);
    const nonce = sivNew(key, plaintext, docId);
    expect(nonce.length).toBe(24);
    const ct = tryEncrypt(key, nonce, plaintext);
    expect(ct.length).toBe(plaintext.length + 16);
    expect(new TextDecoder().decode(tryDecrypt(key, nonce, ct))).toBe('hello world');
    // Tamper → auth failure
    const bad = ct.slice();
    bad[0]! ^= 1;
    expect(() => tryDecrypt(key, nonce, bad)).toThrow();
  });
});
