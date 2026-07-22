import { describe, expect, it } from 'vitest';
import { cborDecode, cborEncode, type CborMap } from '../src/cbor.js';
import { bytesToHex, hexToBytes } from '../src/bytes.js';

describe('deterministic CBOR (wire-format §1)', () => {
  it('encodes shortest-form integers', () => {
    expect(bytesToHex(cborEncode(0))).toBe('00');
    expect(bytesToHex(cborEncode(23))).toBe('17');
    expect(bytesToHex(cborEncode(24))).toBe('1818');
    expect(bytesToHex(cborEncode(255))).toBe('18ff');
    expect(bytesToHex(cborEncode(256))).toBe('190100');
    expect(bytesToHex(cborEncode(65536))).toBe('1a00010000');
    expect(bytesToHex(cborEncode(2n ** 40n))).toBe('1b0000010000000000');
  });

  it('round-trips frames-shaped structures', () => {
    const ext: CborMap = new Map();
    ext.set(2, [new Uint8Array(32).fill(3), [new Uint8Array(32).fill(4)]]);
    const frame = [1, new Uint8Array(32), ['did:web:x', new Uint8Array(32).fill(1)], 7, null, [], 1, ext];
    const bytes = cborEncode(frame);
    const back = cborDecode(bytes);
    expect(bytesToHex(cborEncode(back))).toBe(bytesToHex(bytes));
  });

  it('rejects non-minimal integers', () => {
    expect(() => cborDecode(hexToBytes('1800'))).toThrow(/non-minimal/);
    expect(() => cborDecode(hexToBytes('190017'))).toThrow(/non-minimal/);
  });

  it('rejects indefinite lengths, floats, tags, negatives', () => {
    expect(() => cborDecode(hexToBytes('9f01ff'))).toThrow(/indefinite/);
    expect(() => cborDecode(hexToBytes('f93800'))).toThrow();
    expect(() => cborDecode(hexToBytes('c101'))).toThrow(/tags/);
    expect(() => cborDecode(hexToBytes('20'))).toThrow(/negative/);
  });

  it('rejects unsorted or duplicate map keys', () => {
    // {2: 0, 1: 0} — unsorted
    expect(() => cborDecode(hexToBytes('a202000100'))).toThrow(/sorted/);
    // {1: 0, 1: 0} — duplicate
    expect(() => cborDecode(hexToBytes('a201000100'))).toThrow(/sorted/);
  });

  it('rejects trailing bytes and truncation', () => {
    expect(() => cborDecode(hexToBytes('0000'))).toThrow(/trailing/);
    expect(() => cborDecode(hexToBytes('42ff'))).toThrow(/truncated/);
  });
});
