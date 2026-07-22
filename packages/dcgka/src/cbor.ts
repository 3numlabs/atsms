/**
 * Deterministic CBOR (RFC 8949 §4.2.1 core requirements) per wire-format.md §1:
 * definite lengths only; shortest-form integers; no floats, no tags, no undefined;
 * maps have unsigned-integer keys, sorted by encoded bytes, no duplicates.
 * Strict reader: any non-canonical input throws.
 */

import { compareBytes, concatBytes } from './bytes.js';

export type CborValue =
  | number // unsigned integer (≤ Number.MAX_SAFE_INTEGER)
  | bigint // unsigned integer (> Number.MAX_SAFE_INTEGER)
  | Uint8Array // byte string
  | string // text string
  | boolean
  | null
  | CborValue[]
  | CborMap;

/** Map with unsigned-integer keys (the `ext` slot). */
export type CborMap = Map<number, CborValue>;

const MAX_U64 = (1n << 64n) - 1n;

function encodeHead(major: number, value: bigint): Uint8Array {
  if (value < 0n || value > MAX_U64) throw new Error('cbor: uint out of range');
  const m = major << 5;
  if (value < 24n) return Uint8Array.of(m | Number(value));
  if (value <= 0xffn) return Uint8Array.of(m | 24, Number(value));
  if (value <= 0xffffn) return Uint8Array.of(m | 25, Number(value >> 8n), Number(value & 0xffn));
  if (value <= 0xffffffffn) {
    const out = new Uint8Array(5);
    out[0] = m | 26;
    new DataView(out.buffer).setUint32(1, Number(value));
    return out;
  }
  const out = new Uint8Array(9);
  out[0] = m | 27;
  new DataView(out.buffer).setBigUint64(1, value);
  return out;
}

export function cborEncode(v: CborValue): Uint8Array {
  if (typeof v === 'number') {
    if (!Number.isSafeInteger(v) || v < 0) throw new Error('cbor: number must be a non-negative safe integer');
    return encodeHead(0, BigInt(v));
  }
  if (typeof v === 'bigint') return encodeHead(0, v);
  if (v instanceof Uint8Array) return concatBytes(encodeHead(2, BigInt(v.length)), v);
  if (typeof v === 'string') {
    const b = new TextEncoder().encode(v);
    return concatBytes(encodeHead(3, BigInt(b.length)), b);
  }
  if (typeof v === 'boolean') return Uint8Array.of(v ? 0xf5 : 0xf4);
  if (v === null) return Uint8Array.of(0xf6);
  if (Array.isArray(v)) {
    return concatBytes(encodeHead(4, BigInt(v.length)), ...v.map(cborEncode));
  }
  if (v instanceof Map) {
    const entries = [...v.entries()].map(([k, val]) => {
      if (!Number.isSafeInteger(k) || k < 0) throw new Error('cbor: map keys must be unsigned integers');
      return [cborEncode(k), cborEncode(val)] as const;
    });
    entries.sort((a, b) => compareBytes(a[0], b[0]));
    for (let i = 1; i < entries.length; i++) {
      if (compareBytes(entries[i - 1]![0], entries[i]![0]) === 0) throw new Error('cbor: duplicate map key');
    }
    return concatBytes(encodeHead(5, BigInt(entries.length)), ...entries.flatMap((e) => [e[0], e[1]]));
  }
  throw new Error('cbor: unsupported value');
}

class Reader {
  pos = 0;
  constructor(private buf: Uint8Array) {}

  byte(): number {
    if (this.pos >= this.buf.length) throw new Error('cbor: truncated');
    return this.buf[this.pos++]!;
  }

  bytes(n: number): Uint8Array {
    if (this.pos + n > this.buf.length) throw new Error('cbor: truncated');
    const out = this.buf.subarray(this.pos, this.pos + n);
    this.pos += n;
    return out;
  }

  done(): boolean {
    return this.pos === this.buf.length;
  }
}

function readHead(r: Reader): { major: number; value: bigint } {
  const ib = r.byte();
  const major = ib >> 5;
  const ai = ib & 0x1f;
  if (ai === 31) throw new Error('cbor: indefinite length rejected');
  if (ai < 24) return { major, value: BigInt(ai) };
  let value: bigint;
  let minAi: number;
  if (ai === 24) {
    value = BigInt(r.byte());
    minAi = 24;
    if (value < 24n) throw new Error('cbor: non-minimal integer');
    return { major, value };
  } else if (ai === 25) {
    const b = r.bytes(2);
    value = (BigInt(b[0]!) << 8n) | BigInt(b[1]!);
    if (value <= 0xffn) throw new Error('cbor: non-minimal integer');
    return { major, value };
  } else if (ai === 26) {
    const b = r.bytes(4);
    value = 0n;
    for (const x of b) value = (value << 8n) | BigInt(x);
    if (value <= 0xffffn) throw new Error('cbor: non-minimal integer');
    return { major, value };
  } else if (ai === 27) {
    const b = r.bytes(8);
    value = 0n;
    for (const x of b) value = (value << 8n) | BigInt(x);
    if (value <= 0xffffffffn) throw new Error('cbor: non-minimal integer');
    return { major, value };
  }
  throw new Error('cbor: reserved additional info');
}

function toLength(v: bigint): number {
  if (v > BigInt(Number.MAX_SAFE_INTEGER)) throw new Error('cbor: length too large');
  return Number(v);
}

function decodeItem(r: Reader, depth: number): CborValue {
  if (depth > 64) throw new Error('cbor: nesting too deep');
  const start = r.pos;
  const { major, value } = readHead(r);
  switch (major) {
    case 0:
      return value <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(value) : value;
    case 1:
      throw new Error('cbor: negative integers rejected');
    case 2:
      return new Uint8Array(r.bytes(toLength(value)));
    case 3: {
      const b = r.bytes(toLength(value));
      return new TextDecoder('utf-8', { fatal: true }).decode(b);
    }
    case 4: {
      const n = toLength(value);
      const out: CborValue[] = [];
      for (let i = 0; i < n; i++) out.push(decodeItem(r, depth + 1));
      return out;
    }
    case 5: {
      const n = toLength(value);
      const out: CborMap = new Map();
      let prevKey: Uint8Array | null = null;
      for (let i = 0; i < n; i++) {
        const keyStart = r.pos;
        const key = decodeItem(r, depth + 1);
        if (typeof key !== 'number' && typeof key !== 'bigint') {
          throw new Error('cbor: map keys must be unsigned integers');
        }
        const keyBytes = new Uint8Array(rBuf(r).subarray(keyStart, r.pos));
        if (prevKey !== null && compareBytes(prevKey, keyBytes) >= 0) {
          throw new Error('cbor: map keys must be sorted and unique');
        }
        prevKey = keyBytes;
        const val = decodeItem(r, depth + 1);
        out.set(Number(key), val);
      }
      return out;
    }
    case 6:
      throw new Error('cbor: tags rejected');
    case 7: {
      const simple = value;
      void start;
      if (simple === 20n) return false;
      if (simple === 21n) return true;
      if (simple === 22n) return null;
      throw new Error('cbor: floats/undefined/simple values rejected');
    }
    default:
      throw new Error('cbor: unreachable');
  }
}

// Access the underlying buffer of a Reader (for canonical key comparison).
function rBuf(r: Reader): Uint8Array {
  return (r as unknown as { buf: Uint8Array }).buf;
}

/** Strict decode: one item, no trailing bytes, canonical form enforced. */
export function cborDecode(buf: Uint8Array): CborValue {
  const r = new Reader(buf);
  const v = decodeItem(r, 0);
  if (!r.done()) throw new Error('cbor: trailing bytes');
  return v;
}
