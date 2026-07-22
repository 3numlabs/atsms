/**
 * Per-sender FS-AEAD application chains (beekem-core §7) — same construction
 * as the DCGKA-phase design, reseeded from chainSeed(e, S). Deletion is the
 * forward secrecy: chain keys are overwritten on advance, message keys on use.
 * Constants from parameters.md (p2panda-derived, carried over).
 */

import { chacha20poly1305 } from '@noble/ciphers/chacha';
import { chainMsgKey, chainNext, chainNonce } from './kdf.js';

export const OUT_OF_ORDER_TOLERANCE = 100;
export const MAX_FORWARD_DISTANCE = 1000;
export const MAX_SKIPPED_TOTAL = 2000;

export class SenderChain {
  private ck: Uint8Array;
  generation = 0;

  constructor(seed: Uint8Array) {
    this.ck = seed;
  }

  /** Derive (msgKey, nonce) for the next message and advance (deleting the old ck). */
  next(): { generation: number; msgKey: Uint8Array; nonce: Uint8Array } {
    const generation = this.generation;
    const msgKey = chainMsgKey(this.ck);
    const nonce = chainNonce(this.ck);
    this.ck = chainNext(this.ck);
    this.generation += 1;
    return { generation, msgKey, nonce };
  }
}

interface SkippedKey {
  msgKey: Uint8Array;
  nonce: Uint8Array;
}

export class ReceiverChain {
  private ck: Uint8Array;
  private nextGen = 0;
  private skipped = new Map<number, SkippedKey>();

  constructor(
    seed: Uint8Array,
    /** Group-wide skipped-key budget, shared via the engine (MAX_SKIPPED_TOTAL). */
    private budget: { used: number },
  ) {
    this.ck = seed;
  }

  /** Fetch the key for `generation`, skipping/storing as needed; single-use. */
  keyFor(generation: number): SkippedKey {
    if (generation < this.nextGen) {
      const k = this.skipped.get(generation);
      if (k === undefined) throw new Error('SecretReuse'); // used or never stored
      this.skipped.delete(generation);
      this.budget.used -= 1;
      return k;
    }
    if (generation - this.nextGen > MAX_FORWARD_DISTANCE) throw new Error('MaxForwardDistance');
    while (this.nextGen < generation) {
      if (this.skipped.size >= OUT_OF_ORDER_TOLERANCE) throw new Error('OutOfOrderTolerance');
      if (this.budget.used >= MAX_SKIPPED_TOTAL) throw new Error('MaxSkippedTotal');
      this.skipped.set(this.nextGen, { msgKey: chainMsgKey(this.ck), nonce: chainNonce(this.ck) });
      this.budget.used += 1;
      this.ck = chainNext(this.ck);
      this.nextGen += 1;
    }
    const k = { msgKey: chainMsgKey(this.ck), nonce: chainNonce(this.ck) };
    this.ck = chainNext(this.ck);
    this.nextGen += 1;
    return k;
  }
}

/** ChaCha20-Poly1305 (profile AEAD, beekem-core §3). */
export function sealApp(msgKey: Uint8Array, nonce: Uint8Array, ad: Uint8Array, pt: Uint8Array): Uint8Array {
  return chacha20poly1305(msgKey, nonce, ad).encrypt(pt);
}

export function openApp(msgKey: Uint8Array, nonce: Uint8Array, ad: Uint8Array, ct: Uint8Array): Uint8Array {
  return chacha20poly1305(msgKey, nonce, ad).decrypt(ct);
}
