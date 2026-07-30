/**
 * Encryption-at-rest for the DCGKA durable secrets — envelope (KEK/DEK)
 * encryption over any `StorageAdapter`.
 *
 * The `engine_state` blob (`Session.serialize()` — live group ratchet secrets)
 * and the `device_state` blob (the prekey ring — admission secrets) are the
 * material forward secrecy depends on; they MUST NOT sit in the clear. This
 * decorator encrypts exactly those two blob classes on the way in/out and
 * passes everything else (messages, conversations, certs, observers) through
 * unchanged — message-content encryption is a deliberate fast-follow.
 *
 * Two layers (standard envelope encryption; enables recovery + cheap rotation):
 * - **KEK** — the device master key, **injected** by the app from platform
 *   secure storage (iOS Keychain, Android Keystore, or the web debug PRF seed).
 *   Small; only wraps/unwraps the DEK.
 * - **DEK** — a random data key generated here, doing the bulk
 *   XChaCha20-Poly1305 on the blobs. It is stored **KEK-wrapped** in a reserved
 *   `device_state` keyslot and unwrapped into memory on open. Wrapping the same
 *   DEK under additional KEKs (a recovery key) later lets a new device decrypt
 *   without re-encrypting any data (recovery, task #16) — future work.
 */

import { xchacha20poly1305 } from "@noble/ciphers/chacha";

import { cryptoProvider } from "../crypto-provider.js";
import type { StorageAdapter } from "./interface.js";

/** device_state key holding the KEK-wrapped DEK (self-protecting; NOT DEK-encrypted). */
const KEYSLOT_KEY = "__atsms_dek_keyslot_v1__";
const NONCE_LEN = 24; // XChaCha20-Poly1305
const KEY_LEN = 32;

function randomBytes(n: number): Uint8Array {
  return cryptoProvider.getRandomValues(new Uint8Array(n));
}

/** Encrypt `plaintext` under `key` → `nonce ‖ ciphertext‖tag`. */
function seal(key: Uint8Array, plaintext: Uint8Array): Uint8Array {
  const nonce = randomBytes(NONCE_LEN);
  const ct = xchacha20poly1305(key, nonce).encrypt(plaintext);
  const out = new Uint8Array(NONCE_LEN + ct.length);
  out.set(nonce, 0);
  out.set(ct, NONCE_LEN);
  return out;
}

/** Reverse of {@link seal}. Throws (with a clear message) on a wrong key / tamper. */
function open(key: Uint8Array, blob: Uint8Array, what: string): Uint8Array {
  if (blob.length < NONCE_LEN) throw new Error(`${what}: ciphertext too short`);
  const nonce = blob.subarray(0, NONCE_LEN);
  const ct = blob.subarray(NONCE_LEN);
  try {
    return xchacha20poly1305(key, nonce).decrypt(ct);
  } catch {
    throw new Error(`${what}: cannot decrypt (wrong device master key or corrupt data)`);
  }
}

/** Load the DEK from the keyslot (KEK-unwrap), or generate + wrap + persist one. */
async function loadOrCreateDek(inner: StorageAdapter, kek: Uint8Array): Promise<Uint8Array> {
  const wrapped = await inner.loadDeviceState(KEYSLOT_KEY);
  if (wrapped !== null) {
    return open(kek, wrapped, "storage keyslot");
  }
  const dek = randomBytes(KEY_LEN);
  await inner.saveDeviceState(KEYSLOT_KEY, seal(kek, dek));
  return dek;
}

/**
 * Envelope encryption-at-rest over a `StorageAdapter`. The returned value IS a
 * `StorageAdapter` (transparent to every consumer) — it just encrypts the
 * engine/device state blobs. Instances are not constructed directly; use
 * {@link EncryptedStorageAdapter.wrap}.
 */
export class EncryptedStorageAdapter {
  private constructor() {
    /* factory-only */
  }

  /**
   * Wrap `inner` so `engine_state` + `device_state` blobs are encrypted at rest
   * under a DEK protected by the injected `kek` (the device master key, 32 bytes).
   * Loads-or-creates the keyslot; a wrong `kek` throws here.
   */
  static async wrap(inner: StorageAdapter, kek: Uint8Array): Promise<StorageAdapter> {
    if (kek.length !== KEY_LEN) throw new Error(`device master key must be ${KEY_LEN} bytes`);
    const dek = await loadOrCreateDek(inner, kek);

    // Intercept exactly the two blob classes; delegate everything else verbatim.
    const overrides: Partial<StorageAdapter> = {
      saveEngineState: (convoId: string, state: Uint8Array) => inner.saveEngineState(convoId, seal(dek, state)),
      loadEngineState: async (convoId: string) => {
        const c = await inner.loadEngineState(convoId);
        return c === null ? null : open(dek, c, `engine_state ${convoId}`);
      },
      saveDeviceState: async (key: string, state: Uint8Array) => {
        if (key === KEYSLOT_KEY) throw new Error("device_state key is reserved");
        return inner.saveDeviceState(key, seal(dek, state));
      },
      loadDeviceState: async (key: string) => {
        if (key === KEYSLOT_KEY) throw new Error("device_state key is reserved");
        const c = await inner.loadDeviceState(key);
        return c === null ? null : open(dek, c, `device_state ${key}`);
      },
    };

    return new Proxy(inner, {
      get(target, prop, receiver) {
        const o = (overrides as Record<string | symbol, unknown>)[prop];
        if (o !== undefined) return o;
        const v = Reflect.get(target, prop, receiver);
        return typeof v === "function" ? v.bind(target) : v;
      },
    }) as StorageAdapter;
  }
}
