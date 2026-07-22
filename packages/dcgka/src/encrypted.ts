/** Byte-faithful port of beekem/src/encrypted.rs (the EncryptedSecret half — Phase 1 scope). */

import { deriveSymmetricKey, sivNew, tryDecrypt, tryEncrypt } from './keyhive.js';

/** Rust `EncryptedSecret<ShareSecretKey>`. */
export interface EncryptedSecret {
  /** Siv nonce (24 bytes). */
  nonce: Uint8Array;
  /** XChaCha20-Poly1305 ciphertext ‖ tag. */
  ciphertext: Uint8Array;
  /** The ShareKey used as the DH partner when encrypting. */
  pairedPk: Uint8Array;
}

/**
 * Rust `encrypt_secret(doc_id, secret, sk, paired_pk)`:
 * key = DH-derive(sk, paired_pk); nonce = Siv(key, secret, doc_id); seal.
 */
export function encryptSecret(
  docId: Uint8Array,
  secret: Uint8Array,
  sk: Uint8Array,
  pairedPk: Uint8Array,
): EncryptedSecret {
  const key = deriveSymmetricKey(sk, pairedPk);
  const nonce = sivNew(key, secret, docId);
  const ciphertext = tryEncrypt(key, nonce, secret);
  return { nonce, ciphertext, pairedPk };
}

/** Rust `EncryptedSecret::try_encrypter_decrypt(encrypter_secret_key)`. */
export function tryEncrypterDecrypt(
  encrypted: EncryptedSecret,
  encrypterSecretKey: Uint8Array,
): Uint8Array {
  const key = deriveSymmetricKey(encrypterSecretKey, encrypted.pairedPk);
  return tryDecrypt(key, encrypted.nonce, encrypted.ciphertext);
}
