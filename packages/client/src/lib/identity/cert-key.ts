/**
 * Bridge: extract the device identity public key from an `at.atsms.x509` endpoint
 * certificate in the raw form `@atsms/dcgka` expects.
 *
 * `verifyPrekeyRecord` / `resolvePrekey` verify a prekey bundle's `bundleSig`
 * against the device identity (ECDSA P-256) key — which lives in the endpoint
 * cert. @noble (used inside dcgka) wants the raw public key bytes, so we export
 * the WebCrypto key as the 65-byte uncompressed point (0x04‖X‖Y).
 */

import { loadEndpointCertificate } from "../certificates/index.js";
import { cryptoProvider } from "../crypto-provider.js";

/** The endpoint cert's ECDSA P-256 public key as a raw 65-byte uncompressed point. */
export async function identityPublicKeyFromCert(certPEM: string): Promise<Uint8Array> {
  const cert = loadEndpointCertificate(certPEM);
  const key = await cert.getPublicKey();
  const raw = await cryptoProvider.subtle.exportKey("raw", key);
  return new Uint8Array(raw);
}

/**
 * The device fingerprint (lowercase hex) — the `at.atsms.x509` / `at.atsms.prekey`
 * record rkey that pairs a device's cert with its prekey (identity-devices §4).
 * Computed as SHA-256 of the raw public key point, so publish-side and
 * resolve-side agree.
 *
 * NOTE (flagged): the canonical fingerprint definition still needs pinning in the
 * spec (SHA-256 of the raw point vs the full SPKI) and alignment with the cert's
 * SKI extension + the today-serial-keyed x509 rkey. This is the single source of
 * truth for atsms-lib until then.
 */
export async function deviceFingerprintFromCert(certPEM: string): Promise<string> {
  const raw = await identityPublicKeyFromCert(certPEM);
  // Cast: lib.dom's BufferSource rejects Uint8Array<ArrayBufferLike> (SharedArrayBuffer union).
  const digest = new Uint8Array(await cryptoProvider.subtle.digest("SHA-256", raw as BufferSource));
  let hex = "";
  for (const b of digest) hex += b.toString(16).padStart(2, "0");
  return hex;
}
