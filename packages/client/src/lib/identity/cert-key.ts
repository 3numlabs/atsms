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
