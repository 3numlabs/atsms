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
 * The raw 32-byte P-256 scalar from a PKCS#8 private-key PEM — the device
 * identity signing key in the form @noble (inside dcgka's `buildPrekeyRecord`)
 * expects. WebCrypto can't export a raw EC private scalar directly; go through
 * JWK and decode `d`.
 */
export async function identityScalarFromKey(privateKeyPEM: string): Promise<Uint8Array> {
  const key = await cryptoProvider.subtle.importKey(
    "pkcs8",
    pemToDer(privateKeyPEM) as BufferSource,
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["sign"],
  );
  const jwk = await cryptoProvider.subtle.exportKey("jwk", key);
  if (jwk.d === undefined) throw new Error("private key JWK has no scalar (d)");
  return b64urlToBytes(jwk.d);
}

function pemToDer(pem: string): Uint8Array {
  const b64 = pem.replace(/-----[^-]+-----/g, "").replace(/\s+/g, "");
  const bin = atob(b64);
  const der = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) der[i] = bin.charCodeAt(i);
  return der;
}

function b64urlToBytes(s: string): Uint8Array {
  const b64 = s.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((s.length + 3) % 4);
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

/**
 * The device fingerprint (lowercase hex) — the `at.atsms.x509` / `at.atsms.prekey`
 * record rkey pairing a device's cert with its prekey. Per identity-devices §4:
 * **SHA-256 of the raw uncompressed public-key point** (`0x04‖X‖Y`), RFC 7093
 * method 1, = the cert's SKI. The x509 records, prekey records, worker inboxes,
 * and JWT subject all key on it (integration §8.5 re-keying, executed).
 */
export async function deviceFingerprintFromCert(certPEM: string): Promise<string> {
  return loadEndpointCertificate(certPEM).getDeviceFingerprint();
}
