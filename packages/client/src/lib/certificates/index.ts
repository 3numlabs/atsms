/**
 * Certificate management module
 *
 * Provides abstraction over X.509 certificates for the AT-SMS messaging system
 */

import { X509Certificate } from "@peculiar/x509";

import { ATSMSCertificate } from "./certificate";
import { ATSMSEndpointCertificate } from "./endpoint-certificate";
import { ATSMSP256EndpointCertificate } from "./p256-endpoint-certificate";

export { ATSMSCertificate } from "./certificate";
export { ATSMSEndpointCertificate } from "./endpoint-certificate";
export { ATSMSP256EndpointCertificate } from "./p256-endpoint-certificate";

/**
 * Certificate algorithm type
 */
export type ATSMSCertificateAlgorithm = "RSA" | "P256";

/**
 * Union type for all endpoint certificate types
 */
export type ATSMSAnyEndpointCertificate =
  | ATSMSEndpointCertificate
  | ATSMSP256EndpointCertificate;

/**
 * Detect the algorithm used by a certificate from its PEM
 * @param certPEM - Certificate in PEM format
 * @returns 'RSA' or 'P256' based on the public key algorithm
 */
export function detectCertificateAlgorithm(
  certPEM: string,
): ATSMSCertificateAlgorithm {
  const cert = new X509Certificate(certPEM);
  const algorithm = cert.publicKey.algorithm.name;

  if (algorithm === "ECDSA" || algorithm === "EC") {
    return "P256";
  }
  return "RSA";
}

/**
 * Load an endpoint certificate from PEM, automatically detecting the algorithm
 * @param certPEM - Certificate in PEM format
 * @returns The appropriate certificate class instance (RSA or P-256)
 */
export function loadEndpointCertificate(
  certPEM: string,
): ATSMSAnyEndpointCertificate {
  const algorithm = detectCertificateAlgorithm(certPEM);

  if (algorithm === "P256") {
    return ATSMSP256EndpointCertificate.fromPEM(certPEM);
  }
  return ATSMSEndpointCertificate.fromPEM(certPEM);
}

/**
 * Load an endpoint certificate from PEM with private key, automatically detecting the algorithm
 * @param certPEM - Certificate in PEM format
 * @param keyPEM - Private key in PEM format
 * @returns The appropriate certificate class instance (RSA or P-256) with private key
 */
export async function loadEndpointCertificateWithKey(
  certPEM: string,
  keyPEM: string,
): Promise<ATSMSAnyEndpointCertificate> {
  const algorithm = detectCertificateAlgorithm(certPEM);

  if (algorithm === "P256") {
    return ATSMSP256EndpointCertificate.fromPEMWithKey(certPEM, keyPEM);
  }
  return ATSMSEndpointCertificate.fromPEMWithKey(certPEM, keyPEM);
}

/**
 * Generate an endpoint certificate with the specified algorithm
 *
 * SAN (Subject Alternative Name) format:
 * - DNS: domain (e.g., 'alice.bsky.social')
 * - URI: at://[did]/at.atsms.x509/[serial-hex] (AT Protocol URI)
 * - Email: Deterministic based on DID method:
 *   - PLC: plc.[plc-id]@[emailDomain]
 *   - WEB: web.[base64url(web-part)]@[emailDomain]
 *
 * @param algorithm - 'RSA' or 'P256'
 * @param did - Decentralized identifier
 * @param domain - Domain name / handle
 * @param emailDomain - Email provider domain for deterministic email (e.g., 'atsms.email')
 * @param validityDays - Certificate validity period (default: 10 years)
 * @returns The generated certificate
 */
export async function generateEndpointCertificate(
  algorithm: ATSMSCertificateAlgorithm,
  did: string,
  domain: string,
  emailDomain: string,
  validityDays = 3652,
): Promise<ATSMSAnyEndpointCertificate> {
  if (algorithm === "P256") {
    return ATSMSP256EndpointCertificate.generate(
      did,
      domain,
      emailDomain,
      validityDays,
    );
  }
  return ATSMSEndpointCertificate.generate(did, domain, emailDomain, validityDays);
}

/**
 * Check if a certificate is a P-256 certificate
 */
export function isP256Certificate(
  cert: ATSMSCertificate,
): cert is ATSMSP256EndpointCertificate {
  return cert instanceof ATSMSP256EndpointCertificate;
}

/**
 * Check if a certificate is an RSA certificate
 */
export function isRSACertificate(
  cert: ATSMSCertificate,
): cert is ATSMSEndpointCertificate {
  return (
    cert instanceof ATSMSEndpointCertificate &&
    !(cert instanceof ATSMSP256EndpointCertificate)
  );
}
