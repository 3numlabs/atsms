/**
 * Certificate management module
 *
 * Provides abstraction over X.509 certificates for the ATSMS messaging system.
 * All certificates use P-256 ECDSA for signing and ECDH for key agreement.
 */

export { ATSMSCertificate } from "./certificate";
export { ATSMSEndpointCertificate, ATSMS_GATEWAY_ROLE_OID } from "./p256-endpoint-certificate";

import { ATSMSEndpointCertificate } from "./p256-endpoint-certificate";

/**
 * Load an endpoint certificate from PEM (public certificate only, no private key)
 * @param certPEM - Certificate in PEM format
 * @returns ATSMSEndpointCertificate instance
 */
export function loadEndpointCertificate(
  certPEM: string,
): ATSMSEndpointCertificate {
  return ATSMSEndpointCertificate.fromPEM(certPEM);
}

/**
 * Load an endpoint certificate from PEM with private key
 * @param certPEM - Certificate in PEM format
 * @param keyPEM - Private key in PEM format (PKCS#8)
 * @returns ATSMSEndpointCertificate instance with private key
 */
export async function loadEndpointCertificateWithKey(
  certPEM: string,
  keyPEM: string,
): Promise<ATSMSEndpointCertificate> {
  return ATSMSEndpointCertificate.fromPEMWithKey(certPEM, keyPEM);
}

/**
 * Generate a new self-signed endpoint certificate
 *
 * SAN (Subject Alternative Name) format:
 * - DNS: domain (e.g., 'alice.bsky.social')
 * - URI: at://[did]/at.atsms.x509/[serial-hex] (AT Protocol URI)
 * - Email: Deterministic based on DID method:
 *   - PLC: plc.[plc-id]@[emailDomain]
 *   - WEB: web.[base64url(web-part)]@[emailDomain]
 *
 * @param did - Decentralized identifier
 * @param domain - Domain name / handle
 * @param emailDomain - Email provider domain for deterministic email (e.g., 'atsms.email')
 * @param validityDays - Certificate validity period (default: 10 years)
 * @returns The generated certificate
 */
export async function generateEndpointCertificate(
  did: string,
  domain: string,
  emailDomain: string,
  validityDays = 3652,
): Promise<ATSMSEndpointCertificate> {
  return ATSMSEndpointCertificate.generate(
    did,
    domain,
    emailDomain,
    validityDays,
  );
}
