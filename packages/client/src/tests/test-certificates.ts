/**
 * Test certificate generation utilities
 * Uses the actual certificate classes with self-signed certificates
 * Supports both RSA and P-256 ECDSA certificates
 */

import {
  type ATSMSCertificateAlgorithm,
  generateEndpointCertificate,
} from "../lib/certificates/index.js";

export interface TestCertificateResult {
  cert: string;
  privateKey: string;
  algorithm: ATSMSCertificateAlgorithm;
}

/**
 * Generate a test self-signed endpoint certificate
 * @param did - The DID for the certificate
 * @param domain - The domain/handle for the certificate
 * @param email - Optional email address (defaults to generated from DID and domain)
 * @param algorithm - Certificate algorithm ('RSA' or 'P256', defaults to 'RSA' for backward compatibility)
 */
export async function generateTestEndpointCertificate(
  did: string,
  domain: string,
  email?: string,
  algorithm: ATSMSCertificateAlgorithm = "RSA",
): Promise<TestCertificateResult> {
  const defaultEmail = email || `${did.split(":").pop()}@${domain}`;
  const endpointCert = await generateEndpointCertificate(
    algorithm,
    did,
    domain,
    defaultEmail,
    365,
  );

  const certPEM = endpointCert.toString("pem");
  const privateKeyPEM = endpointCert.certificatePrivateKeyPEM!;

  return {
    cert: certPEM,
    privateKey: privateKeyPEM,
    algorithm,
  };
}

/**
 * Generate a test P-256 endpoint certificate
 * @param did - The DID for the certificate
 * @param domain - The domain/handle for the certificate
 * @param email - Optional email address
 */
export async function generateTestP256EndpointCertificate(
  did: string,
  domain: string,
  email?: string,
): Promise<TestCertificateResult> {
  return generateTestEndpointCertificate(did, domain, email, "P256");
}

/**
 * Alias for generateTestEndpointCertificate for backwards compatibility
 * @deprecated Use generateTestEndpointCertificate instead
 */
export const generateTestClientCertificate = generateTestEndpointCertificate;
