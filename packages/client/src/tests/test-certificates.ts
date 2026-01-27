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

/** Default email domain for test certificates */
const TEST_EMAIL_DOMAIN = "test.atsms.example";

/**
 * Generate a test self-signed endpoint certificate
 * @param did - The DID for the certificate
 * @param domain - The domain/handle for the certificate
 * @param emailDomain - Email domain for deterministic email (defaults to test.atsms.example)
 * @param algorithm - Certificate algorithm ('RSA' or 'P256', defaults to 'RSA' for backward compatibility)
 */
export async function generateTestEndpointCertificate(
  did: string,
  domain: string,
  emailDomain: string = TEST_EMAIL_DOMAIN,
  algorithm: ATSMSCertificateAlgorithm = "RSA",
): Promise<TestCertificateResult> {
  const endpointCert = await generateEndpointCertificate(
    algorithm,
    did,
    domain,
    emailDomain,
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
 * @param emailDomain - Email domain for deterministic email
 */
export async function generateTestP256EndpointCertificate(
  did: string,
  domain: string,
  emailDomain: string = TEST_EMAIL_DOMAIN,
): Promise<TestCertificateResult> {
  return generateTestEndpointCertificate(did, domain, emailDomain, "P256");
}

/**
 * Alias for generateTestEndpointCertificate for backwards compatibility
 * @deprecated Use generateTestEndpointCertificate instead
 */
export const generateTestClientCertificate = generateTestEndpointCertificate;
