/**
 * Test certificate generation utilities
 * Uses P-256 ECDSA self-signed endpoint certificates
 */

import { generateEndpointCertificate } from "../lib/certificates/index.js";

export interface TestCertificateResult {
  cert: string;
  privateKey: string;
}

/** Default email domain for test certificates */
const TEST_EMAIL_DOMAIN = "test.atsms.example";

/**
 * Generate a test self-signed P-256 endpoint certificate
 * @param did - The DID for the certificate
 * @param domain - The domain/handle for the certificate
 * @param emailDomain - Email domain for deterministic email (defaults to test.atsms.example)
 */
export async function generateTestEndpointCertificate(
  did: string,
  domain: string,
  emailDomain: string = TEST_EMAIL_DOMAIN,
): Promise<TestCertificateResult> {
  const endpointCert = await generateEndpointCertificate(
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
  };
}

/**
 * Alias for generateTestEndpointCertificate for backwards compatibility
 * @deprecated Use generateTestEndpointCertificate instead
 */
export const generateTestClientCertificate = generateTestEndpointCertificate;
