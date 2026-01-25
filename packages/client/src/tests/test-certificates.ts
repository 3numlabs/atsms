/**
 * Test certificate generation utilities
 * Uses the actual certificate classes with self-signed RSA certificates
 */

import { ATSMSEndpointCertificate } from '../lib/certificates/index.js'

export interface TestCertificateResult {
  cert: string
  privateKey: string
}

/**
 * Generate a test self-signed endpoint certificate
 * @param did - The DID for the certificate
 * @param domain - The domain/handle for the certificate
 * @param email - Optional email address (defaults to generated from DID and domain)
 */
export async function generateTestEndpointCertificate(
  did: string,
  domain: string,
  email?: string
): Promise<TestCertificateResult> {
  // Generate a self-signed RSA endpoint certificate
  const defaultEmail = email || `${did.split(':').pop()}@${domain}`
  const endpointCert = await ATSMSEndpointCertificate.generate(
    did,
    domain,
    defaultEmail,
    365
  )

  const certPEM = endpointCert.toString('pem')
  const privateKeyPEM = endpointCert.certificatePrivateKeyPEM!

  return {
    cert: certPEM,
    privateKey: privateKeyPEM
  }
}

/**
 * Alias for generateTestEndpointCertificate for backwards compatibility
 * @deprecated Use generateTestEndpointCertificate instead
 */
export const generateTestClientCertificate = generateTestEndpointCertificate
