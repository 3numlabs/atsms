/**
 * Test certificate generation utilities
 * Uses the actual certificate classes with K-256 for root and RSA for client
 */

import { ATSMSRootCertificate } from '../lib/certificates/index.js'

export interface TestCertificateResult {
  cert: string
  privateKey: string
}

/**
 * Generate a test root certificate with K-256
 */
export async function generateTestRootCertificate(
  did: string,
  domain: string
): Promise<TestCertificateResult> {
  // Generate a K-256 root certificate
  const rootCert = await ATSMSRootCertificate.generate(did, domain, 365)
  const certPEM = rootCert.toString('pem')
  const privateKeyPEM = rootCert.certificatePrivateKeyPEM!

  return {
    cert: certPEM,
    privateKey: privateKeyPEM
  }
}

/**
 * Generate a test client certificate signed by root
 */
export async function generateTestClientCertificate(
  rootResult: TestCertificateResult,
  did: string,
  domain: string,
  email?: string
): Promise<TestCertificateResult> {
  // Load the root certificate with private key
  const rootCert = await ATSMSRootCertificate.fromPEMWithKey(rootResult.cert, rootResult.privateKey)

  // Generate client certificate with default email if not provided
  // Note: For certificates loaded from PEM, we need to pass did and domain explicitly
  const defaultEmail = email || `${did.split(':').pop()}@${domain}`
  const endpointCert = await rootCert.generateSignedEndpointCertificate(
    defaultEmail,
    365,
    did,
    domain
  )

  const certPEM = endpointCert.toString('pem')
  const privateKeyPEM = endpointCert.certificatePrivateKeyPEM!

  return {
    cert: certPEM,
    privateKey: privateKeyPEM
  }
}