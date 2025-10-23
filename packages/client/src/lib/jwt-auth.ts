/**
 * JWT Authentication utilities for AT SMS
 * Pure functions for JWT token generation without file I/O
 */

import { decodeJwt, importPKCS8, SignJWT } from 'jose'

/**
 * Generate a JWT token signed with the endpoint's private key
 * @param privateKeyPEM - The private key in PEM format
 * @param endpointCertSerialNumber - The serial number of the endpoint certificate
 * @param did - The DID of the user
 * @returns The signed JWT token
 */
export async function generateJWT(
  privateKeyPEM: string,
  endpointCertSerialNumber: string,
  did: string
): Promise<string> {
  // Create the AT Protocol URL for the user ID
  const userId = `at://${did}/at.atsms.x509/${endpointCertSerialNumber}`

  // Ensure the private key is in proper PKCS#8 format
  if (!privateKeyPEM.includes('BEGIN PRIVATE KEY')) {
    throw new Error('Private key must be in PKCS#8 format (BEGIN PRIVATE KEY)')
  }

  // Import the private key
  const privateKey = await importPKCS8(privateKeyPEM, 'RS256')
  
  // Sign the JWT with RS256 algorithm (RSA with SHA-256)
  const token = await new SignJWT({
    sub: userId,  // Subject is the AT Protocol URL
    iss: did, // Issuer is the DID
    aud: 'atsms-api', // Audience is the API
  })
    .setProtectedHeader({ 
      alg: 'RS256',
      typ: 'JWT',
      kid: endpointCertSerialNumber // Key ID is the certificate serial number
    })
    .setIssuedAt()
    .setExpirationTime('1h')
    .sign(privateKey)

  return token
}

/**
 * Extract expiration date from a JWT token
 * @param token - The JWT token
 * @returns The expiration date as ISO string
 */
export function getTokenExpiration(token: string): string {
  const decoded = decodeJwt(token)
  return new Date((decoded.exp || 0) * 1000).toISOString()
}