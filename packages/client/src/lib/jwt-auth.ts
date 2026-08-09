/**
 * JWT Authentication utilities for AT SMS
 * Pure functions for JWT token generation without file I/O
 * Uses ES256 (P-256 ECDSA) for signing
 */

import { decodeJwt, importPKCS8, SignJWT } from "jose";

/**
 * Generate a JWT token signed with the endpoint's private key (ES256 / P-256 ECDSA)
 *
 * @param privateKeyPEM - The private key in PEM format (PKCS#8)
 * @param deviceFingerprint - The device fingerprint (the at.atsms.x509 record key)
 * @param did - The DID of the user
 * @returns The signed JWT token
 */
export async function generateJWT(
  privateKeyPEM: string,
  deviceFingerprint: string,
  did: string,
): Promise<string> {
  // Create the AT Protocol URI for the user ID — fingerprint-keyed record
  // (identity-devices §4; integration §8.5 re-keying)
  const userId = `at://${did}/at.atsms.x509/${deviceFingerprint}`;

  // Ensure the private key is in proper PKCS#8 format
  if (!privateKeyPEM.includes("BEGIN PRIVATE KEY")) {
    throw new Error("Private key must be in PKCS#8 format (BEGIN PRIVATE KEY)");
  }

  // Import the private key with ES256 (P-256 ECDSA)
  const privateKey = await importPKCS8(privateKeyPEM, "ES256");

  // Sign the JWT
  const token = await new SignJWT({
    sub: userId, // Subject is the AT Protocol URL
    iss: did, // Issuer is the DID
    aud: "atsms-api", // Audience is the API
  })
    .setProtectedHeader({
      alg: "ES256",
      typ: "JWT",
      kid: deviceFingerprint, // Key ID is the device fingerprint (the record rkey)
    })
    .setIssuedAt()
    .setExpirationTime("1h")
    .sign(privateKey);

  return token;
}

/**
 * Extract expiration date from a JWT token
 * @param token - The JWT token
 * @returns The expiration date as ISO string
 */
export function getTokenExpiration(token: string): string {
  const decoded = decodeJwt(token);
  return new Date((decoded.exp || 0) * 1000).toISOString();
}
