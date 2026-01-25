/**
 * JWT Authentication utilities for AT SMS
 * Pure functions for JWT token generation without file I/O
 * Supports both RS256 (RSA) and ES256 (P-256 ECDSA)
 */

import { decodeJwt, importPKCS8, SignJWT } from "jose";

/**
 * Detect the key type from a PKCS#8 PEM private key
 * @param privateKeyPEM - The private key in PEM format
 * @returns 'RSA' or 'EC' based on the key type
 */
function detectKeyType(privateKeyPEM: string): "RSA" | "EC" {
  // Decode the PEM to check the key type
  // PKCS#8 format contains an AlgorithmIdentifier that tells us the key type
  // For simplicity, we check the key header after import
  // EC keys in PKCS#8 have OID 1.2.840.10045.2.1 (ecPublicKey)
  // RSA keys in PKCS#8 have OID 1.2.840.113549.1.1.1 (rsaEncryption)

  const base64 = privateKeyPEM
    .replace(/-----BEGIN .*-----/g, "")
    .replace(/-----END .*-----/g, "")
    .replace(/\s/g, "");

  const der = Uint8Array.from(atob(base64), (c) => c.charCodeAt(0));

  // Check for EC OID (1.2.840.10045.2.1) which appears as: 06 07 2A 86 48 CE 3D 02 01
  // RSA OID (1.2.840.113549.1.1.1) appears as: 06 09 2A 86 48 86 F7 0D 01 01 01
  const derHex = Array.from(der)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");

  // EC OID hex pattern
  if (derHex.includes("06072a8648ce3d0201")) {
    return "EC";
  }

  // Default to RSA
  return "RSA";
}

/**
 * Generate a JWT token signed with the endpoint's private key
 * Automatically detects key type and uses RS256 for RSA or ES256 for P-256
 *
 * @param privateKeyPEM - The private key in PEM format
 * @param endpointCertSerialNumber - The serial number of the endpoint certificate
 * @param did - The DID of the user
 * @returns The signed JWT token
 */
export async function generateJWT(
  privateKeyPEM: string,
  endpointCertSerialNumber: string,
  did: string,
): Promise<string> {
  // Create the AT Protocol URL for the user ID
  const userId = `at://${did}/at.atsms.x509/${endpointCertSerialNumber}`;

  // Ensure the private key is in proper PKCS#8 format
  if (!privateKeyPEM.includes("BEGIN PRIVATE KEY")) {
    throw new Error("Private key must be in PKCS#8 format (BEGIN PRIVATE KEY)");
  }

  // Detect key type
  const keyType = detectKeyType(privateKeyPEM);
  const algorithm = keyType === "EC" ? "ES256" : "RS256";

  // Import the private key with the appropriate algorithm
  const privateKey = await importPKCS8(privateKeyPEM, algorithm);

  // Sign the JWT with the appropriate algorithm
  const token = await new SignJWT({
    sub: userId, // Subject is the AT Protocol URL
    iss: did, // Issuer is the DID
    aud: "atsms-api", // Audience is the API
  })
    .setProtectedHeader({
      alg: algorithm,
      typ: "JWT",
      kid: endpointCertSerialNumber, // Key ID is the certificate serial number
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
