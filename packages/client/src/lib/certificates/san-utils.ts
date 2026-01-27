/**
 * Utility functions for computing SAN (Subject Alternative Name) values
 * Used by endpoint certificate generation
 */

import { cryptoProvider } from "../crypto-provider";

/**
 * Compute deterministic AT-SMS email from DID and email domain
 *
 * Format by DID method:
 * - PLC: plc.[plc-id]@domain → plc.bq5ygkxmmbae7n6z34neuaih@atsms.email
 * - WEB: web.[base64url(web-part)]@domain → web.ZXhhbXBsZS5jb20@atsms.email
 *
 * @param did - Decentralized identifier (e.g., 'did:plc:abc123' or 'did:web:example.com')
 * @param emailDomain - Email provider domain (e.g., 'atsms.email')
 * @returns Deterministic email address
 */
export function computeATSMSEmail(did: string, emailDomain: string): string {
  const parts = did.split(":");
  if (parts.length < 3 || parts[0] !== "did") {
    throw new Error(`Invalid DID format: ${did}`);
  }

  const method = parts[1]; // 'plc' or 'web'

  if (method === "plc" || method === "test") {
    // did:plc:abc123 → plc.abc123@domain
    // did:test:abc123 → test.abc123@domain (for testing)
    const specificId = parts[2];
    return `${method}.${specificId}@${emailDomain}`;
  } else if (method === "web") {
    // did:web:example.com:path → web.[base64url("example.com:path")]@domain
    const webPart = parts.slice(2).join(":");
    const encoded = base64UrlEncode(webPart);
    return `web.${encoded}@${emailDomain}`;
  }

  throw new Error(`Unsupported DID method: ${method}`);
}

/**
 * Compute the AT URI for the certificate SAN
 *
 * Format: at://[did]/at.atsms.x509/[cert serial number lowercase hex]
 *
 * @param did - Decentralized identifier
 * @param serialNumberHex - Certificate serial number in lowercase hex
 * @returns AT Protocol URI
 */
export function computeATSMSUri(did: string, serialNumberHex: string): string {
  return `at://${did}/at.atsms.x509/${serialNumberHex.toLowerCase()}`;
}

/**
 * Generate a random serial number for certificate generation
 * Returns both the hex string and the ArrayBuffer needed by the certificate generator
 *
 * @returns Object with hex string and ArrayBuffer
 */
export async function generateSerialNumber(): Promise<{
  hex: string;
  bytes: ArrayBuffer;
}> {
  // Generate 16 random bytes for the serial number
  const bytes = new Uint8Array(16);
  cryptoProvider.getRandomValues(bytes);

  // Ensure the first byte's high bit is 0 to avoid negative interpretation in ASN.1
  bytes[0] = bytes[0] & 0x7f;

  // Convert to hex string (lowercase)
  const hex = Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");

  return { hex, bytes: bytes.buffer };
}

/**
 * URL-safe Base64 encoding without padding
 * Used for encoding did:web values in email addresses
 */
function base64UrlEncode(str: string): string {
  // Convert string to bytes
  const bytes = new TextEncoder().encode(str);

  // Convert to base64
  const binary = Array.from(bytes, (byte) => String.fromCharCode(byte)).join(
    "",
  );
  const base64 = btoa(binary);

  // Make URL-safe: replace + with -, / with _, remove padding =
  return base64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
