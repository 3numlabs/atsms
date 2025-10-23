/**
 * K-256 (secp256k1) key import support for browsers
 * Provides a workaround for browsers that don't support K-256 natively
 */

import * as secp256k1 from '@noble/secp256k1'

/**
 * Parse a K-256 private key from PKCS8 DER format
 * This is a simplified parser that extracts the raw private key bytes
 */
function parseK256PrivateKeyFromPKCS8(der: Uint8Array): Uint8Array | null {
  // This is a simplified PKCS8 parser for K-256 keys
  // In production, you'd use a proper ASN.1 parser
  
  // Look for the K-256 OID (1.3.132.0.10) in the DER structure
  const k256OID = [0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01]
  
  // Find the OID in the DER
  let oidIndex = -1
  for (let i = 0; i < der.length - k256OID.length; i++) {
    let match = true
    for (let j = 0; j < k256OID.length; j++) {
      if (der[i + j] !== k256OID[j]) {
        match = false
        break
      }
    }
    if (match) {
      oidIndex = i
      break
    }
  }
  
  if (oidIndex === -1) {
    // Not a K-256 key, return null
    return null
  }
  
  // The private key is typically stored as an OCTET STRING after the OID
  // Look for the private key bytes (32 bytes for K-256)
  // This is a simplified approach - in production use proper ASN.1 parsing
  for (let i = oidIndex + k256OID.length; i < der.length - 32; i++) {
    // Look for a 32-byte sequence that could be the private key
    if (der[i] === 0x04 && der[i + 1] === 0x20) {
      // Found a 32-byte OCTET STRING
      return der.slice(i + 2, i + 34)
    }
  }
  
  // Alternative: sometimes the key is at the end
  if (der.length >= 32) {
    // Try the last 32 bytes
    const possibleKey = der.slice(der.length - 32)
    // Basic validation: check if it's a valid secp256k1 private key
    try {
      secp256k1.getPublicKey(possibleKey)
      return possibleKey
    } catch {
      // Not a valid key
    }
  }
  
  return null
}

/**
 * Create a mock CryptoKey for K-256 that stores the raw key data
 * This is used as a workaround for browsers that don't support K-256
 */
export function createK256CryptoKey(
  privateKeyBytes: Uint8Array,
  type: 'private' | 'public' = 'private'
): CryptoKey {
  const publicKeyBytes = type === 'private' 
    ? secp256k1.getPublicKey(privateKeyBytes, false)
    : privateKeyBytes
  
  // Create a mock CryptoKey object
  const key = {
    type,
    extractable: true,
    algorithm: {
      name: 'ECDSA',
      namedCurve: 'K-256'
    },
    usages: type === 'private' ? ['sign'] : ['verify'],
    // Store the raw key data for later use
    _k256PrivateKey: type === 'private' ? privateKeyBytes : undefined,
    _k256PublicKey: publicKeyBytes
  }
  
  return key as any as CryptoKey
}

/**
 * Import a K-256 private key from PEM format
 */
export async function importK256PrivateKeyFromPEM(privateKeyPEM: string): Promise<CryptoKey> {
  // Extract base64 from PEM
  const base64 = privateKeyPEM
    .replace(/-----BEGIN .*-----/g, '')
    .replace(/-----END .*-----/g, '')
    .replace(/\s/g, '')
  
  const der = Uint8Array.from(atob(base64), c => c.charCodeAt(0))
  
  // Try to parse the private key from PKCS8
  const privateKeyBytes = parseK256PrivateKeyFromPKCS8(der)
  
  if (!privateKeyBytes) {
    // If parsing fails, check if it might be raw key bytes
    if (der.length === 32) {
      // Might be raw private key
      try {
        secp256k1.getPublicKey(der)
        return createK256CryptoKey(der, 'private')
      } catch {
        throw new Error('Invalid K-256 private key')
      }
    }
    throw new Error('Could not parse K-256 private key from PEM')
  }
  
  return createK256CryptoKey(privateKeyBytes, 'private')
}

/**
 * Export a K-256 key's public key as JWK for verification
 */
export async function exportK256PublicKeyAsJWK(key: CryptoKey): Promise<any> {
  const keyData = key as any
  if (!keyData._k256PublicKey) {
    throw new Error('Not a K-256 key')
  }
  
  const publicKeyBytes = keyData._k256PublicKey as Uint8Array
  const publicKeyHex = Array.from(publicKeyBytes)
    .map(b => b.toString(16).padStart(2, '0'))
    .join('')
  
  // Extract x and y coordinates from uncompressed public key
  const xHex = publicKeyHex.slice(2, 66)
  const yHex = publicKeyHex.slice(66, 130)
  
  // Convert hex to base64url
  const hexToBase64Url = (hex: string): string => {
    const bytes = new Uint8Array(hex.length / 2)
    for (let i = 0; i < hex.length; i += 2) {
      bytes[i / 2] = parseInt(hex.substring(i, i + 2), 16)
    }
    const binary = Array.from(bytes, byte => String.fromCharCode(byte)).join('')
    const base64 = btoa(binary)
    return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '')
  }
  
  return {
    kty: 'EC',
    crv: 'K-256',
    x: hexToBase64Url(xHex),
    y: hexToBase64Url(yHex)
  }
}

/**
 * Sign data with a K-256 private key
 */
export async function signWithK256(key: CryptoKey, data: Uint8Array): Promise<Uint8Array> {
  const keyData = key as any
  if (!keyData._k256PrivateKey) {
    throw new Error('Not a K-256 private key')
  }
  
  const signature = await secp256k1.sign(data, keyData._k256PrivateKey)
  // Convert signature to Uint8Array if it's not already
  if (signature instanceof Uint8Array) {
    return signature
  }
  // If it's a signature object, convert to Uint8Array
  return new Uint8Array(signature as any)
}

/**
 * Verify a signature with a K-256 public key
 */
export async function verifyWithK256(key: CryptoKey, signature: Uint8Array, data: Uint8Array): Promise<boolean> {
  const keyData = key as any
  if (!keyData._k256PublicKey) {
    throw new Error('Not a K-256 public key')
  }
  
  return secp256k1.verify(signature, data, keyData._k256PublicKey)
}