/**
 * Root Certificate class for self-signed secp256k1 certificates
 */

import { hmac } from '@noble/hashes/hmac.js'
import { sha256 } from '@noble/hashes/sha2.js'
import * as secp256k1 from '@noble/secp256k1'

// Extend the secp256k1 etc type to include our runtime extensions
// We add properties at runtime for backwards compatibility with older versions
type Secp256k1Etc = typeof secp256k1.etc & {
  hmacSha256Sync?: (key: Uint8Array, message: Uint8Array) => Uint8Array
}
import { AsnConvert, AsnSerializer } from '@peculiar/asn1-schema'
import { AlgorithmIdentifier, Certificate as ASN1Certificate, SubjectPublicKeyInfo } from '@peculiar/asn1-x509'
import {
  BasicConstraintsExtension,
  KeyUsageFlags,
  KeyUsagesExtension,
  SubjectAlternativeNameExtension,
  X509Certificate,
  X509CertificateGenerator
} from '@peculiar/x509'

import { cryptoProvider } from '../crypto-provider'
import type { ATSMSCertificateType } from '../types'
import { ATSMSCertificate } from './certificate'
import { ATSMSEndpointCertificate } from './endpoint-certificate'
import { createK256CryptoKey, importK256PrivateKeyFromPEM } from './k256-import'

// Configure secp256k1 with hash functions (required for v3+)
if (secp256k1.hashes && !secp256k1.hashes.sha256) {
  secp256k1.hashes.sha256 = (message: Uint8Array) => {
    return sha256(message)
  }
  secp256k1.hashes.hmacSha256 = (key: Uint8Array, message: Uint8Array) => {
    return hmac(sha256, key, message)
  }
}

// Configure legacy etc object for backwards compatibility
const etc = secp256k1.etc as Secp256k1Etc
if (etc && !etc.hmacSha256Sync) {
  etc.hmacSha256Sync = (key: Uint8Array, message: Uint8Array) => {
    return hmac(sha256, key, message)
  }

  etc.randomBytes = (len?: number) => {
    const length = len || 32
    const bytes = new Uint8Array(length)
    globalThis.crypto.getRandomValues(bytes)
    return bytes
  }
}

/**
 * Root Certificate class - self-signed secp256k1 certificates
 */
export class ATSMSRootCertificate extends ATSMSCertificate {
  private _did?: string
  private _domain?: string

  /**
   * Get the private key for signing (internal use only)
   */
  getSigningKey(): CryptoKey | undefined {
    return this._privateKey
  }
  /**
   * Generate a new self-signed root certificate
   * Default validity is 10 years (ok really 3652 days)
   */
  static async generate(did: string, domain: string, validityDays = 3652): Promise<ATSMSRootCertificate> {

    // Generate K-256 key pair
    const privateKeyBytes = secp256k1.utils.randomSecretKey()
    const publicKeyBytes = secp256k1.getPublicKey(privateKeyBytes, false) // uncompressed

    // Create mock CryptoKey object for K-256 private key
    const privateKey = createK256CryptoKey(privateKeyBytes, 'private')

    // Create certificate with K-256 public key properly embedded
    const cert = await createSelfSignedK256Certificate({
      subject: `CN=${did}`,
      notBefore: new Date(),
      notAfter: new Date(Date.now() + validityDays * 24 * 60 * 60 * 1000),
      publicKeyBytes,
      privateKeyBytes,
      extensions: [
        new BasicConstraintsExtension(true, 2, true),
        new KeyUsagesExtension(
          KeyUsageFlags.digitalSignature |
          KeyUsageFlags.keyCertSign |
          KeyUsageFlags.cRLSign,
          true
        ),
        new SubjectAlternativeNameExtension([
          { type: 'dns', value: domain }, // Used only for humans to see handle that was used when cert made.
          { type: 'url', value: did }
        ])
      ]
    })

    const privateKeyPEM = createK256PrivateKeyPEM(privateKeyBytes)
    const rootCert = new ATSMSRootCertificate(cert.rawData, privateKey, privateKeyPEM)
    // Store DID and domain for later use
    rootCert._did = did
    rootCert._domain = domain
    return rootCert
  }

  /**
   * Create a RootCertificate from DER-encoded bytes (public certificate only)
   */
  static fromDER(derBytes: Uint8Array): ATSMSRootCertificate {
    return new ATSMSRootCertificate(derBytes, undefined, undefined)
  }

  /**
   * Create a RootCertificate from PEM (certificate only, no private key)
   */
  static fromPEM(certPEM: string): ATSMSRootCertificate {
    const derBytes = ATSMSCertificate.pemToDER(certPEM)
    return new ATSMSRootCertificate(derBytes, undefined, undefined)
  }

  /**
   * Extract the raw public key bytes from the certificate's SubjectPublicKeyInfo
   * For secp256k1/K-256 keys, this returns the uncompressed EC point (65 bytes: 0x04 + X + Y)
   */
  extractRawPublicKeyBytes(): Uint8Array {
    // Get the public key info from the certificate
    const certPublicKeyInfo = this.publicKey

    // The subjectPublicKey in the certificate contains a BIT STRING with the actual EC point
    // For EC keys, this is the uncompressed point (0x04 + X + Y coordinates)
    const spkiRaw = certPublicKeyInfo.rawData
    const spkiView = new Uint8Array(spkiRaw)

    // The public key in X.509 certificates for EC keys is in a BIT STRING
    // We need to find the last occurrence of 0x04 followed by 64 bytes (32 bytes X + 32 bytes Y)
    // The BIT STRING is usually preceded by 0x03 (BIT STRING tag) and a length

    let publicKeyBytes: Uint8Array | null = null

    // Search from the end backwards for the uncompressed EC point
    for (let i = spkiView.length - 65; i >= 0; i--) {
      if (spkiView[i] === 0x04) {
        // Check if we have exactly 64 bytes after the 0x04
        if (i + 65 <= spkiView.length) {
          // This looks like an uncompressed EC point
          publicKeyBytes = spkiView.slice(i, i + 65)
          break
        }
      }
    }

    if (!publicKeyBytes) {
      throw new Error('Could not extract public key from certificate')
    }

    return publicKeyBytes
  }

  /**
   * Create a RootCertificate from PEM with private key
   */
  static async fromPEMWithKey(certPEM: string, privateKeyPEM: string): Promise<ATSMSRootCertificate> {
    const derBytes = ATSMSCertificate.pemToDER(certPEM)

    const privateKey = await importK256PrivateKeyFromPEM(privateKeyPEM)

    // Verify that the private key matches the public key in the certificate
    const rootCert = new ATSMSRootCertificate(derBytes, privateKey, privateKeyPEM)

    // Extract the private key bytes from the mock CryptoKey
    const keyData = privateKey as any
    if (keyData._k256PrivateKey) {
      const privateKeyBytes = keyData._k256PrivateKey as Uint8Array

      // Generate public key from private key using secp256k1
      const derivedPublicKey = secp256k1.getPublicKey(privateKeyBytes, false) // uncompressed

      // Get the public key bytes from the certificate using our new method
      const certPublicKeyBytes = rootCert.extractRawPublicKeyBytes()

      // Compare the derived public key with the certificate's public key
      if (certPublicKeyBytes.length !== derivedPublicKey.length) {
        throw new Error('Private key does not match the public key in the certificate (length mismatch)')
      }

      for (let i = 0; i < derivedPublicKey.length; i++) {
        if (derivedPublicKey[i] !== certPublicKeyBytes[i]) {
          throw new Error('Private key does not match the public key in the certificate')
        }
      }
    }

    // Extract and store DID and domain from the certificate
    const cnMatch = rootCert.subject.match(/CN=([^,]+)/)
    if (cnMatch) {
      rootCert._did = cnMatch[1]
    }

    // Try to extract domain from SAN extension - use the getDID logic
    // For now, we'll extract it when needed

    return rootCert
  }

  /**
   * Extract DID from root certificate subject
   */
  getDID(): string {
    // Use stored value if available (from generate())
    if (this._did) {
      return this._did
    }

    // Otherwise extract from subject: "CN=did:plc:..."
    const cnMatch = this.subject.match(/CN=([^,]+)/)
    if (!cnMatch) {
      throw new Error('Could not extract DID from certificate subject')
    }
    return cnMatch[1]
  }

  /**
   * Extract domain from root certificate
   */
  getDomain(): string {
    // Use stored value if available (from generate())
    if (this._domain) {
      return this._domain
    }

    // Otherwise try to extract from subject (fallback for imported certs)
    // This is a best-effort fallback
    throw new Error('Domain not available - certificate was not generated with this library or domain must be provided explicitly')
  }

  /**
   * Sign a endpoint certificate
   * Uses the DID and domain from this root certificate (if available)
   * For certificates loaded from PEM, did and domain may need to be provided explicitly
   */
  async generateSignedEndpointCertificate(
    email: string,
    validityDays = 3652,
    did?: string,
    domain?: string
  ): Promise<ATSMSEndpointCertificate> {
    // Use provided values, or try to extract from certificate
    const finalDID = did || this.getDID()
    const finalDomain = domain || (this._domain || '')

    if (!finalDomain) {
      throw new Error(
        'Domain must be provided for certificates loaded from PEM. ' +
        'Call with: rootCert.generateSignedEndpointCertificate(email, validityDays, did, domain)'
      )
    }

    return ATSMSEndpointCertificate.generateWithRoot(
      this,
      finalDID,
      finalDomain,
      email,
      validityDays
    )
  }

  getType(): ATSMSCertificateType {
    return 'root'
  }


  /**
   * Override exportPrivateKey to handle secp256k1 keys
   */
  async exportPrivateKey(format: 'pkcs8' | 'raw' = 'pkcs8'): Promise<ArrayBuffer> {
    if (!this._privateKey) {
      throw new Error('No private key available to export')
    }

    // Check if this is a K-256 mock key
    const keyData = this._privateKey as any
    if (keyData._k256PrivateKey) {
      // This is a K-256 mock key
      const privateKeyBytes = keyData._k256PrivateKey as Uint8Array
      
      if (format === 'raw') {
        // Return raw bytes for secp256k1
        return privateKeyBytes.buffer as ArrayBuffer
      } else {
        // Create PKCS8 structure for K-256 private key
        const pkcs8 = createK256PKCS8(privateKeyBytes)
        return pkcs8.buffer as ArrayBuffer
      }
    } else {
      // Regular key - use parent class implementation
      return super.exportPrivateKey(format)
    }
  }
}

/**
 * Create a PKCS8 structure for K-256 private key
 */
function createK256PKCS8(privateKeyBytes: Uint8Array): Uint8Array {
  // PKCS8 structure for K-256 (secp256k1)
  // This is a simplified version that includes:
  // - Version (0)
  // - Algorithm identifier (ecPublicKey with secp256k1 OID)
  // - Private key octets

  const k256OID = [0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01] // ecPublicKey
  const secp256k1OID = [0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x0a] // secp256k1

  // Build the PKCS8 structure
  const pkcs8 = new Uint8Array([
    // SEQUENCE
    0x30, 0x81, 0x84 + privateKeyBytes.length,
    // Version INTEGER 0
    0x02, 0x01, 0x00,
    // Algorithm Identifier SEQUENCE
    0x30, 0x13,
    ...k256OID,
    ...secp256k1OID,
    // Private Key OCTET STRING
    0x04, 0x81, 0x20 + privateKeyBytes.length,
    // SEQUENCE containing the private key
    0x30, 0x81, 0x20 + privateKeyBytes.length - 3,
    // Version INTEGER 1
    0x02, 0x01, 0x01,
    // Private key OCTET STRING
    0x04, 0x20,
    ...privateKeyBytes
  ])

  return pkcs8
}

/**
 * Helper function to encode secp256k1 signature to DER format
 */
function encodeDERSignature(signatureCompact: Uint8Array): Uint8Array {
  // Split r and s values (32 bytes each for secp256k1)
  const r = signatureCompact.slice(0, 32)
  const s = signatureCompact.slice(32, 64)

  // Ensure positive integers (add 0x00 if high bit is set)
  const rArray = r[0] & 0x80 ? new Uint8Array([0, ...r]) : r
  const sArray = s[0] & 0x80 ? new Uint8Array([0, ...s]) : s

  // Build DER sequence: SEQUENCE { INTEGER r, INTEGER s }
  const der: number[] = []

  // SEQUENCE tag
  der.push(0x30)

  // Calculate total length
  const totalLen = 2 + rArray.length + 2 + sArray.length
  der.push(totalLen)

  // INTEGER r
  der.push(0x02) // INTEGER tag
  der.push(rArray.length)
  der.push(...rArray)

  // INTEGER s
  der.push(0x02) // INTEGER tag
  der.push(sArray.length)
  der.push(...sArray)

  return new Uint8Array(der)
}

/**
 * Create a self-signed K-256 certificate
 */
async function createSelfSignedK256Certificate(params: {
  subject: string
  notBefore: Date
  notAfter: Date
  publicKeyBytes: Uint8Array
  privateKeyBytes: Uint8Array
  extensions: any[]
}): Promise<X509Certificate> {
  // First create a temporary certificate with P-256 to get the proper structure
  const tempKeyPair = await cryptoProvider.subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-256' },
    true,
    ['sign', 'verify']
  ) as CryptoKeyPair

  const tempCert = await X509CertificateGenerator.createSelfSigned({
    // Let the library generate an RFC 5280 compliant serial number
    name: params.subject,
    notBefore: params.notBefore,
    notAfter: params.notAfter,
    signingAlgorithm: { name: 'ECDSA', hash: 'SHA-256' },
    keys: tempKeyPair,
    extensions: params.extensions
  }, cryptoProvider as any)

  // Parse the certificate to modify it
  const certData = tempCert.rawData
  const parsedCert = AsnConvert.parse(certData, ASN1Certificate)

  // Create K-256 public key ASN.1 structure
  const publicKeyInfo = createK256PublicKeyInfo(params.publicKeyBytes)
  
  // Replace the public key in the certificate
  parsedCert.tbsCertificate.subjectPublicKeyInfo = publicKeyInfo

  // Update signature algorithm to K-256
  parsedCert.tbsCertificate.signature = new AlgorithmIdentifier({
    algorithm: '1.2.840.10045.4.3.2' // ecdsaWithSHA256
  })

  // Serialize TBS (to-be-signed) certificate for signing
  const tbsData = AsnSerializer.serialize(parsedCert.tbsCertificate)

  // Hash the TBS data
  const msgHash = await cryptoProvider.subtle.digest('SHA-256', tbsData)

  // Sign with secp256k1 (returns compact signature as Bytes in v3)
  const signatureBytes = secp256k1.sign(new Uint8Array(msgHash), params.privateKeyBytes)

  // Convert signature to DER format
  const derSignature = encodeDERSignature(signatureBytes)

  // Update the certificate with the K-256 signature
  parsedCert.signatureAlgorithm = new AlgorithmIdentifier({
    algorithm: '1.2.840.10045.4.3.2' // ecdsaWithSHA256
  })
  parsedCert.signatureValue = derSignature.buffer as ArrayBuffer

  // Serialize the final certificate
  const finalCertBuffer = AsnSerializer.serialize(parsedCert)

  // Create X509Certificate from the signed data
  return new X509Certificate(finalCertBuffer)
}

/**
 * Create K-256 public key info ASN.1 structure
 */
function createK256PublicKeyInfo(publicKeyBytes: Uint8Array): SubjectPublicKeyInfo {
  // Create the SubjectPublicKeyInfo structure for K-256
  // The parameters field should contain the raw OID bytes for secp256k1
  const secp256k1OIDBytes = new Uint8Array([0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x0a])
  
  const publicKeyInfo = new SubjectPublicKeyInfo({
    algorithm: new AlgorithmIdentifier({
      algorithm: '1.2.840.10045.2.1', // ecPublicKey
      parameters: secp256k1OIDBytes.buffer as ArrayBuffer // Raw OID bytes
    }),
    subjectPublicKey: publicKeyBytes.buffer as ArrayBuffer
  })
  
  return publicKeyInfo
}

/**
 * Helper function to create a PEM-encoded private key for K-256
 * This creates a simplified PKCS8 structure
 */
function createK256PrivateKeyPEM(privateKeyBytes: Uint8Array): string {
  // This is a simplified version - proper ASN.1 encoding would be more complex
  // For now, we'll store the raw key in a basic format
  const base64 = btoa(String.fromCharCode(...privateKeyBytes))
  return `-----BEGIN PRIVATE KEY-----\n${base64}\n-----END PRIVATE KEY-----`
}