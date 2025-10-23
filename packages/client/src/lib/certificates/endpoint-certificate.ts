/**
 * Client Certificate class for RSA certificates signed by root
 */

import * as secp256k1 from '@noble/secp256k1'
import { AsnConvert, AsnSerializer } from '@peculiar/asn1-schema'
import { AlgorithmIdentifier, Certificate as ASN1Certificate } from '@peculiar/asn1-x509'
import {
  BasicConstraintsExtension,
  ExtendedKeyUsageExtension,
  KeyUsageFlags,
  KeyUsagesExtension,
  SubjectAlternativeNameExtension,
  X509Certificate,
  X509CertificateGenerator
} from '@peculiar/x509'

import { cryptoProvider } from '../crypto-provider'
import type { ATSMSCertificateType } from '../types'
import { ATSMSCertificate } from './certificate'
import type { ATSMSRootCertificate } from './root-certificate'

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
 * Endpoint Certificate class - RSA certificates signed by root
 */
export class ATSMSEndpointCertificate extends ATSMSCertificate {
  private rootFingerprint?: string

  /**
   * Create and sign a endpoint certificate with K-256 root key
   */
  private static async createAndSignClientCertWithK256(
    rootCert: ATSMSRootCertificate,
    rootPrivateKey: CryptoKey,
    endpointPublicKey: CryptoKey,
    domain: string,
    did: string,
    email: string,
    validityDays = 3652
  ): Promise<X509Certificate> {
    // First create a dummy certificate to get the structure
    // We'll use a temporary key and then replace the signature
    const tempKeyPair = await cryptoProvider.subtle.generateKey(
      {
        name: 'ECDSA',
        namedCurve: 'P-256'
      },
      true,
      ['sign', 'verify']
    ) as CryptoKeyPair

    // Create the certificate structure
    const tempCert = await X509CertificateGenerator.create({
      subject: `CN=${domain}`,
      issuer: rootCert.subject,
      notBefore: new Date(),
      notAfter: new Date(Date.now() + validityDays * 24 * 60 * 60 * 1000),
      signingAlgorithm: {
        name: 'ECDSA',
        hash: 'SHA-256'
      },
      publicKey: endpointPublicKey,
      signingKey: tempKeyPair.privateKey,
      extensions: [
        new BasicConstraintsExtension(false, undefined, true),
        new KeyUsagesExtension(
          KeyUsageFlags.digitalSignature |
          KeyUsageFlags.keyEncipherment |
          KeyUsageFlags.dataEncipherment,
          true
        ),
        new ExtendedKeyUsageExtension(['1.3.6.1.5.5.7.3.1', '1.3.6.1.5.5.7.3.2'], false),
        new SubjectAlternativeNameExtension([
          { type: 'dns', value: domain },
          { type: 'url', value: did },
          { type: 'email', value: email }
        ])
      ]
    }, cryptoProvider as any)

    // Parse the certificate to get the ASN.1 structure
    const certData = tempCert.rawData
    const parsedCert = AsnConvert.parse(certData, ASN1Certificate)

    // Update signature algorithm
    parsedCert.tbsCertificate.signature = new AlgorithmIdentifier({
      algorithm: '1.2.840.10045.4.3.2' // ecdsaWithSHA256
    })

    // Serialize TBS (to-be-signed) certificate for signing
    const tbsData = AsnSerializer.serialize(parsedCert.tbsCertificate)

    // Hash the TBS data
    const msgHash = await cryptoProvider.subtle.digest('SHA-256', tbsData)

    // Get the K-256 private key bytes from our mock key
    const keyData = rootPrivateKey as any
    const privateKeyBytes = keyData._k256PrivateKey as Uint8Array

    if (!privateKeyBytes) {
      throw new Error('Root certificate does not have K-256 private key')
    }

    // Sign with secp256k1 (returns compact signature as Bytes in v3)
    const signatureBytes = secp256k1.sign(new Uint8Array(msgHash), privateKeyBytes)

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
   * Generate a new endpoint certificate signed by a root certificate
   */
  static async generateWithRoot(
    rootCert: ATSMSRootCertificate,
    did: string,
    domain: string,
    email: string,
    validityDays = 3652 // Default to ten years
  ): Promise<ATSMSEndpointCertificate> {
    // Validate parameters to prevent common errors
    if (typeof validityDays !== 'number' || isNaN(validityDays) || validityDays <= 0) {
      throw new Error(`Invalid validityDays: must be a positive number, got ${typeof validityDays}: ${validityDays}`)
    }

    // 2. Validate domain is a string and not empty
    if (typeof domain !== 'string' || !domain.trim()) {
      throw new Error(`Invalid domain: must be a non-empty string, got ${typeof domain}: ${domain}`)
    }

    // 3. Validate DID format
    if (typeof did !== 'string' || !did.startsWith('did:')) {
      throw new Error(`Invalid DID: must start with 'did:', got: ${did}`)
    }

    // 4. Minimally validate email format
    if (
      typeof email !== 'string' ||
      email.split('@').length !== 2 ||
      email.split('@')[1].split('.').length < 2
    ) {
      throw new Error(`Invalid email: must be a valid email address, got: ${email}`)
    }

    // Get root's private key for signing
    const rootPrivateKey = rootCert.getSigningKey()
    if (!rootPrivateKey) {
      throw new Error('Root certificate private key not available')
    }

    // Generate RSA key pair for endpoint certificate (2048 bit)
    const rsaAlg = {
      name: 'RSA-PSS',
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: 'SHA-256'
    }

    const rsaKeys = await cryptoProvider.subtle.generateKey(
      rsaAlg,
      true,
      ['sign', 'verify']
    ) as CryptoKeyPair

      // Browser environment or K-256 mock key - use K-256 signing
    const cert = await ATSMSEndpointCertificate.createAndSignClientCertWithK256(
        rootCert,
        rootPrivateKey,
        rsaKeys.publicKey,
        domain,
        did,
        email,
        validityDays
      )

    // Export private key to PEM
    const privateKeyBuffer = await cryptoProvider.subtle.exportKey('pkcs8', rsaKeys.privateKey)
    const privateKeyPEM = ATSMSCertificate.arrayBufferToPEM(privateKeyBuffer, 'PRIVATE KEY')

    // Create endpoint certificate with root fingerprint
    const endpointCert = new ATSMSEndpointCertificate(cert.rawData, rsaKeys.privateKey, privateKeyPEM)
    endpointCert.rootFingerprint = await rootCert.getFingerprint()

    return endpointCert
  }

  /**
   * Create an ATSMSEndpointCertificate from DER-encoded bytes (public certificate only)
   */
  static fromDER(derBytes: Uint8Array): ATSMSEndpointCertificate {
    return new ATSMSEndpointCertificate(derBytes, undefined, undefined)
  }

  /**
   * Create an ATSMSEndpointCertificate from PEM (certificate only, no private key)
   */
  static fromPEM(certPEM: string): ATSMSEndpointCertificate {
    const derBytes = ATSMSCertificate.pemToDER(certPEM)
    return new ATSMSEndpointCertificate(derBytes, undefined, undefined)
  }

  /**
   * Create an ATSMSEndpointCertificate from PEM with private key
   */
  static async fromPEMWithKey(certPEM: string, privateKeyPEM: string): Promise<ATSMSEndpointCertificate> {
    const derBytes = ATSMSCertificate.pemToDER(certPEM)

    // Client certificates always use RSA
    const alg = {
      name: 'RSASSA-PKCS1-v1_5',
      hash: 'SHA-256'
    }
    const privateKey = await ATSMSCertificate.importPrivateKeyPEM(privateKeyPEM, alg)

    // Create certificate instance and verify the private key matches
    const cert = new ATSMSEndpointCertificate(derBytes, privateKey, privateKeyPEM)
    const matches = await cert.verifyPrivateKeyMatchesCert(privateKey)
    if (!matches) {
      throw new Error('Private key does not match the certificate public key')
    }

    return cert
  }

  getType(): ATSMSCertificateType {
    return 'endpoint'
  }

  /**
   * Get the fingerprint of the root certificate that signed this endpoint cert
   */
  getRootFingerprint(): string | undefined {
    return this.rootFingerprint
  }

  /**
   * Verify this certificate was signed by the given root certificate
   */
  async verifyWithRoot(rootCert: ATSMSRootCertificate): Promise<boolean> {
    return this.verifyCertificate(rootCert)
  }

  /**
   * Get the RSA public key for encryption
   */
  async getPublicKeyForEncryption(): Promise<CryptoKey> {
    // Import the public key specifically for RSA-OAEP encryption
    const publicKey = await this.getPublicKey()

    // Export and re-import with RSA-OAEP algorithm
    const exported = await cryptoProvider.subtle.exportKey('spki', publicKey)

    return cryptoProvider.subtle.importKey(
      'spki',
      exported,
      {
        name: 'RSA-OAEP',
        hash: 'SHA-256'
      },
      true,
      ['encrypt']
    )
  }

  /**
   * Get the RSA private key for decryption
   */
  async getPrivateKeyForDecryption(): Promise<CryptoKey> {
    if (!this._privateKey) {
      throw new Error('Private key not available for decryption')
    }

    // Export and re-import with RSA-OAEP algorithm
    const exported = await cryptoProvider.subtle.exportKey('pkcs8', this._privateKey)

    return cryptoProvider.subtle.importKey(
      'pkcs8',
      exported,
      {
        name: 'RSA-OAEP',
        hash: 'SHA-256'
      },
      true,
      ['decrypt']
    )
  }
}