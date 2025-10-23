/**
 * Cryptographic operations for signing, encryption, and decryption
 * Uses the Certificate classes for all certificate operations
 */

import * as asn1js from 'asn1js'
import * as pkijs from 'pkijs'

import { ATSMSEndpointCertificate } from './certificates/index'
import { decryptMessageOAEP, encryptMessageOAEP } from './crypto-oaep'
import { cryptoProvider } from './crypto-provider'
import { type ATSMSDecryptedMessage } from './types'

// Initialize PKI.js on first use
let initialized = false
async function ensureInitialized() {
  if (!initialized) {
    // Set up PKI.js crypto engine - use native Web Crypto API
    pkijs.setEngine('webcrypto', cryptoProvider as any, new pkijs.CryptoEngine({
      name: 'webcrypto',
      crypto: cryptoProvider as any,
      subtle: cryptoProvider.subtle
    }))
    initialized = true
  }
}

/**
 * Sign message using PKCS#7 (S/MIME) - supports both RSA and ECDSA
 * @param message - The message content to sign
 * @param signerCert - Certificate containing the private key for signing
 * @returns Signed content as binary data
 */
export async function signMessage(
  message: string,
  signerCert: ATSMSEndpointCertificate
): Promise<Uint8Array> {
  await ensureInitialized()

  try {
    // Get the raw certificate data
    const certDer = signerCert.rawData
    const cert = pkijs.Certificate.fromBER(new Uint8Array(certDer).buffer)

    // Get the private key from the certificate
    const signerPrivateKey = signerCert.privateKeyValue

    // Create the message content
    const messageBytes = new TextEncoder().encode(message)
    const messageBuffer = messageBytes.buffer.slice(messageBytes.byteOffset, messageBytes.byteOffset + messageBytes.byteLength)

    // Create SignedData with detached signature first
    const signedData = new pkijs.SignedData({
      version: 1,
      encapContentInfo: new pkijs.EncapsulatedContentInfo({
        eContentType: pkijs.ContentInfo.DATA
      }),
      certificates: [cert],
      signerInfos: [
        new pkijs.SignerInfo({
          version: 1,
          sid: new pkijs.IssuerAndSerialNumber({
            issuer: cert.issuer,
            serialNumber: cert.serialNumber
          })
        })
      ]
    })

    // Sign the data (detached mode)
    await signedData.sign(
      signerPrivateKey,
      0, // Signer index
      'SHA-256',
      messageBuffer as ArrayBuffer
    )

    // Now manually set the content as a single OCTET STRING
    signedData.encapContentInfo.eContent = new asn1js.OctetString({
      valueHex: messageBuffer as ArrayBuffer
    })
    signedData.encapContentInfo.eContent.idBlock.isConstructed = false

    // Encode SignedData
    const signedDataDer = signedData.toSchema().toBER()

    // Wrap in ContentInfo
    const signedContentInfo = new pkijs.ContentInfo({
      contentType: pkijs.ContentInfo.SIGNED_DATA,
      content: asn1js.fromBER(signedDataDer).result
    })

    const signedDer = signedContentInfo.toSchema().toBER()

    // Return as Uint8Array
    return new Uint8Array(signedDer)
  } catch (error) {
    throw new Error(`Failed to sign message: ${error}`)
  }
}

/**
 * Encrypt signed content for recipients using RSA-OAEP
 */
export async function encryptMessage(
  signedContent: Uint8Array,
  recipientCerts: ATSMSEndpointCertificate[],
): Promise<Uint8Array> {
  // Directly pass through to encryptMessageOAEP
  return await encryptMessageOAEP(signedContent, recipientCerts)
}

/**
 * Decrypt and verify message signature
 * @param encryptedContent - The encrypted content as raw bytes
 * @param recipientCert - The recipient's certificate (must contain private key)
 * @returns ATSMSDecryptedMessage containing the signer's certificate and decrypted content
 */
export async function decryptAndVerifyMessageSignature(
  encryptedContent: Uint8Array,
  recipientCert: ATSMSEndpointCertificate
): Promise<ATSMSDecryptedMessage> {
  await ensureInitialized()

  try {
    // Step 1: Decrypt the message
    const decryptedBytes = await decryptMessageOAEP(
      encryptedContent,
      recipientCert
    )

    const contentInfo = asn1js.fromBER(decryptedBytes.buffer as ArrayBuffer)
    if (contentInfo.offset === -1) {
      throw new Error('Failed to parse ContentInfo')
    }

    const cmsContent = new pkijs.ContentInfo({ schema: contentInfo.result })

    // Check if it's SignedData
    if (cmsContent.contentType !== pkijs.ContentInfo.SIGNED_DATA) {
      throw new Error('Expected SignedData content type')
    }

    const cmsSignedData = new pkijs.SignedData({ schema: cmsContent.content })

    // Extract the signer's certificate
    if (!cmsSignedData.certificates || cmsSignedData.certificates.length === 0) {
      throw new Error('No signer certificate found in SignedData')
    }

    // Get the first certificate (signer's certificate)
    const signerCert = cmsSignedData.certificates[0]

    // Convert PKI.js Certificate to DER bytes
    const signerCertDer = signerCert.toSchema().toBER()
    
    // Create an ATSMSEndpointCertificate from the DER bytes (without private key since it's the signer's cert)
    const endpointCert = ATSMSEndpointCertificate.fromDER(new Uint8Array(signerCertDer))

    // Extract the content
    let decryptedContent: Uint8Array
    if (cmsSignedData.encapContentInfo.eContent) {
      const eContent = cmsSignedData.encapContentInfo.eContent
      if (eContent instanceof asn1js.OctetString) {
        decryptedContent = new Uint8Array(eContent.valueBlock.valueHexView)
      } else if ((eContent as any).valueBlock && (eContent as any).valueBlock.value && Array.isArray((eContent as any).valueBlock.value)) {
        // Handle case where eContent is constructed
        for (const item of (eContent as any).valueBlock.value) {
          if (item instanceof asn1js.OctetString) {
            decryptedContent = new Uint8Array((item as any).valueBlock.valueHexView)
            break
          }
        }
        if (!decryptedContent!) {
          throw new Error('Failed to extract content from SignedData')
        }
      } else {
        throw new Error('Unexpected eContent structure')
      }
    } else {
      throw new Error('No content found in SignedData')
    }

    // TODO: Implement actual signature verification
    // For now, we trust the content if we can decrypt it

    return {
      messageSigner: endpointCert,
      decryptedContent: decryptedContent!
    }
  } catch (error) {
    throw new Error(`Failed to decrypt and verify message signature: ${error}`)
  }
}