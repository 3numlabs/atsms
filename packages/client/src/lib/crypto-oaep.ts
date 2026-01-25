/**
 * CMS Envelope encryption/decryption using PKI.js and Web Crypto API
 * Supports both RSA-OAEP (KeyTransRecipientInfo) and ECDH (KeyAgreeRecipientInfo)
 */

import * as asn1js from "asn1js";
import * as pkijs from "pkijs";

import {
  type ATSMSAnyEndpointCertificate,
  ATSMSP256EndpointCertificate,
} from "./certificates/index";
import { cryptoProvider } from "./crypto-provider";

// Initialize PKI.js with the crypto provider
pkijs.setEngine(
  "webcrypto",
  cryptoProvider as any,
  new pkijs.CryptoEngine({
    name: "webcrypto",
    crypto: cryptoProvider as any,
    subtle: cryptoProvider.subtle,
  }),
);

/**
 * Encrypt message using CMS EnvelopedData (via PKI.js)
 * Supports both RSA-OAEP (KeyTransRecipientInfo) and ECDH (KeyAgreeRecipientInfo)
 *
 * @param signedBytes - Binary data to encrypt
 * @param recipientCerts - Array of recipient certificates (RSA or P-256)
 * @returns Encrypted content as binary data
 */
export async function encryptMessageOAEP(
  signedBytes: Uint8Array,
  recipientCerts: ATSMSAnyEndpointCertificate[],
): Promise<Uint8Array> {
  // Validate that we have recipients with certificates
  if (!recipientCerts || recipientCerts.length === 0) {
    throw new Error(
      "Cannot encrypt message: Recipient has no AT-SMS certificates. " +
        "The recipient must set up their certificates before they can receive encrypted messages.",
    );
  }

  try {
    // Create EnvelopedData
    const envelopedData = new pkijs.EnvelopedData();

    // Add recipients - detect certificate type and use appropriate method
    for (const recipientCert of recipientCerts) {
      // Use Certificate object - get the raw DER data
      const cert = pkijs.Certificate.fromBER(recipientCert.rawData);

      if (recipientCert instanceof ATSMSP256EndpointCertificate) {
        // P-256 certificate - use KeyAgreeRecipientInfo (ECDH)
        // variant 2 = KeyAgreeRecipientInfo
        envelopedData.addRecipientByCertificate(
          cert,
          {
            kdfAlgorithm: "SHA-256",
            kekEncryptionLength: 256,
          },
          2, // variant for KeyAgreeRecipientInfo
        );
      } else {
        // RSA certificate - use KeyTransRecipientInfo (RSA-OAEP)
        // variant 1 = KeyTransRecipientInfo
        envelopedData.addRecipientByCertificate(
          cert,
          {
            oaepHashAlgorithm: "SHA-256",
            pbkdf2KeyLength: 256,
          },
          1, // variant for KeyTransRecipientInfo
        );
      }
    }

    // Convert signed data to ArrayBuffer
    const signedBuffer = signedBytes.buffer.slice(
      signedBytes.byteOffset,
      signedBytes.byteOffset + signedBytes.byteLength,
    ) as ArrayBuffer;

    // Encrypt the signed data
    await envelopedData.encrypt(
      { name: "AES-CBC", length: 256 } as any,
      signedBuffer,
    );

    // Encode EnvelopedData with definite length
    const envelopedDataDer = envelopedData.toSchema().toBER(false);

    // Wrap in ContentInfo
    const encryptedContentInfo = new pkijs.ContentInfo({
      contentType: pkijs.ContentInfo.ENVELOPED_DATA,
      content: asn1js.fromBER(envelopedDataDer).result,
    });

    const encryptedDer = encryptedContentInfo.toSchema().toBER(false);

    // Return as Uint8Array
    return new Uint8Array(encryptedDer);
  } catch (error) {
    throw new Error(`Failed to encrypt message: ${error}`);
  }
}

/**
 * Decrypt message using CMS EnvelopedData
 * Supports both RSA-OAEP (KeyTransRecipientInfo) and ECDH (KeyAgreeRecipientInfo)
 *
 * @param encryptedBytes - Binary encrypted data
 * @param recipientCert - Certificate containing the private key (RSA or P-256)
 * @returns Decrypted content as binary data
 */
export async function decryptMessageOAEP(
  encryptedBytes: Uint8Array,
  recipientCert: ATSMSAnyEndpointCertificate,
): Promise<Uint8Array> {
  try {
    // Check that the certificate has a private key
    if (!recipientCert.hasPrivateKey()) {
      throw new Error("Certificate must contain private key for decryption");
    }

    // Parse as ContentInfo
    const contentInfo = asn1js.fromBER(encryptedBytes.buffer as ArrayBuffer);
    if (contentInfo.offset === -1) {
      throw new Error("Failed to parse ContentInfo");
    }

    const cmsContent = new pkijs.ContentInfo({ schema: contentInfo.result });

    // Check if it's EnvelopedData
    if (cmsContent.contentType !== pkijs.ContentInfo.ENVELOPED_DATA) {
      throw new Error(`Expected EnvelopedData, got: ${cmsContent.contentType}`);
    }

    // Parse EnvelopedData
    const cmsEnvelopedData = new pkijs.EnvelopedData({
      schema: cmsContent.content,
    });

    // Get the private key from the certificate
    // For both RSA and P-256 certificates, getPrivateKeyForDecryption returns
    // the key with appropriate algorithm for decryption
    const privateKey = await recipientCert.getPrivateKeyForDecryption();

    // Find matching recipient and decrypt
    let decryptedContent: ArrayBuffer | undefined;

    // Try each recipient until we find one that works
    for (let i = 0; i < cmsEnvelopedData.recipientInfos.length; i++) {
      try {
        // Try to decrypt with this recipient
        // pkijs handles both KeyTransRecipientInfo (RSA) and KeyAgreeRecipientInfo (ECDH)
        decryptedContent = await cmsEnvelopedData.decrypt(i, {
          recipientPrivateKey: privateKey,
        });

        // If decryption succeeded, we found the right recipient
        if (decryptedContent) {
          break;
        }
      } catch {
        // This recipient didn't work, try the next one
        continue;
      }
    }

    if (!decryptedContent) {
      throw new Error("No matching recipient found or decryption failed");
    }

    // Return as Uint8Array
    return new Uint8Array(decryptedContent);
  } catch (error) {
    throw new Error(`Failed to decrypt message: ${error}`);
  }
}
