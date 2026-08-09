/**
 * CMS Envelope encryption/decryption using PKI.js and Web Crypto API
 * Uses ECDH (KeyAgreeRecipientInfo) with P-256 certificates
 */

import * as asn1js from "asn1js";
import * as pkijs from "pkijs";

import { ATSMSEndpointCertificate } from "./certificates/index";
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
 * Uses ECDH (KeyAgreeRecipientInfo) with P-256 certificates
 *
 * @param signedBytes - Binary data to encrypt
 * @param recipientCerts - Array of recipient P-256 certificates
 * @returns Encrypted content as binary data
 */
export async function encryptMessageOAEP(
  signedBytes: Uint8Array,
  recipientCerts: ATSMSEndpointCertificate[],
): Promise<Uint8Array> {
  // Validate that we have recipients with certificates
  if (!recipientCerts || recipientCerts.length === 0) {
    throw new Error(
      "Cannot encrypt message: Recipient has no ATSMS certificates. " +
        "The recipient must set up their certificates before they can receive encrypted messages.",
    );
  }

  try {
    // Create EnvelopedData
    const envelopedData = new pkijs.EnvelopedData();

    // Add recipients using KeyAgreeRecipientInfo (ECDH)
    for (const recipientCert of recipientCerts) {
      const cert = pkijs.Certificate.fromBER(recipientCert.rawData);

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
 * Uses ECDH (KeyAgreeRecipientInfo) with P-256 certificates
 *
 * @param encryptedBytes - Binary encrypted data
 * @param recipientCert - P-256 certificate containing the private key
 * @returns Decrypted content as binary data
 */
export async function decryptMessageOAEP(
  encryptedBytes: Uint8Array,
  recipientCert: ATSMSEndpointCertificate,
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

    // Get the ECDH private key for decryption
    const privateKey = await recipientCert.getPrivateKeyForDecryption();

    // Find matching recipient and decrypt
    let decryptedContent: ArrayBuffer | undefined;

    // Try each recipient until we find one that works
    for (let i = 0; i < cmsEnvelopedData.recipientInfos.length; i++) {
      try {
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
