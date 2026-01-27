/**
 * Endpoint Certificate class for self-signed RSA certificates
 */

import {
  BasicConstraintsExtension,
  ExtendedKeyUsageExtension,
  KeyUsageFlags,
  KeyUsagesExtension,
  SubjectAlternativeNameExtension,
  X509CertificateGenerator,
} from "@peculiar/x509";

import { cryptoProvider } from "../crypto-provider";
import type { ATSMSCertificateType } from "../types";
import { ATSMSCertificate } from "./certificate";
import { computeATSMSEmail, generateSerialNumber } from "./san-utils";

/**
 * Endpoint Certificate class - self-signed RSA certificates
 */
export class ATSMSEndpointCertificate extends ATSMSCertificate {
  /**
   * Generate a new self-signed endpoint certificate
   * Uses RSA-2048 for key generation and RSA-PSS-SHA256 for signing
   *
   * SAN (Subject Alternative Name) format:
   * - DNS: domain (e.g., 'alice.bsky.social')
   * - URI: at://[did]/at.atsms.x509/[serial-hex] (AT Protocol URI)
   * - Email: Deterministic based on DID method:
   *   - PLC: plc.[plc-id]@[emailDomain]
   *   - WEB: web.[base64url(web-part)]@[emailDomain]
   *
   * @param did - Decentralized identifier (e.g., 'did:plc:xyz123')
   * @param domain - Domain name / handle (e.g., 'alice.bsky.social')
   * @param emailDomain - Email provider domain for deterministic email (e.g., 'atsms.email')
   * @param validityDays - Certificate validity period (default: 10 years)
   */
  static async generate(
    did: string,
    domain: string,
    emailDomain: string,
    validityDays = 3652, // Default to ten years
  ): Promise<ATSMSEndpointCertificate> {
    // Validate parameters to prevent common errors
    if (
      typeof validityDays !== "number" ||
      isNaN(validityDays) ||
      validityDays <= 0
    ) {
      throw new Error(
        `Invalid validityDays: must be a positive number, got ${typeof validityDays}: ${validityDays}`,
      );
    }

    // Validate domain is a string and not empty
    if (typeof domain !== "string" || !domain.trim()) {
      throw new Error(
        `Invalid domain: must be a non-empty string, got ${typeof domain}: ${domain}`,
      );
    }

    // Validate DID format
    if (typeof did !== "string" || !did.startsWith("did:")) {
      throw new Error(`Invalid DID: must start with 'did:', got: ${did}`);
    }

    // Validate emailDomain is a string and not empty
    if (typeof emailDomain !== "string" || !emailDomain.trim()) {
      throw new Error(
        `Invalid emailDomain: must be a non-empty string, got ${typeof emailDomain}: ${emailDomain}`,
      );
    }

    // Generate serial number first (needed for SAN URI)
    const serialNumber = await generateSerialNumber();

    // Compute deterministic email from DID and email domain
    const sanEmail = computeATSMSEmail(did, emailDomain);

    // Generate RSA key pair for endpoint certificate (2048 bit)
    const rsaAlg = {
      name: "RSA-PSS",
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: "SHA-256",
    };

    const rsaKeys = (await cryptoProvider.subtle.generateKey(rsaAlg, true, [
      "sign",
      "verify",
    ])) as CryptoKeyPair;

    // Create self-signed certificate with RSA-PSS
    const cert = await X509CertificateGenerator.createSelfSigned(
      {
        serialNumber: serialNumber.hex,
        name: `CN=${did}`,
        notBefore: new Date(),
        notAfter: new Date(Date.now() + validityDays * 24 * 60 * 60 * 1000),
        signingAlgorithm: {
          name: "RSA-PSS",
          hash: "SHA-256",
          saltLength: 32,
        } as RsaPssParams,
        keys: rsaKeys,
        extensions: [
          new BasicConstraintsExtension(false, undefined, true), // CA=false
          new KeyUsagesExtension(
            KeyUsageFlags.digitalSignature |
              KeyUsageFlags.keyEncipherment |
              KeyUsageFlags.dataEncipherment,
            true,
          ),
          new ExtendedKeyUsageExtension(
            ["1.3.6.1.5.5.7.3.1", "1.3.6.1.5.5.7.3.2"],
            false,
          ), // serverAuth, clientAuth
          new SubjectAlternativeNameExtension([
            { type: "dns", value: domain },
            { type: "url", value: `at://${did}/at.atsms.x509/${serialNumber.hex}` },
            { type: "email", value: sanEmail },
          ]),
        ],
      },
      cryptoProvider as any,
    );

    // Export private key to PEM
    const privateKeyBuffer = await cryptoProvider.subtle.exportKey(
      "pkcs8",
      rsaKeys.privateKey,
    );
    const privateKeyPEM = ATSMSCertificate.arrayBufferToPEM(
      privateKeyBuffer,
      "PRIVATE KEY",
    );

    // Create endpoint certificate instance
    const endpointCert = new ATSMSEndpointCertificate(
      cert.rawData,
      rsaKeys.privateKey,
      privateKeyPEM,
    );

    return endpointCert;
  }

  /**
   * Create an ATSMSEndpointCertificate from DER-encoded bytes (public certificate only)
   */
  static fromDER(derBytes: Uint8Array): ATSMSEndpointCertificate {
    return new ATSMSEndpointCertificate(derBytes, undefined, undefined);
  }

  /**
   * Create an ATSMSEndpointCertificate from PEM (certificate only, no private key)
   */
  static fromPEM(certPEM: string): ATSMSEndpointCertificate {
    const derBytes = ATSMSCertificate.pemToDER(certPEM);
    return new ATSMSEndpointCertificate(derBytes, undefined, undefined);
  }

  /**
   * Create an ATSMSEndpointCertificate from PEM with private key
   */
  static async fromPEMWithKey(
    certPEM: string,
    privateKeyPEM: string,
  ): Promise<ATSMSEndpointCertificate> {
    const derBytes = ATSMSCertificate.pemToDER(certPEM);

    // Client certificates always use RSA
    const alg = {
      name: "RSASSA-PKCS1-v1_5",
      hash: "SHA-256",
    };
    const privateKey = await ATSMSCertificate.importPrivateKeyPEM(
      privateKeyPEM,
      alg,
    );

    // Create certificate instance and verify the private key matches
    const cert = new ATSMSEndpointCertificate(
      derBytes,
      privateKey,
      privateKeyPEM,
    );
    const matches = await cert.verifyPrivateKeyMatchesCert(privateKey);
    if (!matches) {
      throw new Error("Private key does not match the certificate public key");
    }

    return cert;
  }

  getType(): ATSMSCertificateType {
    return "endpoint";
  }

  /**
   * Verify that this certificate is self-signed
   * Returns true if the certificate's signature can be verified with its own public key
   */
  async verifySelfSignature(): Promise<boolean> {
    return this.verifyCertificate();
  }

  /**
   * Get the RSA public key for encryption
   */
  async getPublicKeyForEncryption(): Promise<CryptoKey> {
    // Import the public key specifically for RSA-OAEP encryption
    const publicKey = await this.getPublicKey();

    // Export and re-import with RSA-OAEP algorithm
    const exported = await cryptoProvider.subtle.exportKey("spki", publicKey);

    return cryptoProvider.subtle.importKey(
      "spki",
      exported,
      {
        name: "RSA-OAEP",
        hash: "SHA-256",
      },
      true,
      ["encrypt"],
    );
  }

  /**
   * Get the RSA private key for decryption
   */
  async getPrivateKeyForDecryption(): Promise<CryptoKey> {
    if (!this._privateKey) {
      throw new Error("Private key not available for decryption");
    }

    // Export and re-import with RSA-OAEP algorithm
    const exported = await cryptoProvider.subtle.exportKey(
      "pkcs8",
      this._privateKey,
    );

    return cryptoProvider.subtle.importKey(
      "pkcs8",
      exported,
      {
        name: "RSA-OAEP",
        hash: "SHA-256",
      },
      true,
      ["decrypt"],
    );
  }
}
