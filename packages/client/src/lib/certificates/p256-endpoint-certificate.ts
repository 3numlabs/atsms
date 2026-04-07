/**
 * Endpoint Certificate class for self-signed P-256 ECDSA certificates
 * Uses P-256 (prime256v1/secp256r1) for signing (ECDSA) and key agreement (ECDH)
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
 * Endpoint Certificate class - self-signed P-256 ECDSA certificates
 * Uses P-256 for both signing (ECDSA) and key agreement (ECDH)
 */
export class ATSMSEndpointCertificate extends ATSMSCertificate {
  /**
   * Generate a new self-signed P-256 endpoint certificate
   * Uses ECDSA with P-256 curve for signing
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

    // Generate P-256 key pair for endpoint certificate
    const ecAlg = {
      name: "ECDSA",
      namedCurve: "P-256",
    };

    const ecKeys = (await cryptoProvider.subtle.generateKey(ecAlg, true, [
      "sign",
      "verify",
    ])) as CryptoKeyPair;

    // Create self-signed certificate with ECDSA
    const cert = await X509CertificateGenerator.createSelfSigned(
      {
        serialNumber: serialNumber.hex,
        name: `CN=${did}`,
        notBefore: new Date(),
        notAfter: new Date(Date.now() + validityDays * 24 * 60 * 60 * 1000),
        signingAlgorithm: {
          name: "ECDSA",
          hash: "SHA-256",
        } as EcdsaParams,
        keys: ecKeys,
        extensions: [
          new BasicConstraintsExtension(false, undefined, true), // CA=false
          new KeyUsagesExtension(
            KeyUsageFlags.digitalSignature | KeyUsageFlags.keyAgreement, // keyAgreement for ECDH
            true,
          ),
          new ExtendedKeyUsageExtension(
            [
              "1.3.6.1.5.5.7.3.1", // serverAuth (future TLS capability)
              "1.3.6.1.5.5.7.3.2", // clientAuth (future TLS capability)
              "1.3.6.1.5.5.7.3.4", // emailProtection (S/MIME)
            ],
            false,
          ),
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
      ecKeys.privateKey,
    );
    const privateKeyPEM = ATSMSCertificate.arrayBufferToPEM(
      privateKeyBuffer,
      "PRIVATE KEY",
    );

    // Create P-256 endpoint certificate instance
    const endpointCert = new ATSMSEndpointCertificate(
      cert.rawData,
      ecKeys.privateKey,
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

    // P-256 certificates use ECDSA
    const alg = {
      name: "ECDSA",
      namedCurve: "P-256",
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
   * Get the algorithm type for this certificate
   */
  getAlgorithm(): "P256" {
    return "P256";
  }

  /**
   * Verify that this certificate is self-signed
   * Returns true if the certificate's signature can be verified with its own public key
   */
  async verifySelfSignature(): Promise<boolean> {
    return this.verifyCertificate();
  }

  /**
   * Get the P-256 public key for ECDH key agreement (encryption)
   * The same key is used for both signing and key agreement
   */
  async getPublicKeyForEncryption(): Promise<CryptoKey> {
    // Import the public key specifically for ECDH key agreement
    const publicKey = await this.getPublicKey();

    // Export and re-import with ECDH algorithm
    const exported = await cryptoProvider.subtle.exportKey("spki", publicKey);

    return cryptoProvider.subtle.importKey(
      "spki",
      exported,
      {
        name: "ECDH",
        namedCurve: "P-256",
      },
      true,
      [], // deriveBits will be used on the private key side
    );
  }

  /**
   * Get the P-256 private key for ECDH key agreement (decryption)
   */
  async getPrivateKeyForDecryption(): Promise<CryptoKey> {
    if (!this._privateKey) {
      throw new Error("Private key not available for decryption");
    }

    // Export and re-import with ECDH algorithm
    const exported = await cryptoProvider.subtle.exportKey(
      "pkcs8",
      this._privateKey,
    );

    return cryptoProvider.subtle.importKey(
      "pkcs8",
      exported,
      {
        name: "ECDH",
        namedCurve: "P-256",
      },
      true,
      ["deriveBits", "deriveKey"],
    );
  }

  /**
   * Verify that a private key matches the certificate's public key
   * Override for EC keys
   */
  protected async verifyPrivateKeyMatchesCert(
    privateKey: CryptoKey,
  ): Promise<boolean> {
    try {
      const privateKeyData = await cryptoProvider.subtle.exportKey(
        "jwk",
        privateKey,
      );
      const certPublicKey = await this.publicKey.export(cryptoProvider as any);
      const certPublicKeyData = await cryptoProvider.subtle.exportKey(
        "jwk",
        certPublicKey,
      );

      if (privateKeyData.kty === "EC" && certPublicKeyData.kty === "EC") {
        // For EC keys, compare x and y coordinates
        return (
          privateKeyData.x === certPublicKeyData.x &&
          privateKeyData.y === certPublicKeyData.y &&
          privateKeyData.crv === certPublicKeyData.crv
        );
      }

      return false;
    } catch (error) {
      console.error("Error verifying private key matches certificate:", error);
      return false;
    }
  }
}
