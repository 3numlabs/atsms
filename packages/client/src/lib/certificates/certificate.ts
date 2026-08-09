/**
 * Base Certificate class for X.509 certificate management
 * Extends X509Certificate from @peculiar/x509 to add private key management
 */

import { X509Certificate } from "@peculiar/x509";
import * as asn1js from "asn1js";
import * as pkijs from "pkijs";

import { cryptoProvider } from "../crypto-provider";
import type { ATSMSCertificateType } from "../types";

// Initialize PKI.js with crypto provider
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
 * Abstract base class for X.509 certificates
 * Extends X509Certificate and adds private key management
 */
export abstract class ATSMSCertificate extends X509Certificate {
  protected _privateKey?: CryptoKey;
  protected privateKeyPEM?: string;

  /**
   * Get the private key for this certificate
   * @throws Error if no private key has been set
   */
  public get privateKeyValue(): CryptoKey {
    if (!this._privateKey) {
      throw new Error(
        "No private key available for this certificate. Load the certificate with its private key.",
      );
    }
    return this._privateKey;
  }

  /**
   * Protected constructor - use factory methods instead
   */
  protected constructor(
    rawData: ArrayBuffer | Uint8Array | string,
    privateKey?: CryptoKey,
    privateKeyPEM?: string, // PEM kept alongside CryptoKey for storage/export convenience
  ) {
    super(rawData as any);
    this._privateKey = privateKey;
    this.privateKeyPEM = privateKeyPEM;
  }

  /**
   * Create a Certificate from DER-encoded bytes (public certificate only)
   * This is a static factory method that must be implemented by subclasses
   */
  static fromDER(_derBytes: Uint8Array): ATSMSCertificate {
    throw new Error("fromDER must be implemented by subclasses");
  }

  /**
   * Parse a certificate from PEM format and return DER bytes
   */
  protected static pemToDER(certPEM: string): Uint8Array {
    // Remove PEM headers and decode base64
    const base64 = certPEM
      .replace(/-----BEGIN CERTIFICATE-----/g, "")
      .replace(/-----END CERTIFICATE-----/g, "")
      .replace(/\s/g, "");

    return Uint8Array.from(atob(base64), (c) => c.charCodeAt(0));
  }

  /**
   * Import a private key from PEM format
   */
  protected static async importPrivateKeyPEM(
    privateKeyPEM: string,
    algorithm: any,
  ): Promise<CryptoKey> {
    const base64 = privateKeyPEM
      .replace(/-----BEGIN .*-----/g, "")
      .replace(/-----END .*-----/g, "")
      .replace(/\s/g, "");

    const der = Uint8Array.from(atob(base64), (c) => c.charCodeAt(0));

    return await cryptoProvider.subtle.importKey(
      "pkcs8",
      der,
      algorithm,
      true,
      ["sign"],
    );
  }

  /**
   * Verify that a private key matches the certificate's public key
   */
  protected async verifyPrivateKeyMatchesCert(
    privateKey: CryptoKey,
  ): Promise<boolean> {
    try {
      // For RSA keys (endpoint certificates), do normal verification
      const privateKeyData = await cryptoProvider.subtle.exportKey(
        "jwk",
        privateKey,
      );
      const certPublicKey = await this.publicKey.export(cryptoProvider as any);
      const certPublicKeyData = await cryptoProvider.subtle.exportKey(
        "jwk",
        certPublicKey,
      );

      if (privateKeyData.kty === "RSA" && certPublicKeyData.kty === "RSA") {
        return (
          privateKeyData.n === certPublicKeyData.n &&
          privateKeyData.e === certPublicKeyData.e
        );
      }

      return false;
    } catch (error) {
      console.error("Error verifying private key matches certificate:", error);
      return false;
    }
  }

  /**
   * Get the common name (CN) from the subject
   */
  get commonName(): string {
    const cnAttr = this.subject
      .split(",")
      .find((part) => part.trim().startsWith("CN="));
    return cnAttr ? cnAttr.split("=")[1].trim() : "";
  }

  /**
   * Get the domain (alias for commonName in ATSMS context)
   */
  get domain(): string {
    return this.commonName;
  }

  /**
   * Get the raw PEM certificate (convenience method)
   */
  get certificatePEM(): string {
    return this.toString("pem");
  }

  /**
   * Get the public key
   */
  async getPublicKey(): Promise<CryptoKey> {
    return this.publicKey.export(cryptoProvider as any);
  }

  /**
   * Get the SHA-256 fingerprint
   */
  async getFingerprint(): Promise<string> {
    const hash = await cryptoProvider.subtle.digest("SHA-256", this.rawData);
    const hashArray = new Uint8Array(hash);
    return Array.from(hashArray)
      .map((b) => b.toString(16).padStart(2, "0"))
      .join(":")
      .toUpperCase();
  }

  private _deviceFingerprint?: string;

  /**
   * The DEVICE fingerprint (identity-devices §2): the full 32-byte SHA-256 of
   * the raw uncompressed P-256 public-key point (`0x04‖X‖Y`, the
   * subjectPublicKey value), lowercase hex — stable across cert re-issuance
   * for the same key. This is the `at.atsms.x509` / `at.atsms.prekey` record
   * key and the per-device inbox key — distinct from `getFingerprint()`,
   * which hashes the whole certificate for display.
   */
  async getDeviceFingerprint(): Promise<string> {
    if (this._deviceFingerprint === undefined) {
      const key = await this.getPublicKey();
      const raw = await cryptoProvider.subtle.exportKey("raw", key);
      const digest = new Uint8Array(await cryptoProvider.subtle.digest("SHA-256", raw));
      this._deviceFingerprint = Array.from(digest)
        .map((b) => b.toString(16).padStart(2, "0"))
        .join("");
    }
    return this._deviceFingerprint;
  }

  /**
   * Get the DID from the Subject Alternative Name extension
   *
   * The DID is extracted from the URI field in the SAN extension.
   * Expected format: at://[did]/at.atsms.x509/[device-fingerprint]
   */
  get did(): string | undefined {
    const uri = this.atUri;
    if (uri === undefined) return undefined;
    const pathStart = uri.indexOf("/at.atsms.x509/");
    const did = uri.slice(5, pathStart);
    return did.startsWith("did:") ? did : undefined;
  }

  /**
   * The full AT URI from the SAN extension —
   * `at://[did]/at.atsms.x509/[device-fingerprint]` (the record path).
   */
  get atUri(): string | undefined {
    try {
      const sanExt = this.extensions.find(
        (ext) => ext.type === "2.5.29.17", // subjectAltName OID
      );

      if (!sanExt || !sanExt.value) return undefined;

      // Parse the SAN extension value to extract URLs
      const der = new Uint8Array(sanExt.value);
      const asn1 = asn1js.fromBER(der.buffer);

      if (asn1.offset === -1) return undefined;

      // Look for URLs (tag 6) in the GeneralNames sequence
      const sequence = asn1.result as any;
      if (sequence.valueBlock && sequence.valueBlock.value) {
        for (const item of sequence.valueBlock.value) {
          // URL has tag 6
          if (item.idBlock && item.idBlock.tagNumber === 6) {
            const valueHex = item.valueBlock.valueHex;
            const valueStr = new TextDecoder().decode(new Uint8Array(valueHex));

            // AT URI format: at://[did]/at.atsms.x509/[fingerprint]
            if (valueStr.startsWith("at://") && valueStr.includes("/at.atsms.x509/")) {
              return valueStr;
            }
          }
        }
      }
    } catch {
      // Failed to parse SAN extension
    }

    return undefined;
  }

  /**
   * Get the email address from the Subject Alternative Name extension
   */
  get email(): string | undefined {
    try {
      const sanExt = this.extensions.find(
        (ext) => ext.type === "2.5.29.17", // subjectAltName OID
      );

      if (!sanExt || !sanExt.value) return undefined;

      // Parse the SAN extension value to extract email addresses
      const der = new Uint8Array(sanExt.value);
      const asn1 = asn1js.fromBER(der.buffer);

      if (asn1.offset === -1) return undefined;

      // Look for RFC822 names (email, tag 1) in the GeneralNames sequence
      const sequence = asn1.result as any;
      if (sequence.valueBlock && sequence.valueBlock.value) {
        for (const item of sequence.valueBlock.value) {
          // RFC822 name (email) has tag 1
          if (item.idBlock && item.idBlock.tagNumber === 1) {
            const valueHex = item.valueBlock.valueHex;
            const valueStr = new TextDecoder().decode(new Uint8Array(valueHex));
            // Basic email validation
            if (valueStr.includes("@")) {
              return valueStr;
            }
          }
        }
      }
    } catch {
      // Failed to parse SAN extension
    }

    return undefined;
  }

  /**
   * Getter for the private key in PEM format
   * @returns The private key PEM string if available, undefined otherwise
   */
  get certificatePrivateKeyPEM(): string | undefined {
    return this.privateKeyPEM;
  }

  /**
   * Check if the certificate has an associated private key
   */
  hasPrivateKey(): boolean {
    return this._privateKey !== undefined;
  }

  /**
   * Check if the certificate is expired
   */
  isExpired(): boolean {
    const now = new Date();
    return now > this.notAfter;
  }

  /**
   * Check if the certificate is not yet valid
   */
  isNotYetValid(): boolean {
    const now = new Date();
    return now < this.notBefore;
  }

  /**
   * Check if the certificate is currently valid
   */
  isValid(): boolean {
    return !this.isExpired() && !this.isNotYetValid();
  }

  /**
   * Verify the certificate signature against an issuer
   */
  async verifyCertificate(issuerCert?: ATSMSCertificate): Promise<boolean> {
    try {
      if (!issuerCert) {
        // Self-signed verification
        return await this.verify({
          publicKey: await this.getPublicKey(),
        });
      } else {
        // Verify against issuer
        return await this.verify({
          publicKey: await issuerCert.getPublicKey(),
        });
      }
    } catch {
      return false;
    }
  }

  /**
   * Convert ArrayBuffer to PEM format
   */
  protected static arrayBufferToPEM(
    buffer: ArrayBuffer,
    label: string,
  ): string {
    const bytes = new Uint8Array(buffer);
    const binary = Array.from(bytes, (byte) => String.fromCharCode(byte)).join(
      "",
    );
    const base64 = btoa(binary);
    const lines = base64.match(/.{1,64}/g) || [];
    return `-----BEGIN ${label}-----\n${lines.join("\n")}\n-----END ${label}-----\n`;
  }

  /**
   * Get the certificate type
   */
  abstract getType(): ATSMSCertificateType;

  /**
   * Check if this is a self-signed certificate (simplified version)
   */
  isSimpleSelfSigned(): boolean {
    return this.subject === this.issuer;
  }

  /**
   * Check if this is a CA certificate
   * Note: In the current architecture, all endpoint certificates are self-signed
   * but they are NOT CA certificates (BasicConstraints: CA=false)
   */
  get isCA(): boolean {
    // Self-signed endpoint certificates are NOT CA certificates
    // This always returns false for endpoint certificates
    return false;
  }

  /**
   * Export the private key using standard Web Crypto API
   */
  async exportPrivateKey(
    format: "pkcs8" | "raw" = "pkcs8",
  ): Promise<ArrayBuffer> {
    if (!this._privateKey) {
      throw new Error("No private key available to export");
    }

    return (await cryptoProvider.subtle.exportKey(
      format as any,
      this._privateKey,
    )) as Promise<ArrayBuffer>;
  }
}
