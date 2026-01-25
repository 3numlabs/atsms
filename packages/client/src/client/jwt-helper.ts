/**
 * JWT Helper utilities for file I/O operations
 * Handles reading/writing JWT tokens and certificates from disk
 */

import * as fs from "fs";
import * as path from "path";

import { ATSMSEndpointCertificate } from "../lib/certificates/index.js";
import { generateJWT, getTokenExpiration } from "../lib/jwt-auth.js";

/**
 * JWT cache structure for disk storage
 */
export interface JWTCache {
  token: string;
  expiresAt: string;
}

/**
 * Check if a cached token is still valid
 * @param cache - The cached JWT data
 * @returns The token if valid, null otherwise
 */
export function getValidCachedToken(cache: JWTCache): string | null {
  try {
    // Check if token has expired (with 5 minute buffer)
    const expiresAt = new Date(cache.expiresAt);
    const now = new Date();
    const buffer = 5 * 60 * 1000; // 5 minutes in milliseconds

    if (expiresAt.getTime() - buffer > now.getTime()) {
      return cache.token;
    }

    // Token is expired or about to expire
    return null;
  } catch {
    // If there's any error, return null
    return null;
  }
}

export class JWTHelper {
  private certsDir: string;
  private jwtCachePath: string;

  constructor(certsDir: string) {
    this.certsDir = certsDir;
    // Standard name for JWT cache file
    this.jwtCachePath = path.join(certsDir, "jwt-token.json");
  }

  /**
   * Get a valid JWT token, either from cache or by generating a new one
   */
  async getJWT(did: string): Promise<string> {
    // Get the endpoint certificate serial number
    const endpointCertPath = path.join(this.certsDir, "endpoint.pem");
    const endpointCertPEM = fs.readFileSync(endpointCertPath, "utf8");
    const endpointCert = ATSMSEndpointCertificate.fromPEM(endpointCertPEM);
    const endpointCertSerialNumber = endpointCert.serialNumber;

    // Check if we have a cached token that's still valid
    const cachedToken = this.getCachedToken();
    if (cachedToken) {
      return cachedToken;
    }

    // Generate a new token
    const newToken = await this.generateNewJWT(did, endpointCertSerialNumber);

    // Cache the token
    this.cacheToken(newToken);

    return newToken;
  }

  /**
   * Generate a new JWT token by reading the private key from disk
   */
  private async generateNewJWT(
    did: string,
    endpointCertSerialNumber: string,
  ): Promise<string> {
    const endpointKeyPath = path.join(this.certsDir, "endpoint-key.pem");

    if (!fs.existsSync(endpointKeyPath)) {
      throw new Error("Endpoint private key not found");
    }

    const privateKeyPEM = fs.readFileSync(endpointKeyPath, "utf8");

    return generateJWT(privateKeyPEM, endpointCertSerialNumber, did);
  }

  /**
   * Get cached token if it exists and is still valid
   */
  private getCachedToken(): string | null {
    try {
      if (!fs.existsSync(this.jwtCachePath)) {
        return null;
      }

      const cacheContent = fs.readFileSync(this.jwtCachePath, "utf8");
      const cache: JWTCache = JSON.parse(cacheContent);

      return getValidCachedToken(cache);
    } catch {
      // If there's any error reading cache, return null
      return null;
    }
  }

  /**
   * Cache the JWT token to disk
   */
  private cacheToken(token: string): void {
    try {
      const cache = {
        token,
        expiresAt: getTokenExpiration(token),
      };
      fs.writeFileSync(this.jwtCachePath, JSON.stringify(cache, null, 2));
    } catch (error) {
      // If caching fails, continue anyway
      console.warn("Failed to cache JWT token:", error);
    }
  }

  /**
   * Clear the cached token
   */
  clearCache(): void {
    try {
      if (fs.existsSync(this.jwtCachePath)) {
        fs.unlinkSync(this.jwtCachePath);
      }
    } catch (error) {
      console.warn("Failed to clear JWT cache:", error);
    }
  }

  /**
   * Get the certificate serial number from the endpoint certificate file
   */
  getCertificateSerialNumber(): string {
    const endpointCertPath = path.join(this.certsDir, "endpoint.pem");
    const certPEM = fs.readFileSync(endpointCertPath, "utf8");
    const endpointCert = ATSMSEndpointCertificate.fromPEM(certPEM);
    return endpointCert.serialNumber;
  }
}
