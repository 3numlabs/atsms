/**
 * Unit tests for JWT Authentication
 * Tests both RS256 (RSA) and ES256 (P-256 ECDSA) algorithms
 */

import { beforeAll, describe, expect, test } from "bun:test";
import { decodeJwt, decodeProtectedHeader } from "jose";

import {
  ATSMSEndpointCertificate,
  ATSMSP256EndpointCertificate,
} from "../lib/certificates/index.js";
import { generateJWT, getTokenExpiration } from "../lib/jwt-auth.js";

describe("JWT Authentication", () => {
  let endpointCert: ATSMSEndpointCertificate;
  const testDid = "did:plc:test123";
  const testEmailDomain = "atsms.example.com";
  const testDomain = "test.atsms.example.com";

  beforeAll(async () => {
    // Generate self-signed endpoint certificate
    endpointCert = await ATSMSEndpointCertificate.generate(
      testDid,
      testDomain,
      testEmailDomain,
      365,
    );
  });

  test("generates valid JWT with certificate", async () => {
    const privateKeyPEM = endpointCert.certificatePrivateKeyPEM!;
    const jwt = await generateJWT(
      privateKeyPEM,
      endpointCert.serialNumber,
      testDid,
    );

    expect(jwt).toBeDefined();
    expect(typeof jwt).toBe("string");
    expect(jwt.split(".")).toHaveLength(3);
  });

  test("JWT payload contains correct claims", async () => {
    const privateKeyPEM = endpointCert.certificatePrivateKeyPEM!;
    const jwt = await generateJWT(
      privateKeyPEM,
      endpointCert.serialNumber,
      testDid,
    );
    const payload = decodeJwt(jwt);

    expect(payload.iss).toBe(testDid);
    expect(payload.aud).toBe("atsms-api");
    expect(payload.sub).toBe(
      `at://${testDid}/at.atsms.x509/${endpointCert.serialNumber}`,
    );
    expect(payload.iat).toBeDefined();
    expect(payload.exp).toBeDefined();
  });

  test("JWT header contains correct algorithm and key ID", async () => {
    const privateKeyPEM = endpointCert.certificatePrivateKeyPEM!;
    const jwt = await generateJWT(
      privateKeyPEM,
      endpointCert.serialNumber,
      testDid,
    );
    const header = decodeProtectedHeader(jwt);

    expect(header.alg).toBe("RS256");
    expect(header.typ).toBe("JWT");
    expect(header.kid).toBe(endpointCert.serialNumber);
  });

  test("throws error when private key is not PKCS#8 format", async () => {
    const invalidKey =
      "-----BEGIN RSA PRIVATE KEY-----\nMIIE...\n-----END RSA PRIVATE KEY-----";

    await expect(
      generateJWT(invalidKey, endpointCert.serialNumber, testDid),
    ).rejects.toThrow("PKCS#8");
  });

  test("JWT expires in 1 hour", async () => {
    const privateKeyPEM = endpointCert.certificatePrivateKeyPEM!;
    const jwt = await generateJWT(
      privateKeyPEM,
      endpointCert.serialNumber,
      testDid,
    );
    const payload = decodeJwt(jwt);

    const iat = payload.iat as number;
    const exp = payload.exp as number;

    // Should be approximately 1 hour (3600 seconds)
    expect(exp - iat).toBe(3600);
  });

  test("getTokenExpiration returns correct ISO string", async () => {
    const privateKeyPEM = endpointCert.certificatePrivateKeyPEM!;
    const jwt = await generateJWT(
      privateKeyPEM,
      endpointCert.serialNumber,
      testDid,
    );
    const expiration = getTokenExpiration(jwt);

    expect(expiration).toBeDefined();
    expect(typeof expiration).toBe("string");
    // Should be a valid ISO date string
    const parsed = new Date(expiration);
    expect(parsed.getTime()).toBeGreaterThan(Date.now());
  });
});

describe("JWT Authentication with P-256 (ES256)", () => {
  let p256Cert: ATSMSP256EndpointCertificate;
  const testDid = "did:plc:p256test123";
  const testEmailDomain = "atsms.example.com";
  const testDomain = "p256test.atsms.example.com";

  beforeAll(async () => {
    // Generate self-signed P-256 endpoint certificate
    p256Cert = await ATSMSP256EndpointCertificate.generate(
      testDid,
      testDomain,
      testEmailDomain,
      365,
    );
  });

  test("generates valid JWT with P-256 certificate", async () => {
    const privateKeyPEM = p256Cert.certificatePrivateKeyPEM!;
    const jwt = await generateJWT(
      privateKeyPEM,
      p256Cert.serialNumber,
      testDid,
    );

    expect(jwt).toBeDefined();
    expect(typeof jwt).toBe("string");
    expect(jwt.split(".")).toHaveLength(3);
  });

  test("JWT payload contains correct claims for P-256", async () => {
    const privateKeyPEM = p256Cert.certificatePrivateKeyPEM!;
    const jwt = await generateJWT(
      privateKeyPEM,
      p256Cert.serialNumber,
      testDid,
    );
    const payload = decodeJwt(jwt);

    expect(payload.iss).toBe(testDid);
    expect(payload.aud).toBe("atsms-api");
    expect(payload.sub).toBe(
      `at://${testDid}/at.atsms.x509/${p256Cert.serialNumber}`,
    );
    expect(payload.iat).toBeDefined();
    expect(payload.exp).toBeDefined();
  });

  test("JWT header contains ES256 algorithm for P-256 key", async () => {
    const privateKeyPEM = p256Cert.certificatePrivateKeyPEM!;
    const jwt = await generateJWT(
      privateKeyPEM,
      p256Cert.serialNumber,
      testDid,
    );
    const header = decodeProtectedHeader(jwt);

    expect(header.alg).toBe("ES256");
    expect(header.typ).toBe("JWT");
    expect(header.kid).toBe(p256Cert.serialNumber);
  });

  test("JWT expires in 1 hour for P-256", async () => {
    const privateKeyPEM = p256Cert.certificatePrivateKeyPEM!;
    const jwt = await generateJWT(
      privateKeyPEM,
      p256Cert.serialNumber,
      testDid,
    );
    const payload = decodeJwt(jwt);

    const iat = payload.iat as number;
    const exp = payload.exp as number;

    // Should be approximately 1 hour (3600 seconds)
    expect(exp - iat).toBe(3600);
  });

  test("getTokenExpiration returns correct ISO string for P-256", async () => {
    const privateKeyPEM = p256Cert.certificatePrivateKeyPEM!;
    const jwt = await generateJWT(
      privateKeyPEM,
      p256Cert.serialNumber,
      testDid,
    );
    const expiration = getTokenExpiration(jwt);

    expect(expiration).toBeDefined();
    expect(typeof expiration).toBe("string");
    const parsed = new Date(expiration);
    expect(parsed.getTime()).toBeGreaterThan(Date.now());
  });
});
