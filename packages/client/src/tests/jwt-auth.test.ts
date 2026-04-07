/**
 * Unit tests for JWT Authentication (ES256 / P-256 ECDSA)
 */

import { beforeAll, describe, expect, test } from "bun:test";
import { decodeJwt, decodeProtectedHeader } from "jose";

import { ATSMSEndpointCertificate } from "../lib/certificates/index.js";
import { generateJWT, getTokenExpiration } from "../lib/jwt-auth.js";

describe("JWT Authentication (ES256)", () => {
  let endpointCert: ATSMSEndpointCertificate;
  const testDid = "did:plc:test123";
  const testEmailDomain = "atsms.example.com";
  const testDomain = "test.atsms.example.com";

  beforeAll(async () => {
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

  test("JWT header contains ES256 algorithm and key ID", async () => {
    const privateKeyPEM = endpointCert.certificatePrivateKeyPEM!;
    const jwt = await generateJWT(
      privateKeyPEM,
      endpointCert.serialNumber,
      testDid,
    );
    const header = decodeProtectedHeader(jwt);

    expect(header.alg).toBe("ES256");
    expect(header.typ).toBe("JWT");
    expect(header.kid).toBe(endpointCert.serialNumber);
  });

  test("throws error when private key is not PKCS#8 format", async () => {
    const invalidKey =
      "-----BEGIN EC PRIVATE KEY-----\nMIIE...\n-----END EC PRIVATE KEY-----";

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
    const parsed = new Date(expiration);
    expect(parsed.getTime()).toBeGreaterThan(Date.now());
  });
});
