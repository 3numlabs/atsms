/**
 * Unit tests for JWT Authentication
 */

import { beforeAll, describe, expect, test } from 'bun:test'
import { decodeJwt, decodeProtectedHeader } from 'jose'

import {
  ATSMSEndpointCertificate,
  ATSMSRootCertificate,
} from '../lib/certificates/index.js'
import { generateJWT, getTokenExpiration } from '../lib/jwt-auth.js'

describe('JWT Authentication', () => {
  let endpointCert: ATSMSEndpointCertificate
  const testDid = 'did:plc:test123'
  const testEmail = 'test@atsms.example.com'
  const testDomain = 'atsms.example.com'

  beforeAll(async () => {
    // Generate test certificates
    const rootCert = await ATSMSRootCertificate.generate(testDid, testDomain)
    endpointCert = await rootCert.generateSignedEndpointCertificate(testEmail, 365)
  })

  test('generates valid JWT with certificate', async () => {
    const privateKeyPEM = endpointCert.certificatePrivateKeyPEM!
    const jwt = await generateJWT(privateKeyPEM, endpointCert.serialNumber, testDid)

    expect(jwt).toBeDefined()
    expect(typeof jwt).toBe('string')
    expect(jwt.split('.')).toHaveLength(3)
  })

  test('JWT payload contains correct claims', async () => {
    const privateKeyPEM = endpointCert.certificatePrivateKeyPEM!
    const jwt = await generateJWT(privateKeyPEM, endpointCert.serialNumber, testDid)
    const payload = decodeJwt(jwt)

    expect(payload.iss).toBe(testDid)
    expect(payload.aud).toBe('atsms-api')
    expect(payload.sub).toBe(`at://${testDid}/at.atsms.x509/${endpointCert.serialNumber}`)
    expect(payload.iat).toBeDefined()
    expect(payload.exp).toBeDefined()
  })

  test('JWT header contains correct algorithm and key ID', async () => {
    const privateKeyPEM = endpointCert.certificatePrivateKeyPEM!
    const jwt = await generateJWT(privateKeyPEM, endpointCert.serialNumber, testDid)
    const header = decodeProtectedHeader(jwt)

    expect(header.alg).toBe('RS256')
    expect(header.typ).toBe('JWT')
    expect(header.kid).toBe(endpointCert.serialNumber)
  })

  test('throws error when private key is not PKCS#8 format', async () => {
    const invalidKey = '-----BEGIN RSA PRIVATE KEY-----\nMIIE...\n-----END RSA PRIVATE KEY-----'

    await expect(
      generateJWT(invalidKey, endpointCert.serialNumber, testDid)
    ).rejects.toThrow('PKCS#8')
  })

  test('JWT expires in 1 hour', async () => {
    const privateKeyPEM = endpointCert.certificatePrivateKeyPEM!
    const jwt = await generateJWT(privateKeyPEM, endpointCert.serialNumber, testDid)
    const payload = decodeJwt(jwt)

    const iat = payload.iat as number
    const exp = payload.exp as number

    // Should be approximately 1 hour (3600 seconds)
    expect(exp - iat).toBe(3600)
  })

  test('getTokenExpiration returns correct ISO string', async () => {
    const privateKeyPEM = endpointCert.certificatePrivateKeyPEM!
    const jwt = await generateJWT(privateKeyPEM, endpointCert.serialNumber, testDid)
    const expiration = getTokenExpiration(jwt)

    expect(expiration).toBeDefined()
    expect(typeof expiration).toBe('string')
    // Should be a valid ISO date string
    const parsed = new Date(expiration)
    expect(parsed.getTime()).toBeGreaterThan(Date.now())
  })
})
