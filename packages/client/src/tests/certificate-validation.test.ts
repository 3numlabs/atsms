/**
 * Tests for validating that generated certificates are valid X.509 certificates
 */

import {afterAll, beforeAll, describe, expect, test} from 'bun:test'
import {exec} from 'child_process'
import {existsSync, mkdirSync, readFileSync, rmSync,writeFileSync} from 'fs'
import path from 'path'
import {promisify} from 'util'

import { generateTestRootCertificate } from './test-certificates.js'

const execAsync = promisify(exec)

describe('Certificate Validation', () => {
  let testDir: string
  let testDID: string
  let _testHandle: string
  let rootCertPath: string
  let rootKeyPath: string

  beforeAll(async () => {
    testDir = path.join(process.cwd(), 'test-cert-validation')
    testDID = 'did:plc:test123456789'
    _testHandle = 'test.example.com'

    // Create test directory
    if (existsSync(testDir)) {
      rmSync(testDir, {recursive: true, force: true})
    }
    mkdirSync(testDir, {recursive: true})

    rootCertPath = path.join(testDir, 'root-cert.pem')
    rootKeyPath = path.join(testDir, 'root-key.pem')

    // Generate a test certificate
    const result = await generateTestRootCertificate(testDID, 'acme.xyz')
    writeFileSync(rootCertPath, result.cert, 'utf8')
    writeFileSync(rootKeyPath, result.privateKey, 'utf8')
  })

  afterAll(() => {
    // Cleanup test directory
    if (existsSync(testDir)) {
      rmSync(testDir, {recursive: true, force: true})
    }
  })

  test('should generate a valid X.509 certificate that OpenSSL can parse', async () => {
    // Verify files exist
    expect(existsSync(rootCertPath)).toBe(true)
    expect(existsSync(rootKeyPath)).toBe(true)

    // Verify PEM format
    const certPEM = readFileSync(rootCertPath, 'utf8')
    expect(certPEM).toContain('-----BEGIN CERTIFICATE-----')
    expect(certPEM).toContain('-----END CERTIFICATE-----')

    try {
      // Use OpenSSL to verify the certificate is valid
      const {stdout} = await execAsync(
        `openssl x509 -in ${rootCertPath} -noout -text`,
      )

      // If we get here without an error, the certificate is valid
      expect(stdout).toContain('Certificate:')
      expect(stdout).toContain('Subject:')
      expect(stdout).toContain('Issuer:')

      // Check for secp256k1 curve
      const hasSecp256k1 =
        stdout.includes('secp256k1') ||
        stdout.includes('1.3.132.0.10') ||
        stdout.includes('ASN1 OID: secp256k1')

      if (hasSecp256k1) {
        console.log('✓ Certificate uses secp256k1 curve')
      } else {
        console.log('Certificate content for debugging:')
        console.log(stdout)
        console.log('Certificate may not be using secp256k1 curve')
      }
    } catch (error) {
      console.error('OpenSSL error:', error)
      console.error('Certificate content:')
      console.error(certPEM)

      // Fail the test with detailed error information
      throw new Error(
        `OpenSSL cannot parse the generated certificate: ${error.message}`,
      )
    }
  })

  test('should generate a certificate with correct subject and issuer', async () => {
    try {
      const {stdout} = await execAsync(
        `openssl x509 -in ${rootCertPath} -noout -subject -issuer`,
      )

      // Check that the subject and issuer contain our DID
      expect(stdout).toContain(testDID)

      // For a self-signed certificate, subject should equal issuer
      const lines = stdout.trim().split('\n')
      const subjectLine = lines.find(line => line.startsWith('subject='))
      const issuerLine = lines.find(line => line.startsWith('issuer='))

      expect(subjectLine).toBeDefined()
      expect(issuerLine).toBeDefined()

      // Extract the CN values
      const subjectCN = subjectLine?.match(/CN\s*=\s*([^,]+)/)?.[1]
      const issuerCN = issuerLine?.match(/CN\s*=\s*([^,]+)/)?.[1]

      expect(subjectCN).toBe(testDID)
      expect(issuerCN).toBe(testDID) // Self-signed
    } catch (error) {
      throw new Error(
        `Failed to extract subject/issuer from certificate: ${error.message}`,
      )
    }
  })

  test('should generate a certificate with valid dates', async () => {
    try {
      const {stdout} = await execAsync(
        `openssl x509 -in ${rootCertPath} -noout -dates`,
      )

      expect(stdout).toContain('notBefore=')
      expect(stdout).toContain('notAfter=')

      // Extract dates and verify they're reasonable
      const notBeforeLine = stdout.match(/notBefore=(.+)/)?.[1]
      const notAfterLine = stdout.match(/notAfter=(.+)/)?.[1]

      expect(notBeforeLine).toBeDefined()
      expect(notAfterLine).toBeDefined()

      const notBefore = new Date(notBeforeLine!)
      const notAfter = new Date(notAfterLine!)
      const now = new Date()

      // Certificate should be valid now
      expect(notBefore.getTime()).toBeLessThanOrEqual(now.getTime())
      expect(notAfter.getTime()).toBeGreaterThan(now.getTime())

      // Should be valid for a reasonable period (at least 1 year)
      const validityPeriod = notAfter.getTime() - notBefore.getTime()
      const oneYear = 365 * 24 * 60 * 60 * 1000
      expect(validityPeriod).toBeGreaterThanOrEqual(oneYear)
    } catch (error) {
      throw new Error(
        `Failed to extract dates from certificate: ${error.message}`,
      )
    }
  })
})
