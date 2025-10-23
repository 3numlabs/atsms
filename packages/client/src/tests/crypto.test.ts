/**
 * Comprehensive tests for cryptographic operations
 * Tests certificate generation, signing, encryption, and decryption
 */

import {afterAll, beforeAll, describe, expect, test} from 'bun:test'
import {existsSync, mkdirSync, readFileSync, rmSync,writeFileSync} from 'fs'
import path from 'path'

import { ATSMSEndpointCertificate,ATSMSRootCertificate } from '../lib/certificates/index.js'
import {
  decryptAndVerifyMessageSignature,
  encryptMessage,
  signMessage} from '../lib/crypto.js'
import { generateTestClientCertificate,generateTestRootCertificate } from './test-certificates.js'

describe('Crypto Functions', () => {
  let testDir: string
  let testDID: string
  let testHandle: string
  let rootCertPEM: string
  let rootKeyPEM: string
  let clientCertPEM: string
  let clientKeyPEM: string

  beforeAll(async () => {
    testDir = path.join(process.cwd(), 'test-certs')
    testDID = 'did:plc:test123456789'
    testHandle = 'test.acme.xyz'

    // Create test directory
    if (existsSync(testDir)) {
      rmSync(testDir, {recursive: true, force: true})
    }
    mkdirSync(testDir, {recursive: true})

    // Generate certificates for all tests
    const rootResult = await generateTestRootCertificate(testDID, 'acme.xyz')
    rootCertPEM = rootResult.cert
    rootKeyPEM = rootResult.privateKey

    const clientResult = await generateTestClientCertificate(
      rootResult,
      testDID,
      testHandle
    )
    clientCertPEM = clientResult.cert
    clientKeyPEM = clientResult.privateKey

    // Write to files for tests that need them
    writeFileSync(path.join(testDir, 'root-cert.pem'), rootCertPEM, 'utf8')
    writeFileSync(path.join(testDir, 'root-key.pem'), rootKeyPEM, 'utf8')
    writeFileSync(path.join(testDir, 'client-cert.pem'), clientCertPEM, 'utf8')
    writeFileSync(path.join(testDir, 'client-key.pem'), clientKeyPEM, 'utf8')
  })

  afterAll(() => {
    // Cleanup test directory
    if (existsSync(testDir)) {
      rmSync(testDir, {recursive: true, force: true})
    }
  })

  describe('Certificate Generation', () => {
    let rootKeyPath: string
    let rootCertPath: string
    let clientKeyPath: string
    let clientCertPath: string

    beforeAll(() => {
      rootKeyPath = path.join(testDir, 'root-key.pem')
      rootCertPath = path.join(testDir, 'root-cert.pem')
      clientKeyPath = path.join(testDir, 'client-key.pem')
      clientCertPath = path.join(testDir, 'client-cert.pem')
    })

    test('should generate K-256 root certificate', async () => {
      const result = await generateTestRootCertificate(testDID, 'acme.xyz')

      expect(result.cert).toBeTruthy()
      expect(result.privateKey).toBeTruthy()

      // Write to files for subsequent tests
      writeFileSync(rootCertPath, result.cert, 'utf8')
      writeFileSync(rootKeyPath, result.privateKey, 'utf8')

      // Verify files exist
      expect(existsSync(rootCertPath)).toBe(true)
      expect(existsSync(rootKeyPath)).toBe(true)

      // Verify certificate format
      expect(result.cert).toContain('BEGIN CERTIFICATE')
      expect(result.cert).toContain('END CERTIFICATE')

      // Verify private key format
      expect(result.privateKey).toContain('BEGIN PRIVATE KEY')
      expect(result.privateKey).toContain('END PRIVATE KEY')

      // Parse and verify certificate details
      const rootCert = await ATSMSRootCertificate.fromPEMWithKey(result.cert, result.privateKey)
      expect(rootCert.subject).toContain(testDID)
      expect(rootCert.getType()).toBe('root')

      // Verify it's a CA certificate
      expect(rootCert.isCA).toBe(true)
    })

    test('should verify root certificate uses K-256 (secp256k1) with openssl', async () => {
      const result = await generateTestRootCertificate(testDID, 'acme.xyz')
      
      // Write certificate to temp file
      const tempCertPath = path.join(testDir, 'test-k256-cert.pem')
      writeFileSync(tempCertPath, result.cert, 'utf8')
      
      // Use openssl to check the certificate's public key algorithm
      const { exec } = await import('child_process')
      const { promisify } = await import('util')
      const execAsync = promisify(exec)
      
      try {
        // Get certificate details including the public key info
        const { stdout } = await execAsync(`openssl x509 -in ${tempCertPath} -text -noout`)
        
        // Check for secp256k1 - OpenSSL shows this as "ASN1 OID: secp256k1"
        const hasSecp256k1 = stdout.includes('ASN1 OID: secp256k1') || 
                             stdout.includes('secp256k1')
        
        if (!hasSecp256k1) {
          console.error('Certificate does not use secp256k1. OpenSSL output:')
          console.error(stdout)
        }
        
        expect(hasSecp256k1).toBe(true)
        
        // Also verify it's an EC key (not RSA or other)
        expect(stdout).toContain('Public Key Algorithm: id-ecPublicKey')
      } catch (error) {
        console.error('OpenSSL verification failed:', error)
        throw error
      }
    })

    test('should generate RSA client certificate signed by root', async () => {
      // Use the pre-generated root certificate from the test certificates
      const rootResult = await generateTestRootCertificate(testDID, 'acme.xyz')
      const result = await generateTestClientCertificate(
        rootResult,
        testDID,
        testHandle
      )
      
      // Write to files for subsequent tests so other tests still work
      writeFileSync(rootCertPath, rootResult.cert, 'utf8')
      writeFileSync(rootKeyPath, rootResult.privateKey, 'utf8')

      expect(result.cert).toBeTruthy()
      expect(result.privateKey).toBeTruthy()

      // Write to files for subsequent tests
      writeFileSync(clientCertPath, result.cert, 'utf8')
      writeFileSync(clientKeyPath, result.privateKey, 'utf8')

      // Verify files exist
      expect(existsSync(clientCertPath)).toBe(true)
      expect(existsSync(clientKeyPath)).toBe(true)

      // Verify certificate format
      expect(result.cert).toContain('BEGIN CERTIFICATE')
      expect(result.cert).toContain('END CERTIFICATE')

      // Verify private key format
      expect(result.privateKey).toContain('BEGIN PRIVATE KEY')
      expect(result.privateKey).toContain('END PRIVATE KEY')

      // Parse and verify certificate details
      const endpointCert = await ATSMSEndpointCertificate.fromPEMWithKey(result.cert, result.privateKey)
      expect(endpointCert.subject).toContain(testHandle)
      expect(endpointCert.getType()).toBe('endpoint')

      // Verify serial number is present
      expect(endpointCert.serialNumber).toBeTruthy()
      expect(endpointCert.serialNumber.length).toBeGreaterThan(0) // Variable length hex string

      // Verify it's not a CA certificate
      expect(endpointCert.isCA).toBe(false)
    })

    test('should extract certificate information', () => {
      const clientCertPEM = readFileSync(clientCertPath, 'utf8')
      const endpointCert = ATSMSEndpointCertificate.fromPEM(clientCertPEM)

      expect(endpointCert.serialNumber).toBeTruthy()
      expect(endpointCert.notAfter).toBeTruthy()
      expect(endpointCert.subject).toContain(`CN=${testHandle}`)
      expect(endpointCert.issuer).toContain(`CN=${testDID}`)

      // Verify date format
      expect(endpointCert.notAfter.getTime()).toBeGreaterThan(Date.now())
    })
  })

  describe('Message Signing and Encryption', () => {
    // Use the certificates from the parent scope

    test('should sign a message', async () => {
      const message = 'Hello, World!'
      const signerCert = await ATSMSEndpointCertificate.fromPEMWithKey(clientCertPEM, clientKeyPEM)
      const signedContent = await signMessage(
        message,
        signerCert
      )

      expect(signedContent).toBeTruthy()
      expect(signedContent.length).toBeGreaterThan(0)
      expect(signedContent).toBeInstanceOf(Uint8Array)
    })

    test('should encrypt a signed message', async () => {
      const message = 'Secret message'
      const signerCert = await ATSMSEndpointCertificate.fromPEMWithKey(clientCertPEM, clientKeyPEM)
      const signedContent = await signMessage(
        message,
        signerCert
      )

      const endpointCert = ATSMSEndpointCertificate.fromPEM(clientCertPEM)
      const encryptedContent = await encryptMessage(
        signedContent,
        [endpointCert] // Encrypt for self
      )

      expect(encryptedContent).toBeTruthy()
      expect(encryptedContent.length).toBeGreaterThan(0)
      expect(encryptedContent).not.toEqual(signedContent)
      expect(encryptedContent).toBeInstanceOf(Uint8Array)
    })

    test('should decrypt and verify a message', async () => {
      const originalMessage = 'Test message for encryption'

      // Sign the message
      const signerCert = await ATSMSEndpointCertificate.fromPEMWithKey(clientCertPEM, clientKeyPEM)
      const signedContent = await signMessage(
        originalMessage,
        signerCert
      )

      // Encrypt for recipient (self in this case)
      const endpointCert = ATSMSEndpointCertificate.fromPEM(clientCertPEM)
      const encryptedContent = await encryptMessage(
        signedContent,
        [endpointCert]
      )

      // Decrypt and verify
      const clientCertWithKey = await ATSMSEndpointCertificate.fromPEMWithKey(clientCertPEM, clientKeyPEM)
      
      const result = await decryptAndVerifyMessageSignature(
        encryptedContent,
        clientCertWithKey
      )
      const decryptedMessage = new TextDecoder().decode(result.decryptedContent)

      expect(decryptedMessage).toBe(originalMessage)
    })

    test('should handle JSON message payload', async () => {
      const messagePayload = {
        version: '1.0',
        contentType: 'atsms/text',
        content: JSON.stringify({
          text: 'Hello from test'
        }),
        sender: {
          handle: testHandle,
          did: testDID
        },
        timestamp: new Date().toISOString()
      }

      const messageString = JSON.stringify(messagePayload)

      // Sign the JSON message
      const signerCert = await ATSMSEndpointCertificate.fromPEMWithKey(clientCertPEM, clientKeyPEM)
      const signedContent = await signMessage(
        messageString,
        signerCert
      )

      // Encrypt
      const endpointCert = ATSMSEndpointCertificate.fromPEM(clientCertPEM)
      const encryptedContent = await encryptMessage(
        signedContent,
        [endpointCert]
      )

      // Decrypt
      const clientCertWithKey = await ATSMSEndpointCertificate.fromPEMWithKey(clientCertPEM, clientKeyPEM)

      const result = await decryptAndVerifyMessageSignature(
        encryptedContent,
        clientCertWithKey
      )
      const decryptedMessage = new TextDecoder().decode(result.decryptedContent)

      // Parse and verify
      const decryptedPayload = JSON.parse(decryptedMessage)
      expect(decryptedPayload.version).toBe('1.0')
      expect(decryptedPayload.contentType).toBe('atsms/text')
      const parsedContent = JSON.parse(decryptedPayload.content)
      expect(parsedContent.text).toBe('Hello from test')
      expect(decryptedPayload.sender.handle).toBe(testHandle)
      expect(decryptedPayload.sender.did).toBe(testDID)
    })

    test('should encrypt for multiple recipients', async () => {
      // Generate a second client certificate for testing
      const rootResult = await generateTestRootCertificate(testDID, 'acme.xyz')
      const recipient2Result = await generateTestClientCertificate(
        rootResult,
        testDID,
        'recipient2.acme.xyz'
      )

      const recipient2CertPath = path.join(testDir, 'recipient2-cert.pem')
      const recipient2KeyPath = path.join(testDir, 'recipient2-key.pem')

      writeFileSync(recipient2CertPath, recipient2Result.cert, 'utf8')
      writeFileSync(recipient2KeyPath, recipient2Result.privateKey, 'utf8')

      const message = 'Message for multiple recipients'

      // Sign with sender's key
      const signerCert = await ATSMSEndpointCertificate.fromPEMWithKey(clientCertPEM, clientKeyPEM)
      const signedContent = await signMessage(
        message,
        signerCert
      )

      // Encrypt for multiple recipients - create Certificate objects
      const endpointCert = ATSMSEndpointCertificate.fromPEM(clientCertPEM)
      const recipient2Cert = ATSMSEndpointCertificate.fromPEM(recipient2Result.cert)
      
      const encryptedContent = await encryptMessage(
        signedContent,
        [endpointCert, recipient2Cert]
      )

      // Both recipients should be able to decrypt
      const clientCertWithKey = await ATSMSEndpointCertificate.fromPEMWithKey(clientCertPEM, clientKeyPEM)
      
      const result1 = await decryptAndVerifyMessageSignature(
        encryptedContent,
        clientCertWithKey
      )
      const decrypted1 = new TextDecoder().decode(result1.decryptedContent)

      const recipient2CertWithKey = await ATSMSEndpointCertificate.fromPEMWithKey(recipient2Result.cert, recipient2Result.privateKey)
      
      const result2 = await decryptAndVerifyMessageSignature(
        encryptedContent,
        recipient2CertWithKey
      )
      const decrypted2 = new TextDecoder().decode(result2.decryptedContent)

      expect(decrypted1).toBe(message)
      expect(decrypted2).toBe(message)
    })
  })

  describe('Error Handling', () => {
    test('should throw error for invalid certificate', () => {
      expect(() => 
        ClientCertificate.fromPEM('invalid certificate data')
      ).toThrow()
    })

    test('should throw error when signing with mismatched key and cert', async () => {
      const clientCertPEM = readFileSync(path.join(testDir, 'client-cert.pem'), 'utf8')
      const wrongKeyPEM = `-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7W8xY1SdCL6fD
invalid key data
-----END PRIVATE KEY-----`

      expect(
        (async () => {
          const wrongCert = await ATSMSEndpointCertificate.fromPEMWithKey(clientCertPEM, wrongKeyPEM)
          return signMessage('test', wrongCert)
        })()
      ).rejects.toThrow()
    })

    test('should throw error when decrypting with wrong key', async () => {
      const clientCertPEM = readFileSync(path.join(testDir, 'client-cert.pem'), 'utf8')
      const clientKeyPEM = readFileSync(path.join(testDir, 'client-key.pem'), 'utf8')

      // Generate another certificate
      const rootResult = await generateTestRootCertificate(testDID, 'acme.xyz')
      const wrongRecipientResult = await generateTestClientCertificate(
        rootResult,
        testDID,
        'wrong.acme.xyz'
      )

      const message = 'Secret message'

      // Sign and encrypt for client cert
      const signerCert = await ATSMSEndpointCertificate.fromPEMWithKey(clientCertPEM, clientKeyPEM)
      const signedContent = await signMessage(
        message,
        signerCert
      )

      const endpointCert = ATSMSEndpointCertificate.fromPEM(clientCertPEM)
      const encryptedContent = await encryptMessage(
        signedContent,
        [endpointCert] // Only encrypted for client cert
      )

      // Try to decrypt with wrong recipient's key
      const wrongRecipientCert = await ATSMSEndpointCertificate.fromPEMWithKey(wrongRecipientResult.cert, wrongRecipientResult.privateKey)
      
      expect(
        decryptAndVerifyMessageSignature(
          encryptedContent,
          wrongRecipientCert
        )
      ).rejects.toThrow(/Failed to decrypt/)
    })
  })
})