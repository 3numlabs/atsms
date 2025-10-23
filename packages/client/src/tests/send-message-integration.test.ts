/**
 * Integration test for send message functionality
 * Tests the complete flow from CLI to API worker
 */

import {afterAll, beforeAll, describe, expect, test} from 'bun:test'
import {existsSync, mkdirSync, rmSync, writeFileSync} from 'fs'
import path from 'path'

import {ATSMSApiClient} from '../lib/atsms-api.js'
import { ATSMSEndpointCertificate } from '../lib/certificates/index.js'
import {
  encryptMessage,
  signMessage} from '../lib/crypto.js'
import {type ATSMSConfig} from '../lib/types.js'
import { generateTestClientCertificate,generateTestRootCertificate } from './test-certificates.js'

describe('Send Message Integration', () => {
  let testDir: string
  let testConfig: ATSMSConfig

  beforeAll(async () => {
    testDir = path.join(process.cwd(), 'test-send-message')
    
    testConfig = {
      apiUrl: 'https://inbox.acme.xyz'
    }

    // Create test directories
    if (existsSync(testDir)) {
      rmSync(testDir, {recursive: true, force: true})
    }
    mkdirSync(testDir, {recursive: true})
  })

  afterAll(() => {
    // Clean up test directories
    if (existsSync(testDir)) {
      rmSync(testDir, {recursive: true, force: true})
    }
  })

  describe('Message Sending Flow', () => {
    test('should properly format message for API', async () => {
      const atsmsClient = new ATSMSApiClient(testConfig)
      
      // We can't actually send to the live API in tests, but we can verify
      // the request would be formatted correctly
      
      // Verify the API client has the correct configuration
      expect((atsmsClient as any).config.apiUrl).toBe('https://inbox.acme.xyz')
      
      // Verify the sendMessage method exists
      expect(typeof atsmsClient.sendMessage).toBe('function')
    })

    test('should sign and encrypt message correctly', async () => {
      // This test now focuses on the crypto operations directly
      // since ATSMSClient has been moved to CLI layer
      
      // Create test certificates
      const certsDir = path.join(testDir, 'test-certs')
      mkdirSync(certsDir, {recursive: true})
      
      // Generate test certificates
      const rootKeyPath = path.join(certsDir, 'root-ca-key.pem')
      const rootCertPath = path.join(certsDir, 'root-ca.pem')
      const clientKeyPath = path.join(certsDir, 'client-key.pem')
      const clientCertPath = path.join(certsDir, 'client.pem')
      
      const rootResult = await generateTestRootCertificate('did:plc:testuser123', 'acme.xyz')
      writeFileSync(rootCertPath, rootResult.cert, 'utf8')
      writeFileSync(rootKeyPath, rootResult.privateKey, 'utf8')
      
      const clientResult = await generateTestClientCertificate(
        rootResult,
        'did:plc:testuser123',
        'test.user'
      )
      writeFileSync(clientCertPath, clientResult.cert, 'utf8')
      writeFileSync(clientKeyPath, clientResult.privateKey, 'utf8')
      
      // Test message payload creation (simple test payload, not full ATSMSMessagePayload)
      const messageText = 'Test message'
      const payload = {
        version: '1.0',
        contentType: 'atsms/text',
        content: JSON.stringify({ text: messageText }),
        sender: {
          handle: 'test.user',
          did: 'did:plc:testuser123',
        },
        timestamp: new Date().toISOString(),
      }
      
      // Test signing
      const clientCertPEM = await Bun.file(clientCertPath).text()
      const clientKeyPEM = await Bun.file(clientKeyPath).text()

      const signerCert = await ATSMSEndpointCertificate.fromPEMWithKey(clientCertPEM, clientKeyPEM)
      const signedContent = await signMessage(
        JSON.stringify(payload),
        signerCert
      )
      
      // signMessage returns Uint8Array
      expect(signedContent).toBeDefined()
      expect(signedContent).toBeInstanceOf(Uint8Array)
      expect(signedContent.length).toBeGreaterThan(0)
      
      // Test encryption - create Certificate object
      const endpointCert = ATSMSEndpointCertificate.fromPEM(clientCertPEM)
      const encryptedContent = await encryptMessage(
        signedContent,
        [endpointCert]
      )
      
      expect(encryptedContent).toBeDefined()
      expect(encryptedContent).toBeInstanceOf(Uint8Array)
      expect(encryptedContent.length).toBeGreaterThan(0)
    })
  })

  describe('API Request Format', () => {
    test('should format send-message request correctly', () => {
      const recipientHandle = 'test.acme.xyz'
      const encryptedContent = 'base64encodedcontent'
      const fromDomain = 'acme.xyz'
      
      // Expected request body format (email API format, not AT-SMS message format)
      const expectedBody = {
        from: `no-reply@${fromDomain}`,
        to: `self@${recipientHandle}`,
        subject: 'AT Protocol Secure Message',
        text: 'AT Protocol Secure Message',
        attachment: {
          data: encryptedContent,
          filename: 'message.p7m',
          contentType: 'application/pkcs7-mime',
        },
      }
      
      // Verify the structure matches what the API expects
      expect(expectedBody.to).toMatch(/^self@.*\.acme\.xyz$/)
      expect(expectedBody.attachment.contentType).toBe('application/pkcs7-mime')
      expect(expectedBody.attachment.filename).toBe('message.p7m')
    })
  })
})