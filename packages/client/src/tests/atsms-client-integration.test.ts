/**
 * Integration tests for ATSMSClient certificate storage
 * This test requires environment variables to be set for a real AT Protocol account
 */

import {AtpAgent} from '@atproto/api'
import {describe, expect, test} from 'bun:test'

import {ATSMSClient} from '../lib/atsms-client.js'
import { ATSMSRootCertificate } from '../lib/certificates/index.js'

// Skip these tests unless credentials are provided
const ATSMS_TEST_HANDLE = process.env.ATSMS_TEST_HANDLE
const ATSMS_TEST_PASSWORD = process.env.ATSMS_TEST_PASSWORD

describe.skipIf(!ATSMS_TEST_HANDLE || !ATSMS_TEST_PASSWORD)(
  'ATSMSClient Integration - Certificate Storage',
  () => {
    let client: ATSMSClient

    test('should store and retrieve certificates from PDS', async () => {
      // Create AtpAgent and login
      const agent = new AtpAgent({service: 'https://bsky.social'})
      console.log(`Logging in as ${ATSMS_TEST_HANDLE}...`)
      const response = await agent.login({
        identifier: ATSMS_TEST_HANDLE!,
        password: ATSMS_TEST_PASSWORD!
      })
      const did = response.data.did
      console.log(`Logged in with DID: ${did}`)
      
      // Create client with authenticated agent
      client = new ATSMSClient(agent, did)

      // Generate test certificates
      const rootKeyPath = '/tmp/test-root-key.pem'
      const rootCertPath = '/tmp/test-root-cert.pem'
      const clientKeyPath = '/tmp/test-client-key.pem'
      const clientCertPath = '/tmp/test-client-cert.pem'

      console.log('Generating test certificates...')
      const rootCert = await ATSMSRootCertificate.generate(did, 'acme.xyz')
      const rootCertPEM = rootCert.toString('pem')
      const rootPrivateKeyPEM = rootCert.certificatePrivateKeyPEM!

      // Read the generated root certificate to pass to client cert generation
      const fs = await import('fs')
      fs.writeFileSync(rootCertPath, rootCertPEM, 'utf8')
      fs.writeFileSync(rootKeyPath, rootPrivateKeyPEM, 'utf8')

      const endpointCert = await rootCert.generateSignedEndpointCertificate({
        did: did,
        domain: ATSMS_TEST_HANDLE!
      })
      const clientCertPEM = endpointCert.toString('pem')
      const clientPrivateKeyPEM = endpointCert.certificatePrivateKeyPEM!
      fs.writeFileSync(clientCertPath, clientCertPEM, 'utf8')
      fs.writeFileSync(clientKeyPath, clientPrivateKeyPEM, 'utf8')

      // Store root certificate
      console.log('Storing root certificate...')
      await client.storeRootCertificate(rootCert)

      // Store client certificate
      console.log('Storing client certificate...')
      await client.storeEndpointCertificate(endpointCert)

      // Retrieve certificates
      console.log('Retrieving certificates...')
      const userCerts = await client.getUserCertificates(did)

      // Verify certificates were stored
      expect(userCerts.rootCert).not.toBeNull()
      expect(userCerts.rootCert?.certificatePEM).toBe(rootCertPEM)
      expect(userCerts.clientCerts.length).toBeGreaterThan(0)

      const storedClientCert = userCerts.clientCerts.find(
        cert => cert.serialNumber === endpointCert.serialNumber
      )
      expect(storedClientCert).toBeDefined()
      expect(storedClientCert?.certificatePEM).toBe(clientCertPEM)

      console.log('✅ Certificates successfully stored and retrieved from PDS!')

      // Cleanup
      fs.unlinkSync(rootKeyPath)
      fs.unlinkSync(rootCertPath)
      fs.unlinkSync(clientKeyPath)
      fs.unlinkSync(clientCertPath)
    }, 30000) // 30 second timeout for integration test
  }
)