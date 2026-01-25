/**
 * Tests for ATSMSClient library
 */

import {AtpAgent} from '@atproto/api'
import {afterAll, beforeAll, describe, expect, test} from 'bun:test'
import {existsSync, mkdirSync, rmSync} from 'fs'
import path from 'path'

import {ATSMSClient} from '../lib/atsms-client.js'
import {ATSMSEndpointCertificate} from '../lib/certificates/index.js'
import {type ATSMSConfig} from '../lib/types.js'

describe('ATSMSClient Library', () => {
  let testDir: string
  
  let _testConfig: ATSMSConfig

  beforeAll(async () => {
    testDir = path.join(process.cwd(), 'test-atsms-client')

    _testConfig = {
      apiUrl: 'https://test.api.acme.xyz'
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

  describe('Client Initialization', () => {
    test('should create ATSMSClient instance', () => {
      const agent = new AtpAgent({service: 'https://bsky.social'})
      const did = 'did:plc:test123'
      const client = new ATSMSClient(agent, did)
      expect(client).toBeDefined()
    })

    test('should require valid DID', () => {
      const agent = new AtpAgent({service: 'https://bsky.social'})
      expect(() => new ATSMSClient(agent, 'not-a-did')).toThrow('Valid DID is required')
    })

    test('should require AtpAgent', () => {
      expect(() => new ATSMSClient(null as any, 'did:plc:test')).toThrow('AtpAgent is required')
    })
  })

  describe('Certificate Storage', () => {
    test('should require authentication for storing endpoint certificate', async () => {
      const agent = new AtpAgent({service: 'https://bsky.social'})
      const did = 'did:plc:test123'
      const client = new ATSMSClient(agent, did)

      // Agent without session (not authenticated)
      expect(agent.session).toBeUndefined()

      // Create a self-signed endpoint certificate
      const endpointCert = await ATSMSEndpointCertificate.generate(
        'did:test:123',
        'test.domain',
        'test@test.domain'
      )

      await expect(
        client.storeEndpointCertificate(endpointCert)
      ).rejects.toThrow('Authentication Required')
    })
  })
})