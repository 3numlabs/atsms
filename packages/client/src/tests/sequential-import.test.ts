/**
 * Test sequential import of client and root certificate private keys
 */

import { describe, expect, it } from 'bun:test'

import { ATSMSEndpointCertificate, ATSMSRootCertificate } from '../lib/certificates/index.js'
import { generateTestClientCertificate, generateTestRootCertificate } from './test-certificates.js'

describe('Sequential Certificate Private Key Import', () => {
  it('should successfully import client private key then root private key', async () => {
    // Generate test certificates
    const rootResult = await generateTestRootCertificate(
      'did:plc:root123',
      'root.acme.xyz'
    )
    
    const clientResult = await generateTestClientCertificate(
      rootResult,
      'did:plc:client123',
      'client.acme.xyz'
    )
    
    // First, load certificates without private keys
    const clientCertWithoutKey = ATSMSEndpointCertificate.fromPEM(clientResult.cert)
    const rootCertWithoutKey = ATSMSRootCertificate.fromPEM(rootResult.cert)
    
    // Verify no private keys are loaded
    expect(clientCertWithoutKey.hasPrivateKey()).toBe(false)
    expect(rootCertWithoutKey.hasPrivateKey()).toBe(false)
    
    // Now import client certificate with private key (simulating first import)
    const clientCertWithKey = await ATSMSEndpointCertificate.fromPEMWithKey(
      clientResult.cert,
      clientResult.privateKey
    )
    
    // Verify client private key is loaded
    expect(clientCertWithKey.hasPrivateKey()).toBe(true)
    expect(clientCertWithKey.privateKeyValue).toBeDefined()
    
    // Now import root certificate with private key (simulating second import)
    const rootCertWithKey = await ATSMSRootCertificate.fromPEMWithKey(
      rootResult.cert,
      rootResult.privateKey
    )
    
    // Verify root private key is loaded
    expect(rootCertWithKey.hasPrivateKey()).toBe(true)
    expect(rootCertWithKey.privateKeyValue).toBeDefined()
    
    // Verify both certificates are functional with their private keys
    expect(clientCertWithKey.getType()).toBe('endpoint')

    expect(rootCertWithKey.getType()).toBe('root')
    
    // Verify certificates can perform crypto operations
    const testClientCert = await rootCertWithKey.generateSignedEndpointCertificate('test@test.acme.xyz', 365, 'did:plc:root123', 'root.acme.xyz')
    expect(testClientCert).toBeDefined()
    expect(testClientCert.getType()).toBe('endpoint')
  })
  
  it('should handle reverse order: root private key then client private key', async () => {
    // Generate test certificates
    const rootResult = await generateTestRootCertificate(
      'did:plc:root456',
      'root2.acme.xyz'
    )
    
    const clientResult = await generateTestClientCertificate(
      rootResult,
      'did:plc:client456',
      'client2.acme.xyz'
    )
    
    // First import root certificate with private key
    const rootCertWithKey = await ATSMSRootCertificate.fromPEMWithKey(
      rootResult.cert,
      rootResult.privateKey
    )
    
    // Verify root private key is loaded
    expect(rootCertWithKey.hasPrivateKey()).toBe(true)
    expect(rootCertWithKey.privateKeyValue).toBeDefined()
    
    // Then import client certificate with private key
    const clientCertWithKey = await ATSMSEndpointCertificate.fromPEMWithKey(
      clientResult.cert,
      clientResult.privateKey
    )
    
    // Verify client private key is loaded
    expect(clientCertWithKey.hasPrivateKey()).toBe(true)
    expect(clientCertWithKey.privateKeyValue).toBeDefined()
    
    // Verify both are functional
    expect(rootCertWithKey.isCA).toBe(true)
    expect(clientCertWithKey.isCA).toBe(false)
  })
})