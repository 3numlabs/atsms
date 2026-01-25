/**
 * Test sequential import of certificate private keys
 * Verifies that multiple certificates can be loaded with private keys independently
 */

import { describe, expect, it } from 'bun:test'

import { ATSMSEndpointCertificate } from '../lib/certificates/index.js'
import { generateTestEndpointCertificate } from './test-certificates.js'

describe('Sequential Certificate Private Key Import', () => {
  it('should successfully import multiple certificate private keys sequentially', async () => {
    // Generate two separate self-signed endpoint certificates
    const cert1Result = await generateTestEndpointCertificate(
      'did:plc:user1',
      'user1.acme.xyz',
      'user1@user1.acme.xyz'
    )

    const cert2Result = await generateTestEndpointCertificate(
      'did:plc:user2',
      'user2.acme.xyz',
      'user2@user2.acme.xyz'
    )

    // First, load certificates without private keys
    const cert1WithoutKey = ATSMSEndpointCertificate.fromPEM(cert1Result.cert)
    const cert2WithoutKey = ATSMSEndpointCertificate.fromPEM(cert2Result.cert)

    // Verify no private keys are loaded
    expect(cert1WithoutKey.hasPrivateKey()).toBe(false)
    expect(cert2WithoutKey.hasPrivateKey()).toBe(false)

    // Now import first certificate with private key
    const cert1WithKey = await ATSMSEndpointCertificate.fromPEMWithKey(
      cert1Result.cert,
      cert1Result.privateKey
    )

    // Verify first private key is loaded
    expect(cert1WithKey.hasPrivateKey()).toBe(true)
    expect(cert1WithKey.privateKeyValue).toBeDefined()

    // Now import second certificate with private key
    const cert2WithKey = await ATSMSEndpointCertificate.fromPEMWithKey(
      cert2Result.cert,
      cert2Result.privateKey
    )

    // Verify second private key is loaded
    expect(cert2WithKey.hasPrivateKey()).toBe(true)
    expect(cert2WithKey.privateKeyValue).toBeDefined()

    // Verify both certificates are functional endpoint certs
    expect(cert1WithKey.getType()).toBe('endpoint')
    expect(cert2WithKey.getType()).toBe('endpoint')

    // Verify both are self-signed (isCA = false)
    expect(cert1WithKey.isCA).toBe(false)
    expect(cert2WithKey.isCA).toBe(false)

    // Verify DIDs are correctly extracted
    expect(cert1WithKey.did).toBe('did:plc:user1')
    expect(cert2WithKey.did).toBe('did:plc:user2')
  })

  it('should handle reverse order: second private key then first private key', async () => {
    // Generate two separate self-signed endpoint certificates
    const cert1Result = await generateTestEndpointCertificate(
      'did:plc:userA',
      'userA.acme.xyz',
      'userA@userA.acme.xyz'
    )

    const cert2Result = await generateTestEndpointCertificate(
      'did:plc:userB',
      'userB.acme.xyz',
      'userB@userB.acme.xyz'
    )

    // Import second certificate with private key first
    const cert2WithKey = await ATSMSEndpointCertificate.fromPEMWithKey(
      cert2Result.cert,
      cert2Result.privateKey
    )

    // Verify second private key is loaded
    expect(cert2WithKey.hasPrivateKey()).toBe(true)
    expect(cert2WithKey.privateKeyValue).toBeDefined()

    // Then import first certificate with private key
    const cert1WithKey = await ATSMSEndpointCertificate.fromPEMWithKey(
      cert1Result.cert,
      cert1Result.privateKey
    )

    // Verify first private key is loaded
    expect(cert1WithKey.hasPrivateKey()).toBe(true)
    expect(cert1WithKey.privateKeyValue).toBeDefined()

    // Verify both are functional
    expect(cert1WithKey.isCA).toBe(false)
    expect(cert2WithKey.isCA).toBe(false)
  })
})
