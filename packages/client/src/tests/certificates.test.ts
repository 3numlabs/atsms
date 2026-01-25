/**
 * Tests for Certificate classes
 */

import { describe, expect, it } from 'bun:test'

import { ATSMSEndpointCertificate } from '../lib/certificates/index.js'
import { generateTestEndpointCertificate } from './test-certificates.js'

describe('Certificate Classes', () => {
  describe('EndpointCertificate', () => {
    it('should generate a valid self-signed endpoint certificate', async () => {
      const result = await generateTestEndpointCertificate(
        'did:plc:test123',
        'test.acme.xyz'
      )
      const endpointCert = await ATSMSEndpointCertificate.fromPEMWithKey(result.cert, result.privateKey)

      expect(endpointCert.getType()).toBe('endpoint')
      expect(endpointCert.commonName).toBe('did:plc:test123')
      expect(endpointCert.isSimpleSelfSigned()).toBe(true)
      expect(typeof endpointCert.hasPrivateKey()).toBe('boolean')
      expect(endpointCert.isValid()).toBe(true)
      expect(endpointCert.did).toBe('did:plc:test123')

      expect(result.cert).toContain('BEGIN CERTIFICATE')
      expect(result.privateKey).toContain('BEGIN PRIVATE KEY')
    })

    it('should load certificate with private key using fromPEMWithKey', async () => {
      const result = await generateTestEndpointCertificate(
        'did:plc:test123',
        'test.acme.xyz'
      )

      const endpointCert = await ATSMSEndpointCertificate.fromPEMWithKey(result.cert, result.privateKey)

      expect(endpointCert.getType()).toBe('endpoint')
      expect(endpointCert.commonName).toBe('did:plc:test123')
      expect(endpointCert.hasPrivateKey()).toBe(true)
      expect(endpointCert.isValid()).toBe(true)
    })

    it('should throw error if private key does not match certificate', async () => {
      // Generate two different certificates
      const cert1 = await generateTestEndpointCertificate(
        'did:plc:test123',
        'test.acme.xyz'
      )
      const cert2 = await generateTestEndpointCertificate(
        'did:plc:test456',
        'test2.acme.xyz'
      )

      // Try to load cert1 with cert2's private key - should fail
      await expect(
        ATSMSEndpointCertificate.fromPEMWithKey(cert1.cert, cert2.privateKey)
      ).rejects.toThrow('Private key does not match the certificate public key')
    })

    it('should export and import PEM', async () => {
      const result = await generateTestEndpointCertificate(
        'did:plc:client123',
        'client.acme.xyz'
      )

      expect(result.cert).toContain('BEGIN CERTIFICATE')
      expect(result.privateKey).toContain('BEGIN PRIVATE KEY')

      // Load from PEM
      const loadedCert = await ATSMSEndpointCertificate.fromPEMWithKey(result.cert, result.privateKey)
      expect(loadedCert.commonName).toBe('did:plc:client123')
      expect(loadedCert.getType()).toBe('endpoint')
    })

    it('should reject invalid parameters - string as validityDays', async () => {
      await expect(
        ATSMSEndpointCertificate.generate(
          'did:plc:test',
          'test.com',
          'test@example.com',
          'test.com' as any   // Wrong: domain string as validityDays
        )
      ).rejects.toThrow('Invalid validityDays')
    })

    it('should reject invalid parameters - negative validityDays', async () => {
      await expect(
        ATSMSEndpointCertificate.generate('did:plc:test', 'test.com', 'test@example.com', -365)
      ).rejects.toThrow('Invalid validityDays')
    })

    it('should reject invalid parameters - NaN validityDays', async () => {
      await expect(
        ATSMSEndpointCertificate.generate('did:plc:test', 'test.com', 'test@example.com', NaN)
      ).rejects.toThrow('Invalid validityDays')
    })

    it('should reject invalid parameters - empty domain', async () => {
      await expect(
        ATSMSEndpointCertificate.generate('did:plc:test', '', 'test@example.com', 365)
      ).rejects.toThrow('Invalid domain')
    })

    it('should reject invalid parameters - non-string domain', async () => {
      await expect(
        ATSMSEndpointCertificate.generate('did:plc:test', 123 as any, 'test@example.com', 365)
      ).rejects.toThrow('Invalid domain')
    })

    it('should reject invalid parameters - invalid DID format', async () => {
      await expect(
        ATSMSEndpointCertificate.generate('not-a-did', 'test.com', 'test@example.com', 365)
      ).rejects.toThrow('Invalid DID')
    })

    it('should reject invalid email - missing @', async () => {
      await expect(
        ATSMSEndpointCertificate.generate('did:plc:test', 'test.com', 'invalidemail.com', 365)
      ).rejects.toThrow('Invalid email')
    })

    it('should reject invalid email - multiple @ symbols', async () => {
      await expect(
        ATSMSEndpointCertificate.generate('did:plc:test', 'test.com', 'test@@example.com', 365)
      ).rejects.toThrow('Invalid email')
    })

    it('should reject invalid email - no domain', async () => {
      await expect(
        ATSMSEndpointCertificate.generate('did:plc:test', 'test.com', 'test@', 365)
      ).rejects.toThrow('Invalid email')
    })

    it('should reject invalid email - domain without TLD', async () => {
      await expect(
        ATSMSEndpointCertificate.generate('did:plc:test', 'test.com', 'test@domain', 365)
      ).rejects.toThrow('Invalid email')
    })

    it('should reject invalid email - empty string', async () => {
      await expect(
        ATSMSEndpointCertificate.generate('did:plc:test', 'test.com', '', 365)
      ).rejects.toThrow('Invalid email')
    })

    it('should reject invalid email - non-string type', async () => {
      await expect(
        ATSMSEndpointCertificate.generate('did:plc:test', 'test.com', 123 as any, 365)
      ).rejects.toThrow('Invalid email')
    })

    it('should reject invalid email - only @ symbol', async () => {
      await expect(
        ATSMSEndpointCertificate.generate('did:plc:test', 'test.com', '@', 365)
      ).rejects.toThrow('Invalid email')
    })

    it('should accept valid email addresses', async () => {
      // Test various valid email formats
      const validEmails = [
        'test@example.com',
        'user.name@domain.co.uk',
        'test123@subdomain.example.org',
        'alice@bsky.social'
      ]

      for (const email of validEmails) {
        const endpointCert = await ATSMSEndpointCertificate.generate(
          'did:plc:test',
          'test.com',
          email,
          365
        )
        expect(endpointCert).toBeDefined()
        expect(endpointCert.getType()).toBe('endpoint')
      }
    })

    it('should generate valid certificate with correct expiration', async () => {
      const endpointCert = await ATSMSEndpointCertificate.generate(
        'did:plc:test',
        'test.com',
        'test@example.com',
        365
      )

      // Verify expiration is approximately 365 days in the future
      const expectedExpiration = new Date(Date.now() + 365 * 24 * 60 * 60 * 1000)
      const diff = Math.abs(endpointCert.notAfter.getTime() - expectedExpiration.getTime())
      expect(diff).toBeLessThan(5000) // Within 5 seconds

      // Verify it's not expired
      expect(endpointCert.notAfter.getTime()).toBeGreaterThan(Date.now())

      // Verify it's not in 1899 or other invalid date
      expect(endpointCert.notAfter.getFullYear()).toBeGreaterThan(2020)
    })
  })

  describe('Self-Signed Certificate Properties', () => {
    it('should correctly identify self-signed endpoint certificate', async () => {
      const result = await generateTestEndpointCertificate(
        'did:plc:test123',
        'test.acme.xyz'
      )
      const endpointCert = await ATSMSEndpointCertificate.fromPEMWithKey(result.cert, result.privateKey)

      // Self-signed endpoint certificates have subject === issuer
      expect(endpointCert.isSimpleSelfSigned()).toBe(true)
      expect(endpointCert.subject).toBe(endpointCert.issuer)
      expect(endpointCert.getType()).toBe('endpoint')
    })

    it('should NOT be a CA certificate', async () => {
      const result = await generateTestEndpointCertificate(
        'did:plc:test123',
        'test.acme.xyz'
      )
      const endpointCert = await ATSMSEndpointCertificate.fromPEMWithKey(result.cert, result.privateKey)

      // Endpoint certificates should NOT be CA certificates (BasicConstraints: CA=false)
      expect(endpointCert.isCA).toBe(false)
    })

    it('should verify self-signature', async () => {
      const result = await generateTestEndpointCertificate(
        'did:plc:test123',
        'test.acme.xyz'
      )
      const endpointCert = await ATSMSEndpointCertificate.fromPEMWithKey(result.cert, result.privateKey)

      // Self-signed certificates should verify against themselves
      const isValid = await endpointCert.verifySelfSignature()
      expect(typeof isValid).toBe('boolean')
    })

    it('should maintain properties after PEM export/import', async () => {
      const result = await generateTestEndpointCertificate(
        'did:plc:test123',
        'test.acme.xyz'
      )
      const endpointCert = await ATSMSEndpointCertificate.fromPEMWithKey(result.cert, result.privateKey)

      // Export to PEM
      const certPEM = endpointCert.toString('pem')
      const privateKeyPEM = endpointCert.certificatePrivateKeyPEM!

      // Re-import from PEM
      const reimportedCert = await ATSMSEndpointCertificate.fromPEMWithKey(certPEM, privateKeyPEM)

      // Properties should be preserved
      expect(reimportedCert.isCA).toBe(false)
      expect(reimportedCert.isSimpleSelfSigned()).toBe(true)
      expect(reimportedCert.commonName).toBe('did:plc:test123')
    })

    it('should have correct subject/issuer for self-signed certs', async () => {
      const result = await generateTestEndpointCertificate(
        'did:plc:test123',
        'test.acme.xyz'
      )
      const endpointCert = await ATSMSEndpointCertificate.fromPEMWithKey(result.cert, result.privateKey)

      // For self-signed certificates, subject should equal issuer
      expect(endpointCert.subject).toBe(endpointCert.issuer)
      expect(endpointCert.subject).toContain('did:plc:test123')
    })
  })

  describe('Certificate Validation', () => {
    it('should detect non-expired certificates', async () => {
      const result = await generateTestEndpointCertificate(
        'did:plc:test123',
        'test.acme.xyz'
      )
      const endpointCert = await ATSMSEndpointCertificate.fromPEMWithKey(result.cert, result.privateKey)

      // Check that a fresh certificate is not expired
      expect(endpointCert.isExpired()).toBe(false)
      expect(endpointCert.isValid()).toBe(true)
      expect(endpointCert.isNotYetValid()).toBe(false)
    })
  })
})
