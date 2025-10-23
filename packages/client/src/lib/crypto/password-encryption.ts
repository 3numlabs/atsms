/**
 * Password-based encryption for private keys
 * Uses PBKDF2 for key derivation and AES-256-GCM for encryption
 */

import * as crypto from 'crypto'

export class PasswordEncryption {
  private static readonly ALGORITHM = 'aes-256-gcm'
  private static readonly SALT_LENGTH = 32
  private static readonly IV_LENGTH = 16
  private static readonly TAG_LENGTH = 16
  private static readonly ITERATIONS = 100000
  private static readonly KEY_LENGTH = 32

  /**
   * Encrypt a private key PEM string with a password
   */
  static encrypt(privateKeyPEM: string, password: string): string {
    // Generate random salt and IV
    const salt = crypto.randomBytes(this.SALT_LENGTH)
    const iv = crypto.randomBytes(this.IV_LENGTH)

    // Derive key from password using PBKDF2
    const key = crypto.pbkdf2Sync(password, salt, this.ITERATIONS, this.KEY_LENGTH, 'sha256')

    // Create cipher
    const cipher = crypto.createCipheriv(this.ALGORITHM, key, iv)

    // Encrypt the private key
    const encrypted = Buffer.concat([
      cipher.update(privateKeyPEM, 'utf8'),
      cipher.final()
    ])

    // Get the authentication tag
    const tag = cipher.getAuthTag()

    // Combine salt, iv, tag, and encrypted data
    const combined = Buffer.concat([salt, iv, tag, encrypted])

    // Return base64 encoded
    return combined.toString('base64')
  }

  /**
   * Decrypt a password-encrypted private key
   */
  static decrypt(encryptedData: string, password: string): string {
    // Decode from base64
    const combined = Buffer.from(encryptedData, 'base64')

    // Extract components
    const salt = combined.slice(0, this.SALT_LENGTH)
    const iv = combined.slice(this.SALT_LENGTH, this.SALT_LENGTH + this.IV_LENGTH)
    const tag = combined.slice(
      this.SALT_LENGTH + this.IV_LENGTH,
      this.SALT_LENGTH + this.IV_LENGTH + this.TAG_LENGTH
    )
    const encrypted = combined.slice(this.SALT_LENGTH + this.IV_LENGTH + this.TAG_LENGTH)

    // Derive key from password using PBKDF2
    const key = crypto.pbkdf2Sync(password, salt, this.ITERATIONS, this.KEY_LENGTH, 'sha256')

    // Create decipher
    const decipher = crypto.createDecipheriv(this.ALGORITHM, key, iv)
    decipher.setAuthTag(tag)

    try {
      // Decrypt the data
      const decrypted = Buffer.concat([
        decipher.update(encrypted),
        decipher.final()
      ])

      return decrypted.toString('utf8')
    } catch {
      throw new Error('Failed to decrypt: Invalid password or corrupted data')
    }
  }

  /**
   * Validate that a password can decrypt the given encrypted data
   */
  static validate(encryptedData: string, password: string): boolean {
    try {
      this.decrypt(encryptedData, password)
      return true
    } catch {
      return false
    }
  }
}