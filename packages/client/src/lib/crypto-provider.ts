/**
 * Crypto provider for browser environments
 * Uses native Web Crypto API
 */

// Use the browser's native crypto
let cryptoProvider: Crypto = globalThis.crypto

export { cryptoProvider }

/**
 * Function to set a custom crypto provider
 * Useful if you want to use a different crypto implementation
 */
export function setCryptoProvider(provider: Crypto): void {
  cryptoProvider = provider
}