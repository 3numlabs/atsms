# Ed25519/X25519 for CMS/S/MIME: Feasibility Assessment

## Summary

Switching ATSMS certificates to Ed25519 (signing) and X25519 (key agreement) is feasible at the WebCrypto level but **blocked by pkijs** for CMS/PKCS#7 operations.

## WebCrypto / Browser Support

- **Ed25519 and X25519** are supported in all major browsers (Chrome 137+, Firefox, Safari) and Cloudflare Workers
- `@peculiar/webcrypto` (our polyfill) supports both since 2021
- `@peculiar/x509` should support Ed25519 certificate generation (delegates to WebCrypto)
- `jose` library supports `EdDSA` for JWT signing

## RFC Standards

- **RFC 8410**: Defines X.509 algorithm identifiers — Ed25519 (`1.3.101.112`), X25519 (`1.3.101.110`)
- **RFC 8418**: Defines X25519 key agreement in CMS EnvelopedData with HKDF-SHA-256
- **RFC 9295**: Clarifications for Ed25519/X25519 key usage in certificates
- Self-issued certificates (Ed25519-signed cert with X25519 subject key) are valid per the RFCs

## pkijs Does NOT Support Ed25519/X25519 (as of v3.4.0)

`CryptoEngine.getAlgorithmParameters()` has no case for Ed25519 or X25519. This means:

- **CMS SignedData**: Cannot sign with Ed25519
- **CMS EnvelopedData**: Cannot use X25519 KeyAgreeRecipientInfo with HKDF

### Evidence

- **Issue #89** (2017, still open): "Add support for 25519 and 448" — never resolved
- **Issue #442** (2025, still open): "X.509 Certificate Signing support for Ed25519" — explicitly calls out the gap in `CryptoEngine`
- **Issue #427** (2025, closed without fix): Maintainer closed saying "not widely supported in certs signing"
- Release notes for v3.3.0 through v3.4.0 contain only dependency bumps, OCSP fixes, and build tooling — no Ed25519/X25519 work
- The maintainers suggested extending `CryptoEngine` yourself (issue #89) but never built it in

## Design Consideration: Two Key Pairs

X25519 keys cannot sign — they're key-agreement only. Each device would need:

1. **Ed25519** key pair for signing and JWT auth
2. **X25519** key pair for encryption key agreement

An "Ed25519-signed X25519 certificate" is **self-issued** (same subject/issuer DN) but **not self-signed**. There are official IETF examples of this pattern.

## Current Library Support

The library currently supports two certificate algorithms, both fully wired through the stack:

| | **RSA (legacy)** | **P-256 (modern)** |
|---|---|---|
| **Key gen** | RSA-PSS 2048-bit | ECDSA P-256 |
| **Cert signing** | RSA-PSS-SHA256 | ECDSA-SHA256 |
| **CMS signing** | RSA-PSS via pkijs SignedData | ECDSA via pkijs SignedData |
| **CMS encryption** | RSA-OAEP + AES-256-CBC (KeyTransRecipientInfo) | ECDH-P256 + AES-256-CBC (KeyAgreeRecipientInfo) |
| **JWT** | RS256 | ES256 |
| **Cert class** | `ATSMSEndpointCertificate` | `ATSMSP256EndpointCertificate` |

Both are S/MIME compatible since they go through pkijs CMS SignedData and EnvelopedData. The `init` CLI defaults to P-256 unless you pass `--algorithm rsa`.

## Options

1. **Keep CMS/PKCS#7, extend pkijs** — Maintains S/MIME interop but requires writing a custom `CryptoEngine` extension for Ed25519/X25519
2. **Drop CMS/PKCS#7, use custom envelope** — Ed25519/X25519 with raw WebCrypto (ECDH + HKDF-SHA-256 + AES-256-GCM), simpler implementation, but loses S/MIME email client compatibility
3. **Hybrid** — Ed25519 for signing/JWT/identity, keep P-256 or RSA for the CMS encryption envelope so S/MIME compat is preserved
