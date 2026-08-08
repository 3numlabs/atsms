# Browser Setup Guide

This guide explains how to use ATSMS in web browsers.

## Requirements

- Modern browser with Web Crypto API support:
  - Chrome/Edge 60+
  - Firefox 57+
  - Safari 11.1+
  - Opera 47+

## Installation

```bash
npm install @atsms/sms
# or
yarn add @atsms/sms
# or
pnpm add @atsms/sms
```

## Basic Usage

### ES Modules (Recommended)

```typescript
import {
  ATSMSClient,
  ATSMSStorageManager,
  platform
} from '@atsms/sms'
import { AtpAgent } from '@atproto/api'

console.log('Platform:', platform.name) // "browser"
console.log('Has WebCrypto:', platform.hasWebCrypto) // true
```

### Using with Bundlers

ATSMS works with all modern bundlers:

**Vite**:
```javascript
// vite.config.js
export default {
  optimizeDeps: {
    include: ['@atsms/sms']
  }
}
```

**Webpack 5**:
```javascript
// webpack.config.js
module.exports = {
  resolve: {
    fallback: {
      // ATSMS will use browser crypto, no Node.js fallbacks needed
      crypto: false,
      stream: false,
      buffer: false
    }
  }
}
```

**Next.js**:
```javascript
// next.config.js
module.exports = {
  webpack: (config) => {
    config.resolve.fallback = {
      ...config.resolve.fallback,
      crypto: false,
      stream: false,
      buffer: false,
    }
    return config
  }
}
```

## Storage Options

Browsers need a storage adapter for local message storage. We recommend IndexedDB for browsers:

### Option 1: Custom IndexedDB Adapter (Recommended)

```typescript
// Create your own IndexedDB adapter implementing StorageAdapter interface
// See docs/STORAGE_ADAPTERS.md for details
```

### Option 2: In-Memory Storage (Testing Only)

```typescript
// For testing, you can use an in-memory adapter
// NOT recommended for production
```

## Complete Example

```html
<!DOCTYPE html>
<html>
<head>
  <title>ATSMS Browser Example</title>
</head>
<body>
  <script type="module">
    import {
      ATSMSClient,
      ATSMSRootCertificate,
      ATSMSEndpointCertificate,
      checkPlatformRequirements
    } from '@atsms/sms'
    import { AtpAgent } from '@atproto/api'

    async function init() {
      // Check platform support
      const requirements = checkPlatformRequirements()
      if (!requirements.ok) {
        alert('Browser not supported: ' + requirements.missing.join(', '))
        return
      }

      // Initialize AT Protocol
      const agent = new AtpAgent({
        service: 'https://bsky.social'
      })

      await agent.login({
        identifier: 'your-handle.bsky.social',
        password: 'your-app-password'
      })

      // Create ATSMS client
      const client = new ATSMSClient(agent, agent.session.did)

      // Generate certificates (first time only)
      const rootCert = await ATSMSRootCertificate.generate(
        agent.session.did,
        'bsky.social',
        365 // days
      )

      await client.storeRootCertificate(rootCert)

      console.log('ATSMS initialized!')
    }

    init().catch(console.error)
  </script>
</body>
</html>
```

## React/Vue/Svelte Integration

### React Example

```typescript
import React, { useEffect, useState } from 'react'
import { ATSMSClient, checkPlatformRequirements } from '@atsms/sms'
import { AtpAgent } from '@atproto/api'

export function ATSMSProvider({ children }) {
  const [client, setClient] = useState(null)
  const [error, setError] = useState(null)

  useEffect(() => {
    const init = async () => {
      // Verify platform
      const requirements = checkPlatformRequirements()
      if (!requirements.ok) {
        throw new Error('Platform not supported')
      }

      // Initialize
      const agent = new AtpAgent({ service: 'https://bsky.social' })
      await agent.login({
        identifier: process.env.REACT_APP_HANDLE,
        password: process.env.REACT_APP_PASSWORD
      })

      const atsmsClient = new ATSMSClient(agent, agent.session.did)
      setClient(atsmsClient)
    }

    init().catch(setError)
  }, [])

  if (error) {
    return <div>Error: {error.message}</div>
  }

  if (!client) {
    return <div>Loading...</div>
  }

  return <ATSMSContext.Provider value={client}>{children}</ATSMSContext.Provider>
}
```

### Vue 3 Example

```typescript
import { ref, onMounted } from 'vue'
import { ATSMSClient, checkPlatformRequirements } from '@atsms/sms'

export function useATSMS() {
  const client = ref(null)
  const error = ref(null)

  onMounted(async () => {
    try {
      const requirements = checkPlatformRequirements()
      if (!requirements.ok) {
        throw new Error('Platform not supported')
      }

      // Initialize client
      // ... setup code
    } catch (err) {
      error.value = err
    }
  })

  return { client, error }
}
```

## WebSocket Support

Browsers have native WebSocket support, no additional setup needed:

```typescript
import { ATSMSWebSocketClient } from '@atsms/sms'

const wsClient = new ATSMSWebSocketClient({
  apiUrl: 'https://inbox.atsms.at',
  did: 'did:plc:...',
  certSerial: '...',
  getToken: async () => generateJWT(...)
})

await wsClient.connect()

wsClient.on('message', (msg) => {
  console.log('New message:', msg)
})
```

## Security Considerations

### Content Security Policy (CSP)

ATSMS uses Web Crypto API which requires these CSP directives:

```html
<meta http-equiv="Content-Security-Policy"
      content="default-src 'self';
               connect-src 'self' https://bsky.social https://inbox.atsms.at wss://inbox.atsms.at;
               script-src 'self' 'wasm-unsafe-eval';">
```

### HTTPS Required

Web Crypto API is only available in secure contexts (HTTPS). Local development works with:
- `http://localhost`
- `http://127.0.0.1`
- `file://` (limited support)

### Private Key Storage

Browser storage options for private keys:

1. **IndexedDB** (recommended): Persistent, larger storage quota
2. **LocalStorage**: Simple but 5MB limit, not secure
3. **SessionStorage**: Temporary, cleared on tab close

**IMPORTANT**: Private keys in browser storage are accessible to JavaScript. For sensitive applications, consider:
- Hardware security keys (WebAuthn)
- Encrypted storage with user password
- Server-side key management

## Performance Optimization

### Code Splitting

Load ATSMS only when needed:

```typescript
// Lazy load
const { ATSMSClient } = await import('@atsms/sms')
```

### Tree Shaking

ATSMS supports tree-shaking. Import only what you need:

```typescript
// Good - only imports what you use
import { ATSMSClient, platform } from '@atsms/sms'

// Avoid - imports everything
import * as ATSMS from '@atsms/sms'
```

### Service Workers

Cache ATSMS bundle for offline support:

```javascript
// service-worker.js
self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open('atsms-v1').then((cache) => {
      return cache.addAll([
        '/node_modules/@atsms/sms/dist/index.browser.js'
      ])
    })
  )
})
```

## Bundle Size

Browser bundle sizes:
- Full bundle: ~400KB minified (~100KB gzipped)
- Core only: ~200KB minified (~50KB gzipped)
- Tree-shaken: Varies based on usage

## Browser Compatibility

| Feature | Chrome | Firefox | Safari | Edge |
|---------|--------|---------|--------|------|
| Web Crypto | 60+ | 57+ | 11.1+ | 79+ |
| WebSocket | ✅ | ✅ | ✅ | ✅ |
| IndexedDB | ✅ | ✅ | ✅ | ✅ |
| ES Modules | 61+ | 60+ | 11+ | 79+ |

## Troubleshooting

### "crypto.subtle is undefined"

**Cause**: Not using HTTPS or browser doesn't support Web Crypto

**Solution**:
- Use HTTPS in production
- For local dev, use `localhost` not IP address
- Update browser to latest version

### Module resolution errors

**Cause**: Bundler configuration issue

**Solution**: Check your bundler's resolve configuration (see examples above)

### Large bundle size

**Solution**:
- Enable minification
- Use tree-shaking
- Load ATSMS lazily
- Check for duplicate dependencies

## Example Projects

See the `examples/` directory:
- `examples/browser-vanilla/` - Plain HTML/JS
- `examples/browser-react/` - React app
- `examples/browser-vue/` - Vue 3 app
- `examples/nextjs/` - Next.js SSR example

## Further Reading

- [Platform Detection API](./PLATFORM_DETECTION.md)
- [Storage Adapters](./STORAGE_ADAPTERS.md)
- [React Native Guide](./REACT_NATIVE.md)
