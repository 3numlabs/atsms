# React Native Setup Guide

This guide explains how to use ATSMS in React Native applications.

## Requirements

- React Native 0.64+
- Expo SDK 43+ (if using Expo)
- Node.js 15+ (for development)

## Installation

```bash
npm install @atsms/sms
# or
yarn add @atsms/sms
```

## Required Polyfills

React Native doesn't include all Web APIs that ATSMS requires. You need **two** polyfills for full functionality:

1. **`react-native-get-random-values`** - Provides `crypto.getRandomValues()` for random number generation
2. **`@peculiar/webcrypto`** - Provides `crypto.subtle` for key generation, signing, and certificate operations

### Installation

```bash
# Install both polyfills
npm install react-native-get-random-values @peculiar/webcrypto
# or
yarn add react-native-get-random-values @peculiar/webcrypto
# or (Expo)
expo install react-native-get-random-values @peculiar/webcrypto
```

## Setup

### 1. Configure Metro Bundler

React Native's Metro bundler needs to be configured to ignore Node.js-only dependencies. Add this to your `metro.config.js`:

```javascript
const { getDefaultConfig } = require('expo/metro-config');

const config = getDefaultConfig(__dirname);

// Ignore Node.js-only modules
config.resolver.resolveRequest = (context, moduleName, platform) => {
  if (moduleName === 'ws' || moduleName === 'better-sqlite3') {
    return { type: 'empty' };
  }
  return context.resolveRequest(context, moduleName, platform);
};

module.exports = config;
```

### 2. Import and Configure Polyfills

**IMPORTANT**: Set up polyfills at the very top of your app entry point (e.g., `App.tsx`, `_layout.tsx`, or `index.js`), **before** any ATSMS imports:

```typescript
// App.tsx or _layout.tsx (MUST be at the very top!)

// Step 1: Import react-native-get-random-values FIRST
import 'react-native-get-random-values'

// Step 2: Set up @peculiar/webcrypto for crypto.subtle
import { Crypto } from '@peculiar/webcrypto'

// Check if crypto.subtle is missing and initialize it
if (typeof globalThis.crypto?.subtle === 'undefined') {
  globalThis.crypto = new Crypto()
  console.log('✅ Initialized @peculiar/webcrypto for React Native')
}

// Step 3: NOW you can safely import ATSMS
import { ATSMSClient, isCryptoProviderAvailable } from '@atsms/sms'
import { AtpAgent } from '@atproto/api'

// Optional: Verify crypto is available before proceeding
if (!isCryptoProviderAvailable()) {
  console.error('❌ Crypto not available - check polyfill setup')
}

// ... rest of your app
```

**Why both polyfills are needed:**
- `react-native-get-random-values`: Provides `crypto.getRandomValues()` for random bytes
- `@peculiar/webcrypto`: Provides `crypto.subtle` for key generation and certificate operations
- Both must be set up **before** ATSMS imports, or certificate generation will fail

### 3. Verify Platform Support

It's good practice to check that all required features are available:

```typescript
import { checkPlatformRequirements, platform } from '@atsms/sms'

// Check platform at app startup
const requirements = checkPlatformRequirements()

if (!requirements.ok) {
  console.error('Missing platform features:', requirements.missing)
  // Show error to user
}

if (requirements.warnings.length > 0) {
  console.warn('Platform warnings:', requirements.warnings)
}

console.log('Running on:', platform.name) // "react-native"
```

## Storage Adapter

ATSMS requires a SQLite database for local storage. Choose one of these options:

### Option 1: Expo SQLite (Recommended for Expo)

```bash
expo install expo-sqlite
```

```typescript
import * as SQLite from 'expo-sqlite'
import { ATSMSStorageManager } from '@atsms/sms'

// Expo SQLite adapter wrapper
class ExpoSQLiteAdapter {
  private db: SQLite.SQLiteDatabase

  constructor(dbName: string) {
    this.db = SQLite.openDatabase(dbName)
  }

  exec(sql: string): void {
    this.db.exec([{ sql, args: [] }], false, () => {})
  }

  prepare(sql: string) {
    return {
      run: (...params: any[]) => {
        this.db.transaction(tx => {
          tx.executeSql(sql, params)
        })
      },
      get: (...params: any[]) => {
        return new Promise((resolve, reject) => {
          this.db.transaction(tx => {
            tx.executeSql(sql, params, (_, result) => {
              resolve(result.rows.item(0))
            }, (_, error) => {
              reject(error)
              return false
            })
          })
        })
      },
      all: (...params: any[]) => {
        return new Promise((resolve, reject) => {
          this.db.transaction(tx => {
            tx.executeSql(sql, params, (_, result) => {
              const rows = []
              for (let i = 0; i < result.rows.length; i++) {
                rows.push(result.rows.item(i))
              }
              resolve(rows)
            }, (_, error) => {
              reject(error)
              return false
            })
          })
        })
      }
    }
  }

  transaction<T>(fn: () => T): T {
    // Expo SQLite handles transactions differently
    return fn()
  }
}

// Usage
const db = new ExpoSQLiteAdapter('atsms.db')
const storage = new ATSMSStorageManager({
  storage: db,
  // ... other config
})
```

### Option 2: react-native-sqlite-storage

```bash
npm install react-native-sqlite-storage
```

Follow the library's setup instructions for native linking, then create a similar adapter wrapper.

## WebSocket Support

React Native includes WebSocket support natively, so no additional setup is required for real-time messaging features.

```typescript
import { ATSMSWebSocketClient } from '@atsms/sms'

const wsClient = new ATSMSWebSocketClient({
  apiUrl: 'https://inbox.atsms.at',
  did: 'did:plc:...',
  certSerial: '...',
  getToken: async () => 'your-jwt-token'
})

await wsClient.connect()
```

## Complete Example

```typescript
// App.tsx
import 'react-native-get-random-values' // First import!

import React, { useEffect, useState } from 'react'
import { View, Text, Button } from 'react-native'
import { ATSMSClient, checkPlatformRequirements } from '@atsms/sms'
import { AtpAgent } from '@atproto/api'
import * as SQLite from 'expo-sqlite'

export default function App() {
  const [ready, setReady] = useState(false)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    const init = async () => {
      // Check platform
      const requirements = checkPlatformRequirements()
      if (!requirements.ok) {
        setError(`Missing: ${requirements.missing.join(', ')}`)
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

      // Initialize ATSMS
      const client = new ATSMSClient(agent, agent.session!.did)

      setReady(true)
    }

    init().catch(err => setError(err.message))
  }, [])

  if (error) {
    return (
      <View>
        <Text>Error: {error}</Text>
      </View>
    )
  }

  if (!ready) {
    return <Text>Loading...</Text>
  }

  return (
    <View>
      <Text>ATSMS Ready!</Text>
    </View>
  )
}
```

## Troubleshooting

### "crypto.getRandomValues is not available"

**Cause**: Missing `react-native-get-random-values` polyfill

**Solution**: Import it at the very top of your entry file:

```typescript
import 'react-native-get-random-values' // Must be FIRST
```

### "Cannot initialize GeneralName from ASN.1 data" or certificate generation errors

**Cause**: `react-native-get-random-values` only provides `crypto.getRandomValues()`, but certificate generation requires the full Web Crypto API including `crypto.subtle`

**Solution**: Install and set up `@peculiar/webcrypto` BEFORE importing ATSMS:

```typescript
// App entry point (e.g., App.tsx or _layout.tsx)

// Step 1: Import react-native-get-random-values first
import 'react-native-get-random-values'

// Step 2: Set up @peculiar/webcrypto for crypto.subtle
import { Crypto } from '@peculiar/webcrypto'

// Check if crypto.subtle is missing and add it
if (typeof globalThis.crypto?.subtle === 'undefined') {
  globalThis.crypto = new Crypto()
  console.log('Initialized @peculiar/webcrypto for React Native')
}

// Step 3: NOW import ATSMS (after crypto is fully set up)
import { ATSMSClient } from '@atsms/sms'

// Rest of your app...
```

**Installation:**
```bash
npm install @peculiar/webcrypto
# or
yarn add @peculiar/webcrypto
# or
bun add @peculiar/webcrypto
```

### "Web Crypto API not available"

**Cause**: Crypto polyfills not set up before ATSMS import

**Solution**: Follow the complete setup in Step 2 above, ensuring both polyfills are imported **before** ATSMS.

### Metro bundler errors with "ws" or "better-sqlite3" package

**Error**: `Unable to resolve "ws" from "node_modules/@atsms/sms/dist/index.native.js"`

**Solution**: The `ws` and `better-sqlite3` packages are Node.js-only. Configure Metro to ignore them by adding this to your `metro.config.js`:

```javascript
const { getDefaultConfig } = require('expo/metro-config');

const config = getDefaultConfig(__dirname);

config.resolver.resolveRequest = (context, moduleName, platform) => {
  // Ignore Node.js-only modules
  if (moduleName === 'ws' || moduleName === 'better-sqlite3') {
    return {
      type: 'empty',
    };
  }

  // Use default resolution for everything else
  return context.resolveRequest(context, moduleName, platform);
};

module.exports = config;
```

**For plain React Native (non-Expo)**:

```javascript
module.exports = {
  resolver: {
    resolveRequest: (context, moduleName, platform) => {
      if (moduleName === 'ws' || moduleName === 'better-sqlite3') {
        return { type: 'empty' };
      }
      return context.resolveRequest(context, moduleName, platform);
    },
  },
  // ... rest of your config
};
```

### SQLite errors

**Solution**: Make sure you've:
1. Installed expo-sqlite or react-native-sqlite-storage
2. Created a proper adapter wrapper (see examples above)
3. Initialized the storage manager with your adapter

## Bundle Size

The React Native bundle (index.native.js) is optimized for mobile:
- ~400KB minified
- ~100KB gzipped
- Tree-shaking enabled

## Performance Tips

1. **Lazy load certificates**: Don't load all certificates at startup
2. **Use IndexedDB adapter**: If targeting web+RN, consider a cross-platform storage adapter
3. **Batch operations**: Use bulk message send/receive methods
4. **Cache aggressively**: Enable certificate caching in storage manager

## Platform-Specific Features

| Feature | React Native | Notes |
|---------|-------------|-------|
| Web Crypto | ✅ (with polyfill) | Requires react-native-get-random-values |
| WebSocket | ✅ (native) | Built into React Native |
| SQLite | ✅ (with library) | Requires expo-sqlite or similar |
| File System | ✅ | Use react-native-fs if needed |
| Background Tasks | ⚠️ | Limited, use Expo Tasks or native modules |

## Example Projects

See the `examples/` directory for complete working examples:
- `examples/expo-example/` - Expo managed workflow
- `examples/rn-example/` - Plain React Native

## Further Reading

- [Platform Detection API](./PLATFORM_DETECTION.md)
- [Storage Adapters](./STORAGE_ADAPTERS.md)
- [Browser Guide](./BROWSER.md)
