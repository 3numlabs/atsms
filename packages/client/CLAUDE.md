# CLAUDE.md

Guidance for Claude Code working in **packages/client** (`@atsms/client`).

## What this is

`packages/client` is the **app-facing SDK** for ATSMS: end-to-end encrypted messaging/calling on AT Protocol
identities. It is an **unreleased prototype** being reshaped in place into **`@atsms/client`** — a clean
two-surface API (a stateless `send()` verb + a stateful `conversations` noun) over the advanced-E2EE engine
`@atsms/dcgka`. Build in place toward that shape; the SDK-monorepo move is a later migration. See the umbrella
the repository [`README.md`](../../README.md) and the specs in [`spec/`](../../spec/).

Layer: **[Protocol]** — this is the open ATSMS core, not Haiven-operator product.

## Commands (bun)

```bash
bun install                 # deps (bun is the package manager, not npm)
bun test src/tests          # test suite (bun:test)
bun test src/tests/foo.test.ts
bun run typecheck           # tsc over lib + tests + scripts (no emit)
bun run build               # 3 bundles (browser/node/native) + tsc .d.ts
bun run build-types         # just tsc (type-check + emit .d.ts, lib only)
bun run lint  / lint:fix
```

`tsc` is **`strict: true`**. `@atsms/dcgka` ships built `.d.ts` (so the client package's tsc uses declarations, not
dcgka source); runtime (bun) still runs dcgka source.

**Two tsconfigs, on purpose.** `tsconfig.json` is the EMIT config: `src/lib` only, `rootDir` set,
declarations to `dist/`. `tsconfig.test.json` extends it for CHECKING — adds `src/tests` and `scripts`,
`noEmit`, and ES2022/esnext (what bun actually runs them under). Before this split the tests were
excluded from every tsc invocation, so a rename could pass `tsc` and fail at runtime one test at a
time — and stale fields (`certSerial` after the §8.5 fingerprint re-keying) sat in transport and
websocket tests for weeks, quietly asserting URLs containing `undefined`. Run `bun run typecheck`
after any refactor.

## Architecture — the two surfaces + their modules

The target API (built, mostly): `ATSMS.create({ identity, storage, transport, pds, rng })` →
`atsms.send({to, payload})` (stateless) and the stateful surface `atsms.conversations.with(did)` /
`.createGroup({members, title})` / `.get(id)` / `.all$`, with membership verbs on the handle
(`convo.addMember/removeMember/grantAdmin/leave`). Two open-verbs on purpose: a DM always exists
(idempotent per pair), a group is created (any number with the same people).

| Module (`src/lib/`) | Role |
|---|---|
| **`client/`** | `ATSMS` — the top-level client: `create()` wiring, inbound envelope **dispatch**, outbound **auto-routing**. `send({to,text})` (stateless one-shots), `conversations.with/createGroup/get/all$`, `peers`, `myDevices()`/`enrolDevice()`, `received$`. |
| **`conversations/`** | Stateful DCGKA surface. `Conversation` (app-facing: `messages$`, `send`, `addMember`, `deliverEnvelope`) wraps `ConversationSession` (sealed + persisted: wraps a `@atsms/dcgka` `Session` + `SealLayer`; every op returns per-recipient `Outbound {to,url,envelope}`; engine state persisted via `Session.serialize()`). |
| **`send/`** | Stateless **X509 baseline** one-shots: sign-then-encrypt (`sealOneShot`/`openOneShot` over the salvaged `prepareMessageForSending` + `decryptAndVerifyMessageSignature`), deterministic `oneShotConvoId`, `oneShotSenderProblem` (signer cert must resolve under the claimed DID). Reaches recipients who are NOT DCGKA-capable. |
| **`identity/`** | `ATSMSPdsClient` (implements dcgka's `PdsClient` over an `@atproto/api` `Agent`; did:web + did:plc), `ATSMSDeviceIdentity` (cert → `DeviceID`/fingerprint + the `PrekeyManager` ring, persisted as a `device_state` blob), capability discovery (`resolveDeviceCapabilities`/`selectGroupPath`), `cert-key` bridge (`deviceFingerprintFromCert/…FromKey`, `identityScalarFromKey`), `seed` (PRF-seed derivation — **debug only**, see below). |
| **`transport/`** | `EnvelopeTransport` interface + `ATSMSWorkerEnvelopeTransport` (opaque sealed-envelope carriage to/from the relay worker: anonymous `POST /inbox/{did}` out; JWT `?type=atsms-envelope` backfill + WS push in; handle-then-delete ack). |
| **`storage/`** | `StorageAdapter` interface; `SQLiteAdapter`, `IndexedDBAdapter` (takes a `dbName` — one DB per account), `EncryptedStorageAdapter` (envelope encryption at rest — see below). Holds messages + conversations + the **`engine_state`** and **`device_state`** blob tables (the DCGKA durable secrets). |
| **`certificates/`** | `ATSMSEndpointCertificate` (self-signed P-256), `getDeviceFingerprint()` + `atUri`, `generate()/generateWithKey()`. |
| **`crypto*.ts`** | The X509/CMS pipeline (sign PKCS#7 / encrypt CMS EnvelopedData via `pkijs` + WebCrypto, ECDH P-256). |
| **`messages.ts`** | `ATSMSMessagePayload`, `createMessagePayload`/`createTextContent`, dialect content types (`atsms/text`, webrtc). |
| **`jwt-auth.ts`** | ATSMS API JWT (ES256, `sub = at://<did>/at.atsms.x509/<deviceFingerprint>`). |

## Load-bearing integration facts

- **`@atsms/dcgka` is a `file:` dep — a COPY, not a symlink.** After ANY dcgka change: `bun run build` in
  dcgka (it must ship `.d.ts`) then **`bun install --force`** here, or the copy is stale.
- **`@noble/curves` must stay `^1.9.x`.** v2 renamed/relocated entry points (`/p256`, `/ed25519`); a v2 hoist
  breaks every dcgka import. (dcgka is on 1.9.7.)
- **Device fingerprint = the full 32-byte SHA-256 of the raw uncompressed P-256 public-key point**
  (`0x04‖X‖Y`, the `subjectPublicKey` value) — lowercase hex; **not** the whole-cert hash, **not** the DER
  SPKI, untruncated. It is the `at.atsms.x509` **and** `at.atsms.prekey` rkey, the per-device worker inbox key,
  and the JWT `sub`/`kid` (the serial→fingerprint re-keying is executed — integration §8.5). Distinct from
  `getFingerprint()` (whole-cert display hash).
- **`AtpAgent` must be imported from `@atsms/client`** (re-exported) by `file:` consumers, never a direct
  `@atproto/api` dep — a second copy's `AtpAgent` is a nominally different class (tsc `#private` mismatch).
  `ATSMSPdsClient`/`ATSMSClient` accept the base `Agent` (so an OAuth session agent works too).
- **`WebSocket`/`ws`** is only dynamically imported on the Node path; browser/RN use the global. Consumers
  bundling for the browser must alias `ws` to a stub (see atsms-web).

## Storage & encryption-at-rest

`StorageAdapter` persists messages/conversations, the **`engine_state`** blob (`Session.serialize()` — live
group ratchet secrets), and the **`device_state`** blob (the prekey ring — admission secrets). These blobs
**must be encrypted at rest** (forward secrecy depends on it).

`EncryptedStorageAdapter` (envelope encryption) decorates any inner adapter:
- **KEK** (device master key) is **injected** by the app from platform secure storage (iOS Keychain,
  Android Keystore, or — debug only — the web PRF seed via `deriveStorageKey`). It only wraps/unwraps.
- **DEK** (data key) is **lib-generated**, does the bulk **XChaCha20-Poly1305** on the blobs, and is stored
  **KEK-wrapped** in a reserved `device_state` keyslot. Wrapping the same DEK under multiple KEKs is what
  enables recovery (a new device unwraps with a recovery KEK, no re-encryption) — future work.
- v1 encrypts **state blobs only** (engine + device); message content is a fast-follow. Rotation is punted
  (the two-layer structure makes it cheap to add).

## Clients

The legacy god-object clients (`src/client/*`, `ATSMSClient`, `ATSMSStorageManager`) are **deleted** as of
the v2 message-format cut-over (2026-07-31); all three reference clients (`atsms-cli`, `atsms-web`,
`atsms-demo`) run on the v2 client. The current thin reference clients are **`atsms-cli/`** (sibling repo, a
REPL over `@atsms/client`) and
**`atsms-web/`** (a browser **debug tool** — its passkey/PRF flow is debug-only, NOT the product identity
model; the product is a native mobile app).

## Known limitation — lost-prekey / lost-state device (SDK-level, unfixed)

If a device loses its local storage (cleared IndexedDB/SQLite, browser eviction, fresh profile) but keeps
its identity key (e.g. passkey-recovered), it keeps the same **fingerprint** but loses its **prekey ring**
(`device_state`) and **conversation sessions** (`engine_state`). A `create`/`welcome` a peer sealed to the
old published prekey can no longer be opened: the dispatcher logs `drop-unopenable`, the transport acks +
deletes, and the device is silently "invited but unjoinable." `reconcileDevices` does NOT heal it — same
fingerprint means the group thinks it's a healthy member and never re-keys it. The real fix is a
device-recovery / re-enrollment flow ("I lost my state — remove + re-admit me"), tracked for the identity
phase. (First seen live 2026-07-27; write-up moved here from atsms-web at its EOL.)

## Message content structure (v2)

The application message is the **v2 content format** — deterministic CBOR, MIMI-congruent — defined in the
[`spec/message-format.md`](../../spec/message-format.md) and implemented in `src/lib/format/`:
`MessageContent` (envelope fields `replaces`/`topicId`/`inReplyTo`/`expires`/`ephemeral`/`fallback` +
`body: Part[]`), a part-kind registry with handling classes (render/apply/signal), **derived** message IDs
(sender + convoId + content + salt — never carried), and 33-byte context-tagged conversation IDs. Build
content with the `format/` constructors (`textPart`, `reactionPart`, `callPart`, …), render via the shared
`renderModel`/`textOf`/`transcriptMessages` helpers (§5.2 unknown-kind policy), and ingest inbound messages
through `storage/apply.ts`'s `ingestMessage` (reaction/edit/retraction projections). The crypto/storage
layers treat the encoded bytes as opaque. The pre-v2 JSON payload (`ATSMSMessagePayload`, `atsms/text`,
`atsms/webrtc`) is deleted.

## Branding

- **`ATSMS`** — everywhere: prose, docs, commits, and code identifiers (`ATSMSClient`, `window.ATSMS`,
  `import * as ATSMS`). **Never hyphenated.** `AT-SMS` is the old spelling and was swept out on
  2026-08-08; do not reintroduce it.
- **`atsms`** — AT Protocol collections (`at.atsms.x509`) and npm scope (`@atsms/client`). Don't "correct" these.
- Avoid in-group jargon in docs/comments/APIs (no "floor"/"facade"); prefer plain terms.

## Code style

- **NO inline imports** — all `import`s at top of file (rare documented exceptions only; CLI dynamic imports ok).
- **`ATSMS` type prefix** for all ATSMS-specific types; types defined once in `types.ts`.
- **P-256 ECDSA only** — no RSA, no algorithm detection.
- **`strict: true`** — no discriminated-union-narrowing kludge casts; fix at the type level.
- **No backward compatibility** — unreleased; refactor freely, add new storage tables, don't keep dead
  variants. (Removed once we publish 0.0.1.)
- Set the crypto provider early in browser environments (`setCryptoProvider()`); `typeof window` for platform
  detection; never serialize/transmit private keys.

## Testing

- `bun:test`, in-memory SQLite / `fake-indexeddb`. Test certs via `src/tests/test-certificates.ts`.
- Integration tests (real PDS/API) gate on env vars (`ATSMS_TEST_HANDLE`, `ATSMS_TEST_PASSWORD`,
  `ATSMS_API_URL`) and skip otherwise.
- The end-to-end suite (`src/tests/atsms-e2e.test.ts`) runs the full `ATSMS` client over a loopback transport +
  mock PDS (open-by-DID, one-shots, multi-device, restart).
