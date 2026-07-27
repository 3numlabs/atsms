# Testing AT-SMS with Two Clients

## Prerequisites

- Two Bluesky accounts (e.g., `chaosmokey.skyfi.social` and `aib0b.bsky.social`)
- App passwords for each (create at bsky.app Settings > App Passwords)
- Local atsms-worker running at `http://localhost:8787`

## Step 1 — Generate certs for both users

```bash
# chaosmokey
bun src/client/atsms.ts init \
  --handle chaosmokey.skyfi.social \
  --endpoint-cert ./chaosmokey-cert.pem \
  --endpoint-key ./chaosmokey-key.pem \
  --email-domain atsms.example.com \
  --publish-to-pds \
  --password 'chaosmokey-app-password'

# aib0b
bun src/client/atsms.ts init \
  --handle aib0b.bsky.social \
  --endpoint-cert ./aib0b-cert.pem \
  --endpoint-key ./aib0b-key.pem \
  --email-domain atsms.example.com \
  --publish-to-pds \
  --password '12345678'
```

`--publish-to-pds` logs in, resolves the real DID, and publishes the cert to the PDS under `at.atsms.x509`. Without it, `init` generates a local cert with a fake test DID, and `send` won't be able to look up the recipient's cert.

## Step 2 — Send a message (chaosmokey to aib0b)

```bash
bun src/client/atsms.ts send \
  --api-url http://localhost:8787 \
  --handle chaosmokey.skyfi.social \
  --sender-cert ./chaosmokey-cert.pem \
  --sender-key ./chaosmokey-key.pem \
  --recipient aib0b.bsky.social \
  --message "Hello from chaosmokey" \
  --password 'jfh73^dshg'
```

This will: log in as chaosmokey, look up aib0b's cert from his PDS, encrypt the message for aib0b's device(s), and send via the local worker.

## Step 3 — Receive as aib0b

```bash
bun src/client/atsms.ts receive \
  --api-url http://localhost:8787 \
  --handle aib0b.bsky.social \
  --endpoint-cert ./aib0b-cert.pem \
  --endpoint-key ./aib0b-key.pem \
  --password '12345678'
```

## Notes

- `init` doesn't take `--api-url` since it only talks to the PDS, not the inbox worker. Only `send` and `receive` need it.
- The `--password` is a Bluesky **app password**, not your main account password.
