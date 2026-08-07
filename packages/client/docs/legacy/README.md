# Legacy documentation — describes an API that no longer exists

These documents predate the v2 message-format cut-over (2026-07-31), which deleted the god-object
clients (`ATSMSClient`, `ATSMSStorageManager`) they are written against. They are kept for history and
for the design reasoning inside them; **do not follow their instructions**.

For the current API see the repository [`CLAUDE.md`](../../CLAUDE.md) and the umbrella
`docs/sdk-shape.md`. For a working example, read `atsms-cli` — it is a thin REPL over the public client
API and is deliberately small enough to read in one sitting.
