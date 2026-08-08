# oracle/

Differential-oracle tooling (beekem-core §11.1).

`beekem-vectors/` drives the upstream `beekem` crate and regenerates
`../test-vectors/beekem-oracle.json`. To run:

1. `git clone https://github.com/inkandswitch/keyhive` **next to this directory**
   (path deps expect `oracle/keyhive/beekem`), checked out at the commit recorded
   in the `generator` field of `../test-vectors/beekem-oracle.json`.
2. Generate, passing the upstream commit so the next reader can reproduce what
   you produced:

   ```bash
   cd beekem-vectors
   rustup override set 1.92.0
   KEYHIVE_COMMIT=$(git -C ../keyhive rev-parse HEAD) \
     cargo run --release > ../../test-vectors/beekem-oracle.json
   ```

   Vectors generated without `KEYHIVE_COMMIT` record `unrecorded` and cannot be
   reproduced exactly. The vectors currently in the repository predate this and
   name only a date (2026-07-09); regenerating replaces that with a commit.

The generator asserts Rust-side that every member decrypts every expected root
secret before emitting vectors.
