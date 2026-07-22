# oracle/

Differential-oracle tooling (beekem-core §11.1).

`beekem-vectors/` drives the upstream `beekem` crate and regenerates
`../test-vectors/beekem-oracle.json`. To run:

1. `git clone https://github.com/inkandswitch/keyhive` **next to this directory**
   (path deps expect `oracle/keyhive/beekem`), pinned to the commit recorded in
   the vector file header.
2. `cd beekem-vectors && rustup override set 1.92.0 && cargo run --release > ../../test-vectors/beekem-oracle.json`

The generator asserts Rust-side that every member decrypts every expected root
secret before emitting vectors.
