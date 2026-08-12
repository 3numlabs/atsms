# AI disclosure

Most of the code in this repository was written by an AI. This document says exactly what that means,
because anyone deciding how far to trust this project should not have to reconstruct the answer from
commit history.

## What was used, and for what

Anthropic's Claude models, working through Claude Code in long interactive sessions with the maintainer.
Within those sessions, the AI drafted:

- most of the TypeScript in `packages/dcgka` and `packages/client`, and their test suites
- the differential-oracle harness and the convergence fuzz harness
- much of the specification prose, this repository's documentation, and the measurement scripts

The maintainer directed the work and owns every decision in it: the architecture, what to build, what to
reject, and when something the AI produced was wrong — which happened, and is part of why the
verification below exists. Protocol decisions are recorded in the specifications with dates and explicit
sign-off (the D-numbers, e.g. `spec/parameters.md`), and the majority of commits carry a
`Co-Authored-By` trailer naming the model. The trailer is a marker of assistance, not an audit trail.

## What the AI did not do

It did not invent cryptography, and we would not have accepted it if it had tried. The constructions
here are published research: BeeKEM ([Ink & Switch](https://github.com/inkandswitch/keyhive)), the DCGKA
framework of Weidner, Kleppmann, Hugenroth and Beresford (CCS 2021), and p2panda's strong-remove
semantics. The tree core is a port, and the port is held to a **differential oracle**: `oracle/` drives
Ink & Switch's Rust implementation through the same scenarios as our TypeScript, and the test suite
requires byte-for-byte agreement on the key material. When the two disagree, ours is presumed wrong.

## Why authorship is not the trust model

This project was designed so that you do not have to trust its authors — and that holds whether the
author is a person or a model:

- the differential oracle above, for the cryptographic core
- several hundred unit tests and a multi-scenario convergence fuzz gate (`bun run test`)
- live multi-device, multi-client testing against a deployed relay, with the findings published rather
  than fixed quietly ([`KNOWN-ISSUES.md`](./KNOWN-ISSUES.md))
- an **external cryptographic review as a gating requirement** before any of this carries traffic that
  matters ([`SECURITY.md`](./SECURITY.md), [`spec/review-scope.md`](./spec/review-scope.md))

A hand-written implementation with the same verification would deserve exactly as much trust as this
one. Neither deserves it before the review.

## The limits of AI

AI-written code can be wrong in ways that are fluent enough to pass a casual read — that is a good prior
for a reviewer to hold, and we hold it ourselves. It is one more reason the review gate exists, not a
reason to trust the project less than its verification supports. `KNOWN-ISSUES.md` is the running record
of what live testing has actually found.

## Contributions

If you contribute, say in the pull request whether and how AI was used. Either way, you are responsible
for what you submit, and it will be reviewed on what it is rather than on how it was made.
