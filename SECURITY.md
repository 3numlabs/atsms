# Security policy

## Read this first: the cryptography has not been independently reviewed

ATSMS is a **proof of concept**. It implements a novel composition — sealed sender over a concurrent
group key agreement, with a dynamic group manager acting as the validity filter for the ratchet tree —
and **no external cryptographic review has taken place**. Such a review is a gating requirement before
any of this carries real traffic, and it has not happened yet.

Do not use this to protect anything that matters. We say the same thing in the demo before you sign in.

## What we do claim

We did not invent primitives. The tree below the `PcsKey` boundary is a port of Ink & Switch's Rust
`beekem` crate, validated against it by a differential oracle — on shared scenarios the two
implementations must agree byte for byte — plus a convergence fuzz harness. The group-management
obligations come from Weidner et al. (CCS 2021) and the strong-remove semantics from p2panda-auth.

What is genuinely new is the *composition*, and that is exactly the part nobody has checked.

## We publish our own weak spots

Two documents are maintained deliberately, and we would rather you read them than rediscover them:

- **[`KNOWN-ISSUES.md`](./KNOWN-ISSUES.md)** — findings from live testing, including the ones still
  open: forward secrecy that no code currently enforces, welcomes that outgrow their size bucket until a
  group can no longer accept members, and application-message loss with no recovery path built.
- **[`spec/review-scope.md`](./spec/review-scope.md)** — the brief we would hand a reviewer: what is
  novel, what is unfinished, and the specific questions we want answered.

If you are looking for somewhere to dig, start there. Several entries are open invitations.

## Reporting a vulnerability

Please report privately rather than opening a public issue, using **GitHub's private vulnerability
reporting** on this repository (Security → Report a vulnerability).

Tell us what you found, how to reproduce it, and what you think the impact is. We will confirm receipt,
work the issue with you, and credit you in the fix unless you would rather we did not. Since this
protects no production traffic today, we would rather move fast and be honest than run a formal embargo
process.

## Scope

In scope: the protocol and its implementations in this repository and the ATSMS client libraries and
reference clients — key agreement, group management and authorization, the ordering and repair layer,
the sealed-envelope format, and identity binding through AT Protocol records.

Out of scope: the primitives themselves (X25519, XChaCha20-Poly1305, P-256 ECDSA, HPKE, BLAKE3, SHA-256),
availability of any relay we happen to run, and anything in a repository marked end-of-life.
