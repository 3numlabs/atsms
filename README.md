# atsms

ATSMS is an open, decentralized protocol for secure group messaging. Its defining goal is to be **open
the way email is open**: any client that follows the protocol can reach any other, across independent
operators, with **no central or always-on server** in the middle — while still delivering strong
end-to-end encryption (forward secrecy, post-compromise security, and real multi-party groups),
self-sovereign identity, and metadata protection. That openness is the constraint everything else
answers to: a protocol that must run without a privileged, always-on coordinator cannot adopt a design
that requires one.

So there is no sequencer, no delivery service, no privileged party. Members change the group whenever
they like, and every device converges on the same keys from whatever order the network delivers.

This repository holds the protocol — its specifications and record schemas — together with the
TypeScript reference implementation: the key agreement engine and the client SDK applications build on.

**Status: BUILT and running.** The engine, the ordering and authentication layer, sealed sender,
identity and lexicon flows, and the SDK integration are all in place, exercised by 138 unit tests plus a
four-scenario simulation fuzz gate, and live-tested across a browser client and a terminal client
against a deployed relay.

**Not reviewed.** BeeKEM has no formal security proof, and the composition here — sealed sender over a
concurrent group key agreement, with the group manager acting as the validity filter for the key tree —
has not been examined by anyone outside the project. External cryptographic review is a **gating
requirement** before this carries real traffic. See [`SECURITY.md`](./SECURITY.md),
[`KNOWN-ISSUES.md`](./KNOWN-ISSUES.md) for what we already know is wrong, and
[`spec/review-scope.md`](./spec/review-scope.md) for the brief we would hand a reviewer.

**Built on [BeeKEM](https://github.com/inkandswitch/keyhive)**, Ink & Switch's concurrent TreeKEM for
local-first systems, under an ATSMS messaging profile. Their implementation is in Rust and ours is in
TypeScript, so we ported it and hold the port to a differential oracle: `oracle/` drives the upstream
crate and `packages/dcgka/test/oracle.test.ts` requires byte-for-byte agreement on shared scenarios. The
layering, group management, ordering and identity designs carry over from the earlier Weidner-DCGKA
phase (CCS 2021, [eprint 2020/1281](https://eprint.iacr.org/2020/1281)), whose core specs are kept as
superseded design records. Pre-BeeKEM state is preserved at git tag **`dcgka-classic-v1`**.

## Running it

```bash
bun install         # one workspace; the client links the engine as a sibling
bun run test        # both packages, including the fuzz gate (a few minutes)
bun run test:unit   # 138 engine + 256 client tests, seconds
bun run test:fuzz   # the four fuzz scenarios only
bun run typecheck
bun run build
```

The specifications and record schemas at the root are the protocol. The packages are one implementation
of it — a second implementation, in another language, would read `spec/` and `lexicons/` and need
nothing from `packages/`.

## Documents

**Start here:** [`spec/overview.md`](./spec/overview.md) — goals, threat model, limitations, and a
map of the layers.

| Doc | What |
|---|---|
| [`spec/`](./spec/) | The normative spec set. Core: [`beekem-core.md`](./spec/beekem-core.md) (tree + messaging profile: DGM-filtered ops, `rootCommit`, per-sender chains, coverage, eviction, checkpoints), [`dgm.md`](./spec/dgm.md) (membership, roles, strong remove — also the tree's validity filter), [`ordering-auth.md`](./spec/ordering-auth.md) (causal delivery: deps and readiness, key rotation, repair, re-invitation). Around them: [`identity-devices.md`](./spec/identity-devices.md), [`sealed-sender.md`](./spec/sealed-sender.md), [`group-state.md`](./spec/group-state.md), [`wire-format.md`](./spec/wire-format.md), [`atsms-integration.md`](./spec/atsms-integration.md), [`parameters.md`](./spec/parameters.md) |
| [`KNOWN-ISSUES.md`](./KNOWN-ISSUES.md) | What we know is broken or unfinished, from live testing |
| [`AI.md`](./AI.md) | How AI was used to build this, what it did not do, and why authorship was never the trust model |
| [`TODO.md`](./TODO.md) | Work on the repository itself, rather than the protocol — currently what stands between these packages and npm |
| [`spec/review-scope.md`](./spec/review-scope.md) | The brief we would hand a security reviewer, including the questions we cannot answer ourselves |
| [`spec/loss-and-reordering.md`](./spec/loss-and-reordering.md) | Every message type audited against "what if this is dropped" and "what if this arrives out of order" |
| [`packages/client`](./packages/client) | **`@atsms/client`** — the TypeScript SDK an application uses: `send()`, `conversations`, storage adapters, transport, AT Protocol plumbing |
| [`packages/dcgka`](./packages/dcgka) | **`@atsms/dcgka`** — the group key agreement engine the client builds on |
| [`lexicons/`](./lexicons/) | The three AT Protocol record schemas the protocol defines: `at.atsms.x509` (a device's endpoint certificate), `at.atsms.prekey` (its bootstrap key), `at.atsms.inbox` (where to reach an identity) |
| [`proposals/`](./proposals/) | Protocol ideas that are **not yet the protocol**. Nothing in `spec/` depends on them. Currently [0001 — group drop point](./proposals/0001-group-drop-point.md) |
| [`docs/history/`](./docs/history/) | How the design was arrived at: the BeeKEM decision, the two gate spikes, the alternatives rejected, and the earlier plans. Not normative |

## Two things worth knowing before you read the specs

**The layers are separable, and that is why the core could be replaced.** Ordering, group management,
sealed sender and identity were each designed against an abstract group-key core rather than against a
particular one. When the core changed — the original DCGKA construction swapped out for BeeKEM — it was a
bounded rewrite rather than a restart. If you are reading one layer, you can mostly ignore the others.

**BeeKEM was built for document sync, and messaging wants the opposite.** In a shared document, anyone
who gains access should be able to read the whole history, so nothing is ever thrown away. Messaging
needs old keys to die. That difference is the source of every deviation in the messaging profile —
eviction, coverage, checkpoints, and the root commitment — and
[`spike-a-messaging-profile.md`](./docs/history/spike-a-messaging-profile.md) works through why each one
exists. Where the port must match upstream exactly, the differential oracle enforces it; above that
boundary, our own frozen test vectors do.
