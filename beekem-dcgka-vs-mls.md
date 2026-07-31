# How ATSMS's BeeKEM DCGKA works — and how it differs from MLS

> **Explainer, not a spec** (2026-07-30). The important aspects only — for the full normative detail see
> [`spec/overview.md`](spec/overview.md) (entry point), [`spec/beekem-core.md`](spec/beekem-core.md) (the tree
> + key schedule), [`spec/dgm.md`](spec/dgm.md) (membership), [`spec/ordering-auth.md`](spec/ordering-auth.md)
> (causal ordering + signing), and [`spec/sealed-sender.md`](spec/sealed-sender.md). The design rationale for
> choosing this over MLS is in [`mls-analysis.md`](mls-analysis.md) and [`beekem-analysis.md`](beekem-analysis.md).

## The one-sentence difference

**MLS requires all members to agree on exactly one Commit per epoch, which needs an ordering authority (a
per-group sequencer / Delivery Service). Our BeeKEM DCGKA is concurrency-native: members issue operations
concurrently and converge from a causal partial order — no sequencer, no privileged relay role.**

Everything else follows from that. We chose it because of a hard constraint (decision **D0**): *no protocol
correctness may depend on any always-on infrastructure role* — relays store-and-forward and are swappable.
MLS-with-a-sequencer violates that; a concurrent CGKA doesn't.

Both are **CGKAs** (Continuous Group Key Agreement) built on a **ratchet tree (TreeKEM)** and both deliver the
same headline guarantees — confidentiality, **forward secrecy**, and **post-compromise security**. The
differences are all about *how agreement is reached* and *what infrastructure is assumed*.

## The important aspects

**1. Ordering & concurrency — the crux.**
MLS has **linear epochs**: each Commit advances the group to the next epoch, and RFC 9420 requires that
everyone apply *the same* Commit for a given epoch — concurrent Commits *fork* the group, so the losers must
be rejected and retried. In practice that agreement is the job of a **Delivery Service** that linearizes
Commits (a sequencer role). Our design instead keeps operations in a **causal DAG** (each op names its causal
predecessors); members apply ops in any causal-respecting order and **provably converge** on the same tree and
keys (Weidner-DCGKA Lemma 8). Concurrent updates to the same tree path are merged deterministically with
**conflict keys** (BeeKEM's contribution). No single-winner-per-epoch, no fork to resolve, no sequencer.

**2. The ratchet tree.**
Both use a binary TreeKEM tree — leaves are members' (here: devices') public keys, inner nodes hold subgroup
secrets, an update re-keys a leaf-to-root path in ~O(log n). MLS uses *blank nodes* and one path update per
Commit. **BeeKEM** is a *concurrent* TreeKEM: when two members update overlapping paths concurrently, it
records **conflict keys** and replays deterministically so every replica lands on the same tree — the thing
plain TreeKEM can't do without a sequencer. (Below our `PcsKey` seam the tree is byte-for-byte the Ink & Switch
`beekem` Rust crate; our profile layer sits above it.)

**3. Epochs, healing (PCS), and the application ratchet.**
In both, a member heals a compromise by updating its leaf. In MLS that heal is a **Commit that must be
accepted** (i.e., ordered/agreed). In ours, PCS takes effect **on processing the update — no ack round-trip**.
Above the per-epoch root secret (`PcsKey_e`) we run **per-sender FS-AEAD chains** for message keys (forward
secrecy within an epoch), seeded from the tree root — analogous in spirit to MLS's secret tree / key schedule,
but organized per-sender and epoch-scoped with an explicit eviction/GC discipline.

**4. Membership (the cost of having no sequencer).**
MLS handles Add/Remove/Update via Proposals + Commits, and because the Delivery Service **linearizes** them,
"who is in the group" is decided by ordinary policy over an already-ordered log — little design burden. We pay
for concurrency here: we need a **DGM (Dynamic Group Management)** that resolves *concurrent* membership changes
correctly — notably **strong remove** (a removal takes effect even when it races other ops, so you can't be
"un-removed" by a concurrent update). The DGM was our single biggest design risk; it's the price of not having
a linearizer.

**5. Identity & authentication.**
MLS binds identity to a leaf via **Credentials** (X.509 or "basic") + a signature key, verified against an
**Authentication Service**. Ours: **each device is a member**, its identity is the **AT Protocol DID**, and its
leaf/signing authority chains from its **`at.atsms.x509` endpoint certificate** published in the DID repo
(delegation = publication). The per-message **protocol signing key rotates** on each of a member's control ops
(PCS for *authenticity*, not just confidentiality) — its initial value is declared in the prekey bundle. No
central AS; trust roots in the DID/repo.

**6. Delivery & metadata.**
MLS assumes two infrastructure roles: a **Delivery Service** (ordered fan-out) and an **Authentication
Service**. Ours assumes **neither** — a **dumb store-and-forward relay** (or SMTP, or gossip) over
`at.atsms.inbox`, plus **sealed sender** (HPKE-bootstrapped, symmetric in-conversation envelopes) so a relay or
observer learns *neither the sender identity nor the message class* — only mailbox, timing, and padded size.
MLS says nothing about metadata protection; it's native here.

**7. Maturity & assurance.**
This is where MLS is ahead. **MLS is RFC 9420**, with audited implementations (OpenMLS) and formal security
analysis of TreeKEM. **BeeKEM is novel** (an Ink & Switch research design) with **no formal proof** yet; we
mitigate with a **differential oracle** (below the `PcsKey` seam our TypeScript port must be byte-equivalent to
the Rust `beekem` crate on shared scenarios) + a convergence fuzz harness, and **external cryptographic review
is a gating requirement before v1 alpha carries real traffic.**

## Summary

| Aspect | MLS (RFC 9420) | ATSMS BeeKEM DCGKA |
|---|---|---|
| Agreement model | One Commit **agreed** per epoch (linear epochs) | Concurrent ops, **causal DAG**, provable convergence |
| Ordering authority | **Delivery Service / sequencer** (per group) | **None** — no sequencer, no privileged relay (D0) |
| Tree | TreeKEM, blank nodes, one path/Commit | Concurrent TreeKEM, **conflict keys**, deterministic merge |
| PCS heal | On accepted Commit | **On processing** an update (no ack round-trip) |
| Membership | Proposals/Commits, linearized by the DS | **DGM** with **strong remove** (concurrency-safe) |
| Identity | Credentials + AS | **Device = member**, AT Proto DID + endpoint cert; rotating signing keys |
| Delivery infra | DS (ordered) + AS assumed | Dumb relay / SMTP / gossip; **sealed sender** built in |
| Metadata privacy | Out of scope | **Sender + message-class hidden** from relays/observers |
| Maturity | RFC, audited impls, proofs | Novel; oracle-tested + fuzzed; **external review gating** |

## The trade in one line

We give up MLS's **maturity and formal assurance** (mitigated by review + a differential oracle) and take on a
**DGM design burden**, in exchange for the thing MLS can't give us: **no sequencer, no privileged relay role,
local-first correctness, and native sealed-sender metadata protection** — the properties the Bourbon Protocol's
"relay is dumb and swappable" north star (D0) requires.
