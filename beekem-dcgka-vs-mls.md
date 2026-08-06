# How ATSMS's BeeKEM DCGKA works — and how it differs from MLS

> **Explainer, not a spec** (2026-07-30). The important aspects only.

## What ATSMS is for

ATSMS is an open, decentralized protocol for secure group messaging. Its defining goal is to be **open the way
email is open**: any client that follows the protocol can reach any other, across independent operators, with
**no central or always-on server** in the middle — while still delivering strong end-to-end encryption
(forward secrecy, post-compromise security, and real multi-party groups), self-sovereign identity, and
metadata protection. That openness goal is why the comparison below opens where it does: a protocol that must
run without a privileged, always-on coordinator cannot adopt a design that requires one.

## The one-sentence difference

**MLS requires all members to agree on exactly one Commit per epoch, which needs an ordering authority (a
per-group sequencer / Delivery Service). Our BeeKEM DCGKA is concurrency-native: members issue operations
concurrently and converge from a causal partial order — no sequencer, no privileged relay role.**

Everything else follows from that. We chose this concurrency-native design because of a hard constraint: *no
protocol correctness may depend on any always-on infrastructure role* — relays store-and-forward and are
swappable.
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
plain TreeKEM can't do without a sequencer. (Below the `PcsKey` boundary the tree is byte-for-byte the Ink & Switch
`beekem` Rust crate; our profile layer sits above it.)

**3. Epochs, healing (PCS), and the application ratchet.**
In both, a member heals a compromise by updating its leaf. In MLS that heal is a **Commit that must be
accepted** (i.e., ordered/agreed). In ours, PCS takes effect **on processing the update — no ack round-trip**.
Above the per-epoch root secret (`PcsKey_e`) we run **per-sender FS-AEAD chains** for message keys (forward
secrecy within an epoch), each seeded from that epoch's root secret. These are the well-understood
**"sender keys"** construction — the same symmetric-only forward-secure ratchet Signal uses for *group*
messages and MLS uses for its per-epoch application keys (*not* Signal's pairwise Double Ratchet; there is no
per-message Diffie-Hellman). That means the chains give forward secrecy but **not** post-compromise security on
their own: PCS comes entirely from re-keying the BeeKEM tree (a new `PcsKey_e` reseeds every chain). MLS
divides the same labor the same way — TreeKEM for PCS, application-ratchet keys for in-epoch forward secrecy —
though MLS arranges those keys as a tree indexed by member position, while we keep a simpler
one-chain-per-sender set.

**4. Membership (the cost of having no sequencer).**
MLS handles Add/Remove/Update via Proposals + Commits, and because the Delivery Service **linearizes** them,
"who is in the group" is decided by ordinary policy over an already-ordered log — little design burden. We pay
for concurrency here: we need a **DGM (Dynamic Group Management)** that resolves *concurrent* membership changes
correctly — notably **strong remove** (a removal takes effect even when it races other ops, so you can't be
"un-removed" by a concurrent update). This isn't our invention: the DGM's required properties (determinism,
add-only entry, no-remove-undo, convergence) are the proof obligations from the **Weidner et al. DCGKA paper**
(CCS 2021), and the **strong-remove** resolver semantics come from the **p2panda-auth** project's
`StrongRemove` — both from the decentralized-access-control literature. What *is* ours is the integration:
since adopting BeeKEM, the DGM also acts as the **validity filter** for the ratchet tree. Every membership or
key operation is applied to the tree *only if* the DGM judges it valid at its position in the causal history;
an operation ruled invalid (say, a `remove` issued by a non-admin, or an op from an already-removed device)
still exists in the log as history but never changes any key. Because that judgment is deterministic over the
same set of operations, every member filters down to the identical subset — which is exactly what lets all
replicas converge on the same tree and keys. Even so, resolving concurrent membership was our single biggest design risk — the
price of not having a linearizer.

**5. Identity & authentication — where MLS leaves the choices open.**
Unlike the sections above, this is *not* really a protocol-level difference — it's the layer where MLS is
deliberately a framework and ATSMS is one concrete way to fill it in. MLS ties each leaf to a **Credential**
(it defines `basic` and `x509`, plus an extension point for custom types) validated by an abstract
**Authentication Service** *role* — which a deployment can realize as a CA, a key-transparency log, or any PKI
it likes. MLS leaves are already per-client, so "one device = one leaf" is MLS's model too, not a divergence;
MLS members can even rotate their leaf signing key. An MLS deployment that bound leaves to AT Protocol DIDs and
treated the DID PKI as its Authentication Service would land in nearly the same place we do.

What ATSMS *fixes concretely*: identity is a self-sovereign **AT Protocol DID**; a device's leaf/signing
authority chains from its **`at.atsms.x509` endpoint certificate** published in the DID repo — publishing the
cert is itself the act of delegating authentication to it — so the "Authentication Service" is just the
DID/repo PKI with **no central issuer**, the same principle that runs through the rest of the design: no
privileged, always-on party is trusted for correctness. On top of that the per-message **protocol signing
key rotates** on each control op, extending PCS to *authenticity* (its initial value is pinned in the prekey
bundle).

The same holds for compromise recovery, and it's worth being explicit that this is *not* a difference from
MLS. Healing a leaked ephemeral key by **rotating your leaf in place** — versus **removing and re-adding** a
device when its durable identity key is lost or stolen — is the ordinary CGKA distinction between an *update*
and a *remove*, and MLS works the same way (an MLS Update self-heals a leaf; a compromised credential is
handled by Remove + re-Add plus identity-layer revocation). The only difference is the concurrency one this
document keeps returning to: MLS applies that update or remove as a single agreed commit per epoch, whereas
here it takes effect on processing, with strong-remove resolving concurrent removals.

**6. Delivery, addressing & metadata.**
MLS deliberately *abstracts delivery away*: it posits a **Delivery Service** that fans messages out in order
(and an **Authentication Service** for credentials), but says nothing about how you find a party or where their
messages go — addressing and transport are left to each deployment. And that Delivery Service is necessarily an
ordered, typically centralized server, because it's what agrees one commit per epoch (the concurrency point
above).

ATSMS instead makes delivery **part of the protocol**: every identity publishes *where its inbox lives* — an
`at.atsms.inbox` record in its AT Protocol repo, alongside the endpoint certificate — so any conforming client
can resolve any other and deliver straight to it. Resolution is the ordinary DID path: the DID document names
the identity's repo host, and the inbox record is read from the repo itself, so discovery needs no shared
directory — across independent operators, exactly the way any mail server can reach any email address. The
transport underneath is only **dumb store-and-forward**, and relays are commodity and swappable: no centralized
or privileged server sits in the middle, and correctness never depends on any particular one being up. **This
is what makes ATSMS open the way email is open** — you reach anyone by resolving their published address, not by
joining a single network behind a shared interop API.

One refinement keeps that openness cheap on privacy: the public `at.atsms.inbox` address carries only **first
contact** — welcomes and invites, where the two parties share no secret yet. Once a conversation exists, each
device advertises its ongoing delivery endpoint **in-band, inside the authenticated group channel** (learned
peer-to-peer, never published), so the high-volume, linkable traffic address never appears in any public
record. The public footprint stays exactly one inbox entry.

Layered on that addressing is **sealed sender** (an asymmetric bootstrap, then symmetric in-conversation
envelopes), so a relay or observer learns *neither the sender's identity nor the message class* — only the
destination mailbox, the arrival time, and the **coarse size bucket** the envelope falls into (every message is
padded up to a fixed bucket, so its true length stays hidden). MLS leaves metadata protection out of scope
entirely; here it's native.

**7. Maturity & assurance.**
This is where MLS is ahead. **MLS is RFC 9420**, with audited implementations (OpenMLS) and formal security
analysis of TreeKEM. **BeeKEM is novel** (an Ink & Switch research design) with **no formal proof** yet; we
mitigate with a **differential oracle** (below the `PcsKey` boundary our TypeScript port must be byte-equivalent
to the Rust `beekem` crate on shared scenarios) + a convergence fuzz harness, and **external cryptographic review
is a gating requirement before v1 alpha carries real traffic.**

## Summary

| Aspect | MLS (RFC 9420) | ATSMS BeeKEM DCGKA |
|---|---|---|
| Agreement model | One Commit **agreed** per epoch (linear epochs) | Concurrent ops, **causal DAG**, provable convergence |
| Ordering authority | **Delivery Service / sequencer** (per group) | **None** — no sequencer, no privileged relay |
| Tree | TreeKEM, blank nodes, one path/Commit | Concurrent TreeKEM, **conflict keys**, deterministic merge |
| PCS heal | On accepted Commit | **On processing** an update (no ack round-trip) |
| Membership | Proposals/Commits, linearized by the DS | **DGM** with **strong remove** (concurrency-safe) |
| Identity | **Pluggable** — Credentials + abstract Authentication Service role | One concrete fill-in: self-sovereign DID, endpoint cert in the DID repo, **no central issuer** |
| Delivery & addressing | Abstract Delivery Service (ordered); addressing left to the deployment | **In-protocol inbox discovery** (`at.atsms.inbox`); dumb, swappable store-and-forward relays |
| Metadata privacy | Out of scope | **Sender + message-class hidden** from relays/observers |
| Maturity | RFC, audited impls, proofs | Novel; oracle-tested + fuzzed; **external review gating** |

## The trade in one line

We give up MLS's **maturity and formal assurance** (mitigated by review + a differential oracle) and take on a
**DGM design burden**, in exchange for the thing MLS can't give us: **no sequencer, no privileged or always-on
server, local-first correctness, and native sealed-sender metadata protection** — exactly the properties that
let ATSMS be open the way email is open, where any conforming client reaches any other with no central server
in the middle.
