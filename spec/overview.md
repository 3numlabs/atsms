# spec/overview.md — ATSMS Advanced E2EE (BeeKEM): Protocol Overview & Threat Model

> **Status: DRAFT v0.2 (2026-07-22) — for review.** *(v0.2: D11 — the CGKA core is BeeKEM;
> dcgka-core/2sm superseded by [`beekem-core.md`](./beekem-core.md); doctrine #4, §5 performance, and
> §6 limitations re-based.)* [Protocol] · Phase 0/0b deliverable.
> Closes gaps **G16** (size/performance envelope) and **G17** (security-model fine print) from
> [`../docs/history/gap-analysis.md`](../docs/history/gap-analysis.md).
> **This document supersedes [`../docs/history/atsms-dcgka-spec.md`](../docs/history/atsms-dcgka-spec.md) (v1.1) as the entry point**
> to the specification; where the one-page spec and the `spec/` set conflict, the `spec/` set wins. The
> one-page spec remains as design history (its §4.1 cert-profile and §6–§9 design notes are consolidated
> into the sub-specs listed below). MUST/SHOULD/MAY per RFC 2119.

## 1. What this protocol is

This is the advanced end-to-end encryption layer of the Bourbon Protocol:
**decentralized secure group messaging with sealed-sender metadata protection over untrusted
store-and-forward mailboxes**, based on **BeeKEM** (Ink & Switch's concurrent TreeKEM variant for
local-first systems — decision **D11**, 2026-07-22, [`../docs/history/beekem-analysis.md`](../docs/history/beekem-analysis.md))
under an ATSMS messaging profile ([`beekem-core.md`](./beekem-core.md)). The DGM, ordering, sealed-sender,
and identity layers carry over from the Weidner-DCGKA design phase (eprint 2020/1281 — its
proof-shaped layering remains this spec set's skeleton; dcgka-core.md/2sm.md are retained as superseded
design records). It replaces the crypto core of `packages/client` (`@atsms/client`) while layering **over** — not
replacing — the X509/S-MIME interop floor (decision D1; [`atsms-integration.md`](./atsms-integration.md)).

Properties delivered (each with its owning sub-spec):

- **Confidentiality & integrity** — only current group members decrypt; per-sender FS-AEAD chains over
  per-epoch tree root secrets ([`beekem-core.md`](./beekem-core.md)).
- **Forward secrecy** — compromised state reveals no past messages (deletion/eviction discipline,
  beekem-core §7/§8 — a deliberate divergence from Keyhive's retain-forever document-sync posture).
- **Post-compromise security** — leaf-rotation updates heal the group **on processing, no ack
  round-trip** (beekem-core §5); signing keys rotate too ([`ordering-auth.md`](./ordering-auth.md) §5).
- **Decentralized consistency** — eventual agreement on membership and keys with **no ordering server, no
  sequencer, no privileged relay role** (D0, hard constraint); convergence from a causal partial order
  ([`dgm.md`](./dgm.md), ordering-auth).
- **Sealed sender** — providers and observers learn neither sender identity nor message class
  ([`sealed-sender.md`](./sealed-sender.md)).
- **Multi-device** — each device is an independent protocol member; rotation/loss/compromise collapse to
  one mechanism ([`identity-devices.md`](./identity-devices.md)).
- **DMs are 2-member groups** (D6) — one code path, FS/PCS for DMs included.

## 2. Design doctrine (the non-negotiables)

1. **Local-first, transport-agnostic** (user decision D0, 2026-07-14): no protocol *correctness* may
   depend on any specific always-on infrastructure role. Relays store and forward; every one of them is
   swappable. This is why MLS-with-sequencer was rejected and DCGKA chosen.
2. **Layer over the X509 floor** (D1): X509/S-MIME remains the interop baseline (email bridge, legacy
   endpoints); DCGKA is the default between capable endpoints, selected by capability discovery. Refined
   by **D9 (2026-07-22)**: the floor is *identity + signing* — X509 certs, JWT auth, CMS `SignedData`;
   every ATSMS encryption path is HPKE to raw keys (no CMS `EnvelopedData` except inbound classic S/MIME
   from external senders — sealed-sender §10).
3. **Devices are members**: the group-membership unit is the device, identified by its endpoint-cert
   keypair; identity is the AT Protocol DID; delegation is publication in the DID repo
   (identity-devices.md §1–§2).
4. **The reference implementation + frozen vectors are the contract** *(re-based 2026-07-22 by D11 —
   BeeKEM has no formal security proof, §6.1)*: below the `PcsKey` seam the port MUST be byte-equivalent
   to the `beekem` Rust crate on shared scenarios; every profile addition above the seam is explicit,
   allowlisted, and pinned by our frozen vectors (beekem-core §11). **External cryptographic review is a
   gating requirement before v1 alpha carries real traffic** (was a scheduled mitigation; §6.13).
5. **TypeScript v1** (D3) with audited `@noble/*` primitives; the `beekem` crate is porting reference and
   differential-test oracle; engine kept behind a serialize-in/out boundary for a later Rust swap.

## 3. Layer stack & document map

```
┌ Application: dialects (ATSMSMessagePayload: atsms/text, atsms/webrtc, …)  — unchanged, rides as plaintext
├ BeeKEM core: ratchet tree (membership ops, path encryption, conflict-key
│    merge/replay) + ATSMS messaging profile (per-sender chains, coverage,
│    eviction, checkpoints, rootCommit)                                     — beekem-core.md
│    └ DGM: pure membership function (strong remove, roles) — also the
│         validity filter gating tree application (D11)                    — dgm.md
├ Ordering & authentication: causal delivery (deps, FIFO, signatures,
│    replay, repair, stale-member surfacing) — BeeKEM's assumed substrate   — ordering-auth.md
├ Sealed sender: two modes — HPKE bootstrap envelope + symmetric
│    in-conversation envelope (pseudonymous tags); padding, anon ingress    — sealed-sender.md
└ Delivery: baseline HTTPS mailbox (MANDATORY), WebSocket, P2P, SMTP, Tor   — spec v1.1 §7 + atsms-integration.md
     └ Inbound contract (common ATSMS): at.atsms.inbox discovery + bindings +
          per-DID intake → per-device fan-out (payload-agnostic)             — inbound-delivery.md

Identity (vertical): DID → endpoint cert → {prekey record,
     protocol signing keys}; PDS records                                    — identity-devices.md
Bytes (vertical): deterministic CBOR, every schema, labels, test vectors    — wire-format.md
Constants: every tunable in one registry                                    — parameters.md
Integration: @atsms/client + atsms-worker changes, migration                   — atsms-integration.md
Superseded design records (D11): dcgka-core.md, 2sm.md
```

Gap coverage: G1→dissolved by D11 (no pairwise channel; record in beekem-core);
G2/G3/G7/G11/G15→beekem-core; G4/G12→ordering-auth; G5/G14→dgm; G6/G8→identity-devices;
G9→sealed-sender; G10→atsms-integration; G13→wire-format; G16/G17→this document.

## 4. Threat model

**Adversary capabilities assumed:**

- Full passive observation of every transport and mailbox (all ciphertext + delivery metadata).
- Active network control: drop, delay, reorder, replay, inject (signatures/dedup/readiness defend —
  ordering-auth §1).
- **Adaptive device compromise**: full state of any device at chosen times, with recovery expected via PCS
  (but see the non-adaptive-proof caveat, §6).
- Malicious mailbox providers: store/forward infrastructure that may withhold selectively (surfaced, not
  prevented — §6), correlate what it sees, and collude with observers. It does **not** break crypto.
- Malicious *members*, for metadata and DoS: a member sees in-group metadata by design; an equivocating
  member is detectable and removable (dgm.md §8), not preventable.
- Hostile or compromised PDS: can serve stale/mixed records (signatures reject — identity-devices §4.3) and
  can deny service; in alpha, trust-the-PDS resolution is a documented relaxation (identity-devices §1).

**Trust anchors:** the user's DID signing key (self-sovereign, user-held); each device's endpoint-cert
key. Nothing else is trusted for confidentiality or authenticity — relays and PDSes are liveness roles.

## 5. Performance & size envelope (G16 — normative budget)

- **Group size: typical 25, maximum 150 — counted in DEVICES**, not users (25 users × 3 devices = 75
  members; identity-devices §5). All O(n) statements count devices. Registered in
  [`parameters.md`](./parameters.md).
- Per-operation cost *(re-based 2026-07-22, D11)*: an `update` is **O(log n) common case** — ~2–3 kB at
  n = 150 vs ~40 kB under the DCGKA design (wire-format §10) — degrading toward O(n) only when the path
  crosses heavily blanked/conflicted regions (post-membership-change or concurrency bursts), healing on
  the next update through them. **No per-op acks.** Envelope fan-out remains one seal per recipient
  mailbox per message (sym mode ≈ n symmetric encryptions, negligible; sealed-sender §11.3).
- **The concurrency lower bounds still stand** (CoCoA, DeCAF, Key Lattice; eprint 2023/1123):
  decentralized + concurrent + worst-case O(log n) cannot be had simultaneously — BeeKEM does not beat
  them; it buys the *common case*, paying O(n) under heavy concurrency exactly as the bounds require.
  The 150-device max is retained as the design envelope (worst-case budgets are still sized to it);
  raising it post-v1 is a product decision the protocol no longer forbids. D0 unaffected.
- Bandwidth shaping: padding buckets add ≤ 2× on small frames (sealed-sender §5); media rides blob offload
  (upload once), so fan-out cost is envelopes only.

## 6. Limitations (G17 — document, don't hide)

1. **No formal security proof** *(re-based 2026-07-22, D11 — the largest limitation, accepted with
   eyes open)*: BeeKEM has design rationale and informal security argument, not a game-based proof;
   the reference implementation is pre-alpha and unaudited upstream. Mitigations, all normative:
   doctrine #4's byte-equivalence contract, the TreeKEM family's extensive literature as indirect
   support, and external cryptographic review as a **gating** requirement (§6.13). The DCGKA-phase
   specs (proven construction) remain on file as the documented fallback.
2. **KDFs as random oracles**: BLAKE3 (tree layer) and HKDF-SHA256 (profile layer) are both modeled as
   random oracles (beekem-core §3 KDF split).
3. **No post-impersonation security**: an attacker holding a member's current signing state can sign as
   that member until the victim's next processed rotation (ordering-auth §5).
4. **Bad-randomness fragility, narrowed** *(2SM's Remark-11 both-parties fragility retired with 2SM)*:
   a leaked update coin compromises that epoch until the next honest update; mitigation remains CSPRNG
   quality + injectable-RNG testing (beekem-core §3).
5. **Concurrent-remove collusion window** (inherited posture): members that have not yet processed a
   remove keep sending under keys the removed member holds, bounded by causal propagation; a member that
   *has* processed it cannot send at all until a fresh update (beekem-core §10) — narrower than the
   DCGKA-era window, not wider.
6. **Insider equivocation, split by kind** *(improved by D11)*: divergent *key material* in one signed
   op is **rejected at processing** via `rootCommit` — an MLS-confirmation-tag analog BeeKEM's single
   root secret makes possible (beekem-core §4.3); divergent *op histories* remain detect-and-remove via
   the consistency digest (dgm.md §8), with group re-creation as the fallback.
7. **Liveness is not guaranteed**: withholding transports can delay healing and delivery indefinitely;
   the protocol surfaces staleness (ordering-auth §9) and repairs end-to-end (§8), it cannot force
   delivery. A silent member blocks its own healing (its leaf never rotates) and everyone's GC
   (coverage frontier stalls — beekem-core §5/§8).
8. **Traffic analysis residuals**: arrival timing, mailbox identity, volume, and pusher IP remain visible
   to providers (sealed-sender §8); Tor/mixnet are optional strengthening, not defaults.
9. **In-group metadata is visible to members**: who added/removed whom, sender identity, and (in
   welcomes) op history back to the checkpoint — sealed sender protects against outsiders, not members
   (beekem-core §6).
10. **Envelope-layer FS**: `sealed-sym` (all in-conversation traffic) inherits ratchet-grade FS/PCS
    (sealed-sender §11.5); the remaining bounded, metadata-only exposure (sealed-sender §9) applies to
    the rare `sealed-asym` bootstrap surface only, within the weekly-rotating signed prekey's ≤ 2-week
    window (D10).
11. **No deniability treatment**: signatures inside envelopes give strong in-group attribution; a formal
    deniability analysis has not been done and is not claimed either way.
12. **Post-quantum: REGRESSED by D11 — D8 re-opened (2026-07-22); position recorded, not yet solved.**
    Under DCGKA the HNDL funnel was bootstrap-only; under BeeKEM **every path encryption is X25519 DH**,
    so harvest-now-decrypt-later exposure extends to group key material generally. Worse, the tree's
    bidirectional-DH trick (encrypter re-decrypts via the same DH pair) has no pure-KEM analog — an
    ML-KEM hybrid tree requires restructuring path encryption to MLS-style per-resolution encapsulation,
    i.e. diverging from upstream. Recorded position: v1 classical; the PQ-hybrid reservation survives on
    the envelope `suite` id (wire-format §6) and the bootstrap surface; the tree's HNDL exposure is
    **documented and accepted** until a KEM-tree fork or upstream support exists. The `sealed-sym`
    envelope mode and all chain/KDF layers remain quantum-safe as specced. Signatures stay classical.
13. **Composition novelty**: sealed sender × BeeKEM, the ATSMS messaging profile (eviction, coverage,
    checkpoints, `rootCommit` — all deviations from the upstream document-sync posture), and the D10/D11
    joint use of the signed prekey (identity-devices §3.1) are compositions no one has analyzed;
    **external cryptographic review is a gating requirement** (doctrine #4) before v1 alpha carries real
    traffic (implementation plan Phase 6, G18).

## 7. Conformance

A conforming v1 endpoint MUST implement: the BeeKEM tree with the ATSMS messaging profile — DGM-filtered
ops, `rootCommit`, per-sender chains, coverage, eviction, checkpoints (beekem-core), the strong-remove
DGM (dgm.md), the ordering/auth layer incl. repair (ordering-auth), sealed envelopes with padding
(sealed-sender), the wire formats and test-vector suite (wire-format), the baseline HTTPS mailbox
transport profile + per-recipient fan-out + blob offload (spec v1.1 §7/§9 profiles 1 + 3), and the
identity/record model (identity-devices). OPTIONAL: WebSocket push, P2P transports, Tor, the group
drop-point profile (post-v1 design).

## 8. Conventions used across the spec set

- RFC 2119 keywords; **[deviation]** marks a departure from the reference (since D11: the `beekem`
  crate; in superseded docs: eprint 2020/1281); DECIDED/PROPOSED/DEFERRED status on every constant in
  [`parameters.md`](./parameters.md) (single source of truth — specs reference, never redefine).
- "Oracle" = the `beekem` crate (inkandswitch/keyhive, Rust; differential-test source of truth below the
  `PcsKey` seam). "Paper" = the BeeKEM paper for the tree; eprint 2020/1281 in the superseded
  DCGKA-phase docs. p2panda-encryption and trvedata/key-agreement retired as oracles 2026-07-22 (D11).
- Each sub-spec ends with **Test obligations** (normative for the implementation) and **Open questions**
  (decision log — resolved items struck through with their date, so review never re-litigates).
