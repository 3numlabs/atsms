# spec/overview.md — ATSMS-DCGKA: Protocol Overview & Threat Model

> **Status: DRAFT v0.1 (2026-07-16) — for review.** [Protocol] · Phase 0 deliverable.
> Closes gaps **G16** (size/performance envelope) and **G17** (security-model fine print) from
> [`../gap-analysis.md`](../gap-analysis.md).
> **This document supersedes [`../atsms-dcgka-spec.md`](../atsms-dcgka-spec.md) (v1.1) as the entry point**
> to the specification; where the one-page spec and the `spec/` set conflict, the `spec/` set wins. The
> one-page spec remains as design history (its §4.1 cert-profile and §6–§9 design notes are consolidated
> into the sub-specs listed below). MUST/SHOULD/MAY per RFC 2119.

## 1. What this protocol is

ATSMS-DCGKA is the advanced end-to-end encryption layer of the Bourbon Protocol (umbrella roadmap
Phase 7): **decentralized secure group messaging with sealed-sender metadata protection over untrusted
store-and-forward mailboxes**, based on DCGKA (Weidner, Kleppmann, Hugenroth, Beresford — CCS 2021,
eprint 2020/1281; use the eprint version, Appendices B & D are load-bearing). It replaces the crypto core
of `atsms-lib` (`@atsms/sms`) while layering **over** — not replacing — the X509/S-MIME interop floor
(decision D1; [`atsms-integration.md`](./atsms-integration.md)).

Properties delivered (each with its owning sub-spec):

- **Confidentiality & integrity** — only current group members decrypt; per-sender FS-AEAD ratchets
  ([`dcgka-core.md`](./dcgka-core.md)).
- **Forward secrecy** — compromised state reveals no past messages (deletion discipline, dcgka-core §7/§8).
- **Post-compromise security** — updates + **acks** heal the group (acks are the PCS mechanism,
  dcgka-core §5); signing keys rotate too ([`ordering-auth.md`](./ordering-auth.md) §5).
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
4. **The paper's proof is the contract**: every deviation from eprint 2020/1281 is marked `[deviation]` in
   the owning sub-spec, and the relaxed delivery order we implement is exactly the one the paper proves
   sufficient (§8.1 + Lemma 8: per-sender FIFO, ack-after-referent, welcome-first — no total order).
5. **TypeScript v1** (D3) with audited `@noble/*` primitives; p2panda-encryption is porting reference and
   differential-test oracle; engine kept behind a serialize-in/out boundary for a later Rust swap.

## 3. Layer stack & document map

```
┌ Application: dialects (ATSMSMessagePayload: atsms/text, atsms/webrtc, …)  — unchanged, rides as plaintext
├ DCGKA core: membership ops, outer/inner ratchets, acks, welcomes          — dcgka-core.md
│    ├ DGM: pure membership function (strong remove, roles)                 — dgm.md
│    └ 2SM: internal pairwise channel (rotating-PKE, X3DH bootstrap)        — 2sm.md
├ Ordering & authentication: the ACB substitute (deps, FIFO, signatures,
│    replay, repair, stale-member surfacing)                                — ordering-auth.md
├ Sealed sender: two modes — HPKE bootstrap envelope + symmetric
│    in-conversation envelope (pseudonymous tags); padding, anon ingress    — sealed-sender.md
└ Delivery: baseline HTTPS mailbox (MANDATORY), WebSocket, P2P, SMTP, Tor   — spec v1.1 §7 + atsms-integration.md

Identity (vertical): DID → endpoint cert → {prekey bundle,
     protocol signing keys}; PDS records                                    — identity-devices.md
Bytes (vertical): deterministic CBOR, every schema, labels, test vectors    — wire-format.md
Constants: every tunable in one registry                                    — parameters.md
Integration: @atsms/sms + atsms-worker changes, migration                   — atsms-integration.md
```

Gap coverage: G1→2sm; G2/G3/G7/G11/G15→dcgka-core; G4/G12→ordering-auth; G5/G14→dgm;
G6/G8→identity-devices; G9→sealed-sender; G10→atsms-integration; G13→wire-format; G16/G17→this document.

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
- Per-operation cost is inherently **O(n)**: one 2SM ciphertext per member per create/update/remove
  (~40 kB total at n = 150 — wire-format §10), n acks per op, one HPKE seal per recipient per message
  (≲ 0.15 s CPU at max fan-out, sealed-sender §9). The paper measured n = 128: ≈ 40 kB/update,
  ≤ ~100 ms/op/participant (2021 Java); app messages ~139 B overhead, < 1 ms.
- **Sublinear group operations are explicitly out of scope**: the follow-up literature (CoCoA, DeCAF, Key
  Lattice; lower bounds in eprint 2023/1123) shows decentralized + concurrent + O(log n) cannot be had
  simultaneously. We chose decentralized + concurrent at O(n), n ≤ 150 devices. Do not revisit without
  revisiting D0.
- Bandwidth shaping: padding buckets add ≤ 2× on small frames (sealed-sender §5); media rides blob offload
  (upload once), so fan-out cost is envelopes only.

## 6. Honest limitations (G17 — document, don't hide)

1. **Non-adaptive proof**: the paper's security proof is against non-adaptive corruptions (adversary picks
   compromise times before the game); we assume the construction degrades gracefully under adaptive
   compromise but carry no proof. (Paper §9; standard for this family.)
2. **HKDF as random oracle**: the PRF-PRNG abstraction is instantiated with HKDF-SHA256 modeled as a
   random oracle (paper App. A).
3. **No post-impersonation security**: an attacker holding a member's current signing state can sign as
   that member until the victim's next processed rotation (ordering-auth §5); 2SM likewise (2sm.md §7).
4. **Bad-randomness fragility** (paper Remark 11): a leaked send-coin in 2SM partially compromises both
   parties; mitigation is CSPRNG quality + injectable-RNG testing, not protocol structure (2sm.md §7).
5. **Concurrent-remove collusion window** (paper App. C): concurrently removed members can collude on
   messages sent before a dominating operation exists; the dominating-update rule (dcgka-core §10) closes
   it at first opportunity but a window exists.
6. **Insider equivocation is detected, not prevented**: divergent seeds cause ratchet divergence; the
   consistency digest detects and attributes, removal + update heals, group re-creation is the fallback
   (dgm.md §8). No MLS-style confirmation tags.
7. **Liveness is not guaranteed**: withholding transports can delay healing and delivery indefinitely;
   the protocol surfaces staleness (ordering-auth §9) and repairs end-to-end (§8), it cannot force
   delivery. A silent member blocks its own healing and everyone's GC (dcgka-core §5).
8. **Traffic analysis residuals**: arrival timing, mailbox identity, volume, and pusher IP remain visible
   to providers (sealed-sender §8); Tor/mixnet are optional strengthening, not defaults.
9. **In-group metadata is visible to members**: who added/removed whom, sender identity, and (in welcomes)
   op history — sealed sender protects against outsiders, not members (dcgka-core §6).
10. **Envelope-layer FS**: `sealed-sym` (all in-conversation traffic) inherits ratchet-grade FS/PCS
    (sealed-sender §11.5); the remaining bounded, metadata-only exposure (sealed-sender §9) applies to
    the rare `sealed-asym` bootstrap surface only, within the weekly-rotating signed prekey's ≤ 2-week
    window (D10).
11. **No deniability treatment**: signatures inside envelopes give strong in-group attribution; a formal
    deniability analysis has not been done and is not claimed either way.
12. **Post-quantum: classical v1, hybrid scheduled at the funnel (decided 2026-07-20).** The symmetric
    core (ratchets, KDF chains, hashing, and the `sealed-sym` envelope mode) is quantum-safe as specced;
    the entire harvest-now-decrypt-later exposure funnels through the KEM surface — 2SM/X3DH plus
    `sealed-asym` envelopes. Plan: **phase 1** ships classical X25519 with the reservations paid up front
    (envelope `suite` id, X3DH `KEM_ss` slot, `at.atsms.prekey` suites hook, `Kem` provider seam —
    wire-format §5/§6, 2sm.md §5.2); **phase 2** upgrades that bootstrap surface to **hybrid
    X25519 + ML-KEM-768** (PQXDH-style; never PQ-only) — landing **before v1 alpha carries real user
    conversations**, since HNDL exposure accrues from first real traffic. Signatures stay classical
    indefinitely (no harvest urgency). Cost lands only on rare bootstrap-class messages (~1.1 KB each);
    steady-state traffic needs nothing.
13. **Composition novelty**: sealed sender × DCGKA is a composition the paper does not analyze, and the
    D10 joint use of the signed prekey by X3DH and HPKE (identity-devices §3.1) has no off-the-shelf
    joint proof; external cryptographic review is a scheduled mitigation (implementation plan Phase 6,
    G18), not optional.

## 7. Conformance

A conforming v1 endpoint MUST implement: the DCGKA state machine with mandatory acks (dcgka-core), the
App. D-discipline 2SM (2sm.md), the strong-remove DGM (dgm.md), the ordering/auth layer incl. repair
(ordering-auth), sealed envelopes with padding (sealed-sender), the wire formats and test-vector suite
(wire-format), the baseline HTTPS mailbox transport profile + per-recipient fan-out + blob offload
(spec v1.1 §7/§9 profiles 1 + 3), and the identity/record model (identity-devices). OPTIONAL: WebSocket
push, P2P transports, Tor, the group drop-point profile (post-v1 design), OPKs until their design lands
(pre-v1; 2sm.md §5.0.1).

## 8. Conventions used across the spec set

- RFC 2119 keywords; **[deviation]** marks a departure from the paper; DECIDED/PROPOSED/DEFERRED status on
  every constant in [`parameters.md`](./parameters.md) (single source of truth — specs reference, never
  redefine).
- "Paper" = eprint 2020/1281 (May 2021 revision). "Prototype" = trvedata/key-agreement (Java). "p2panda" =
  p2panda-encryption (Rust; differential oracle).
- Each sub-spec ends with **Test obligations** (normative for the implementation) and **Open questions**
  (decision log — resolved items struck through with their date, so review never re-litigates).
