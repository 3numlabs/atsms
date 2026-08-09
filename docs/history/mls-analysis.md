# MLS (RFC 9420) with decentralized delivery vs. the DCGKA plan

> Third leg of the alternatives comparison (see [`q-channel-analysis.md`](q-channel-analysis.md) for
> Quilibrium's Triple Ratchet). Evaluates standard MLS run over our untrusted dumb-mailbox relay network,
> against [`implementation-plan.md`](implementation-plan.md) / [`gap-analysis.md`](gap-analysis.md).
> Based on RFC 9420 + RFC 9750 (architecture), the decentralized-MLS state of the art as of mid-2026
> (Matrix DMLS, draft-kohbrok-mls-dmls/FREEK, draft-xue-distributed-mls, CoCoA/DeCAF/Key Lattice), shipped
> systems (Discord DAVE, Wire, XMTP, Nostr Marmot, Cloudflare Orange Meets, IETF MIMI), and the implementation
> ecosystem (OpenMLS, mls-rs, ts-mls). Written 2026-07-14. **[Protocol] research note.**
>
> **Unlike Q-channel, this is a real contender.** It materially changes the decision landscape and this doc
> ends with a revised recommendation framework, not a reaffirmation.

## Headline findings

1. **MLS's crypto never needs a trusted server — but its state machine needs one thing our mailboxes don't
   give: agreement on a single Commit per epoch** (RFC 9420 §14, a normative MUST). Concurrent commits fork
   the transcript hash permanently; there is no in-protocol merge. Every production MLS deployment solves this
   with a per-group sequencing point: Discord DAVE (gateway broadcasts first valid commit, drops the rest),
   Wire (backend rejects stale commits), IETF MIMI (per-room hub), even "decentralized" XMTP (bought total
   order from a BFT appchain). Truly fork-tolerant MLS (Matrix DMLS; FREEK → draft-kohbrok-mls-dmls with
   punctured key schedules) exists only as expired individual drafts and proofs-of-concept — **unshipped
   research, not a buildable dependency**.
2. **Sequencing is a liveness power, not a confidentiality power.** A malicious sequencer can delay/censor,
   partition the group (detectable via `epoch_authenticator` cross-checks), and suppress a member's healing
   commits (a real PCS attack) — but can never read messages, forge messages, or add itself (RFC 9750 §8.4.2,
   9420 §16.9). Critically, **our mailbox relays already hold the withholding/censorship lever** — a relay
   that drops envelopes delays DCGKA's ack-driven healing the same way. So "relay as sequencer" is a smaller
   trust concession than it first sounds: same trust *class* our relays already occupy, scoped per group,
   swappable.
3. **The engineering asymmetry is stark and favors MLS.** With MLS we inherit the entire hardest layer —
   TreeKEM, key schedule, framing, Welcome, external commits — standardized, interop-test-vectored, and (for
   OpenMLS) **independently audited** (SRLabs, published May 2026), with a concrete PQ path (ML-KEM/X-Wing
   ciphersuite drafts; ts-mls already ships them). What remains custom is a small amount of well-precedented
   distributed-systems glue. With DCGKA we inherit fork-freedom by construction, but must build (or adopt
   young) **cryptography**: 2SM, PRF-PRNG ratchets, the DGM — with no standard, no audit to lean on, and
   ourselves as the only implementation. (One mitigation surfaced: **p2panda-encryption**, a Rust DCGKA
   variant shipped Feb 2025 for exactly our group sizes — young, single-project, audit unconfirmed.)
4. **At our scale (25–150 devices), MLS's O(log n) is noise** — worst-case commits ≈ 150 HPKE ciphertexts
   (~10–20 kB) vs DCGKA's measured ~40 kB at n=128. p2panda reached the same conclusion. Efficiency is *not*
   why you'd pick MLS; the ecosystem is.
5. **Directly relevant prior art exists for our exact topology.** Nostr's **Marmot/NIP-EE** runs OpenMLS over
   dumb relays with: first-commit-wins + deterministic tie-break (lowest timestamp/ID), short previous-state
   retention for revert, Welcome released only after the commit is confirmed, last-resort KeyPackages with
   mandatory post-join rotation, and rotating group routing IDs for relay-side metadata. And **Germ Network**
   ships draft-xue-distributed-mls (per-sender MLS groups, fork-free by construction, O(n)) in production —
   **and is integrating with AT Protocol**, our identity layer. Both are watch-closely projects.

## How MLS would run on our network (the buildable shape)

All pieces below are shipped prior art, none are research:

1. **Per-group sequencer role on a Relay Node** — a Durable Object per group (our stack's natural form):
   first valid commit per epoch wins; later commits for that epoch bounce with the current epoch number;
   Welcome messages are released only for winning commits (Discord's rule + Marmot's Welcome rule). The
   sequencer stores only `groupId → (epoch, acceptedCommitHash)` and reads only the cleartext `epoch` field —
   commits stay end-to-end encrypted as PrivateMessage. Application messages need **no sequencing at all**;
   only membership changes touch the sequencer.
2. **Client-side fallback** for sequencer failover/migration: deterministic tie-break (e.g., lowest commit
   hash) + bounded retention of the previous epoch's state to revert a losing commit — RFC 9750 §5.2.2
   explicitly blesses this; the forward-secrecy cost is bounded (hours, not the open-ended retention of full
   DMLS).
3. **Partition/suppression detection**: `epoch_authenticator` cross-checks inside application messages +
   "my commits keep losing" alarms; group-initiated sequencer migration (the genuinely novel design bit —
   a final "move" commit naming the new sequencer relay).
4. Optionally, a **designated-committer heuristic** (lowest live leaf index commits; Cloudflare Orange Meets
   pattern, TLA+-modeled) to make races rare — a politeness optimization, not the correctness mechanism.

Doctrinal cost: membership changes (only) depend on one relay's availability per group, and that relay gains
censorship power **it already effectively had as our mailbox**. The role is dumb (an epoch counter) and
swappable — arguably still within the "gateway is dumb and swappable; interfaces are the product" north star.

## Comparison against the implementation plan

| Dimension | MLS + relay-sequencer | DCGKA plan (this repo) |
|---|---|---|
| Crypto core provenance | RFC 9420 standard; OpenMLS **audited** (SRLabs 2026); interop test vectors; multi-implementation ecosystem | CCS 2021 paper + Java research prototype; we'd be the only production implementation (or adopt young p2panda crate) |
| Sequencing requirement | **One commit per epoch MUST be agreed** — per-group sequencer role (untrusted, liveness-only power) | **None** — concurrency-native by construction; no sequencer, no forks |
| Concurrent membership ops | Forks prevented by sequencer; races at failover handled by tie-break + bounded revert | Proven convergence under causal order (paper Lemma 8); G11 caveats with normative mitigations |
| PCS speed | **One commit heals the committer immediately** — faster than DCGKA (which needs the update delivered *and acked* by members) | Update + ack round; offline members delay healing; same offline-member caveat both ways (idle devices must be evicted — RFC 9750 §8.2.2 says the same) |
| FS | Optimal per RFC deletion schedule; degraded (boundedly) by the revert-retention window | Optimal, proven; degraded by never-acking members retaining member secrets |
| Sender authentication | Signed framing; membership-scoped; insider forgery excluded | Per-sender signatures with rotation (our spec/ordering-auth.md) |
| Insider consistency attacks | Transcript hash + confirmation tags give **built-in agreement** — inconsistent commits are detected cryptographically (better than DCGKA, our G14) | Malicious member can split ratchets undetected; G14 mitigation is bespoke (epoch-hash gossip) |
| App message cost | O(1) ciphertext to the group's delivery stream, but still fanned out to per-device mailboxes → O(n) envelopes (same as us) | O(n) sealed envelopes |
| Commit/update cost | O(log n)→O(n) under churn; ~10–20 kB worst case at n=150 — immaterial at our scale | O(n), ~40 kB at n=128 — immaterial at our scale |
| Metadata / sealed sender | **PrivateMessage hides sender in-group natively** (stronger than Signal out of the box); leaks `group_id`+epoch to relays → rotating routing IDs (Marmot pattern); Welcome × public KeyPackage pool links joiners → deliver Welcomes sealed to mailboxes; avoid DS-hosted GroupInfo/ratchet_tree (membership exposure + PCS trap) | Sealed sender designed in; DCGKA's n−1 2SM + n−1 ack fan-out per update is a *chattier, more distinctive* relay-visible pattern — padding must hide it (G9) |
| Prekey/KeyPackage on public PDS | Same problem as ours (public pull = everything is last-resort); **documented playbook exists** (Marmot: batch + rotate + mandatory post-join update; draft-ietf-mls-extensions `last_resort`) | G8 — same mitigations, designed by us |
| Multi-device | No user concept — device = leaf; add-device = Add in every group; no standard (MIMI/Wire patterns) | Same pain (G6); designed by us either way |
| Group management model | Proposals/Commits + application-defined policy; MIMI has room-policy prior art; **no DGM-equivalent design burden** — the sequencer linearizes, policy is ordinary code | G5 — the DGM must be designed and verified by us; identified as our highest design risk |
| PQ path | Concrete: draft-ietf-mls-pq-ciphersuites (ML-KEM hybrids), X-Wing; ts-mls ships PQ suites today | None; we'd design PQ variants of 2SM ourselves (G17) |
| Implementations for our stack | **OpenMLS** (Rust, MIT, audited, WASM verified — but WASM in RN/Workers needs validation); **mls-rs** (Apache-2, most featureful, WASM experimental, no audit); **ts-mls** (pure TS, PQ suites, active — but single-maintainer, no audit) | None; build from paper in TS, or bind p2panda-encryption (Rust/WASM, unaudited?) |
| Residual custom work | Sequencer DO + failover/migration protocol (novel), KeyPackage lifecycle, multi-device, sealed envelope, desync recovery policy | The entire crypto core (2SM, DCGKA engine, DGM, ordering) + prekey lifecycle, multi-device, sealed envelope |
| Standards trajectory | IETF WG, MIMI federation, GSMA RCS adoption, growing deployments | Academic lineage; no standardization path |

## Mapped to our gap list

Switching to MLS would **dissolve** several of our hardest gaps rather than answer them:

- **G1 (2SM), G2 (acks), G3 (app ratchet), G7 (welcome contents)** — cease to exist; MLS's equivalents are
  part of the standard and the libraries.
- **G5 (DGM)** — our single biggest design risk **is replaced by ordinary policy code** on a linearized
  history (who may add/remove becomes commit-validation rules, prior art in MIMI room policy). This is the
  strongest single argument for MLS.
- **G14 (insider consistency)** — *better than* our DCGKA answer: transcript agreement is built into MLS.
- **G4/G12 (ordering, liveness)** — transformed, not removed: instead of causal-buffering predicates we need
  the sequencer DO + failover/migration + fork-revert policy. Smaller and better-precedented, but the
  migration protocol is genuinely novel design.
- **G6 (multi-device), G8 (keys on PDS), G9 (sealed sender), G13 (wire format — partially: MLS wire is
  standardized, our envelope isn't)** — unchanged; ours to design either way.
- **New gaps MLS introduces:** per-group sequencer availability & migration; Welcome/KeyPackage-pool
  linkability on a public PDS (mitigable); the RFC 9750 §5.3 GroupInfo/external-join PCS trap (avoid
  DS-hosted GroupInfo in v1); WASM footprint & RN/Workers compatibility validation for OpenMLS (or
  bus-factor acceptance for ts-mls).

## Impact on the implementation plan

If MLS is chosen, the plan restructures substantially: Phase 0's `../../spec/dcgka-core.md`, `../../spec/2sm.md`, and
`../../spec/dgm.md` are replaced by `../../spec/mls-profile.md` (ciphersuite, extensions, credential type binding DIDs,
KeyPackage lifecycle), `../../spec/sequencing.md` (sequencer DO contract, tie-break, revert window, migration), and
`../../spec/group-policy.md`; Phases 1–2 become library integration + the sequencer DO instead of crypto
implementation; D3 (language) becomes "OpenMLS-WASM vs ts-mls" — and the relay (`atsms-worker`) gains a small
**per-group sequencer duty**, which must be reconciled with the "Relay Nodes are permissionless and dumb"
doctrine in `docs/architecture.md` §2. Decisions D1 (X509 floor layering), D2 (package split), D4–D6 carry
over nearly unchanged.

## Recommendation — revised three-way framing

The Q-channel analysis reaffirmed DCGKA; **this analysis genuinely weakens it.** Scorecard:

- **Quilibrium Triple Ratchet: out** (see q-channel-analysis.md — no membership layer, no sender auth, no
  analysis, AGPL).
- **MLS + per-group relay sequencer (+ Marmot-style fallback): lowest engineering and audit risk.** Audited
  standard crypto; our custom surface shrinks to well-precedented glue; our worst design risk (G5/DGM)
  dissolves; built-in insider-consistency detection; real PQ path. Cost: a per-group sequencing role on a
  relay — liveness-only trust, comparable to power relays already hold, but a **doctrinal concession** that
  membership changes depend on one (swappable) relay per group, plus a novel migration protocol.
- **DCGKA: the sequencer-free option.** Architecturally purest fit for "no central anything"; concurrency is
  native, not patched. Cost: we build unaudited bespoke crypto from a paper (or bet on p2panda-encryption),
  own the DGM design risk, and have no standards/PQ trajectory. p2panda chose this for a *pure* p2p network
  with **no stable infrastructure** — but we already operate always-on relays (Durable Objects), which
  removes DCGKA's main structural advantage while keeping MLS's ecosystem advantage.

**The deciding question is doctrinal, not technical:** is a per-group, swappable, liveness-only sequencing
role on a Relay Node acceptable within "the relay is dumb and swappable"? If yes → **MLS is the lower-risk
build** (recommended default). If sequencer-freedom is a hard protocol requirement → DCGKA remains the only
proven framework that delivers it, and the existing plan stands (consider p2panda-encryption as an accelerant
before implementing from the paper). Two external watch-items either way: **Germ's distributed-MLS + AT
Protocol integration** (fork-free MLS variant, shared identity layer — potential interop partner or design
donor) and **draft-kohbrok-mls-dmls** (if it gets WG adoption and OpenMLS mainlines punctured key schedules,
fork-tolerant MLS stops being research and the doctrinal dilemma dissolves).

This supersedes the "stay on DCGKA" bottom line in q-channel-analysis.md, which compared against Q-channel
only. A decision memo (D0: MLS-with-sequencer vs DCGKA) should precede any Phase 0 spec writing.
