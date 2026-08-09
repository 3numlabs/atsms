# Quilibrium "channel" (Triple Ratchet) vs. the DCGKA plan

> Analysis of [QuilibriumNetwork/channel](https://github.com/QuilibriumNetwork/channel) (Rust) as an alternative
> to the DCGKA approach in [`implementation-plan.md`](implementation-plan.md) /
> [`gap-analysis.md`](gap-analysis.md). Based on a full read of the Rust source (all ~3,100 lines), its tests
> (pass), the WASM/uniffi bindings, Quilibrium's E2EE docs, and a diff against the canonical copy in
> `QuilibriumNetwork/monorepo` `crates/channel`. Written 2026-07-14. **[Protocol] research note.**

## Headline findings

1. **The GitHub repo you found is a stale mirror.** Four commits, all by Cassandra Heart, last pushed Dec 2024.
   The canonical, actively maintained crate is `crates/channel` in `QuilibriumNetwork/monorepo` (tags v2.1.0.x,
   commits through June 2026) — and it contains **security fixes the mirror lacks** (state-mutation-before-AEAD-
   verification fix, skipped-key deletion, DoS caps, zeroization). Any evaluation must target the monorepo copy.
   License changes too: mirror is MIT, monorepo is **AGPL-3.0** — a real constraint for an MIT/Apache-style
   3NUM Labs protocol stack.
2. **"Triple Ratchet" here is not the academic Triple Ratchet** (eprint 2022/355 / 2025/078 are unrelated). It is
   Quilibrium's own construction: Signal Double Ratchet (over **Ed448**, with encrypted headers) + a third
   **Feldman-VSS distributed-key-generation ratchet**. The n-party DKG produces a *group public key* that
   replaces the counterparty key in the DH ratchet; data messages use per-sender symmetric chains
   (sender-keys style). **One ciphertext per group message regardless of group size** — that's its core pitch.
3. **It solves the part we already have, and lacks the part we identified as the hard design work.** It is a
   clean, transport-agnostic group *encryption* engine — but it has **no membership layer** (mirror: none at
   all; monorepo: threshold-2-only resharing with orchestration pushed into the Quorum app), no concurrency
   semantics, no per-message sender authentication, and **no spec, proof, or audit** of the group construction.

## How it works (short version)

- **Setup:** members exchange X3DH-bootstrapped pairwise Double Ratchet channels, then run a **4-round Feldman
  DKG** over them (share fragments → ZKPoK commitments → reveals → Lagrange "Shamir-in-the-exponent"
  recombination) to derive the group public key. O(n²) messages; **all n members must complete the sequenced
  rounds before anyone can send** — a permanently offline invitee stalls group creation.
- **Messaging:** sender does one DH against the *group* key per receive-epoch and — the clever/alarming trick —
  ships the **ephemeral private scalar inside the header** (encrypted under the group header key) so every
  member can recompute the DH without per-member ciphertexts. AES-256-GCM body, HMAC-SHA512 chains, skipped-key
  store for out-of-order delivery.
- **Healing (PCS):** in the async mode Quorum actually uses, rotation piggybacks Feldman share-multiplications
  on normal messages and is **hard-coded to threshold = 2**: any 2 members' contributions re-derive the group
  key. Sync mode re-runs the full DKG ("fully-online model, not applicable here," per their own docs).
- **Embedding:** genuinely standalone — no Quilibrium network dependency. Stateless FFI
  (`state_json in → state_json + envelope out`), uniffi bindings (Kotlin/Swift/Go) + `wasm-bindgen` for JS.
  Runs over any dumb mailbox, including our `atsms-worker` inbox DO, unmodified.

## Comparison against the implementation plan

| Dimension | Q-channel Triple Ratchet | DCGKA plan (this repo) |
|---|---|---|
| Group ciphertext size | **O(1)** — single envelope for all members | O(n) sealed envelopes per app message (one per member mailbox) |
| Group creation | 4 sequenced DKG rounds, **all members online-ish**, O(n²) | Fully asynchronous — create + welcome via 2SM; offline members catch up |
| Membership add/remove | **Absent from the library.** Monorepo `ratchet_resize` requires threshold = 2; exclusion-of-removed-member semantics live in app code | First-class `add`/`remove` control messages; DGM function defines semantics incl. concurrency (our G5 design work — but the framework for it exists and is proven) |
| Concurrent operations | No semantics; concurrent rotations race (last-writer-wins), concurrent resize unhandled | Proven convergence under relaxed causal order (paper Lemma 8); known caveats (G11) with normative mitigations |
| PCS | Threshold-2 share-mul rekey — novel, **unanalyzed**; long-lived Feldman shares between rotations | Ack-driven per-member healing with a security proof (with the dominating-update caveat) |
| FS | Yes (chain + epoch DH); mirror version broken (never deletes used keys — fixed in monorepo) | Yes, optimal, proven |
| Sender authentication | **None** — no signatures; any member can forge messages as any other member (all key material is group-shared, even ephemeral DH secrets) | Per-sender signatures with PCS key rotation (spec/ordering-auth.md); insider forgery excluded |
| Deniability | Strong (flip side of no signatures) | Weaker (signed control/app messages) — noted in G17 |
| Metadata protection | Encrypted headers in-group; sealed-sender exists only in monorepo; network anonymity delegated to Quilibrium mixnet | Sealed sender designed into our stack (spec/sealed-sender.md, relay ingress D5) |
| Security analysis | **No spec, no proof, no audit**; their own docs defer auditing | CCS 2021 paper with game-based proof; our composition still needs review (G18) |
| Multi-device | None (device = member, no delegation story) | Designed in (G6, `../../spec/identity-devices.md`) |
| Identity | Raw Ed448 key bundles, host-supplied | AT Protocol DIDs + `at.atsms.prekey` lexicon (G8) |
| Transport assumptions | Mailbox per member; per-sender rough FIFO (skip window 100/2000); DKG rounds phase-ordered by host; **cross-epoch reordering fragile** (only current+next header keys tried) | Explicit causal-buffering predicates; unbounded reordering tolerated by design |
| Group size | Pitch: beyond sender-keys ~1k pain point (O(1) data msgs); reality: O(n²) creation, n−1 DR states, and a **`u32` overflow in polynomial eval** that silently corrupts shares at threshold ≥ 3 with large member IDs | 150 devices, O(n) ops — matches our stated target (G16) |
| Language / embedding | Rust + WASM/uniffi — would satisfy our "swap in a Rust core later" seam (D3) | TypeScript + @noble (D3), interfaces kept WASM-swappable |
| License | Mirror MIT (stale/insecure); **canonical monorepo AGPL-3.0** | Our code, our license |
| Maturity | Production use in Quorum (beta since Dec 2024); but bus factor ≈ 1, `unwrap()` on network data, empty benches, no CI on mirror | Nothing built yet — plan only |
| Post-quantum path | None (Ed448 throughout) | None either, but 2SM's PKE is an identified swap point (G17) |

## Mapped to our gap list

- **Gaps it would solve:** essentially none of the hard ones. G1/G3 (2SM, app ratchet) it replaces with its own
  primitives — but those were never the risky part.
- **Gaps it leaves equally open:** G5 (DGM/membership — you would rebuild exactly this, now *without* a formal
  framework), G6 (multi-device), G8 (prekeys/lexicon), G9 (sealed sender — partial, monorepo-only), G12
  (mailbox liveness), G13 (wire format — theirs is JSON/base64 double-encoding), G14 (insider attacks — G14
  gets **worse**: not just DoS but full message forgery by insiders), G18 (audit — worse: no underlying proof
  to lean on).
- **New risks it introduces:** unanalyzed bespoke DKG ratchet (ephemeral-secret-in-header, threshold-2 healing),
  AGPL, single-maintainer upstream, Ed448 lock-in, group-creation liveness (all-members-online rounds), the
  `u32` share-corruption bug.

## What's worth stealing regardless of direction

- **O(1) group data messages** via a group-shared key + per-sender chains. This is the one axis where DCGKA is
  strictly worse (O(n) sealed envelopes per message). If bandwidth at n≈150 devices ever bites, a hybrid is
  conceivable: DCGKA for membership/key agreement, a group-derived "sender-keys" layer for bulk data — but note
  that's roughly what MLS application messages are, and it re-opens the insider-forgery question unless messages
  are signed (which costs the deniability Q-channel gets for free).
- **Stateless serialize-in/serialize-out FFI shape** — a good API discipline for our engine module regardless of
  language (pairs well with D3's WASM-swappable seam).
- Their monorepo's `// SECURITY:` fix — never mutate ratchet state before AEAD verification — goes straight into
  `../../spec/dcgka-core.md` as a normative rule.
- Encrypted headers (header keys derived from group state) as a cheap in-group metadata measure.

## Recommendation

**Stay on the DCGKA path.** The summary of Q-channel: it is a *group encryption* library with production
mileage, but it is not a *group messaging protocol* — membership management, concurrency semantics, sender
authentication, and any security argument are all missing, and those are precisely the items our gap analysis
identified as the actual work (G5 chief among them). Adopting it would trade our known, provable design work for
unknown, unprovable design work on top of an unanalyzed bespoke construction, under AGPL, from a bus-factor-1
upstream. The two systems share the same skeleton (pairwise channels bootstrapping group secrets + per-sender
chains + periodic rotation); DCGKA is the version of that skeleton with a proof, asynchronous membership, and
authenticated senders.

The legitimate counter-argument is message volume: if O(n) envelopes per app message at 150 devices proves
unacceptable in practice, revisit the hybrid above — as a *later optimization inside* the DCGKA framework, not a
reason to switch frameworks. Track it as an open question in `../../spec/overview.md` §Performance.
