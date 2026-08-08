# Spike A — ATSMS Messaging Profile over BeeKEM

> **Status: SPIKE COMPLETE (2026-07-22) — verdict PASS.** Gate 1 of decision D11
> ([`beekem-analysis.md`](beekem-analysis.md) §5). This is the §-level draft of the future
> `../../spec/beekem-core.md`; nothing here is normative until Phase 0b lands it.
> Problem being solved: Keyhive built BeeKEM for encrypted **document sync** (history stays
> decryptable forever); ATSMS needs **messaging FS** (history becomes *undecryptable by schedule*).
> Sources: `beekem/src/{cgka,tree,pcs_key,keys}.rs` (clone 2026-07-09), dcgka-core.md §7/§8
> (the FS bar to match), sealed-sender.md §11, ordering-auth.md §8/§9.

## 1. Terms & seam

- **Epoch** `e` = one BeeKEM `Update` op (identified by `pcs_update_op_hash` — content-addressed,
  maps 1:1 onto our MessageID discipline). `PcsKey_e` = the root secret its path encryption
  establishes.
- The **engine seam is `PcsKey`**: everything below it (tree, path encryption, merge, replay) is
  ported BeeKEM and stays byte-compatible with the Rust oracle; everything above it (chains,
  envelope keys, eviction) is ATSMS profile and deliberately deviates from Keyhive's
  `derive_application_secret` (which we do not use).
- KDF split (**PROPOSED**): tree-internal ratchets keep **BLAKE3** (oracle byte-compatibility);
  all profile derivations above `PcsKey` use **HKDF-SHA256** with `atsms-beekem:v1:*` labels
  (house discipline, registered in wire-format §7 at Phase 0b).

## 2. Key schedule above `PcsKey`

```
chainSeed(e, S) = Expand(PcsKey_e, "atsms-beekem:v1:chain" ‖ enc(S))     // S = sender Membership
envKey(e, S)    = Expand(PcsKey_e, "atsms-seal:v1:sym"    ‖ enc(S))     // sealed-sender §11.2'
```

- **Per-sender FS-AEAD chains** (restores per-message FS inside an epoch — the property Keyhive's
  flat per-content derivation lacks): identical construction to dcgka-core §7 —
  `msgKey`/`nonce`/`ck'` steps, delete-on-advance, delete-on-use, skipped-key store with the same
  constants (`OUT_OF_ORDER_TOLERANCE` 100, `MAX_FORWARD_DISTANCE` 1000, `MAX_SKIPPED_TOTAL` 2000).
  Only the seed root changes: `chainSeed(e, S)` instead of the per-sender outer ratchet (which
  does not exist under BeeKEM).
- **`sealed-sym` change is one line**: today `envKey = Expand(I_sender, …)` with no sender in the
  info (the ikm was already per-sender); under BeeKEM the ikm (`PcsKey_e`) is shared, so the
  sender Membership moves into the info string. Everything else in sealed-sender §11 — per-recipient
  PRF tags, fresh-nonce re-encryption, table maintenance, grace rules — survives verbatim. Epochs
  are group-scoped rather than per-sender now, so all senders' envKeys/tags rotate together on each
  update (more tag-table churn, no protocol change; entries are added when the new `PcsKey` is
  derived, exactly the §11.4 rule).
- App AEAD AD stays `enc(groupId ‖ senderMembership ‖ generation)`; the epoch is bound by the key
  (a ciphertext decrypts under exactly one epoch's chain) — same argument as the 2026-07-16
  epoch-anchor decision, now with `pcs_update_op_hash` as the anchor dependency.

## 3. Sending rules & epoch lifecycle under concurrency

- **No root key → update first (normative)**: any app send when `has_pcs_key()` is false MUST be
  preceded by the sender's own `Update` (upstream already does this — `cgka.rs:new_app_secret_for`).
  This single rule covers: after any add/remove (paths blanked), after any concurrent-update merge
  (root conflicted), and after joining. It **absorbs most of dcgka-core §10's dominating-update
  rule**; the remaining §10 case (retroactive DGM invalidation) is Spike B §7.
- **Mandatory post-join self-update** survives unchanged and gains a second justification: the
  joiner's leaf key is its *published prekey* until its first own update — rotation replaces it
  with a never-published key (heals prekey-window exposure; identity-devices §4.2 grace).
- Concurrent updates: merged per BeeKEM (conflict keys); each op still defines its own epoch whose
  `PcsKey` remains derivable by members who processed it while live; in-flight traffic under a
  superseded epoch decrypts from **retained epoch state** (§4) — the explicit
  `(pcs_key_hash, pcs_update_op_hash)` pair on encrypted content makes lookup exact, no trial.

## 4. Deletion schedule (the FS core — all normative)

The single biggest deviation from upstream: Keyhive retains; we evict. Definitions: an op X is
**covered** by member M iff M has authored any signed frame Y with X ≼ Y (causal descent, from the
ordering layer's deps — no new mechanism); **covered-by-all** = covered by every member of the
evaluator's current view. Epoch e is **closed** when its update op is covered-by-all, or at
`T_EPOCH_GRACE` (**PROPOSED** = `T_REPAIR_GIVEUP` = 30 d) — whichever first.

| Item | Rule |
|---|---|
| `PcsKey_e` + `chainSeed`s + `envKey`s | delete when e is closed AND a strictly later epoch is established; receive chains for e deleted with them |
| chain keys / msgKeys | delete-on-advance / delete-on-use (unchanged from dcgka-core §7) |
| skipped msgKeys | caps above; expire when their epoch closes |
| own superseded leaf/path secrets (`ShareKeyMap` entries) | evict when the pk appears in a `PathChange.removed_keys` of an op that is covered-by-all (+ grace); the map becomes bounded-evicting — **upstream's `ShareKeyMap` only ever `extend`s; the port MUST NOT** |
| `pcs_keys` cache | bounded by open epochs (Keyhive's own TODO in `cgka.rs:63` is exactly this hook) |
| retained frames (repair store) | until covered-by-all (replaces "acked-by-all"), cap 30 d — ordering-auth §8 numbers unchanged |
| public op graph | prunable **only** behind a checkpoint frontier (§5) |

Consequence, stated as the feature it is: `rebuild_pcs_key`-style historical derivation
(`cgka.rs:508-539`) is **impossible beyond the grace window** — the secrets no longer exist.
Late ciphertext beyond grace is undecryptable-by-design and surfaces through the existing repair /
give-up machinery. Joiners can decrypt nothing before the first post-add update (their path was
blanked) — the no-history-to-joiners property holds by construction.

## 5. Coverage, GC, and the checkpoint frontier (replay vs FS reconciled)

- **Coverage replaces acks — with a latency trade we take with eyes open.** DCGKA acks were
  load-bearing for PCS (mandatory, `T_ACK` 60 s). Under BeeKEM, **PCS completes when a member
  processes the update op itself — no ack round-trip** (a strict healing-latency improvement).
  Coverage is needed only for GC/eviction timing and staleness attribution, so it can be lazy:
  it is implicit in every frame's deps; a member with nothing to send SHOULD emit a small
  `coverage` control frame within **`T_COVER` = 24 h (PROPOSED)** of processing a membership op —
  padded and jittered like everything else. Trade recorded: GC latency 60 s → up to 24 h;
  memory cap (30 d) unchanged; ack *storms* (n frames within seconds of every op — the thing
  sealed-sender §5's buckets were sized around) are gone.
- **Checkpoint frontier (bounds replay + storage).** Upstream replays from `init_add` and keeps
  the whole op graph forever. Port requirement: maintain a **checkpoint** = serialized tree state
  at a covered-by-all frontier; replay runs from checkpoint; ops strictly behind it are pruned.
  *Safety*: once a frontier is covered-by-all, every member has authored a frame descending from
  it, so no future valid op can be concurrent with anything behind it (its predecessors transitively
  include the frontier) — replay never needs pruned ops. Frames referencing pre-frontier state
  fall to the existing readiness/repair rules. (The interaction with retroactive DGM invalidation
  is proven in Spike B §6 — cascades cannot cross a covered-by-all frontier.)
- Stale members block coverage → the frontier → GC, exactly as they blocked acked-by-all before:
  the 7 d warn / 30 d eviction-proposal policy (parameters.md) carries over unchanged.

## 6. Root-key commitment (new integrity check BeeKEM makes possible)

A malicious updater could craft a `PathChange` whose encryptions deliver **different secrets to
different resolutions** — same signed op, divergent derived roots; an op-set digest would never
see it. Because BeeKEM has a *single* root secret per epoch (unlike DCGKA's per-member secrets),
the fix is cheap and total: the update op carries `rootCommit = H(PcsKey_e)`; every member MUST
verify its derived `PcsKey` against `rootCommit` before use — mismatch ⇒ reject op, surface
security event (MLS-confirmation-tag analog). This **upgrades G14 equivocation handling from
detect-and-attribute (dgm.md §8 digests) to reject-at-processing** for key material; the digest
mechanism narrows to op-set/head comparison. Deviation from upstream (no such field) — flagged
for the oracle allowlist.

## 7. FS/PCS parity vs the current spec set (exit criterion)

| Property | DCGKA specs today | BeeKEM + this profile |
|---|---|---|
| Per-message FS within epoch | per-sender chains + deletion | **same construction**, reseeded from `chainSeed(e,S)` — parity |
| FS across epochs | update secrets + deletion | epoch eviction (§4) — parity |
| PCS after update | after update **+ ack round-trip** per member | on processing the update op — **better** |
| PCS after remove | remove op reseeds (minus target) | remove blanks root ⇒ forced fresh update excludes target — parity (window analysis in Spike B §7) |
| Welcome/history to joiner | none (DGM-state welcome) | none (blanked path) — parity, by construction |
| Envelope FS/PCS (`sealed-sym`) | per-sender-epoch envKey | per-sender-epoch envKey (shared-ikm variant) — parity |
| Bad-randomness blast radius | 2SM Remark-11 fragility (leaked send-coin hits both parties) | **2SM gone**; a leaked update coin compromises that epoch until next update — strictly simpler story |
| Insider seed equivocation | detect via ratchet-state digests | **reject via rootCommit** (§6) — better |
| Post-impersonation / deniability | unchanged | unchanged (frame signatures, ordering-auth §5) |

**Verdict: PASS.** Every deviation from upstream is additive (eviction, chains, checkpoint,
rootCommit, coverage frames) and none touches tree/merge semantics — differential testing against
the Rust oracle remains valid for everything at or below the `PcsKey` seam, on scenarios with
profile features disabled.

## 8. Carried to Phase 0b

New/changed constants for parameters.md: `T_COVER` 24 h, `T_EPOCH_GRACE` 30 d, checkpoint cadence
(suggest: every covered-by-all membership op); labels `atsms-beekem:v1:{chain,…}` + amended
`atsms-seal:v1:sym` info shape; dead rows: `T_ACK`, ack-batching rows. Open items: BLAKE3/HKDF
split sign-off (§1); whether `coverage` frames double as digest carriers (dgm.md §8 cadence).
