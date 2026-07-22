# BeeKEM analysis — adopt as the CGKA core? (2026-07-22)

> Evaluation of **BeeKEM** (Ink & Switch / Keyhive) as a replacement for the Weidner-DCGKA core
> currently specified in `spec/`. Sources: the BeeKEM paper (`../BeeKEM.pdf`), the crate README
> (canonical algorithm description), and a source read of `keyhive/beekem/src` (~3.5k lines Rust,
> clone at commit 2026-07-09 "Improve API for access levels (#209)").
> Companion to [`mls-analysis.md`](./mls-analysis.md), [`p2panda-analysis.md`](./p2panda-analysis.md),
> [`q-channel-analysis.md`](./q-channel-analysis.md). Everything here is **PROPOSED** — the switch
> decision (D11 below) awaits user sign-off.

## 1. What BeeKEM is

A **concurrent TreeKEM variant** purpose-built for local-first, peer-to-peer systems: MLS-style
binary ratchet tree (leaves = members holding X25519 keys; inner nodes = subgroup secrets;
root = group secret) **without any delivery service or sequencer** — the exact property whose
absence made us reject MLS (D0) and choose DCGKA. Requires only **causal delivery of signed ops**.

- **Update** = fresh leaf keypair + path encryption to the root: O(log n) common case.
  Each ancestor secret is a BLAKE3 ratchet of the child secret; encrypted to the sibling's
  *resolution* via X25519 DH + ChaCha20-Poly1305 (`tree.rs`, README "Path Encryption").
- **Concurrency**: concurrent updates overlapping at a node retain **all** public keys as
  *conflict keys* (`keys.rs:NodeKey::ConflictKeys`); conflicted/blank nodes are treated as blank →
  encrypt to their resolution (degrades toward O(n) under heavy concurrency, heals to O(log n) on
  the next update through the node). Concurrent membership changes trigger a deterministic
  **full replay** of the op graph from the initial add (`cgka.rs:replay_ops_graph`), with removes
  applied last and concurrently-added leaves re-sorted — convergence without a server.
- **Add** encrypts nothing: it places the joiner's published **prekey** (`ShareKey`) at a leaf and
  blanks the path; the next update's path encryption includes the new leaf in its resolutions.
  **No X3DH, no pairwise channel, anywhere.**
- **Keys out**: per-update-epoch `PcsKey` (root secret); per-content `ApplicationSecret` =
  BLAKE3-KDF(PcsKey, content-ref, pred-refs, op-hash) (`pcs_key.rs`).
- **Crypto**: X25519, Ed25519-signed ops, BLAKE3, ChaCha20-Poly1305 — all in our `@noble` reach.
- **License Apache-2.0** (no Quilibrium-style AGPL problem). **WASM + TypeScript bindings exist**
  (`keyhive_wasm`) — the thing p2panda lacked.
- **Maturity: pre-alpha.** Repo says verbatim: "DO NOT use this release in production
  applications… not been through a security audit." Version 0.3.0, APIs unstable, active
  development. The paper's security section is **informal argument, not a game-based proof** —
  there is no analogue of eprint 2020/1281's Theorems/Appendix B.

## 2. Score against our decision framework

| Criterion | Weidner DCGKA (current specs) | BeeKEM | Winner |
|---|---|---|---|
| **D0** no sequencer, local-first, transport-agnostic | ✅ by design | ✅ **by design** — this is its native habitat (causal delivery only, which our ordering-auth layer already provides) | tie |
| Update cost @ n=150 devices | O(n): ~40 kB (n 2SM DMs) **+ n acks** | O(log n): ~1–2 kB single broadcast op, **no protocol acks** | **BeeKEM** |
| Security proof | CCS 2021 theorems; "the paper's proof is the contract" (doctrine #4) | **None.** Informal notes only; unaudited pre-alpha | **DCGKA, decisively** |
| Per-message FS inside an epoch | Per-sender FS-AEAD ratchets + deletion discipline (dcgka-core §7/§8) | One `PcsKey` derives **all** app secrets of the epoch; Keyhive *retains* old PcsKeys and share secrets for historical decryption (document-sync feature: `ShareKeyMap` only ever extends; `pcs_keys` eviction is a TODO in `cgka.rs`) | **DCGKA** — fixable with a messaging profile (§4) |
| PCS | acks-are-PCS + updates | leaf rotation path updates; conflict-key rule blocks fork-compromise crossover | tie (different mechanisms, both credible) |
| Bootstrap complexity | X3DH + App-D 2SM mesh + the unsolved **OPK serve-once problem** + `retry-signed-only` | **All of it disappears.** Adds target the published prekey directly | **BeeKEM** |
| PQ path (D8) | HNDL funnel = 2SM/X3DH + sealed-asym; hybrid = `Kem` seam swap | Path encryption uses **bidirectional DH** (encrypter re-decrypts via the same DH pair, `keys.rs:try_decrypt_encryption`) — ML-KEM cannot slot in without restructuring to MLS-style per-resolution encapsulation; a hybrid means forking upstream | **DCGKA** |
| Group-size headroom | hard ceiling by O(n) budget (150 devices) | log n common case; ceiling becomes product choice, not protocol budget | BeeKEM |
| Implementation surface (TS port, D3) | dcgka-core + 2SM + DGM ≈ large; p2panda as oracle | beekem crate ≈ 3.5k lines, clean module cut (depends only on `keyhive_crypto`); Rust crate as differential oracle; WASM/TS bindings exist upstream | **BeeKEM** |
| State per group | γ + n² directional 2SM sessions + skipped-key stores | tree + op graph + key maps; **but op graph is retained forever** (replay depends on it — GC tension, §4) | mixed |
| Metadata/sealed-sender fit | D7 `sealed-sym` keyed from per-sender `I_sender` | No per-sender update secrets; derive per-sender envelope keys from `PcsKey` instead (secret-tree style) — D7 machinery survives with one derivation change | tie (edit, not redesign) |
| Ecosystem trajectory | trvedata prototype (dead), p2panda (stalled audit) | Ink & Switch + Automerge community, active, funded, same local-first doctrine as us | **BeeKEM** |

**Bottom line**: BeeKEM wins on everything we *feel* daily (complexity, bandwidth, the two hardest
open design risks — 2SM discipline and OPKs) and loses on the two things our doctrine says are
non-negotiable-ish (proof, PQ posture). Note the overview §5 lower-bound statement survives:
BeeKEM does **not** beat the decentralized-concurrency lower bounds — it degrades to O(n) under
concurrency and heals; it buys the good *common case*, which the lower bound permits.

## 3. What survives of Phase 0 (the honest inventory)

The spec set was deliberately layered; that pays off now.

| Doc | Fate under BeeKEM |
|---|---|
| `overview.md` | **Revise** (doctrine 4 wording, §5 perf, §6 limitations incl. proof downgrade + PQ note) |
| `ordering-auth.md` | **Survives ~intact** — BeeKEM *assumes* exactly what this layer provides: signed ops, causal deps, per-sender FIFO, repair, dedup. Op hash ≙ our MessageID; `predecessors` ≙ our deps |
| `sealed-sender.md` | **Survives** — asym mode + padding + anonymous ingress unchanged; §11 `sealed-sym` re-keys `envKey = Expand(PcsKey, label ‖ sender)` instead of `I_sender` |
| `identity-devices.md` | **Survives with simplification** — `at.atsms.prekey` drops `identityDh` (no X3DH); `signedPrekey` becomes the BeeKEM leaf/add key + sealed-asym target (D10's joint-use note updates; the pairing is *simpler* — both uses are DH-encrypt-to) |
| `dgm.md` | **Survives as the policy layer** (roles, admin rules, user→device expansion, ban-on-remove discussion) — BeeKEM owns key agreement, not authorization. Needs a reconciliation pass: strong-remove semantics vs BeeKEM's removes-applied-last merge |
| `wire-format.md` | **Skeleton survives** (CBOR discipline, envelope layouts, label registry, vector suite); op/frame schemas replaced by `CgkaOperation` shapes |
| `atsms-integration.md` | **Survives ~intact** — engine boundary (serialize-in/out), capability discovery, worker contract, migration stages are all CGKA-agnostic. The relay never sees the difference |
| `parameters.md` | Survives; constants change (ack cadence rows die, replay/GC bounds appear) |
| `dcgka-core.md` | **Superseded** → replaced by a `beekem-core.md` (tree, merge/replay, PcsKey handling, messaging profile) |
| `2sm.md` | **Superseded entirely** — with it die the App-D rotation discipline, the X3DH bootstrap, the OPK serve-once problem, and `retry-signed-only`. Largest single win |
| Analyses (mls/p2panda/q-channel) | Historical record — keep |

Decisions: D0–D2, D4–D6, D9 unchanged. D3 (TypeScript) unchanged — port beekem to TS with the
Rust crate as differential oracle (same strategy as p2panda, smaller surface). D7 survives with the
derivation change. D10 survives with an updated joint-use argument. **D8 must be re-opened** (§4).

## 4. The three real problems (what "adopt" must solve)

1. **Messaging profile vs document profile (FS/GC).** Keyhive built BeeKEM for encrypted document
   sync where re-decrypting history is a *feature*: old `PcsKey`s are cached indefinitely, old
   share secrets accumulate (`ShareKeyMap.extend`, never delete), and any historical root secret is
   re-derivable by replaying the op graph (`cgka.rs:rebuild_pcs_key`). Our FS bar is deletion-based.
   An **ATSMS messaging profile** must specify: PcsKey eviction (grace = the sealed-sym §11.4
   window), leaf/path secret deletion on supersession, per-sender chain keys layered over `PcsKey`
   for per-message FS inside an epoch (MLS-secret-tree-style, cheap), and the **GC-vs-replay
   reconciliation** — replay needs the *public* op graph (retainable; it's the same in-group
   metadata our welcomes already carry), while FS needs the *secrets* destroyed; late-arriving
   ciphertext beyond the grace window is then undecryptable-by-design, surfaced via the existing
   repair/staleness machinery (T_REPAIR_GIVEUP). Design work: real but bounded; nothing upstream
   contradicts it (their eviction TODO is exactly this hook).
2. **Proof downgrade.** Doctrine #4 ("the paper's proof is the contract") cannot be satisfied —
   BeeKEM has no proof. Mitigations: the TreeKEM family is the most-analyzed CGKA shape in the
   literature; our composition already carries a novelty flag with scheduled external review
   (overview §6.13) — adopting BeeKEM raises that review from "scheduled mitigation" to
   **gating requirement**, and doctrine #4 is rewritten as "the *reference implementation +
   test-vector equivalence* is the contract; external review before v1 alpha carries real traffic."
   This is a genuine loss. It is the price of the performance/simplicity column in §2.
3. **PQ regression (re-open D8).** The bidirectional-DH trick in path encryption blocks a pure
   ML-KEM slot-in; a hybrid tree means restructuring path encryption to per-resolution
   encapsulation (MLS-shape) — i.e., forking from upstream. Position to record: v1 classical
   (unchanged), PQ-hybrid lands on the *bootstrap + envelope* surface as before, and the tree's
   HNDL exposure is accepted-and-documented until a KEM-tree fork or upstream support exists.
   HNDL now covers group key material rather than only bootstraps — this must go into overview §6
   honestly.

## 5. Verdict

**Adopt BeeKEM as the CGKA core — proposed decision D11, gated on two design spikes** (write
before any spec rewrite):

- **Spike A — messaging profile** — ✅ **COMPLETE 2026-07-22, PASS**
  ([`spike-a-messaging-profile.md`](./spike-a-messaging-profile.md)): eviction/deletion schedule,
  per-sender chains over `PcsKey`, coverage-replaces-acks (PCS latency *improves* — no ack
  round-trip), checkpoint frontier reconciling replay with GC, and a new `rootCommit` check that
  upgrades seed-equivocation handling from detect to reject. FS parity table at §7: parity or
  better on every row.
- **Spike B — DGM reconciliation** — ✅ **COMPLETE 2026-07-22, PASS**
  ([`spike-b-dgm-reconciliation.md`](./spike-b-dgm-reconciliation.md)): DGM survives as the pure
  validity filter gating tree application (P1–P5 lift through); SR2 cascades ride BeeKEM's own
  replay trigger; the concurrent-remove collusion window is not reopened (it narrows on the
  processing side); checkpoint-cascade safety proven (frontier lemma, §6). Port requirements
  PR-1..3 recorded.

**Both gates passed → D11 is ready for sign-off.** On sign-off, Phase 0b (§6) executes.

If either spike fails, fall back to the current DCGKA specs (they remain complete and signed off
through D10). The rejected alternatives stay rejected: MLS still requires the sequencer (D0),
Q-channel still has no membership layer.

Why adopt despite §4: BeeKEM is the first design that passes D0 *natively* while giving
TreeKEM-class efficiency; it deletes our two largest unsolved/highest-risk areas (OPK serve-once,
2SM discipline correctness) rather than solving them; it has a living, license-compatible,
WASM-capable reference implementation aligned with our doctrine; and at 25-device typical groups
it cuts per-op traffic ~30×, ack storms included (which also simplifies the padding story the
buckets were sized for).

## 6. Plan update (if D11 signs off)

Phase 0 re-enters for the affected docs only — call it **Phase 0b** (est. same order of effort as
the 2026-07-16 drafting pass, minus 2SM):

1. Spikes A + B (above) — gate.
2. `beekem-core.md` (replaces dcgka-core.md): tree/merge/replay normative text, messaging profile,
   PcsKey→app-secret derivation with our HKDF-vs-BLAKE3 choice made explicit, test obligations
   keyed to the Rust crate as differential oracle.
3. Surgical edits: sealed-sender §11.2 (envKey derivation), identity-devices §3/§4.2 + D10 note
   (drop `identityDh`, prekey = leaf key), dgm.md reconciliation section, wire-format op schemas,
   parameters.md rows, overview doctrine/limitations, atsms-integration §6 API verbs (unchanged
   shape, renamed events).
4. Supersession banners on dcgka-core.md + 2sm.md (keep in place — they are the record of why
   2SM/OPK complexity exists and why we escaped it).
5. Implementation phases 1–2 re-scope: port `beekem` crate to TS behind the same serialize-in/out
   boundary; differential-test against the Rust crate (seeded RNG), replacing the p2panda oracle
   role. Phases 3–5 (sealed sender, identity, integration) largely unaffected.
6. D8 re-opened and re-recorded with the §4.3 position.

## 7. History capture & the archive question

**Do not wipe or wholesale-replace the directory.** Most of the spec set survives (§3), and the
analyses + decision logs D1–D10 are the project's institutional memory — the READMEs of *why*.

The actual gap: `atsms-dcgka/` **is not a git repository** — there is no history to archive beyond
what the docs' decision logs record. Minimal capture, in order:

1. `git init` + initial commit of the tree exactly as it stands today, tagged
   **`dcgka-classic-v1`** ("Phase 0 complete through D10, pre-BeeKEM"). That single commit *is*
   the minimal history — reversible, zero information loss, no file shuffling.
2. If D11 signs off: evolve in place on top of that commit — banners on superseded docs, new
   `beekem-core.md`, surgical edits elsewhere. Git carries the rest of the history from here.
3. Directory/package name: "DCGKA" reads fine generically (decentralized continuous group key
   agreement — BeeKEM *is* one), so no rename is required; if a rename to `atsms-cgka` is wanted
   later it's a separate, deliberate move (umbrella rule: confirm cross-repo renames first).
