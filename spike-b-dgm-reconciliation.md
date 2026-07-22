# Spike B — DGM / Strong-Remove Reconciliation with BeeKEM

> **Status: SPIKE COMPLETE (2026-07-22) — verdict PASS.** Gate 2 of decision D11
> ([`beekem-analysis.md`](./beekem-analysis.md) §5). Answers: do dgm.md's P1–P5 and SR1–SR5
> survive when the key-agreement executor is BeeKEM's tree instead of DCGKA's seed fan-out, and
> does the removes-applied-last merge rule reopen the concurrent-remove collusion window beyond
> what dcgka-core §10 accepted?
> Sources: dgm.md (whole), dcgka-core.md §10, `beekem/src/{cgka,tree,keys,operation,topsort}.rs`.

## 1. Architecture: DGM stays the law, BeeKEM becomes the plumbing

Keyhive does authorization in `keyhive_core` (capability graph) — **we do not adopt that layer**.
Our DGM remains exactly what dgm.md §1 says: a pure, deterministic function from the signed op DAG
to `members_view`. The reconciliation is one rule:

> **An op is applied to the BeeKEM tree iff the DGM judges it valid at its causal position.**
> Invalid ops remain in the DAG as causal history (predecessor references to them are legal) but
> never touch the tree.

Since DGM validity is a deterministic function of the op set + causal order (P1), all honest
members compute the same accepted subset, and BeeKEM's own deterministic apply/merge/replay then
yields identical trees (P5 lifts through). **Port requirement PR-1**: the validity filter hooks
`apply_operation` / `apply_epochs` / `replay_ops_graph` (upstream applies unconditionally).

Two graphs, one truth: the ordering layer's frame DAG (all frames, incl. role ops) ⊇ BeeKEM's
CGKA op graph (create/add/remove/update only). `grantAdmin`/`revokeAdmin` never touch the tree —
they are ordering-layer control frames whose effect is entirely inside the DGM evaluation.
DGM validity of a CGKA op is evaluated at its position in the **full** frame DAG (**PR-2**).

## 2. Property-by-property (dgm.md §3)

- **P1 Determinism** — preserved. BeeKEM adds no clocks; `topsort` tie-breaks are content-hash
  based; the concurrent-add re-sort is "deterministically by identity" (`tree.rs` sort step). Our
  MemberId instantiation = the device fingerprint (32-byte SHA-256 SPKI) — stable and total order.
- **P2 Sequential self-consistency** — preserved (BeeKEM applies own ops immediately; replay
  reproduces them in causal order).
- **P3 Add-only entry** — preserved: only an applied `Add` creates a leaf; the re-sort step
  reshuffles *where* concurrently-added leaves sit, never *whether* (no conflict rule admits
  anyone). `cgka.rs:add` refuses an id already in the tree.
- **P4 No remove-undo** — preserved and mechanically enforced: removes are applied **last** within
  a concurrent epoch and the removed path is **re-blanked after merge** (README "Merging Concurrent
  Membership Changes") — a concurrent update cannot leave usable key material on a removed path.
  This is strictly stronger than what P4 asks.
- **P5 Convergence** — lifts through the filter (§1) + BeeKEM's replay guarantee.

## 3. Membership identity mapping

`Membership = (DeviceID, admittedBy)` maps directly: `admittedBy` = the digest of the signed
`Add`/`create` op (`Digest<Signed<CgkaOperation>>` ≙ our content-addressed MessageID — same
construction). Re-add after remove is **permitted by upstream** (id no longer in tree ⇒ fresh
leaf, fresh prekey) and produces a fresh Membership; all profile keys (chainSeeds, envKeys,
Spike A §2) are keyed by Membership, so **no state resumption is structurally possible**. This
resolves the 2026-07-17 worry ("nobody has shipped bare-key IDs + re-add + ratchet state
together") cleanly: BeeKEM ships re-add; the Membership keying supplies the state separation
p2panda lacked. **Ban-on-remove stays parked** (dgm.md §10) — it is pure policy in the DGM filter
and BeeKEM neither helps nor hinders it.

## 4. SR1–SR5 under the filter

- **SR1 (invalidate concurrent ops of the removed)**: a removed member's concurrent `Update`
  becomes DGM-invalid → filtered from the tree. Note BeeKEM would be *safe* even unfiltered
  (re-blanking clears the removed path; conflict-key rule prevents fork crossover), but filtering
  is still required so the *membership view* (and seed of §4-role decisions) matches dgm.md — the
  tree and the DGM must never disagree about who is a member.
- **SR2 (transitive cascade)**: an invalidated `Add` ⇒ that member never admitted ⇒ all its ops
  invalid recursively. Mechanically this is a replay-with-filter from a state before the cascade
  root — and BeeKEM **already owns exactly this trigger**: a concurrent membership change sets
  `pending_ops_for_structural_change` and forces `replay_ops_graph()` (`cgka.rs:should_replay`).
  Retroactive invalidation and BeeKEM replay are the *same event* — no new machinery, just the
  filter riding along (**PR-3**: cascade recomputation happens inside the existing replay).
- **SR3 (mutual removes)**: both removes valid → epoch applies both last → both paths blanked,
  both out. Matches.
- **SR4 (no resurrection)**: filter-only concern, unchanged; the tree never re-admits (P3).
- **SR5 (self-leave priority)**: a self-remove is DGM-valid regardless of concurrent removes of
  the same target; tree-side both blank the same leaf — idempotent. Upstream's
  `RemoveLastMember` guard aligns with the last-admin/last-member freeze semantics (dgm.md §4);
  group dissolution remains an app-layer act.

## 5. Same-DID authorization, roles, user→device expansion

Untouched. These are all evaluated inside the DGM filter (§1) before any tree contact: same-DID
add/remove by any member device of that DID; cross-DID requiring admin; `grantAdmin` requiring a
current member device; user-level intents expanding to per-device op batches. The concurrent-add
re-sort does not interact with authorization (invalid adds were filtered before sorting).

## 6. Checkpoint-frontier safety (the cross-spike lemma)

Spike A §5 prunes ops behind a **covered-by-all frontier**. Retroactive invalidation must never
need them. Lemma: *no SR cascade crosses a covered-by-all frontier.* Argument: (i) a frontier is
covered-by-all ⇒ every member has authored a frame causally descending from it ⇒ any later valid
op's predecessors transitively include the frontier ⇒ **no new op is concurrent with anything
behind the frontier**; (ii) SR1 invalidates only ops *concurrent with or authored after* the
remove, so a post-frontier remove touches only post-frontier ops; (iii) SR2 cascades through ops
authored by members admitted by invalidated adds — a member's ops causally follow its admitting
add, so a post-frontier invalidated add implies post-frontier cascade members. Hence replay-from-
checkpoint with the filter is complete. (Property test in §9.)

## 7. The concurrent-remove collusion window (dcgka-core §10 / paper App. C)

Accepted posture today: concurrently-removed members can collude on messages sent *before a
dominating operation exists*; the dominating-update rule manufactures one ASAP. Under BeeKEM:

- Once a member processes a `Remove`, the root is blanked — **it cannot send at all** until a
  fresh update excludes the removed leaf (Spike A §3 forces exactly that). Zero post-processing
  traffic under stale keys — better than the DCGKA baseline, where sending continued under
  existing chains until reseeding completed.
- Members who have **not yet seen** the remove keep sending under the old epoch's `PcsKey`, which
  the removed member holds — the classic window, identical in kind and duration (bounded by causal
  propagation) to the accepted App. C posture. Not reopened, not widened.
- Removes-applied-last does not extend the window: it governs merge order within an epoch batch,
  and the re-blank guarantees the post-merge tree contains nothing the removed member can use.
- **Residual rule retained (normative, from dgm.md §5 note)**: after any *retroactive* DGM
  invalidation, a member MUST issue its own update before its next app send. Reason: a cascade can
  invalidate an `Add` without any root-blanking op in between — the surviving root's resolutions
  may have included the now-invalid leaf, so the epoch key must be treated as exposed even though
  `has_pcs_key()` is still true. This is the one §10 case the "no root key → update" rule does
  not absorb.

## 8. What dgm.md needs in Phase 0b (all edits, no redesign)

§1 executor note (tree applies filtered ops); §2 `admittedBy` = signed-op digest (terminology
only); §6 rewritten — **ack-tracking dies with acks**: `members_view(viewer)` re-bases on coverage
(frames authored / causally seen by the viewer, Spike A §5) — same shape, different signal, and
welcomes carry checkpoint + op suffix instead of "processed DGM state + ratchet states"; §8
digests narrow to head-set/tree-hash comparison, with key-material equivocation now rejected
outright by Spike A §6's `rootCommit`.

## 9. Test obligations carried to Phase 0b

1. Permutation determinism (dgm.md §9.1) re-run **through the filtered tree**: identical
   `members_view` AND identical tree hash across ≥ many interleavings.
2. All strong-remove vectors (§9.2) re-expressed as op-DAG fixtures asserting both view and tree:
   add∥remove-of-adder (SR2 through replay), mutual admin remove (SR3), remove∥target-adds-device,
   re-add fresh-Membership no-state-resumption (chainSeed/envKey isolation), cascade depth ≥ 3,
   last-admin/last-member guards.
3. **Frontier-cascade property test** (§6 lemma): random DAGs with checkpoint pruning at every
   covered-by-all frontier — filtered replay from checkpoint ≡ filtered replay from init.
4. Collusion-window vector (§7): removed member's decryption capability ends exactly at the first
   post-remove update; late senders' pre-knowledge messages decryptable by the removed member —
   asserted as *documented*, matching the accepted posture.
5. Oracle boundary: upstream Rust crate runs the same DAG fixtures **unfiltered** — divergences
   MUST occur only where the filter fired (explicit allowlist), proving the port's tree mechanics
   are otherwise byte-faithful.

**Verdict: PASS.** The DGM survives as specified (policy unchanged, one signal swap in §6);
BeeKEM's own replay trigger is the natural host for SR retroactivity; the collusion window is not
reopened — it narrows on the processing side. Port requirements: PR-1 filter hook, PR-2 full-DAG
evaluation, PR-3 cascade-inside-replay, plus Spike A's eviction/checkpoint/rootCommit set.
