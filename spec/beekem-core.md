# spec/beekem-core.md — BeeKEM Core & ATSMS Messaging Profile

> **Status: DRAFT v0.1 (2026-07-22) — for review.** [Protocol] · Phase 0b deliverable (decision
> **D11**, [`../beekem-analysis.md`](../beekem-analysis.md)).
> **Supersedes [`dcgka-core.md`](./dcgka-core.md) and [`2sm.md`](./2sm.md)** — re-answers gaps
> **G1** (dissolved: no pairwise channel exists), **G2** (coverage lifecycle), **G3** (application
> ratchet), **G7** (welcome/checkpoints), **G11** (concurrency mitigations), **G15** (storage/GC).
> Inputs: BeeKEM paper (`../BeeKEM.pdf`) + `inkandswitch/keyhive` `beekem` crate (clone 2026-07-09 —
> the **differential-test oracle**, replacing p2panda), [`../spike-a-messaging-profile.md`](../spike-a-messaging-profile.md)
> (normative content incorporated), [`../spike-b-dgm-reconciliation.md`](../spike-b-dgm-reconciliation.md)
> (PR-1..3), [`dgm.md`](./dgm.md), [`ordering-auth.md`](./ordering-auth.md). MUST/SHOULD/MAY per RFC 2119.
> The ordering layer feeds this machine only **ready, authenticated, deduplicated** frames; the DGM
> supplies validity judgments (§4.1).

## 1. Two-layer key schedule (overview)

- **Tree layer (ported BeeKEM, below the `PcsKey` seam)**: a binary ratchet tree — leaves hold
  member (device) X25519 keys, inner nodes hold subgroup secrets encrypted via DH to sibling
  resolutions, the root secret of epoch `e` is **`PcsKey_e`**. Updates re-key a leaf-to-root path
  in O(log n) common case; concurrency is merged with **conflict keys** and deterministic replay.
  Everything in this layer stays byte-compatible with the Rust oracle (§3 KDF split).
- **Profile layer (ATSMS, above the seam)**: per-sender FS-AEAD chains seeded from `PcsKey_e`
  (§7), sealed-sym envelope keys (sealed-sender §11.2), the eviction/GC schedule (§8), coverage
  (§5), checkpoints (§6), and the `rootCommit` integrity check (§4.3). Nothing in this layer
  touches tree/merge semantics.

There is **no pairwise 2SM channel and no X3DH**: admission encrypts to the joiner's published
prekey via ordinary tree path encryption (identity-devices §4.2).

## 2. State (γ, per device per group)

```
γ = {
  myId:          Membership,                     // (DeviceID, admittedBy) — dgm.md §2
  groupId:       MessageID,                      // = MessageID(create), ordering-auth §2.1
  tree:          BeeKemTree,                     // leaves, secret stores, conflict keys (oracle-shaped)
  opGraph:       CgkaOpGraph,                    // applied + pending CGKA ops, heads; prunable per §6
  checkpoint:    { frontier: [MessageID], treeState } | ⊥,
  leafSks:       Map<pk, sk>,                    // own leaf/path secrets — BOUNDED-EVICTING (§8)
  epochs:        Map<opId, { pcsKey, chainSeeds, envKeys, closedAt }>,   // open epochs only (§8)
  send:          SenderChainState,               // own chain in current epoch (§7)
  recv:          Map<(Membership, opId), ReceiverChainState>,  // + skipped-key stores (§7)
  coverage:      Map<Membership, frontier>,      // per-member covered frontier (§5)
  retained:      processed SignedFrames until covered-by-all (repair store, ordering-auth §8)
}
```

All of γ is serializable, encrypted at rest, and mutated **copy-on-success only** (§9).

## 3. Key schedule — byte-exact domain separation

**KDF split (DECIDED 2026-07-22, user sign-off)**: *below* the `PcsKey` seam, derivations are **BLAKE3**
exactly as the oracle computes them (`blake3::derive_key`; per-level path ratchet, DH→symmetric
key derivation) — byte-fidelity to the reference implementation is the port's primary correctness
anchor in the absence of a formal proof. *Above* the seam, derivations are **HKDF-SHA256**
(`Expand` as before), labels registered in wire-format §7:

| Value | Derivation |
|---|---|
| epoch | `e` ≙ the establishing `update` op's MessageID; `PcsKey_e` = tree root secret after applying it |
| per-sender chain seed | `chainSeed(e, S) = Expand(PcsKey_e, "atsms-beekem:v1:chain" ‖ enc(S))`, `S` = sender Membership |
| inner chain step | `msgKey = Expand(ck, "atsms-beekem:v1:msgkey")`; `nonce = Expand(ck, "atsms-beekem:v1:nonce")[0..12]`; `ck' = Expand(ck, "atsms-beekem:v1:next")` |
| sealed-sym envelope key | `envKey(e, S) = Expand(PcsKey_e, "atsms-seal:v1:sym" ‖ enc(S))` (sealed-sender §11.2 — sender now in the info because the ikm is shared) |
| root commitment | `rootCommit = H(PcsKey_e)` (§4.3; H = SHA-256) |

AEAD is **ChaCha20-Poly1305** (profile layer) — the tree layer's internal AEAD follows the oracle
(ChaCha20-Poly1305 with synthetic IV). Seeds/leaf keys are 32 bytes from a CSPRNG (injectable —
required by the oracle, §11).

## 4. Operations & the state machine

CGKA op set: `create`, `add`, `remove`, `update` — signed frames (class `control`), content-
addressed; the op's causal predecessors are the frame's `deps` (CGKA-op heads; ordering-auth §3).
`grantAdmin`/`revokeAdmin` are DGM-only control ops that never touch the tree.

### 4.1 DGM validity filter (PR-1/PR-2 — normative)

**An op is applied to the tree iff `dgm.md` judges it valid at its causal position in the full
frame DAG.** Invalid ops stay in the DAG as causal history (references to them are legal) but
MUST NOT touch tree state. The filter runs identically in incremental application and in replay
(PR-3: retroactive SR1/SR2 invalidation is handled by the replay BeeKEM already triggers on
concurrent membership changes — Spike B §4).

### 4.2 Handlers (semantics; tree mechanics per the oracle)

- `create(initialDevices, initialAdmins)` → the creator's leaf at index 0, `groupId` per
  ordering-auth §2.1, followed immediately by the creator's first `update` (no root exists before
  it). Founding members are admitted by the `create` (their Memberships derive from it) and enter
  the tree as leaves holding their published prekeys.
- `add(device)` → places the device's **published prekey** (`at.atsms.prekey.signedPrekey`,
  verified per identity-devices §4.2 before use, pinned in the signed op args) at the next leaf;
  **blanks the new leaf's path** — the root is invalidated until the next `update`. Welcome per §6.
- `remove(membership)` → blanks the target leaf and its path (`removedKeys` recorded in the op for
  merge bookkeeping); root invalidated. Removal of the last member is invalid (group dissolution
  is an application act).
- `update()` → fresh own leaf keypair + path encryption to the root: new secret per ancestor
  (one-way ratchet per level), encrypted to each node of the sibling's **resolution** (single key
  common case; blank/conflict nodes → their highest non-blank descendants). Emits the
  `PathChange` (+ `rootCommit`, §4.3). Establishes epoch `e` = this op.
- **Merge (concurrent ops)**: per the oracle — concurrent updates merge public keys into
  **conflict keys** and merge secret-store versions (superseded keys substituted via
  `removedKeys`); a conflicted root has **no valid `PcsKey`** until a fresh update. Any epoch
  containing a membership change forces **replay** from the checkpoint (§6) in deterministic
  topological order, removes applied last, removed paths re-blanked, concurrently-added leaves
  re-sorted by MemberId (= device fingerprint — deterministic total order).

### 4.3 Root commitment (normative; deviation from the oracle)

Every `update` op carries `rootCommit = H(PcsKey_e)`. On deriving `PcsKey_e`, a member MUST
verify it against `rootCommit`; mismatch ⇒ **reject the op** (no state change) and surface a
security event naming the author. This closes insider **seed equivocation** (one signed op whose
path encryptions deliver different secrets to different resolutions) at processing time —
possible because BeeKEM has a single root secret per epoch, where DCGKA's per-member secrets
forced after-the-fact digest detection (dgm.md §8, now narrowed). Excluded from oracle
byte-comparison (allowlist, §11).

## 5. Coverage lifecycle (replaces acks — G2)

**There are no protocol acks.** PCS needs none: member `M` is healed, for everyone, the moment
they process `M`'s `update` op — no round-trip (a strict improvement over the ack design;
dominant PCS latency is now delivery, not ack turnaround).

**Coverage** exists for GC, eviction, and staleness only. Op `X` is **covered** by `M` iff `M`
authored any signed frame `Y` with `X ≼ Y` (causal descent via `deps` — implicit in all ordinary
traffic). **Covered-by-all** = covered by every member of the evaluator's current view.

- A member that has processed a membership op or `update` and has nothing else to send SHOULD
  emit a `coverage` control frame (empty payload; deps carry the information) within
  **`T_COVER` = 24 h (PROPOSED**, [`parameters.md`](./parameters.md)**)** — jittered, padded, and
  a natural carrier for the consistency digest (dgm.md §8).
- Trade recorded: GC/eviction latency rises (60 s ack flush → ≤ `T_COVER`); memory stays bounded
  by the 30 d caps (§8); the post-op **ack storm disappears** (n frames within seconds of every
  op — the traffic signature sealed-sender §5's buckets were sized around).
- A silent member blocks coverage → frontier → GC, exactly as it blocked acked-by-all: surfaced
  via ordering-auth §9 (7 d warn / 30 d eviction proposal, values unchanged).

## 6. Welcomes & checkpoints (G7)

- **Checkpoint** = serialized tree state + op-graph frontier at a **covered-by-all** frontier.
  Members maintain one; ops strictly behind it are pruned (with their retained frames, §8).
  *Safety*: no future valid op can be concurrent with anything behind a covered-by-all frontier
  (every member has authored a frame descending from it), and SR cascades cannot cross it
  (Spike B §6 lemma) — replay from checkpoint is complete. Suggested cadence (**PROPOSED**):
  advance at every covered-by-all membership op.
- **Welcome** (to a joiner, sealed-asym): `checkpoint` + the op-suffix since it (SignedFrames —
  joiner re-validates every suffix signature and runs the DGM itself) + delivery map + profile.
  The checkpoint portion is adder-asserted (the joiner cannot re-validate pruned history) — the
  same trust the adder already holds (it could equally omit ops); divergence is caught by the
  digest/`rootCommit` machinery. Oversize welcomes ride blob offload (sealed-sender §5).
- The joiner can decrypt **nothing prior to the first `update` after its `add`** (its path was
  blanked): no-history-to-joiners holds by construction. **Healing rule (normative)**: every
  joiner MUST send its own `update` immediately after processing its welcome — its leaf key until
  then is its *published* prekey (exposure window = prekey rotation + grace; identity-devices
  §4.2), and the first self-update replaces it with a never-published key.

## 7. Application-message ratchet (G3)

Unchanged in construction from the superseded design — only the seed root moved:

- Per-sender FS-AEAD chains, reseeded per epoch: on deriving `PcsKey_e`, each member computes
  `chainSeed(e, S)` for every member `S` (§3); sender chains start at generation 0.
- Per message: derive `msgKey`/`nonce`, encrypt with AD = `enc(groupId ‖ senderMembership ‖
  generation)`, increment, **delete** `msgKey` and the pre-step `ck` immediately.
- **Epoch anchor** = the establishing `update` op, expressed **only** as the ordering-layer dep of
  the epoch's first app message (ordering-auth §3) — never in payload or AEAD (the per-epoch key
  already binds the epoch; same argument as the 2026-07-16 decision, same
  `(ciphertext, generation)` wire shape, wire-format §4.4).
- Out-of-order handling via the skipped-key store, constants unchanged:
  `OUT_OF_ORDER_TOLERANCE = 100`, `MAX_FORWARD_DISTANCE = 1000`, `MAX_SKIPPED_TOTAL = 2000`
  per group; single-use skipped keys; epoch-expiry per §8.

## 8. Storage, eviction & GC (G15 — the FS core)

The single deliberate divergence from Keyhive's document-sync posture: **Keyhive retains; we
evict.** Epoch `e` is **closed** when its op is covered-by-all, or at `T_EPOCH_GRACE`
(**PROPOSED** = `T_REPAIR_GIVEUP` = 30 d), whichever first.

| Item | Bound / prune rule |
|---|---|
| `PcsKey_e`, `chainSeed`s, `envKey`s, receive chains of `e` | delete when `e` is closed AND a later epoch is established |
| chain keys / msgKeys | delete-on-advance / delete-on-use (§7) |
| skipped msgKeys | §7 caps; expire when their epoch closes |
| own leaf/path secrets (`leafSks`) | evict when the pk appears in a covered-by-all op's `removedKeys` (+ epoch grace) — **the oracle's `ShareKeyMap` only ever extends; the port MUST evict** |
| open-epoch map | bounded by unclosed epochs (≤ 30 d each) |
| retained SignedFrames (repair store) | until covered-by-all, cap 30 d (ordering-auth §8, values unchanged) |
| public op graph | prunable strictly behind the checkpoint frontier (§6) |

Consequences (features, not caveats): historical `PcsKey` re-derivation à la the oracle's
`rebuild_pcs_key` is **impossible beyond grace** — the port MUST NOT implement unbounded
rebuild; ciphertext arriving after its epoch closed is undecryptable-by-design and surfaces via
repair give-up. Encrypted-at-rest and best-effort zeroization rules carry over verbatim
(JS-runtime limits documented; accepted consequence of D3).

## 9. State-mutation discipline (normative)

Carried unchanged from the superseded design: `process()` MUST NOT mutate persistent state before
all verification succeeds (signatures upstream; tree decryption, `rootCommit`, DGM validity,
AEAD here) — copy-on-success / transactional commit. A forged or corrupt frame must not advance
chains, stuff skipped-key stores, grow the op graph, or perturb tree state.

## 10. Concurrency & healing rules (G11)

- **No-root → update-first (normative)**: any app send while the tree has no uncontested root
  key (after any add/remove; after a concurrent-update merge conflicts the root; after joining)
  MUST be preceded by the sender's own `update`. This absorbs the old dominating-update rule's
  concurrency cases and matches the oracle's behavior.
- **Retroactive-invalidation update (normative, retained)**: after any retroactive DGM
  invalidation (SR1/SR2), a member MUST send its own `update` before its next app message — a
  cascade can invalidate an `add` without any root-blanking op, leaving a root whose resolutions
  included the invalid leaf (Spike B §7).
- **Collusion window (documented)**: identical in kind to the accepted App-C posture and narrower
  in practice — a member that has processed a `remove` cannot send at all until a fresh update
  excludes the target (blanked root); only members that have not yet seen the remove extend the
  window, bounded by causal propagation.
- **Sender-view guarantee (documented)**: unchanged — a sender knows exactly which member set
  could decrypt each message; UX surfacing duties unchanged.

## 11. Test obligations

1. **Differential oracle (`beekem` Rust crate, replaces p2panda)**: seeded scenario transcripts —
   tree state, `PathChange` bytes, `PcsKey`s — byte-compared below the seam; profile features
   (`rootCommit`, eviction, chains, checkpoints, coverage) on an explicit allowlist; oracle runs
   unfiltered on DGM scenarios with divergences required to occur only where the filter fired
   (Spike B §9.5).
2. **FS/PCS game tests**: per-message FS in-epoch (chains), epoch eviction FS (closed-epoch
   ciphertext undecryptable), PCS-on-update-processing (no ack dependency), conflict-key
   fork-compromise vector (compromising one fork's path secrets does not open the other), the §10
   collusion-window vector.
3. **Merge/replay vectors**: concurrent updates (conflict keys, no-root state), concurrent
   add/add re-sort determinism, remove∥update re-blank, structural-change replay ≡ incremental.
4. **Frontier property test**: random DAGs, checkpoint pruning at every covered-by-all frontier —
   filtered replay from checkpoint ≡ from init (Spike A §5 / Spike B §6).
5. **`rootCommit` vectors**: honest match; crafted mismatched-resolution op rejected with no
   state change.
6. **Crash-consistency**: kill/restart between receive and commit at every boundary (§9).

## 12. Open questions (tracked for review)

- ~~KDF split~~ **DECIDED 2026-07-22 (user sign-off)**: BLAKE3 below / HKDF-SHA256 above the seam (§3).
- ~~`T_COVER` / `T_EPOCH_GRACE` / checkpoint cadence~~ **DECIDED 2026-07-22 (user sign-off)**: 24 h /
  30 d / every covered-by-all membership op ([`parameters.md`](./parameters.md)).
- **Coverage frames as digest carriers** (§5, dgm.md §8 cadence interaction) — drafted as
  natural pairing; confirm.
- **`rootCommit` upstream divergence** (§4.3): consider proposing upstream to keyhive; until
  then it is a permanent oracle-allowlist entry.
- **D8 (post-quantum) re-opened by D11** — position recorded in overview §6.12: the tree's
  bidirectional-DH path encryption cannot take ML-KEM without restructuring; v1 classical,
  hybrid on the envelope/bootstrap surface, tree HNDL exposure documented.
