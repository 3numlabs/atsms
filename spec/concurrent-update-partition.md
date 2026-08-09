<!-- cSpell:words DCGKA BeeKEM prekey prekeys asym sym CGKA blanked rootless -->

# Concurrent-update partition — root cause and proposed fix

> **Status: ACCEPTED (2026-08-01) — implementing 4.1 + 4.2 + 4.3.** Root cause confirmed by a
> reproducible trace; fix shape settled after researching `create` vs first-`update` across
> BeeKEM/Keyhive, the WKHB DCGKA paper, p2panda, and MLS (see §4 grounding). Wire-level create+update
> fusion was considered and **rejected on security grounds** (it reintroduces the concurrent-update
> PCS attack BeeKEM's "No secret after merge" property exists to prevent). Supersedes the preliminary
> hypotheses in [`../KNOWN-ISSUES.md`](../KNOWN-ISSUES.md).

## 1. What happened live

First multi-client test of two independent devices (CLI creator + browser joiners, 4 devices in one
group). Symptom: **no messages crossed between the creator and the joiners, in either direction,
with no errors on either side.** Joiner↔joiner traffic worked. Inspecting both persisted engines
showed identical membership but disjoint live epochs — the creator holding only its own, the
joiners only theirs.

## 2. The mechanism (confirmed by trace)

Reproduced deterministically with a two-member group (`epoch-diag-repro`, §6):

```
after create:              A cur=null      live=[]           | B cur=null   live=[]
A updates (in flight):     A cur=82bcc987  live=[82bcc987]   | B cur=null   live=[]
B updates concurrently:    A cur=82bcc987  live=[82bcc987]   | B cur=103fff62 live=[103fff62]
A's update delivered to B: A cur=82bcc987  live=[82bcc987]   | B cur=null   live=[103fff62]
B's update delivered to A: A cur=null      live=[82bcc987]   | B cur=null   live=[103fff62]
A heals (update):  sealEpochFor(heads) = 82bcc987     ← an epoch ONLY A holds
B heals (update):  sealEpochFor(heads) = 103fff62     ← an epoch ONLY B holds
after A's healing update:  A cur=39015712 live=[82bcc987,39015712] | B cur=null live=[103fff62]
>>> messages B received: 0
```

Step by step:

1. **Concurrent updates at genesis.** The creator runs its mandatory post-create `update()`. A
   joiner, having bootstrapped from the `create` frame, tries to send before that update arrives,
   hits `NoRootKey`, and self-heals with its *own* `update()` (the client's documented retry path).
   Two updates now sit at the same causal depth, each concurrent with the other.
2. **Each side derives only its own epoch.** An update's path is encrypted from the author's leaf;
   the author derives the root immediately (`registerEpoch`). The counterparty's update arrives as
   a *concurrent* op, so on merge the tree keeps conflict keys and **the root is blanked** — by
   BeeKEM design (beekem-core §4: concurrent updates leave the root underivable until a subsequent
   update). So neither side ever derives the other's epoch.
3. **Post-merge, both sides are rootless but each still holds a live epoch** — its own, now
   effectively private. `currentEpochId` is correctly `null` on both.
4. **The healing update is sealed under that private epoch.** `Engine.sealEpochFor(deps)` picks the
   latest live epoch among the frame's causal ancestors. Each side's own stale epoch qualifies
   (it is live locally, and it is an ancestor), so the frame that would repair the group is
   `sealed-sym` under a key **the recipients have never derived**.
5. **The recipient cannot open it, and says nothing.** The seal layer finds no matching tag, pushes
   the envelope into an in-memory FIFO buffer, emits no event — while the transport has already
   acked and deleted the relay copy. The repair frame is gone.
6. **Permanent partition.** Each side happily derives further epochs from its own healing updates
   and sends into the void; the other side buffers and drops. No timeout, no error, no recovery
   path. Joiner↔joiner traffic is unaffected because those devices did converge on one epoch.

## 3. The violated invariant — and where it lives

> *A frame may only be sealed under an epoch that every recipient can be expected to have derived.*

`sealEpochFor` approximates "the group's established epoch" with "the latest live epoch among my
ancestors". That approximation is exact **only while the causal history is linear**. A merge that
blanks the root is precisely the event that makes a locally-live epoch *not* group-shared — and it
is the one case the rule does not account for. The bootstrap escape hatch that should apply here
already exists and is already used for the first update after `create` (where `sealEpochFor`
returns `null` and the frame rides `sealed-asym` to each recipient's prekey); it simply is not
reached, because a stale epoch is found first.

**The bug is in our sealed-sender layer, not in the CGKA.** This is worth stating precisely,
because it decides the fix (§4). Two facts about upstream BeeKEM (the `beekem` crate, our
differential-test oracle; and the formal BeeKEM paper, `../BeeKEM.pdf`):

1. **A blank-root-after-merge is expected, benign BeeKEM behavior.** The paper elevates it to a
   named security property — *"No secret after merge: there is no new group secret defined after
   the merge of concurrent operations; only an Update can define a group secret"* (BeeKEM paper
   §4.2). This is exactly what gives BeeKEM post-compromise security under concurrency: the WKHB
   DCGKA and Causal TreeKEM designs, which *do* define a secret from concurrent updates, have
   concrete attacks where a compromised member's concurrent update lets the attacker compute the
   new group secret. BeeKEM closes that class by refusing the secret. Keyless genesis is the same
   rule at birth (*"there is no group secret defined upon group creation"*, §4.3.2). Upstream
   recovers from the blanked state trivially — *someone updates again* — and converges.

2. **Upstream's send-gate already treats a post-merge state as unsendable.** `has_pcs_key()` is
   *stricter* than "has a root key": it also requires a single ops-graph head and `< 2` add heads
   (`beekem/src/cgka.rs`), so a merged-but-unresolved history cannot send even if a root key
   technically materialized. Our engine's send-gate matches this — after the merge `currentEpochId`
   is correctly `null` on both sides (see the trace, `currentEpochId is correctly null on both`).

So the CGKA is behaving exactly as designed and as the oracle specifies. What upstream does *not*
have is a per-epoch sealed-sender layer: in Keyhive, "update again" reaches everyone and converges.
**We added sealed sender (§11.4), and its `sealEpochFor` strands the very frame that would repair
the group** — sealing the healing update under a locally-live-but-orphaned epoch, which our
transport then silently buffers and acks away. The gap is between beekem-core's merge semantics and
sealed-sender §11.4's epoch-selection rule; the CGKA is not implicated, and neither is the message
format.

## 4. Proposed fix

Grounding (research 2026-08-01, `create` vs first-`update` across BeeKEM/DCGKA-paper/p2panda/MLS):
the create/update split is **not** cosmetic and must not be collapsed at the wire. For a tree-based,
sequencer-free design — our exact setting — keyless genesis is load-bearing for the "No secret after
merge" security property (§3). The designs that fuse creation with key establishment are either
seed-broadcast (DCGKA paper, p2panda — and they *pay* with the concurrent-update PCS attack) or
sequenced (MLS — no genesis concurrency to reconcile). **A secret-bearing `create` would reintroduce
the attack class BeeKEM exists to prevent**, and BeeKEM itself deliberately removed exactly that
(the "separate Cgka construction from update" refactor). Fusion is therefore rejected on security
grounds, not merely oracle-fidelity. The fix keeps the two-op shape and corrects our own seal layer.

### 4.1 Primary — seal-epoch selection must respect "no usable key after merge" (engine)

This is **porting upstream's `has_pcs_key` strictness up into `sealEpochFor`**: an epoch orphaned by
a root-blanking merge is not a usable key, so it must not be a seal target — the same invariant the
send-gate already enforces, applied to seal-selection.

The rule is a **stateless predicate, not a stored flag**: an epoch is sealable iff its establishing
`update` op is an **ancestor of every current head**. That is exactly "not orphaned by a concurrent
sibling update" — if two updates collide, neither is an ancestor of the other's head, so both are
disqualified; but a *shared parent* epoch that both updates descend from is still an ancestor of all
heads and stays sealable. `sealEpochFor` filters live epochs through this predicate before choosing
the maximal one:

- **Genesis race** (concurrent first-updates, no shared parent): both epochs are heads, neither an
  ancestor of the other → both unsealable → `sealEpochFor` returns `null` → the seal layer's
  existing `null` branch sends the healing update **`sealed-asym` to each recipient's prekey** (the
  same bootstrap-class path used after `create`).
- **Established-group race** (two members update concurrently on top of a shared epoch `E0`): the
  two new epochs are unsealable, but `E0`'s op is an ancestor of all heads → `E0` stays sealable →
  the healing update rides **`sealed-sym` under `E0`**, which everyone still holds. Strictly better
  than forcing asym, and it is why the rule is a predicate rather than a blanket flag.
- An epoch derived *after* the merge (from a healing update everyone can now open) becomes an
  ancestor of the new heads and is sealable again; normal `sealed-sym` operation resumes.

Why it cannot regress the healthy path: in any linear history the returned epoch's op is always an
ancestor of all heads, so the predicate changes nothing — it differs from the pre-fix behavior
**only** when an epoch has been made concurrent by a merge. Recovery then falls out of the existing
machinery, exactly as upstream's "update again" converges: A's healing update reaches B, B applies
the path, derives the same root, both converge, traffic flows. Cost: one predicate + one filter
clause in `sealEpochFor` (`engine.ts`). No stored state, no wire change, no new op, no round trip;
and it moves us *toward* the oracle, not away.

### 4.2 Genesis — orchestration fusion, not wire fusion (client)

The genesis race is the common *trigger*: a joiner, bootstrapped from `create` but not yet holding
the creator's first-update epoch, tries to send, hits `NoRootKey`, and self-heals with its own
update — concurrently with the creator's mandatory update. That is the collision.

The correct fix mirrors BeeKEM's **own** API-layer discipline (it establishes the first key eagerly
in `Document::generate` — create → add → update, emitted together — and lazily in
`new_app_secret_for`): the creator's first update is *part of creating the group*, so a joiner that
has membership but no epoch should **wait** for it rather than reflexively heal. Concretely: on
`NoRootKey` at a member that has never held any epoch, wait a bounded, jittered interval for the
creator's update to arrive before minting a self-heal; self-heal only if it never comes (creator
vanished). This removes the trigger with a client-only change and zero oracle divergence. (For
established-group concurrency — two members healing at once after an add/remove — 4.1 is what makes
it converge rather than partition; the wait only addresses genesis.)

### 4.3 Make undecryptable traffic loud and durable (seal layer + transport)

- Emit a security event when a sym envelope survives the buffer window unopened ("unknown epoch tag
  from a member") instead of silently FIFO-dropping. This alone would have made the live bug a
  five-minute diagnosis.
- Do not let the transport delete a relay copy of an envelope that was neither opened nor
  definitively rejected. Needs a small policy decision, since sealed sender makes "not mine" and
  "not mine *yet*" indistinguishable — proposal: ack on open **or** on buffer eviction, and treat
  the relay's own TTL as the backstop.

### 4.4 Caveat to note during implementation

The asym re-bootstrap encrypts to the prekey recorded in the `create`/`add` op (leaf key = signed
prekey, D10). If a member's prekey has rotated beyond the grace window, that fallback silently
reaches nobody (`if (pk !== undefined)`). Fine for the genesis race (minutes-old prekeys); for
long-lived groups the host should be able to refresh a member's current prekey from its published
record. Flagging as a follow-up, not part of this fix.

## 4b. Add-flow variant — the adder must establish the post-add epoch (FIXED 2026-08-01)

Live 3-way testing surfaced a second, worse instance: A+B converge, A adds C, then A's post-add
send and C's post-join heal race — and the group **permanently forks** (the adder isolated on one
epoch lineage, the rest on another), not even converging on repeated sends. This is distinct from
§2/§4: the divergence is in the *tree*, below the seal layer, so 4.1 cannot reconcile it.

Root cause: an `add` blanks the root (beekem-core §10). The current flow built the welcome
immediately after the add, so its op log ended rootless; the joiner then had to heal, *concurrently*
with the adder's own post-add heal (triggered by the adder's next send). Two concurrent updates over
a freshly-changed membership produce different merged trees on different members — a fork that never
heals. (The synchronous-delivery e2e "add carol" test never caught this because it serializes.)

Fix (`packages/client` `ConversationSession.addMember`, orchestration only): **add → update → buildWelcome**.
The adder establishes the post-add epoch as part of the add (its own update, encrypted to
resolutions that include the new leaf), and the welcome's op log now carries that update. The joiner
derives the post-add epoch directly on welcome replay — no heal race — and its own FS heal then lands
cleanly on top of the shared epoch. This is the same "born with an epoch" orchestration as the
genesis fix (§4.2), applied to membership changes; the serialized-delivery path already proved the
machinery. Reproduced + verified in `packages/client/src/tests/add-concurrency.test.ts` (a controllable
buffered hub makes the race deterministic, unlike the synchronous loopback).

## 5. What this does *not* fix

Groups already partitioned (e.g. the live test's) stay broken: the epochs each side needs were
never derived and cannot be reconstructed. There is no repair for existing poisoned conversations —
recreate them. A general "I cannot read your traffic, re-bootstrap me" repair protocol is the
proper long-term answer and remains open work for the identity/recovery phase.

## 6. Test plan — DONE (`packages/client/src/tests/partition.test.ts`)

All five pass; they exercise the real sealed path (`deliverEnvelope` → seal layer → `sealEpochFor`),
which is where the bug lived. The engine unit suite (117) and the convergence fuzz (4, real timeout)
stay green, confirming the predicate changes behavior only under a blanking merge.

1. **Regression (the trace above):** two members, concurrent genesis updates, cross-deliver, heal —
   asserts bidirectional delivery. Was the confirmed failure; now converges. The heal seals
   `sealed-asym` (verified via `envelopeMode`), reaches the peer, both derive one epoch.
2. **N-way:** creator + 3 joiners all self-heal concurrently — asserts convergence to a single epoch
   (all engines report the same `currentEpoch`) and full-mesh delivery.
3. **No regression in the linear case:** asserts a healthy app send still seals `sealed-sym`
   (`envelopeMode === MODE_SYM`) under the established epoch — 4.1 does not push traffic onto asym.
4. **Decryption of pre-merge traffic:** a message sealed under `E0` and delivered *after* a merge
   orphaned `E0` still opens — an orphaned epoch stays decryptable, only unsealable.
5. **Loud unopenable (§4.3):** foreign sym traffic a member cannot open surfaces
   `unopenable-envelope` after the retry threshold instead of buffering silently.

Still open: a live two-client smoke deliberately reproducing the original race (joiner sends
immediately on bootstrap) — to run against the deployed worker.

### Implementation landed

- **4.1** `packages/dcgka/src/engine.ts` — `sealEpochFor` filters live epochs through
  `hasConcurrentUpdate` (an epoch is sealable iff its establishing update has no concurrent sibling).
  Stateless; no wire change. *(Note: an earlier "ancestor of all heads" predicate was wrong — a
  merged sibling makes an orphaned epoch an ancestor of the later heal — corrected to the
  concurrency test.)*
- **4.2** `packages/client` `ATSMSConversation.send` — on `NoRootKey` at genesis
  (`Conversation.awaitingFirstEpoch`), waits `genesisWaitMs` (default 4000; `ATSMSConfig` field, 0
  for synchronous tests) for the creator's update before self-healing.
- **4.3** `packages/dcgka/src/seal-layer.ts` — per-envelope retry counter; emits `unopenable-envelope`
  via a new `onEvent` sink (wired through `ConversationDeps.onEvent` → the client `onEvent`) after
  `UNOPENABLE_REPORT_AT` refreshes. The **durable** half (transport must not ack an envelope it never
  opened) is deferred — with 4.1 the healing update rides fresh asym envelopes, so recovery no longer
  depends on redelivering the buffered sym copy; tracked as a transport follow-up.
