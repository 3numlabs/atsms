<!-- cSpell:words DCGKA BeeKEM prekey prekeys asym sym CGKA blanked rootless -->

# Concurrent-update partition — root cause and proposed fix

> **Status: ANALYSIS + PROPOSAL (2026-08-01) — awaiting approval before implementation.**
> Supersedes the preliminary hypotheses in [`../KNOWN-ISSUES.md`](../KNOWN-ISSUES.md), which was
> written mid-investigation. The root cause below is confirmed by a reproducible trace.

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

## 3. The violated invariant

> *A frame may only be sealed under an epoch that every recipient can be expected to have derived.*

`sealEpochFor` approximates "the group's established epoch" with "the latest live epoch among my
ancestors". That approximation is exact **only while the causal history is linear**. A merge that
blanks the root is precisely the event that makes a locally-live epoch *not* group-shared — and it
is the one case the rule does not account for. The bootstrap escape hatch that should apply here
already exists and is already used for the first update after `create` (where `sealEpochFor`
returns `null` and the frame rides `sealed-asym` to each recipient's prekey); it simply is not
reached, because a stale epoch is found first.

Note this is not a message-format issue, and not a client issue: the engine, seal layer, and
transport each behave as specified in isolation. It is a gap between beekem-core's merge semantics
and sealed-sender §11.4's epoch-selection rule.

## 4. Proposed fix

### 4.1 Primary — a blanking merge makes live epochs unsealable (engine)

Add a per-epoch `sealable` flag (default `true`):

- When a replay/merge produces a canonical tree with **no root key** (the blanked state), mark
  every currently-live epoch `sealable = false`. They stay in `epochs` and remain usable for
  **decrypting** already-received traffic (no forward-secrecy or history regression); they are
  merely disqualified from sealing new frames.
- `sealEpochFor` considers only `sealable` epochs. In the partitioned state it therefore returns
  `null`, and the seal layer's existing `null` branch sends the healing update **`sealed-asym` to
  each recipient's prekey** — the same bootstrap-class path used after `create`.
- An epoch derived *after* the merge (from a healing update that everyone can now open) is
  `sealable` again, and normal `sealed-sym` operation resumes.

Recovery then falls out of the existing machinery: A's healing update reaches B, B applies the
path, derives the same root, both converge on one epoch, traffic flows.

Cost: a handful of lines in `engine.ts` (flag + filter + one line in `replay`), no wire change, no
new op type, no protocol round trip.

### 4.2 Secondary — break the heal symmetry (client)

With 4.1, two members healing simultaneously simply produce another concurrent pair and heal again;
it converges probabilistically but can ping-pong. Make the retry asymmetric: on `NoRootKey`, wait a
short jittered delay and re-check whether an epoch arrived before minting an update, and/or prefer
the deterministically-lowest membership key as the healer. Cheap, and it also removes the genesis
race that started this (a joiner sending immediately after bootstrap).

### 4.3 Secondary — make undecryptable traffic loud and durable (seal layer + transport)

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

## 5. What this does *not* fix

Groups already partitioned (e.g. the live test's) stay broken: the epochs each side needs were
never derived and cannot be reconstructed. There is no repair for existing poisoned conversations —
recreate them. A general "I cannot read your traffic, re-bootstrap me" repair protocol is the
proper long-term answer and remains open work for the identity/recovery phase.

## 6. Test plan

1. **Regression (the trace above):** two members, concurrent genesis updates, cross-deliver, heal,
   assert bidirectional delivery. Currently fails; must pass. (Repro exists.)
2. **N-way:** creator + 3 joiners, all joiners self-heal concurrently — assert convergence to a
   single epoch and full-mesh delivery.
3. **No regression in the linear case:** assert the healthy path still seals `sealed-sym` under the
   parent epoch (i.e. 4.1 does not push everything onto the asym path — a metadata/size regression
   if it did).
4. **Decryption of pre-merge traffic:** messages sent before the merge must remain readable after
   epochs are marked unsealable.
5. Re-run the full dcgka + atsms-lib suites, then a live two-client smoke reproducing the original
   race deliberately (joiner sends immediately on bootstrap).
