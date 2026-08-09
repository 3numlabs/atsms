# Known issues (live-testing findings)

A running list of engine/protocol-level findings from live multi-client testing —
and the list of protocol fixes to finish before the v1 release. Issues 1–3 came
from the first live test of the v2 message format (2026-08-01); later findings are
appended as they are found.

Findings that need an outside eye rather than a fix are carried into
[`spec/review-scope.md`](./spec/review-scope.md), the brief for the gating external
cryptographic review.

Issues 1–3 were found during that first test (CLI creator ↔ demo/web joiners, group
of 4 devices). All three are engine/protocol-level — the v2 content format is not
implicated. Input for the Phase 6 external crypto review; fix ordering TBD.

> **FIXED (2026-08-01):** the three symptoms below are one bug — a merge that blanks the tree root
> leaves each side holding a private live epoch, and `sealEpochFor` sealed the repair frame under
> it. Fixed via the sealable-epoch predicate (4.1) + genesis-wait (4.2) + loud unopenable envelopes
> (4.3); regression suite `atsms/packages/client/src/tests/partition.test.ts` (5) green, dcgka unit (117) + fuzz
> (4) green. Full analysis, fix, and test plan:
> [`spec/concurrent-update-partition.md`](spec/concurrent-update-partition.md). Existing partitioned
> conversations are not repairable (recreate them). The sections below are the original symptom
> record.

## 1. Concurrent-update epoch divergence (SEVERE)

**Live evidence:** group `02c663ca…` — all four members hold the identical
membership list, but the creator's engine holds live epoch `a572cfdc…` while
every joiner-side device holds `7113a3df…`. Neither side can decrypt the
other's sym-sealed traffic; the group is permanently partitioned
(creator ↔ joiners), while joiner ↔ joiner traffic converged.

**Genesis shape:** creator ran `create → advertiseEndpoint → update`; two of
the three joiner devices were live and self-healed with their own updates
(`NoRootKey` path in `ATSMSConversation.send`) concurrently with the
creator's in-flight update. Serialized versions of this flow pass (see the
repro scripts below: 2–5 leaves, with the advert, all green). The failure
needs the concurrent-update interleaving.

**Repro scripts** (from the session's diagnostics, runnable under
`atsms/packages/client/src/tests/`):
- `tree-size-diagnostic.test.ts` — serialized genesis, sizes 2–5: PASSES.
- `concurrent-update-diagnostic.test.ts` — joiner update racing creator
  update: FAILS (see issue 2, which it hits first).

## 2. Joiner self-heal update yields no sendable epoch

A bootstrapped joiner that runs `update()` *before* processing the creator's
first update still throws `NoRootKey: update before sending` on `send()` —
its own update op mints no locally-usable epoch. The client's NoRootKey
self-heal (`update → retry send`) therefore cannot work for a joiner that
races ahead of the creator's update; live, it "worked" only by riding
whichever epoch happened to arrive first, which is what set up issue 1.

## 3. Unknown-tag sym envelopes: silent, unbounded, unrecoverable

Sym envelopes with unrecognized hint tags are buffered in memory (FIFO cap)
with **no event emitted** and **no recovery protocol**: after divergence
(issue 1), each side buffers the other's traffic forever with zero
diagnostics, and the transport has already acked+deleted the envelopes at
the relay (durability gap: ack-before-durable). Consequences to design for:
- an "unknown epoch tag from a member" signal should exist (at least as an
  engine/security event, at best driving a repair/re-key request);
- the transport should not delete relay copies that were neither opened nor
  definitively rejected (needs a policy decision — sealed sender makes
  "not mine" vs "not yet mine" indistinguishable);
- the CLI now surfaces `onEvent` (it silently swallowed all drops before).

## 4. Unopenable-envelope reporting counts deliveries, not evidence — OPEN, pre-v1

*Found 2026-08-04, during the live lossy-relay (§8 repair) run.*

> **Deferred 2026-08-05.** Not to be fixed until the demo has had more testing —
> the report is noisy but never fatal, and further live data may change the shape of
> the fix. Re-evaluate before the v1 release.

The "loud unopenable envelope" signal added as fix 4.3 for issue 3 cries wolf.
`SealLayer` buffers a sym envelope whose hint tag it cannot place, and reports
`unopenable-envelope` once that envelope has survived `UNOPENABLE_REPORT_AT = 8`
**refreshes** (`seal-layer.ts`). But `refresh()` runs on every delivery, so a fan-out
burst — a group create seals one copy per recipient device, and the relay fans every
copy of a frame to every device of the addressed DID — spins eight refreshes in
milliseconds. The envelope is dropped and reported as probable divergence before the
epoch it needs has even been derived. Live cost: three spurious reports from merely
setting up a two-account group, and ~15 during the repair run, all in a demonstrably
healthy conversation. The signal is a diagnostic and never fatal, but it fires loudest
exactly when the group is busy and well, which is how a divergence alarm decays into
background noise.

**Root cause.** Refresh count stands in for "we have had a fair chance to learn this
epoch", and the proxy breaks under bursts: retries that learn nothing are not evidence.

**Recommended fix — count epoch generations, not refreshes.** Bump a counter only when
`refresh()` installs tags for an epoch never seen before; record that counter on each
buffered envelope; report only once N *new epochs* have been learned and it still will
not open. Burst-proof, and it needs no clock — the engine forbids ambient clocks
(timers are the host's, cf. the injected `now` in `records.ts`). It keeps the signal for
the issue-1 partition case, where both branches do keep advancing. Accepted cost: in a
fully quiet group a genuinely divergent envelope may sit buffered without ever being
reported — harmless (the buffer is FIFO-bounded at 256) but silent.

**Alternative, if that silence is unacceptable:** inject a host clock into `SealLayer`
the way `records.ts` already takes `now`, and require both a retry count and elapsed
wall-clock time before reporting.

Note the interaction with fan-out copies: the sym body is encrypted under the
per-(epoch, sender) envelope key and the per-recipient tag is only a routing hint, so
any member holding that epoch key can open any copy — a copy addressed to another of
our own devices is normally salvaged, not buffered. What actually buffers is traffic
under an epoch we do not hold, which is precisely why the report should be keyed to
epochs learned.

---

*Issues 5–9 come from the loss-and-reordering survey of 2026-08-05 — every message type audited
against "what if this is dropped for good" and "what if this arrives out of order". The full
per-message analysis, with enough background to read it cold, is
[`spec/loss-and-reordering.md`](./spec/loss-and-reordering.md).*

## 5. First contact has no retry and nothing to repair from — RECOVERY BUILT 2026-08-06

> **Built:** re-invitation, specified as [`ordering-auth.md` §8.2](./spec/ordering-auth.md) and
> implemented across `@atsms/dcgka` (`Session.pendingMembers()` / `reinvite()`, `SealLayer.reinvite()`)
> and `@atsms/client` (`convo.pendingMembers` / `convo.reinvite(did)`), with `/members` and `/reinvite` in
> the reference CLI. A founding member gets the identical `create` frame back (its id is the group id, so
> a rebuild would found a second group); a later joiner gets a welcome rebuilt against the same `add` op,
> which lands them on current state. Any member can do it, not only the adder. Tests:
> `packages/dcgka/test/reinvite.test.ts` and the re-invite scenario in
> `atsms/packages/client/src/tests/membership-churn.test.ts`.
>
> **What remains open** is detection, and it is open by choice: the only signal is silence, which covers a
> lost invitation, a quiet member, and a refusal alike. Keeping those indistinguishable is a requirement
> of recipient-side admission control (see the tracked admission-control work), so re-invitation is a
> deliberate human action — never automatic — and clients must say "invited", never "delivery failed".
> Also unrecovered by design: a device whose prekey rotated past its grace window needs a fresh add.

The original finding follows.

### Original finding

A conversation begins with one best-effort envelope sealed to the recipient's prekey: a `create`
(founding a conversation) or a `welcome` (admitting a new device). If it is lost, nothing recovers it.
The sender gets no acknowledgement — deliberate, since security properties attach to *processing*, not
to acks — and the recipient cannot ask for it, because repair is a conversation-level mechanism and the
recipient has no conversation. Any later group traffic arrives as a symmetric envelope matching no known
conversation, so it is discarded and deleted at the relay rather than held.

Consequences today: a lost `create` means the recipient never learns the conversation exists, silently,
with no signal on either side. A lost `welcome` means the joiner never joins while every other member's
view already contains them; the only cure is a human noticing and doing remove-then-re-add. The same
gap makes the ordering case lossy: traffic that overtakes a welcome is dropped rather than buffered.

This is the most consequential of the five — it is how every conversation starts. **Design it together
with inbound admission control**, which touches the same moment: an invitation held pending a policy
decision must not trigger a re-request, since that would signal to the sender exactly what holding it
back is meant to conceal.

Candidate directions (undecided): sender-side retransmission with a bounded schedule; a holding area
for envelopes that match no known conversation, so a late `create`/`welcome` can still make sense of
them; making stale-member surfacing (ordering-auth §9) real so a never-arrived joiner becomes visible
to the group rather than invisible.

## 6. Application-message loss recovery is specified but unbuilt — OPEN, pre-v1

`ordering-auth.md` §8.1 is a complete design, marked DESIGNED 2026-07-23, with no implementation. Today
a user message that is never delivered is lost silently at both ends. Two shapes: an **interior gap**
(message 5 arrived, 4 never did) is locally detectable — the skipped-key store records the hole — but no
request is ever issued for it; a **trailing gap** (the sender sent three more, then went quiet) is
undiscoverable, because nothing advertises how many messages exist.

Reordering, by contrast, is handled well and passively: kept skipped keys mean a late message still
decrypts when it turns up.

The design needs: a per-epoch high-water advert (`appHW`) on coverage frames, app-range repair requests
naming `(sender, epoch, fromGen, toGen)`, and serving from any member (the inner ciphertext is identical
for every recipient, so any holder can answer). Note it depends on coverage frames actually being sent
— issue 7. Recovery stays bounded by forward secrecy: past epoch eviction the ciphertext can be
re-served but is undecryptable by design, and the client must then say so rather than omit the message.

## 7. Head-reconciliation adverts are built but never sent — OPEN, pre-v1

`coverage()` / `advertiseHeads()` exist in the engine — a frame whose dependencies are the sender's
current frontier, carrying a consistency digest, so a peer missing anything buffers it and repairs.
Nothing in `@atsms/client` ever schedules one.

Consequence: gaps are discovered only because *later* traffic depends on the missing operation. That
covers a busy conversation, but in one that has gone quiet a trailing control gap sits undetected — a
member can be a full epoch behind and neither side notices until someone speaks. Scheduling coverage on
idle is a small host-side change, and it is also the carrier issue 6 needs, so the two should land
together.

## 8. A restart erases the evidence of a gap — OPEN, pre-v1

`Session.serialize()` persists the retained frame log, the secrets and the counters — deliberately not
the buffer of frames waiting on a hole, nor the seal layer's envelopes waiting for an epoch. Both are
in-memory only, and both were already acknowledged and deleted at the relay.

So a restart loses the data *and* the knowledge that something is missing: the buffer is empty, so the
repair timer sees nothing to repair and never fires. The hole resurfaces only if new traffic happens to
depend on the missing operation. This is the durability half of issue 3 (ack-before-durable) — the fix
is either to persist the pending state alongside the session, or to stop deleting at the relay until an
envelope has been genuinely consumed, which sealed sender makes hard to define ("not mine" and "not
mine yet" are indistinguishable by design).

## 9. Forward secrecy is claimed but not enforced at runtime — OPEN, pre-v1

Retained frames are never evicted (`retain()` only ever adds), and nothing in the host calls the
engine's epoch eviction. The specified retention rules — keep until covered by all members, or 30 days
(`T_REPAIR_GIVEUP`) — are not implemented anywhere.

The visible symptom is storage growing without bound, which is the mild part. The real cost is that old
epoch keys stay live, so the forward-secrecy window the spec describes never actually closes: a device
compromised today still yields yesterday's traffic. This also interacts with issue 6, whose bounded
recovery story assumes eviction is real. It should be on the external crypto review's list either way —
a claimed property that no code enforces is exactly what a review exists to catch.

## 10. Welcomes outgrow the seal bucket, and a group stops accepting members — OPEN, pre-v1

*Measured 2026-08-06 against the engine, one add + one remove per round (four control ops each).*

| Group size | Welcome after 3 rounds | Exceeds the 64 KiB bucket at |
|---|---|---|
| 2 devices | 7.8 KiB | round 25 |
| 8 devices | 14.9 KiB | round 14 |
| 20 devices | 25.6 KiB | round 8 |

A welcome carries the entire retained control log, and nothing evicts it (issue 9), so it grows
monotonically — and faster in bigger groups, where longer tree paths make each `update` fatter. A
20-device group, well inside the 150-device design point, cannot survive eight membership changes.

**The failure is not graceful.** `addMembers` authors the add, the update and the welcome, and only
then fails at seal time; `drainSealed` has already taken the outbox, so the frames are dropped rather
than left queued. The add and update are retained and can come back through §8 repair once some later
frame references them. The **welcome is not retained** (deliberately — that is the nesting fix), so it
is simply gone, and re-invitation (§8.2) rebuilds one from the same oversized log and fails the same
way. That member is permanently unjoinable and the group is effectively closed to newcomers.
Ordinary messaging keeps working: app frames are small and sealed symmetrically. It is growth that dies.

**The designed-in answer is stubbed**: the welcome body is `[checkpoint, ops, deliveryMap, profile]`
and `checkpoint` is `null`. A joiner should receive a state snapshot plus a short tail.

**But checkpointing is a trust change, not a compaction.** Today a joiner verifies a chain of signed
ops back to genesis; a snapshot is an assertion by whoever built it, and a malicious builder could
misstate membership or admins with nothing to check it against. This is the same failure mode as the
selective-omission question in [`spec/review-scope.md`](./spec/review-scope.md) §3.1 and wants one
answer — a frontier commitment, or a checkpoint corroborated by the consistency digests members
already sign on coverage frames.

Also note: scheduling coverage adverts (issue 7) grows the log on a timer rather than only on churn.
Whether coverage frames can be excluded from welcomes needs checking — other frames' deps may
reference them. And the 64 KiB bucket is policy, not physics: `OversizeError` says "blob offload
required", so a welcome could ride a blob, trading a hard wall for an availability dependency at first
contact, which is the worst possible moment for one.
