# Known issues (live-testing findings)

A running list of engine/protocol-level findings from live multi-client testing —
and the list of protocol fixes to finish before the v1 release. Issues 1–3 came
from the first live test of the v2 message format (2026-08-01); later findings are
appended as they are found.

Issues 1–3 were found during that first test (CLI creator ↔ demo/web joiners, group
of 4 devices). All three are engine/protocol-level — the v2 content format is not
implicated. Input for the Phase 6 external crypto review; fix ordering TBD.

> **FIXED (2026-08-01):** the three symptoms below are one bug — a merge that blanks the tree root
> leaves each side holding a private live epoch, and `sealEpochFor` sealed the repair frame under
> it. Fixed via the sealable-epoch predicate (4.1) + genesis-wait (4.2) + loud unopenable envelopes
> (4.3); regression suite `atsms-lib/src/tests/partition.test.ts` (5) green, dcgka unit (117) + fuzz
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
`atsms-lib/src/tests/`):
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
