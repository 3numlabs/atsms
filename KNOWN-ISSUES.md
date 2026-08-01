# Known issues (live-testing findings, 2026-08-01)

Found during the first live multi-client test of the v2 message format
(CLI creator ↔ demo/web joiners, group of 4 devices). All three are
engine/protocol-level — the v2 content format is not implicated. Input for
the Phase 6 external crypto review; fix ordering TBD.

> **ROOT CAUSE FOUND (2026-08-01):** the three symptoms below are one bug — a merge that blanks
> the tree root leaves each side holding a private live epoch, and `sealEpochFor` then seals the
> repair frame under it. Full analysis + proposed fix:
> [`spec/concurrent-update-partition.md`](spec/concurrent-update-partition.md). The sections below
> are the original observations, kept as the symptom record.

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
