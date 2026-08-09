# Design history

How this design was arrived at. None of it is normative — where any of it disagrees with
[`spec/`](../../spec/), the spec wins.

It is kept because the reasoning is often more useful than the conclusion, particularly for a reviewer
asking why a decision went the way it did, or for anyone considering the same alternatives.

## How the core was chosen

| | |
|---|---|
| [`beekem-analysis.md`](beekem-analysis.md) | The evaluation that replaced the original DCGKA core with BeeKEM (decision D11): what survived the swap, what it cost, what the risks are |
| [`spike-a-messaging-profile.md`](spike-a-messaging-profile.md) | Gate spike: can a messaging profile sit on BeeKEM at all? Explains why the eviction, coverage, checkpoint and rootCommit deviations exist — BeeKEM was built for document sync, where history stays readable, and messaging needs the opposite |
| [`spike-b-dgm-reconciliation.md`](spike-b-dgm-reconciliation.md) | Gate spike: does strong-remove group management reconcile with a concurrent tree? |

## Alternatives evaluated and rejected

| | |
|---|---|
| [`mls-analysis.md`](mls-analysis.md) | MLS. Rejected because agreeing one commit per epoch needs something to order commits, and in practice that is a per-group server |
| [`p2panda-analysis.md`](p2panda-analysis.md) | p2panda. Adopted as an oracle, then retired; its strong-remove semantics live on in our group manager |
| [`q-channel-analysis.md`](q-channel-analysis.md) | Quilibrium's Triple Ratchet channel. No membership layer |

## Earlier plans and baselines

| | |
|---|---|
| [`implementation-plan.md`](implementation-plan.md) | Decision log D1–D11, parity inventory, and the phase plan. Phase 6 is still live: it holds the external-review scope, now expanded in [`spec/review-scope.md`](../../spec/review-scope.md) |
| [`gap-analysis.md`](gap-analysis.md) | Completeness evaluation against the DCGKA paper and the existing stack — gaps G1–G18. A historical baseline; G1 dissolved with D11 |
| [`atsms-dcgka-spec.md`](atsms-dcgka-spec.md) | The original one-page spec, v1.1, before the spec set was written |
| [`monorepo-structure.md`](monorepo-structure.md) | Why the protocol, the engine and the SDK ended up in one repository, written while they were in three |
| [`webrtc-over-atsms.md`](webrtc-over-atsms.md) | Lessons from running call signalling as persisted messages, and why the ephemeral message class exists |
