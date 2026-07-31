# atsms-dcgka

**[Protocol] · Status: Phase 0b specs DECIDED · Phases 1–2 BUILT** (engine +
ordering/auth + fuzz gate; `packages/dcgka`, 67 unit tests + a simulation fuzz
gate, byte-faithful to the Rust BeeKEM oracle). Phases 3–5 (sealed-sender impl,
identity/lexicon publish flows, `@atsms/sms` integration) are next.

Decentralized group messaging — the planned replacement for the crypto core of `atsms-lib`
(`@atsms/sms`), delivering forward secrecy, post-compromise security, real group key agreement,
multi-device, and sealed-sender metadata protection over the existing dumb-mailbox relay model.
Umbrella roadmap **Phase 7**; supersedes the MLS direction in `atsms-lib/docs/mls.md`.

**Based on (since D11, 2026-07-22): [BeeKEM](https://github.com/inkandswitch/keyhive)** — Ink & Switch's
concurrent TreeKEM for local-first systems (paper: `../BeeKEM.pdf`; the `beekem` Rust crate is the
differential-test oracle) — under an ATSMS messaging profile. The spec set's layering, DGM, ordering,
sealed-sender, and identity designs carry over from the earlier Weidner-DCGKA phase (CCS 2021,
[eprint 2020/1281](https://eprint.iacr.org/2020/1281)), whose core specs are retained as superseded
design records. Pre-BeeKEM state preserved at git tag **`dcgka-classic-v1`**.

## Documents

| Doc | What |
|---|---|
| [`beekem-dcgka-vs-mls.md`](./beekem-dcgka-vs-mls.md) | Plain-language explainer: how our BeeKEM DCGKA works and the important ways it differs from MLS (start here for the "why not MLS" intuition) |
| [`beekem-analysis.md`](./beekem-analysis.md) | The D11 evaluation: BeeKEM vs DCGKA, what survives, risks, plan update |
| [`spike-a-messaging-profile.md`](./spike-a-messaging-profile.md) · [`spike-b-dgm-reconciliation.md`](./spike-b-dgm-reconciliation.md) | The two D11 gate spikes (both PASS): messaging profile over BeeKEM; DGM/strong-remove reconciliation |
| [`implementation-plan.md`](./implementation-plan.md) | Decision log D1–D11, parity inventory, Phases 0–6 |
| [`gap-analysis.md`](./gap-analysis.md) | Completeness evaluation vs the DCGKA paper + the existing stack — gaps G1–G18 (historical baseline; G1 dissolved by D11) |
| [`mls-analysis.md`](./mls-analysis.md) · [`p2panda-analysis.md`](./p2panda-analysis.md) · [`q-channel-analysis.md`](./q-channel-analysis.md) | Alternatives evaluated and rejected (MLS: sequencer vs D0; p2panda: adopted as oracle then retired; Q-channel: no membership layer) |
| [`atsms-dcgka-spec.md`](./atsms-dcgka-spec.md) | The original one-page spec, v1.1 — design history; where it conflicts with `spec/`, `spec/` wins |
| `spec/` | Normative spec set. **Entry point:** [`overview.md`](./spec/overview.md) (goals, threat model, honest limitations, layer/doc map). Core: [`beekem-core.md`](./spec/beekem-core.md) (BeeKEM tree + messaging profile: DGM-filtered ops, `rootCommit`, per-sender chains, coverage, eviction, checkpoints), [`dgm.md`](./spec/dgm.md) (membership, roles, strong remove — also the tree's validity filter), [`ordering-auth.md`](./spec/ordering-auth.md) (causal delivery: deps/readiness, key rotation, repair). Around it: [`identity-devices.md`](./spec/identity-devices.md) (DID/device model, `at.atsms.x509`, `at.atsms.prekey`, revocation), [`sealed-sender.md`](./spec/sealed-sender.md) (two envelope modes; padding buckets, anonymous ingress/D5), [`wire-format.md`](./spec/wire-format.md) (deterministic CBOR schemas, label registry, test vectors), [`atsms-integration.md`](./spec/atsms-integration.md) (capability discovery, `@atsms/sms` + `atsms-worker` change lists, migration), [`parameters.md`](./spec/parameters.md) (every tunable constant). **Superseded design records:** [`dcgka-core.md`](./spec/dcgka-core.md), [`2sm.md`](./spec/2sm.md) |

## Read this first

1. The layering is the survivor: ordering/DGM/sealed-sender/identity were designed as separable layers
   around an abstract group-key core, which is what made the D11 core swap a bounded rewrite instead of
   a restart.
2. BeeKEM has **no formal security proof** (unlike the DCGKA paper it replaced). Doctrine #4 is now:
   byte-equivalence to the `beekem` Rust oracle below the `PcsKey` seam + frozen vectors above it, with
   **external cryptographic review as a gating requirement** before v1 alpha carries real traffic
   (overview §6.1/§6.13). The proven DCGKA specs remain on file as the documented fallback.
3. Keyhive built BeeKEM for document sync (history stays decryptable); messaging FS required the
   profile deviations in beekem-core §5–§8 (eviction, coverage, checkpoints, `rootCommit`) — read
   Spike A for why each exists.
