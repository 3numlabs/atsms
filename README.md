# atsms-dcgka

**[Protocol] · Status: DESIGNED (no code yet)**

DCGKA-based decentralized group messaging — the planned replacement for the crypto core of `atsms-lib`
(`@atsms/sms`), delivering forward secrecy, post-compromise security, real group key agreement, multi-device,
and sealed-sender metadata protection over the existing dumb-mailbox relay model. Umbrella roadmap **Phase 7**;
supersedes the MLS direction in `atsms-lib/docs/mls.md`.

Based on: Weidner, Kleppmann, Hugenroth, Beresford — *Key Agreement for Decentralized Secure Group Messaging
with Strong Security Guarantees* (CCS 2021), [eprint 2020/1281](https://eprint.iacr.org/2020/1281) (use the
eprint version — Appendices B & D matter) + prototype [trvedata/key-agreement](https://github.com/trvedata/key-agreement).

## Documents

| Doc | What |
|---|---|
| [`atsms-dcgka-spec.md`](./atsms-dcgka-spec.md) | The original one-page spec, v1.1 (2026-07-15: transport-generalized, identity/device model settled, sealed-sender/X509 unification). **Superseded as entry point by [`spec/overview.md`](./spec/overview.md)** — kept as design history; where it conflicts with `spec/`, `spec/` wins |
| [`gap-analysis.md`](./gap-analysis.md) | Completeness evaluation vs the paper + the existing stack — gaps G1–G18 |
| [`implementation-plan.md`](./implementation-plan.md) | Decisions D1–D6, parity inventory, Phases 0–6 to spec + build the replacement |
| `spec/` *(Phase 0 — full set drafted 2026-07-16)* | Normative spec set, all v0.1 drafts for review. **Entry point:** [`overview.md`](./spec/overview.md) (goals, threat model, honest limitations, layer/doc map — supersedes the one-page spec as the way in). Core: [`dcgka-core.md`](./spec/dcgka-core.md) (state machine, key schedule, ack lifecycle, app ratchet, GC), [`dgm.md`](./spec/dgm.md) (membership, roles, strong remove, divergence detection), [`2sm.md`](./spec/2sm.md) (rotating-PKE 2SM: X3DH + HPKE), [`ordering-auth.md`](./spec/ordering-auth.md) (ACB substitute: deps/readiness, key rotation, repair). Around it: [`identity-devices.md`](./spec/identity-devices.md) (DID/device model, two-cert `at.atsms.x509` profile, `at.atsms.prekey` canonical shape, revocation), [`sealed-sender.md`](./spec/sealed-sender.md) (two envelope modes: HPKE bootstrap + symmetric in-conversation with pseudonymous tags; padding buckets, anonymous ingress/D5), [`wire-format.md`](./spec/wire-format.md) (deterministic CBOR schemas, label registry, test-vector suite), [`atsms-integration.md`](./spec/atsms-integration.md) (D1/D2/D6 applied; capability discovery, `@atsms/sms` + `atsms-worker` change lists, migration). Plus [`spec/parameters.md`](./spec/parameters.md) — the single registry of every tunable constant (value, status, what it does) |

## Read this first

1. The one-page spec's architecture is sound — the paper (§8.1, Lemma 8) explicitly supports unordered-mailbox
   delivery with client-side causal buffering.
2. But it is **not buildable as written**: its 2SM recommendation (X3DH+Double Ratchet or HPKE) fails the
   paper's security requirements (G1), acks are wrongly treated as optional when they *are* the PCS mechanism
   (G2), and the group-management model (DGM) — which the paper deliberately leaves abstract — is entirely
   undesigned (G5).
3. Phase 0 of the implementation plan turns each gap into a normative sub-spec before any code is written.
