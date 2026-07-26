# atsms-dcgka — Implementation Plan

> Plan to grow [`atsms-dcgka-spec.md`](./atsms-dcgka-spec.md) v1.0 into a complete specification set and a
> production library that replaces the crypto core of `atsms-lib` (`@atsms/sms`). Companion to
> [`gap-analysis.md`](./gap-analysis.md) (gaps G1–G18 referenced throughout).
>
> Layer tag: **[Protocol]** — this is open-source 3NUM Labs territory; nothing here is Haiven-specific.
> Umbrella fit: this is roadmap **Phase 7** ("Advanced encryption + real group encryption"), and it supersedes
> the MLS direction sketched in `atsms-lib/docs/mls.md`.
> Status: **DESIGNED** — no code exists in this repo yet.

---

## 1. Decisions needing sign-off before code (per working style: confirm large moves)

**D1 — Replace vs. layer over the X509 floor.** `docs/architecture.md` §6 declares the X509/S-MIME scheme "the
baseline interoperability layer… stays forever," while this effort's charter is a "full-blown replacement."
Recommendation: **layer, then deprecate by attrition** — DCGKA becomes the default for all DM + group traffic
between capable endpoints; X509/S-MIME remains the interop fallback (email bridge, legacy endpoints) behind the
same `ATSMSStorageManager` facade, selected per-recipient by capability discovery (presence of the new
`at.atsms.prekey` record). A hard replacement would break the email dialect and the gateway story for no security
gain on paths DCGKA doesn't cover.

**D2 — Package strategy.** Recommendation: new package **`@atsms/dcgka`** (this repo) containing the protocol
engine, consumed by `@atsms/sms`, which keeps the app-facing API (`ATSMSStorageManager`, storage adapters,
transport) and swaps its crypto core. Consumers (`atsms-demo`, future Haiven app) keep importing `@atsms/sms`.
Alternative (rejected): fork atsms-lib wholesale — loses the working transport/storage layers and doubles
maintenance.

**D3 — Language & core strategy. ✅ RESOLVED 2026-07-15: TypeScript for v1.** User decision: the first app
is React Native-based, and RN (Hermes) has no WASM — a Rust core would force uniffi native bindings on the
primary platform from day one, so **v1 is a TypeScript implementation** with `@noble/*` audited primitives
(`@noble/curves` X25519/Ed25519/P-256, `@noble/ciphers` ChaCha20-Poly1305, `@noble/hashes` HKDF-SHA256),
covering bun/browser/RN/CF-Workers with one artifact. Performance is not a factor at n≤150 (O(n) ops,
~40 kB/update).

Consequences kept from the evaluation (see [`p2panda-analysis.md`](./p2panda-analysis.md) §Addendum):
- **p2panda-encryption is the porting reference and differential-testing oracle** — its seedable RNG makes
  whole-protocol runs deterministic; generate cross-implementation test vectors from the Rust side and
  assert byte-equality in TS (fix the known `process_ack` &&→|| bug in our port; file it upstream anyway).
- **Own the reimplementation risk explicitly**: the TS port is a new unaudited implementation — Phase 2's
  permutation/simulation harness and Phase 6's external review are the mitigations, not optional extras.
- **Keep module interfaces narrow** (engine behind a serialize-in/serialize-out boundary, p2panda-style) so
  a Rust/WASM-or-native core (the shelved D3-a) can be swapped in later if audit, PQ, or platform economics
  change — re-evaluate if p2panda ships v1.0 with a JS story or their audit publishes.

**D4 — Prekey serving.** G8: one-time prekeys can't be atomically dispensed from a public PDS. Recommendation:
**signed prekey + last-resort key in the PDS lexicon now** (no new infrastructure, weaker first-message FS,
matches Signal's degraded mode), with an optional Relay-Node one-time-prekey checkout service (`atsms-worker`
DO) as a fast-follow — architecture.md already assigns "distributes pre-keys" to Relay Nodes.

**D5 — Anonymous ingress + abuse control on the relay.** G9: sealed sender requires the worker to accept
envelope pushes without sender auth. Recommendation: new unauthenticated `POST /envelope/:mailboxId` +
per-mailbox rate limits and size caps first; unlinkable sender tokens (Privacy-Pass style) as hardening.
Changes `atsms-worker` — cross-repo, so flagged here.

**D6 — DM unification.** Run 2-person conversations as 2-member DCGKA groups (one code path, FS/PCS for DMs
too, deterministic group IDs replace `generateDMConvoId`) vs. keeping DMs on bare 2SM. Recommendation:
**2-member groups**; bare 2SM stays an internal building block only.

**D7 — Two envelope modes. ✅ DECIDED 2026-07-20.** `sealed-sym` (symmetric, keyed from `I_sender`,
per-recipient PRF-tag lookup) for **all** in-conversation traffic; `sealed-asym` (HPKE) reserved for
bootstrap-class messages only (welcomes, first contact, floor one-shots). Spec: sealed-sender §11.
Benefits: KEM-free steady state (~55 B overhead), ratchet-grade envelope FS/PCS, and the PQ cost confined
to rare messages.

**D8 — Post-quantum sequencing. ✅ DECIDED 2026-07-20.** Phase A: classical X25519 v1 with reservations
paid up front (envelope `suite` id, X3DH `KEM_ss` slot, prekey `suites` hook, injectable `Kem` seam).
Phase B: **hybrid X25519+ML-KEM-768** (PQXDH-style, never PQ-only) on the bootstrap surface — 2SM/X3DH +
sealed-asym — landing **before v1 alpha carries real user conversations** (HNDL accrues from first real
traffic). Signatures stay classical. Spec: overview §6.12, 2sm.md §5.2, wire-format §5/§6.

**D9 — Encryption floor relaxed to HPKE. ✅ DECIDED 2026-07-22.** X509/CMS is the *identity + signing*
floor only (endpoint certs, JWT auth, CMS `SignedData`, inbound classic S/MIME from external senders);
every ATSMS encryption path is HPKE to a raw X25519 key resolved from PDS records. Rationale: CMS
`EnvelopedData` interop never materialized (no mainstream MUA supports RFC 8418 X25519, and self-signed
DID certs are untrusted by MUAs regardless — the S/MIME bet's payoff was library-level SignedData + the
X509 identity artifact, which stays), and sealed-sender §10 had already moved sealed encryption to HPKE.
Spec: sealed-sender §10, identity-devices §4.1.

**D12 — Base-wire framing = strict deterministic CBOR (DRISL profile, map-free). ✅ DECIDED 2026-07-24.**
The cryptographically load-bearing base layer (signed frames, content-addressed IDs) is CBOR restricted to
the **DRISL** deterministic profile (dasl.ing/drisl.html), further constrained to be **map-free**: every
signed structure is a fixed positional array, and `FrameBody.ext` becomes an **opaque byte string** with a
positional `ExtBody = [version, digest?, rotation?, appHW?]` interior. This deletes the subtlest CBOR
canonicalization surface — map key ordering / dedup — from the signed base *by construction*, not by a
runtime check. **Alternatives evaluated and rejected**: **Postcard** (bijective-by-construction but
non-self-describing, Rust-serde-centric — raises the third-party/multi-language bar for an open protocol,
no CID story, bundles a pull toward a Rust base reversing D3); **protobuf** (serialization not
deterministic — a signature footgun). Chose CBOR for self-describing multi-language openness, IETF/reviewer
familiarity, native content-addressing, and ATProto alignment (repos use dag-cbor), narrowing its one
weakness (determinism *enforced* not *constructed*) by anchoring strictness to the published DRISL profile
rather than bespoke rules, and by dropping maps. Size was not a factor — the ~5–8% framing delta vs
Postcard is neutralized by padding buckets. DRISL's newness (published 2026-07-17) is acceptable: we depend
on it as the *spec we align to*, with our frozen vectors as the KAT. The app-payload layer stays
unconstrained (opaque bytes to the base). Prototyped: `cbor.ts` map path removed, `ext.ts` added; 88 unit +
4 fuzz green. Spec: wire-format §1/§1.1/§3.2.

**D13 — Non-welcome delivery addressing = advertised in-band, not via a public record. ✅ DECIDED 2026-07-25.**
"Provider" is dropped as a protocol concept. A DID's **welcome** address MUST be publicly discoverable — the
per-DID `at.atsms.inbox` singleton (rkey `self`; ordered `endpoints`, transport = URI scheme, `mailto:` floor
/ `https:` upgrade; supersedes+retires the per-device `inviteAddress`, inbound-delivery.md §3) — a party adding
you shares no secret with you yet, so it can only find you publicly. A **non-welcome** frame is only ever sent by a party
that already shares group state, so its (high-volume, linkable) address is advertised **in-band** in the
signed frame `ext` (`FrameExt.endpoint`) — the same self-authored, LWW, in-band advert shape as signing-key
rotation, stamped on change + re-adverted on `coverage`, learned into a per-device table, resolved locally
by the seal layer (no network lookup, exactly as prekeys are). Public footprint shrinks to the one welcome
record. **Granularity is device policy, not a protocol fork**: the slot is per-(device, group) already; v1
ships the **reuse policy** (one https URL per device); per-group opaque tokens (unlinkability against an
untrusted endpoint) are post-v1 with **no wire change**. Recovery is via re-`welcome`, so no public
non-welcome record is needed. Built: `ext.ts` `endpoint` slot (length-tolerant, no version bump),
`Session.setEndpoint/endpointOf` + `applyEndpoint`, `SealLayer` emits `{to, url, envelope}`; `frames.json`
regenerated (frame wrapper only — no oracle-compat impact). Spec: sealed-sender §12, wire-format §3.2.

**D11 — CGKA core = BeeKEM. ✅ DECIDED 2026-07-22 (gates passed same day).** Replace the Weidner-DCGKA
core with BeeKEM (Ink & Switch concurrent TreeKEM — Apache-2.0, `inkandswitch/keyhive` `beekem` crate as
differential oracle) under an ATSMS messaging profile. Gated on two spikes, both PASS:
`spike-a-messaging-profile.md` (per-sender chains over `PcsKey`, eviction replaces Keyhive's
retain-forever posture, coverage replaces acks — PCS completes on op processing, checkpoint frontier
bounds replay/storage, `rootCommit` rejects seed equivocation) and `spike-b-dgm-reconciliation.md` (DGM
= validity filter, PR-1..3; SR1–SR5/P1–P5 preserved; collusion window narrows). Wins: O(log n) updates
(~2–3 kB vs ~40 kB at n = 150), no ack storms, 2SM/X3DH/OPK complexity deleted. Costs, accepted:
**no formal proof** (doctrine #4 re-based to oracle byte-equivalence + frozen vectors; external review
now GATING — overview §6.1/§6.13) and **D8 re-opened** (below). Specs: beekem-core.md (new; supersedes
dcgka-core.md + 2sm.md), Phase 0b edits across dgm/ordering-auth/sealed-sender/identity-devices/
wire-format/parameters/overview/atsms-integration. Baseline preserved as git tag `dcgka-classic-v1`.

**D8 — RE-OPENED by D11 (2026-07-22).** The tree's bidirectional-DH path encryption cannot take ML-KEM
without restructuring to MLS-style per-resolution encapsulation (fork territory); HNDL exposure widens
from bootstrap-only to group key material. Recorded position: v1 classical; hybrid reservation survives
on the envelope `suite` id; tree HNDL exposure documented and accepted until a KEM-tree fork or upstream
support exists (overview §6.12). The X3DH `KEM_ss` slot and prekey `suites` hook died with 2SM.

**D10 — Sealing key = signed prekey; sealing cert deleted. ✅ DECIDED 2026-07-22.** `sealed-asym`
envelopes seal to `at.atsms.prekey.signedPrekey` (weekly rotation + one-week grace; recipients
trial-decrypt ≤ 2 secrets, unchanged in count); the second `at.atsms.x509` cert type, its EKU OID,
`deviceCert` field, and AKI/SKI pairing rules are removed. The joint X3DH + HPKE use of one X25519 key is
a documented deviation with a KDF-label domain-separation argument (identity-devices §3.1) and an
external-review obligation (overview §6.13). Amends G9's "dedicated sealing key"; tightens the envelope
metadata-FS window from 30–97 d to ≤ 2 weeks. Spec: identity-devices §3.1/§4, sealed-sender §2/§9/§10.

---

## 2. What "replacement" must cover (parity inventory)

From the atsms-lib survey — the surfaces consumers actually use and what happens to each:

| atsms-lib surface | Fate under this plan |
|---|---|
| `ATSMSStorageManager` (start/send/sync, RxJS streams, SQLite/IndexedDB) | **Kept** — facade re-wired onto the DCGKA engine (Phase 5) |
| `ATSMSTransportLayer` / `ATSMSApiClient` / `ATSMSWebSocketClient` | **Kept** — carries opaque sealed envelopes; + anonymous push (D5) |
| `ATSMSMessagePayload` + dialects (`atsms/text`, `atsms/webrtc`, facets) | **Kept unchanged** — becomes the inner plaintext of app messages (G10) |
| `ATSMSClient` PDS resolution (`at.atsms.x509`) | **Extended** — also resolves `at.atsms.prekey` (G8; its `signedPrekey` is the sealed-asym target — D10) |
| `generateJWT` mailbox auth | **Kept for fetch/own-mailbox**; sending goes anonymous (D5) |
| X509 certs + S/MIME (`encryptMessage`/`signMessage`/…) | **Kept as interop floor** per D1; no longer the default path |
| Naive group fan-out + random convoIds | **Replaced** — DCGKA groups, deterministic `groupId = H(signed create)` |
| Email dialect (`atsms-email`, `extractP7MFromEmail`) | **Kept on X509 floor** (out of DCGKA scope) |

---

## 3. Phase 0 — Specification set (write the missing design docs)

The one-page spec becomes a `spec/` directory; each doc closes the listed gaps and must be reviewable
standalone. This is the bulk of the *design* work — treat these as the real deliverable of "flesh out the spec."

| Doc | Contents | Closes |
|---|---|---|
| `spec/overview.md` — **DRAFTED v0.2** | Rewritten master spec: goals, threat model (incl. honest limitations — no formal proof post-D11, insider DoS, liveness dependence, PQ regression), layer diagram, normative-language conventions | G16, G17 |
| `spec/beekem-core.md` — **DRAFTED v0.1 (Phase 0b, D11)** | BeeKEM tree + ATSMS messaging profile: DGM-filtered ops (PR-1..3), `rootCommit`, per-sender chains over `PcsKey`, coverage lifecycle, eviction schedule, checkpoint frontier, oracle-keyed test obligations. **Supersedes dcgka-core.md + 2sm.md** | G1 (dissolved), G2, G3, G7, G11, G15 |
| ~~`spec/dcgka-core.md`~~ — **SUPERSEDED 2026-07-22 (D11)** | State machine per paper Fig. 4 with deviations marked (MessageID op-IDs, DGM-state welcomes, process-ack OR fix); byte-exact HKDF labels (`atsms-dcgka:v1:*`); ack lifecycle normative (T_ACK, batching/piggyback, GC coupling); skipped-key app ratchet with p2panda constants; dominating-update rule (G11); storage/GC table; copy-on-success mutation discipline | G2, G3, G7, G11, G15 |
| ~~`spec/2sm.md`~~ — **SUPERSEDED 2026-07-22 (D11)** | App. D rotation discipline over HPKE (p2panda instantiation); X3DH bootstrap against `at.atsms.prekey/<fingerprint>` (identity-DH key + weekly signed prekey, one `bundleSig`); **interim mode is signed-prekey-only — OPK design being formulated, ships before v1 release**; `inviteAddress` moved to the x509 endpoint record (identity layer); mandatory post-join update heals; key-index GC via cross-layer ack optimization; Remark 11 + post-impersonation caveats documented | G1 |
| `spec/dgm.md` — **DRAFTED v0.1** | **The group-management model** (the flagged gap): strong-remove semantics (SR1–SR5), admin/member roles evaluated purely from history, user-vs-device op expansion, re-add nonces (= add-op MessageID), eviction policy hook, determinism test obligations, insider-divergence digest + recovery | G5, G14 |
| `spec/identity-devices.md` — **DRAFTED v0.1** | Identity model per spec v1.1 §4/§4.1: device identity **is** the `at.atsms.x509` endpoint-cert keypair (delegation = publication in the DID repo); ~~medium-lived sealing cert as second cert type~~ (removed 2026-07-22, D10 — `signedPrekey` is the sealed-asym target, joint-use analysis §3.1); **`at.atsms.prekey`** lexicon (rkey = **device fingerprint**, re-keyed from cert serial 2026-07-17 — structural pairing; identity-DH key + weekly signed prekey + `bundleSig` only — E2EE-session material; canonical shape lives here); reachability = the per-DID `at.atsms.inbox` singleton (D13 2026-07-25 — supersedes+retires the per-device `inviteAddress`; serves S/MIME, one-shot sealed, and DCGKA alike; inbound-delivery.md §3); **OPK layer being formulated — deferred during prototyping, ships before v1** (serve-once checkout endpoint candidate); multi-device model (`DeviceID` + `Membership(admittedBy)` split, 2026-07-17; rotation/loss/compromise = remove(+add)); revocation tombstones | G6, G8 |
| `spec/ordering-auth.md` — **DRAFTED v0.1** | The ACB substitute: content-addressed MessageIDs (signature covers seq/deps), dependency rules per message class, readiness predicates (FIFO, referent-before-ack, welcome-first, instance-based add-ready), bounded buffering, protocol-signing-key rotation chained to the device identity cert, replay rules, membership gating incl. removed-member race, end-to-end repair, stale-member surfacing | G4, G12 |
| `spec/sealed-sender.md` | Envelope format (no cleartext recipient-device ID), signed-prekey sealed-asym target (D10), HPKE suite, padding buckets sized so ack storms are indistinguishable, envelope-level idempotency, anonymous ingress + abuse control per D5, Tor note | G9 |
| `spec/wire-format.md` | Deterministic CBOR schemas for every message; version negotiation; the canonical **test-vector suite** definition (cross-checked against the Java prototype) | G13 |
| `spec/atsms-integration.md` | D1/D2/D6 outcomes; capability discovery & X509 fallback rules; dialect layering; `atsms-worker` change list; migration & coexistence sequencing | G10 |

Exit criteria: every G1–G13 gap has a normative answer; specs cross-reviewed against paper sections cited in the
gap analysis (keep local copies of the eprint PDF + prototype sources for reference).

## 4. Phase 1 — Primitives & tree  *(first code; re-scoped 2026-07-22 by D11) — ✅ BUILT*

Landed in `packages/dcgka`: keyhive-compatible crypto (BLAKE3 below the seam,
byte-identical to the Rust oracle — passes the upstream `separable.rs` doctest),
treemath, the full BeeKEM tree, the deterministic-CBOR codec, and the frozen
test-vector suite (`test-vectors/{beekem-oracle,kdf,frames}.json` +
`test/vectors.test.ts`, wire-format §9). CI at `.github/workflows/ci.yml`.

- `packages` skeleton, CI, deterministic-CBOR codec + canonical test vectors.
- Primitive wrappers over `@noble/*` (X25519, Ed25519, **BLAKE3 + HKDF-SHA256 per the beekem-core §3 KDF
  split — freeze the split before vector generation**, (X)ChaCha20-Poly1305, CSPRNG injection for
  deterministic tests) — single `CryptoProvider` seam (mirrors atsms-lib's `setCryptoProvider` pattern).
  *(The D8 `Kem` sub-seam moved to the envelope layer only — D8 re-opened note above.)*
- **BeeKEM tree port** (`tree`/`treemath`/`keys`/`secret_store` from the `beekem` crate, ~3.5k lines):
  path encryption, resolutions, conflict-key merge — **byte-compared against the seeded Rust oracle**
  below the `PcsKey` seam.
- Property tests: tree invariants + seeded oracle transcript equivalence.

## 5. Phase 2 — BeeKEM core, DGM, ordering  *(the engine; re-scoped 2026-07-22 by D11) — ✅ BUILT*

Landed: `engine.ts` (op graph/epochs/replay + DGM filter + PcsKey seam +
chains/coverage/eviction/checkpoints + `rootCommit`), `dgm.ts` (strong-remove
SR1–SR5 with SCC-based remove-concurrency), `ordering.ts`/`frames.ts` (signed
frames, §5 rotation, readiness/buffering, welcome, repair, **head reconciliation
via coverage adverts + dgm §8 digest**), and the **simulation fuzz gate**
(`test/fuzz.test.ts`) which drove out 5 ordering defects + 2 convergence fixes.
67 unit tests + 4 fuzz groups green. Deferred: confirmed digest equivocation
detector (soft signal for now — sound defenses are rootCommit + signatures).

- `beekem-core`: op graph, epochs/topsort, merge/replay with the **DGM validity filter** (PR-1..3),
  checkpoints, `rootCommit`, per-sender chains + skipped-key store, coverage tracking, eviction schedule
  (beekem-core §4–§8).
- `dgm`: strong-remove DGM per `spec/dgm.md` + authorization + device-expansion rules (unchanged scope).
- `ordering-auth`: seq/FIFO enforcement, rotating signatures, delivery predicates, buffer, repair requests.
- **Simulation harness** (the key quality gate): N in-memory clients over a lossy/reordering/withholding
  fake mailbox; fuzzed op schedules; asserts — identical member views AND identical filtered-tree hashes
  under all delivery permutations, FS/PCS game checks incl. closed-epoch undecryptability and the
  frontier-cascade property (Spike A §5/Spike B §6), bounded state after full coverage.

## 6. Phase 3 — Sealed sender & delivery

**Status:** tranches 1–3 BUILT. (1) `envelope.ts` — sym seal + tag table + padding buckets + dedup;
(2) `hpke.ts` + asym seal; (3) `seal-layer.ts` — `SealLayer` binds `Session` to the wire: `drainSealed()`
emits per-recipient `{to, envelope}` (the "engine emits sealed message + recipient list" boundary), `deliver()`
unseals + feeds frames back in, mode chosen by `engine.sealEpochFor(deps)` (parent-epoch sym per §11.4, asym
only pre-first-epoch), bounded unknown-tag buffering. End-to-end sealed-transport test green (create/update/app/
add/heal all over envelopes). (4) **In-band delivery addressing (D13):** `FrameExt.endpoint` + `Session.setEndpoint/
endpointOf`; `SealLayer` emits `{to, url, envelope}` resolving the recipient's in-band-advertised URL — welcome
routes via the public `at.atsms.inbox` record, non-welcome via the in-band endpoint. Remaining: the receive-
side reference binding (per-DID intake → per-device fanout) lives in `atsms-worker`. (5) **Inbound-delivery
contract DRAFTED** (`spec/inbound-delivery.md` v0.1, common ATSMS — payload-agnostic, serves the stateless
one-shot email semantics too): inbox discovery via the per-DID `at.atsms.inbox` singleton (rkey `self`; ordered
`endpoints`, transport = URI scheme, `mailto:` floor / `https:` upgrade), SMTP⇄HTTPS byte-convergence, sender
group-by-destination fan-out, receiver intake→per-device fanout + forward-unmanaged. **Sign-off DONE
(2026-07-25)**: `at.atsms.inbox` supersedes+retires the per-device `inviteAddress` (identity-devices §4.1).
(6) **Receive-side reference binding BUILT** (cross-repo, `atsms-worker` branch `dcgka-inbound-delivery`):
`POST /inbox/{did}` — anonymous per-DID HTTPS intake for an opaque DCGKA envelope → fans a `dcgka`-typed copy
into each per-device cert inbox; no sender IP recorded (privacy budget §7); Inbox DO accepts `messageType:
dcgka` on the opaque path; list `?type=dcgka` filter. **Both bindings done**: the SMTP `mailto:` floor too —
an `application/atsms-envelope` attachment classifies to `dcgka` and byte-converges with `POST /inbox`
(66 worker tests green). Deferred there: managed-cert filtering (multi-provider), real anonymous-ingress rate
limiting.

- `sealed-sender` module: both modes per D7 — asym seal/unseal + sym envelope (envKey derivation, tag
  table with grace epochs, per-recipient fresh-nonce fan-out), padding buckets, envelope dedup.
- `delivery` module binding to the existing `ATSMSTransportLayer` (WS + HTTP) with the new envelope type.
- **`atsms-worker` changes (cross-repo):** anonymous `POST /envelope` ingress + rate limiting (D5); mailbox
  addressing for DCGKA devices; keep JWT auth for fetch. Keep the worker "dumb" — north star: relay never learns
  more than mailbox + timing.

## 7. Phase 4 — Identity, lexicon, multi-device

- `at.atsms.prekey` lexicon in this repo's `lexicons/` (sealing-cert type dropped — D10); publish/rotate/revoke flows via `@atproto/api` (reuse
  `ATSMSClient` PDS plumbing).
- IdentityManager: device key generation, user-signed delegation, epoch-nonced member IDs, lost-device
  revocation flow driving group removes.
- Prekey serving per D4 (PDS records now; relay checkout later).

## 8. Phase 5 — atsms-lib integration & reference client

- Wire `@atsms/dcgka` into `@atsms/sms`: `ATSMSStorageManager` grows group lifecycle APIs
  (`createGroup/addMember/removeMember/updateKeys` + membership streams); send path selects DCGKA vs X509 floor
  by capability discovery (D1); deterministic groupIds replace random convoIds; DMs become 2-member groups (D6).
- Storage: new tables for engine state (tree, op graph, checkpoint, epochs, chains), pending buffers —
  encrypted at rest, key-deletion verified (FS depends on it).
- `atsms-demo`: group chat UI as the proving ground (this unblocks demo Phase 3), including add/remove/device
  flows and stale-member ("not covering") surfacing.

## 9. Phase 6 — Hardening & review

- G14 insider-divergence detection (epoch-hash gossip) or documented recovery; G15 GC bounds enforced; padding &
  batching tuned against the G16 budget (state the 150-device cap in docs).
- External cryptographic review of the composed system (sealed sender × DCGKA is a novel composition the paper
  does not analyze) — G18.
- Interop/perf runs at n = 8/32/64/128/150 devices against the paper's numbers.

---

## 10. Risks & mitigations

- **DGM subtlety** (highest design risk): strong-remove semantics are easy to get wrong under concurrency —
  mitigate by porting `StrongRemoveDgm` behavior faithfully + permutation testing before adding our
  authorization extensions.
- **Divergence from the paper in translation:** mitigate with test vectors generated from the Java prototype and
  byte-exact domain-separation constants specified in Phase 0.
- **Scope creep toward MLS-class features** (O(log n), server-aided concurrency): out of scope — the follow-up
  literature (CoCoA, DeCAF, Key Lattice, eprint 2023/1123) shows you can't have decentralized + concurrent +
  sublinear at once; we chose decentralized + concurrent at O(n), n ≤ 150 devices.
- **Cross-repo coupling** (`atsms-worker` D5 changes): keep the envelope contract in `spec/sealed-sender.md`
  versioned so worker and lib can ship independently.

## 11. Sequencing summary

```
Phase 0 specs (G1–G13 answered; D1–D12 signed off; Phase 0b re-based the set on BeeKEM 2026-07-22)
  → Phase 1 primitives+2SM → Phase 2 engine+DGM+ordering (simulation gate)
  → Phase 3 sealed sender+relay ingress ─┐
  → Phase 4 identity+lexicon+devices ────┴→ Phase 5 @atsms/sms integration + demo groups
  → Phase 6 hardening + external review
```

Each phase lands with its spec doc frozen first — plans before code, per the umbrella working style.
