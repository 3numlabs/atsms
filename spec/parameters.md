# spec/parameters.md — Protocol Parameter Registry

> **Single source of truth for every tunable constant** in the ATSMS-DCGKA spec set. Each owning spec
> references this table; when a value changes, change it here and in the owning section together.
> Status: **DECIDED** (user sign-off) · **PROPOSED** (default awaiting sign-off) · **DEFERRED** (travels
> with a deferred design). Last updated 2026-07-22.

| Parameter | Value | Status | What it does | Owner |
|---|---|---|---|---|
| Group size — **profile 1**, per-recipient delivery | recommended **25** devices, max **128** | DECIDED (2026-08-10; replaces a single 150-device figure) | A **sender-uplink** budget, not a protocol limit. The sender uploads one sealed copy per recipient device, so cost is linear in group size: a message is ~1.06 KiB × devices (25 KiB at 25 devices, 134 KiB at 128) and an unhealed re-key is 2.0 MiB at 128. The max sits just under a measured step: the re-key frame crosses from the 16 KiB padding bucket into the 32 KiB one at **130 devices**, doubling the sender's fan-out to 4.0 MiB. Reproduce with `packages/dcgka/scripts/fanout-cost.ts`. | spec v1.1 |
| Group size — with a **group drop point** (PROPOSED, not spec) | no size-driven limit in the tested range | **PROPOSED** — see [proposals/0001](../proposals/0001-group-drop-point.md) | The sender uploads once, so group size stops driving sender cost and the profile-1 numbers above do not apply. What still grows is the update **frame** (~0.11 KiB per device, unhealed): 16 KiB at 129 devices, 32 KiB at 200, and it reaches the largest padding bucket near **560**, at which point it needs blob offload. The drop point itself is a **proposal**: the sealing is undesigned and nothing in this spec depends on it. | proposals/0001 |
| Endpoint-cert validity | ~10 years | DECIDED (carried from packages/client) | Device identity lifetime; rotation = remove+add device. | spec v1.1 §4.1 |
| Sealed-asym recipient key | = signed prekey (weekly rotation, one-period grace) | DECIDED (2026-07-22) | D9/D10: sealing cert deleted; `sealed-asym` envelopes seal to `at.atsms.prekey.signedPrekey`; recipients trial-decrypt ≤ 2 live secrets; envelope metadata-FS window ≤ 2 weeks (was 30–97 d). | identity-devices §3.1 / sealed-sender §2 |
| Signed-prekey rotation | weekly | DECIDED | Bounds the admission-window exposure (published leaf key until the joiner's first self-update) and the sealed-asym metadata-FS window. | identity-devices §4.2 |
| Signed-prekey grace | one rotation period (retain current + previous secret) | DECIDED | Lets adds pinning a just-superseded prekey complete and grace-window envelopes open; each rotation promotes current→previous, deletes old previous. | identity-devices §4.2 |
| ~~OPK batch / replenish~~ | — | RETIRED (2026-07-22, D11) | OPK layer dissolved with X3DH/2SM (identity-devices §8). | — |
| Consistency-digest cadence `K` | every 50 own messages | DECIDED | How often an active member piggybacks the insider-equivocation fingerprint; bounds detection latency in busy groups. | dgm.md §8 |
| Consistency-digest backstop | 7 days | DECIDED | Attach a digest to any outgoing frame if the last one is older than this; no standalone digest frames (decided) — totally silent members are covered by staleness instead. | dgm.md §8 |
| Stale-member **warn** | 7 days silent | PROPOSED | Surface to app: member neither sending nor acking — PCS hole + GC blocker forming. | ordering-auth §9 / dgm.md §7 |
| Stale-member **alarm** / eviction proposal | 30 days silent | PROPOSED | Escalation: propose admin eviction (ordinary remove); aligns with repair give-up. | ordering-auth §9 / dgm.md §7 |
| ~~`T_ACK`~~ | — | RETIRED (2026-07-22, D11) | Acks retired; PCS completes on processing the update op itself. Coverage replaces the GC signal (`T_COVER` below). | beekem-core §5 |
| `T_COVER` | 24 h | DECIDED (2026-07-22, user sign-off) | Max delay before a member with nothing else to send emits a `coverage` frame after processing a membership op/update — GC/eviction signal only, jittered, digest carrier. | beekem-core §5 |
| `T_EPOCH_GRACE` | 30 d (= `T_REPAIR_GIVEUP`) | DECIDED (2026-07-22, user sign-off) | Hard cap on how long an uncovered epoch stays open before its keys are evicted regardless (FS bound). | beekem-core §8 |
| Checkpoint cadence | every covered-by-all membership op | DECIDED (2026-07-22, user sign-off) | When the tree checkpoint (replay base + op-graph prune frontier) advances. | beekem-core §6 |
| KDF split | BLAKE3 below the `PcsKey` seam / HKDF-SHA256 above | DECIDED (2026-07-22, user sign-off) | Oracle byte-fidelity for tree internals; house label discipline for the profile layer. Frozen before vector generation. | beekem-core §3 |
| `OUT_OF_ORDER_TOLERANCE` | 100 | DECIDED (2026-07-16; from p2panda) | Max backward gap per sender chain: how many missing earlier messages can still be decrypted later (skipped-key cache per epoch). | beekem-core §7 |
| `MAX_FORWARD_DISTANCE` | 1000 | DECIDED (2026-07-16; from p2panda) | Max fast-forward per sender chain in one step; caps CPU on a malicious/huge index jump. | beekem-core §7 |
| `MAX_SKIPPED_TOTAL` | 2000 per group | DECIDED (2026-07-16; from p2panda hardening) | Global cap on cached skipped message keys — memory-DoS bound. | beekem-core §7 |
| `MAX_BUFFERED_PER_SENDER` | 200 | DECIDED (2026-07-16) | Ordering-layer buffer cap per member for not-yet-ready messages (seq gaps / unresolved deps) — memory-DoS bound. | ordering-auth §4.4 |
| `MAX_BUFFERED_TOTAL` | 2000 per group | DECIDED (2026-07-16) | Group-wide ordering-buffer cap; overflow drops newest from largest queue + issues repair (never drops a ready message). | ordering-auth §4.4 |
| `T_REPAIR` | 60 s online / on next connect | DECIDED (2026-07-16) | How long a seq gap or unresolved dep may self-heal via in-flight delivery before a repair request is sent to the sender. | ordering-auth §8 |
| `T_REPAIR_FALLBACK` | 24 h | DECIDED (2026-07-16) | If the original sender doesn't answer, ask any other member (all retain processed messages until covered-by-all). | ordering-auth §8 |
| `T_REPAIR_GIVEUP` | 30 d | DECIDED (2026-07-16) | Stop repairing an unresolvable message; drop with surfaced warning. Aligned with the 30 d stale-member alarm. | ordering-auth §4.4/§8 |
| Envelope padding buckets | 1 / 2 / 4 / 8 / 16 / 32 / 64 KiB | PROPOSED | Sealed-plaintext size classes; oversize content MUST move to blob offload, never a bigger envelope. | sealed-sender §5 |
| Send jitter (non-interactive frames) | 0–30 s (MAY) | PROPOSED | Optional random delay on acks/digests to blunt timing correlation; never on user-visible messages. | sealed-sender §6 |
| Anonymous ingress quota | 600 envelopes / 20 MB per mailbox-hour | PROPOSED | Relay abuse control on unauthenticated envelope pushes (operator default, not protocol). | sealed-sender §7 |
| Revocation tombstone grace | 30 d | PROPOSED | How long a revoked `at.atsms.x509` record is retained (tombstoned) before it MAY be deleted. | identity-devices §7 |
| Cert-cache staleness bound | ≤ 24 h | PROPOSED | Max age before cached cert/prekey records SHOULD be revalidated against the PDS. | identity-devices §7 |
| Sealed-sym hint tag width | 8 B | DECIDED (2026-07-20) | Per-recipient per-epoch PRF pseudonym; exact-lookup, multi-hit trial-open makes width a non-safety parameter. | sealed-sender §11.3 |
| Sealed-sym envelope-key grace | until epoch covered-by-all, cap 30 d (= `T_EPOCH_GRACE`) | PROPOSED (re-based 2026-07-22) | How long superseded epoch envKeys (and their tags) stay in the lookup table so offline receivers recognize missed-epoch envelopes. | sealed-sender §11.4 / beekem-core §8 |
