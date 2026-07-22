# spec/parameters.md — Protocol Parameter Registry

> **Single source of truth for every tunable constant** in the ATSMS-DCGKA spec set. Each owning spec
> references this table; when a value changes, change it here and in the owning section together.
> Status: **DECIDED** (user sign-off) · **PROPOSED** (default awaiting sign-off) · **DEFERRED** (travels
> with a deferred design). Last updated 2026-07-22.

| Parameter | Value | Status | What it does | Owner |
|---|---|---|---|---|
| Group size (typical / max) | 25 / 150 devices | DECIDED | Design envelope; "max" counts **devices**, not users. Drives O(n) cost budgets and test sizes. | spec v1.1 |
| Endpoint-cert validity | ~10 years | DECIDED (carried from atsms-lib) | Device identity lifetime; rotation = remove+add device. | spec v1.1 §4.1 |
| Sealed-asym recipient key | = signed prekey (weekly rotation, one-period grace) | DECIDED (2026-07-22) | D9/D10: sealing cert deleted; `sealed-asym` envelopes seal to `at.atsms.prekey.signedPrekey`; recipients trial-decrypt ≤ 2 live secrets; envelope metadata-FS window ≤ 2 weeks (was 30–97 d). | identity-devices §3.1 / sealed-sender §2 |
| Signed-prekey rotation | weekly | DECIDED | Bounds first-message FS exposure and initiation-replay window for 2SM bootstraps (interim signed-only mode especially). | 2sm.md §5.0 |
| Signed-prekey grace | one rotation period (retain current + previous secret) | DECIDED | Lets X3DHs computed against a just-superseded bundle complete; each rotation promotes current→previous, deletes old previous. | 2sm.md §5.0 |
| OPK batch / replenish | 20 / daily | DEFERRED (with OPK design; ships before v1) | One-time prekey pool per device once the serve-once design lands. | 2sm.md §5.0.1 |
| Consistency-digest cadence `K` | every 50 own messages | DECIDED | How often an active member piggybacks the insider-equivocation fingerprint; bounds detection latency in busy groups. | dgm.md §8 |
| Consistency-digest backstop | 7 days | DECIDED | Attach a digest to any outgoing frame if the last one is older than this; no standalone digest frames (decided) — totally silent members are covered by staleness instead. | dgm.md §8 |
| Stale-member **warn** | 7 days silent | PROPOSED | Surface to app: member neither sending nor acking — PCS hole + GC blocker forming. | ordering-auth §9 / dgm.md §7 |
| Stale-member **alarm** / eviction proposal | 30 days silent | PROPOSED | Escalation: propose admin eviction (ordinary remove); aligns with repair give-up. | ordering-auth §9 / dgm.md §7 |
| `T_ACK` | 60 s (online); flush on reconnect before app messages | DECIDED (2026-07-16) | Max delay before broadcasting a pending ack — acks are the PCS mechanism; delay = healing latency. | dcgka-core §5 |
| `OUT_OF_ORDER_TOLERANCE` | 100 | DECIDED (2026-07-16; from p2panda) | Max backward gap per sender chain: how many missing earlier messages can still be decrypted later (skipped-key cache per epoch). | dcgka-core §7 |
| `MAX_FORWARD_DISTANCE` | 1000 | DECIDED (2026-07-16; from p2panda) | Max fast-forward per sender chain in one step; caps CPU on a malicious/huge index jump. | dcgka-core §7 |
| `MAX_SKIPPED_TOTAL` | 2000 per group | DECIDED (2026-07-16; from p2panda hardening) | Global cap on cached skipped message keys — memory-DoS bound. | dcgka-core §7 |
| `MAX_BUFFERED_PER_SENDER` | 200 | DECIDED (2026-07-16) | Ordering-layer buffer cap per member for not-yet-ready messages (seq gaps / unresolved deps) — memory-DoS bound. | ordering-auth §4.4 |
| `MAX_BUFFERED_TOTAL` | 2000 per group | DECIDED (2026-07-16) | Group-wide ordering-buffer cap; overflow drops newest from largest queue + issues repair (never drops a ready message). | ordering-auth §4.4 |
| `T_REPAIR` | 60 s online / on next connect | DECIDED (2026-07-16) | How long a seq gap or unresolved dep may self-heal via in-flight delivery before a repair request is sent to the sender. | ordering-auth §8 |
| `T_REPAIR_FALLBACK` | 24 h | DECIDED (2026-07-16) | If the original sender doesn't answer, ask any other member (all retain processed messages until acked-by-all). | ordering-auth §8 |
| `T_REPAIR_GIVEUP` | 30 d | DECIDED (2026-07-16) | Stop repairing an unresolvable message; drop with surfaced warning. Aligned with the 30 d stale-member alarm. | ordering-auth §4.4/§8 |
| Envelope padding buckets | 1 / 2 / 4 / 8 / 16 / 32 / 64 KiB | PROPOSED | Sealed-plaintext size classes; oversize content MUST move to blob offload, never a bigger envelope. | sealed-sender §5 |
| Send jitter (non-interactive frames) | 0–30 s (MAY) | PROPOSED | Optional random delay on acks/digests to blunt timing correlation; never on user-visible messages. | sealed-sender §6 |
| Anonymous ingress quota | 600 envelopes / 20 MB per mailbox-hour | PROPOSED | Relay abuse control on unauthenticated envelope pushes (operator default, not protocol). | sealed-sender §7 |
| Revocation tombstone grace | 30 d | PROPOSED | How long a revoked `at.atsms.x509` record is retained (tombstoned) before it MAY be deleted. | identity-devices §7 |
| Cert-cache staleness bound | ≤ 24 h | PROPOSED | Max age before cached cert/prekey records SHOULD be revalidated against the PDS. | identity-devices §7 |
| Sealed-sym hint tag width | 8 B | DECIDED (2026-07-20) | Per-recipient per-epoch PRF pseudonym; exact-lookup, multi-hit trial-open makes width a non-safety parameter. | sealed-sender §11.3 |
| Sealed-sym envelope-key grace | until epoch acked-by-all, cap 30 d (= `T_REPAIR_GIVEUP`) | PROPOSED | How long superseded per-sender-epoch envKeys (and their tags) stay in the lookup table so offline receivers recognize missed-epoch envelopes. | sealed-sender §11.4 |
