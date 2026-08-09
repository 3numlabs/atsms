# atsms-dcgka — Spec Gap Analysis

> Evaluation of [`atsms-dcgka-spec.md`](atsms-dcgka-spec.md) v1.0 for completeness, against
> (a) the DCGKA paper it is based on — Weidner, Kleppmann, Hugenroth, Beresford, *"Key Agreement for
> Decentralized Secure Group Messaging with Strong Security Guarantees"*, CCS 2021,
> [eprint 2020/1281](https://eprint.iacr.org/2020/1281) (use the **eprint version**, revised May 2021 — it adds
> Appendices B and D, which are load-bearing here), plus the prototype
> [trvedata/key-agreement](https://github.com/trvedata/key-agreement); and
> (b) the existing `atsms-lib` (`@atsms/sms`) this protocol is meant to replace.
>
> Layer tag: **[Protocol]**. Status: everything below is **DESIGNED** at best.

## Verdict

The spec is a **good architectural sketch, not the "complete, buildable blueprint" it claims to be** (§1, §11).
Its core bet is correct and is actually *endorsed by the paper itself*: DCGKA §8.1 + Lemma 8 prove correctness and
security under a **relaxed partial order** (per-sender FIFO + ack-after-referent + welcome-first), so full causal
broadcast is not required and client-side causal buffering over dumb mailboxes preserves every proven guarantee —
provided the client layer supplies what ACB supplied (authentication, ordering metadata, replay defense).

But the paper's own contribution is *only* the DCGKA state machine (its Fig. 4) plus a 2SM construction (eprint
App. D). It explicitly **assumes** three building blocks — ACB, DGM, 2SM — and the spec either under-specifies
them or (in the 2SM case) recommends constructions that **do not satisfy the paper's security requirements**.
The spec also has no group-management model, no multi-device model at the group layer, no ack lifecycle, and no
integration story with the existing ATSMS identity/transport/dialect stack.

Gaps are numbered **G1–G18**, grouped by severity:

- **BLOCKER** — the spec as written produces a broken or unprovable protocol.
- **DESIGN** — a component the paper leaves abstract; we must design and specify it ourselves.
- **INTEGRATION** — required to make this a replacement for `atsms-lib` in the Bourbon/ATSMS stack.
- **HARDENING** — needed for production; can trail the first working implementation.

---

## A. BLOCKER — correctness-critical errors in the spec

### G1. The 2SM recommendation is wrong (spec §3, §5)

Spec says: *"2SM: Implement a minimal Signal-like protocol (X3DH + Double Ratchet) or use HPKE (RFC 9180) for
simplicity."* **Neither qualifies.**

- The DCGKA proof requires a 2SM with **per-message FS and PCS** (eprint App. B: every message counts as a PCS
  update; the `2SM-safe` predicate). The **Double Ratchet explicitly does not qualify** — it heals only after a
  full DH round trip, not on every send (paper §5.3 says this in so many words).
- Bare **HPKE has no ratcheting at all** — a single key compromise is permanent. HPKE is the *PKE primitive
  inside* the 2SM, not the 2SM.

**Required:** implement the paper's own 2SM (eprint **Appendix D, Fig. 13**; prototype
`crypto/TwoPartyProtocol.java`): IND-CPA PKE (X25519-based) with aggressive key rotation — every send generates a
fresh keypair for yourself **and** a fresh keypair for the peer, sent inside the ciphertext; indexed `mySks[]`
with deletion of all keys ≤ received index; X3DH prekeys only for the *first* message to a device. Security bound:
Theorem 10, ε₂sm = 2q·ε_pke. Two documented caveats to carry into our spec: **no bad-randomness resilience**
(Remark 11 — a leaked send-coin partially compromises both parties; Jost et al.'s fix doesn't port to Curve25519)
and **no post-impersonation security** (acceptable because the outer authentication layer provides authenticity).

### G2. Acks are treated as optional; they are the PCS mechanism (spec §9)

Spec says: *"(Optional) Send a lightweight ack if needed for causality."* **Acks are not optional and not about
causality.** A member X's outer KDF chain advances **only when X's ack is processed** (`process-ack` applies X's
member secret to X's chain, for everyone including X). Consequences the spec must specify:

- Every member broadcasts an ack for **every** create/update/remove (and `add-ack` for adds, carrying its
  2SM-encrypted ratchet state to the new member). That's O(n) ack traffic per operation — it's in the paper's
  cost model (§2.1) and missing from the spec's flow (§9).
- Until X acks update U: U has **not healed X's sending channel** (an adversary with X's earlier state still
  reads X's messages), and every member must retain `memberSecret[·,·,X]` and associated 2SM keys —
  **unbounded state growth** for never-acking members (§2.1, §8.1).
- Policy needed: ack batching/piggybacking on next app message (sanctioned by §8.1), "member X hasn't acked in
  N days" surfacing, and state-GC rules. See also G12 (mailbox withholding).

### G3. Application ratchet mis-specified (spec §3, §11)

Spec says *"per-sender Double Ratchet or HKDF chain."* The construction is fixed by the paper (Fig. 1 +
forward-secure AEAD, per Alwen et al.): a **symmetric PRG/KDF chain per sender, reseeded by each update secret**
from DCGKA, message index as AEAD associated data, keys deleted after use, with bounded out-of-order key caching
(skipped-message keys). A Double Ratchet here is wrong (there is no pairwise DH partner in a group fan-out) and
an unbounded plain HKDF chain without a skipped-key store breaks under out-of-order mailbox delivery. Prototype
reference: `InOrderForwardSecureEncryptionProtocol.java` (we need the out-of-order variant).

### G4. The authentication layer (ACB's other half) is under-specified (spec §5, §6)

The paper's ACB assumption includes **authenticity with PCS**: every message's content *and ordering metadata*
signed, and **on every DCGKA update the sender rotates its signing keypair**, broadcasting the new public key
signed under the old one (§5.1, following Cremers et al.; prototype `RotatingSignatureProtocol.java`). If the
adversary can forge or splice control messages/acks, the whole security model collapses (the game's `deliver`
oracle only permits honest, ordering-respecting delivery).

The spec's sealed-envelope signature (§6) covers the inner content but never mentions: signing-key rotation and
its verification chain; that the signature must cover **seq + causality metadata** (not just payload); per-sender
FIFO enforcement via `seq`; replay/duplicate rejection rules; rejecting messages from non-members (needs DGM
output); retransmission/repair of gaps. All of this must be specified as a first-class **Ordering &
Authentication layer** with exact predicates: per-sender FIFO, ack-after-referent, welcome-first + the
**`add-ready`** rule for re-added members (paper §8.1, footnote 4; prototype `AckOrderer.java` + `VectorClock.java`).

---

## B. DESIGN — components the paper deliberately leaves abstract

### G5. DGM / group management model — the biggest hole (spec §5)

The spec's entire treatment: *"Recompute current member view from the causally ordered history of
add/remove/create messages."* **That is the function's type signature, not a design.** The paper deliberately
leaves DGM abstract (§5.2) and only requires: a **pure deterministic function** of (membership ops, causal
relation) — independent of local arrival order — plus the §6.2 restrictions (sequential semantics from each
sender's own view; users enter **only** via an add targeting them; a remove may never be "undone" by a concurrent
remove, i.e. Matrix semantics are explicitly excluded by the proof).

We must design and write a **DGM spec** answering, at minimum:

- **Authorization model:** who may add/remove? Options: (a) creator-is-admin with admin-grant ops, (b) any-member
  egalitarian (paper prototype's implicit model), (c) policy-per-group. Permissions must be *part of the pure
  function* (evaluated from history, not local state).
- **Concurrent add ∥ remove of the adder:** pick a semantics. The prototype's `StrongRemoveDgm.java` (~500 LOC,
  the only concrete key-agreement-compatible DGM in existence, *not* described in the paper) implements
  **strong-remove**: removing a user transitively removes anyone they added that the remover hadn't acked.
  Recommended starting point; adopt or consciously deviate.
- **Remove ∥ remove (mutual):** both removes apply (both users out) — and note the related security caveat G11.
- **Re-add semantics:** a re-added user is a **fresh protocol instance** — member IDs must carry a nonce/epoch
  (paper §2.1 "unique additions") so old state is never resumed.
- **Group metadata ops** (name, avatar, description) and whether they ride the DGM history or the app layer.
- **Determinism proof obligation:** test harness that permutes delivery orders and asserts identical member views
  (the property the proof depends on).

### G6. Multi-device model at the group layer (spec §4)

The paper **never mentions multi-device**; each ID is one device. The spec's identity section (device certs
delegated by the user key — consistent with today's `at.atsms.x509` one-cert-per-device model) stops before the
hard questions:

- **Group membership unit = device.** 25 users × 3 devices = 75 DCGKA members; the "max 150" target is a
  **device** budget, not a user budget. State the accounting explicitly.
- **User-level operations must expand to device-level ops:** "remove Alice" = remove every device of Alice's;
  "Alice adds a device" = a group `add` in **every group Alice belongs to** — authorized how? Proposal to
  evaluate: any of Alice's existing devices may add/remove Alice's own devices (authenticated by the user-signed
  device certificate), while adding/removing *users* follows the G5 authorization model. The DGM function must
  encode both rules.
- **Device revocation** (lost phone): user-signed revocation → group remove in all groups + cert/prekey cleanup in
  the PDS; interaction with PCS healing (a stolen device is exactly the compromise scenario — removal must be
  possible from another device of the same user).
- **DCGKA member ID format:** `(userDID, deviceID, epoch-nonce)` — needs exact encoding (feeds G5 re-add rule and
  G8 lexicons).

### G7. Welcome contents, history growth, and metadata exposure (spec §9)

The welcome to a new member carries the adder's **entire membership-op history including acks** (needed to
evaluate the DGM) plus the adder's live ratchet state; every other member then 2SM-sends **its** ratchet state in
`add-ack`. The spec doesn't mention any of this. Must specify:

- **History compaction:** naïve history is unbounded; the paper suggests shipping the causal DAG (Matrix-style)
  instead of raw acks — O(n′) typical, O(n′²) worst case with heavy concurrency. Define the wire format and a
  pruning rule (paper §10: prune once fully acked).
- **Metadata disclosure policy:** the history reveals to every (new) member who added/removed whom and when — at
  odds with the spec's metadata-protection ambitions. Document as an accepted in-group disclosure (sealed sender
  protects against *outsiders/providers*, not against members).
- **Welcome/add-ack are on the proof's critical path** (their 2SM leak = chain compromise) — they must ride the
  same hardened 2SM as seeds, never a weaker "bootstrap" path.

### G8. Prekeys on a public PDS don't work as specified (spec §1, §4)

Spec: *"Per-device prekeys are stored in the user's PDS and broadcast via the AT Protocol firehose."* Two
problems:

- **One-time prekeys can't be served from a public PDS.** A PDS record is a public, repeatedly-fetchable
  document; there is no atomic "hand out exactly once and delete." Without one-time semantics you get prekey
  reuse across initiators (weakens X3DH's FS for the first message, invites replay). Options: (a) **signed
  prekey + last-resort key only** in the PDS, rotated on a schedule (Signal's fallback model — simplest,
  recommended floor); (b) a **Relay-Node prekey service** (the `atsms-worker` inbox DO already fronts per-device
  state; architecture.md §2 already assigns "distributes pre-keys" to Relay Nodes) doing atomic one-time-prekey
  checkout, with the PDS holding only the signed prekey; (c) both. Decide and spec it.
- **No lexicon exists.** Today's only messaging lexicon is `at.atsms.x509`. Need a new **`at.atsms.prekey`** (name decided 2026-07-15) (or
  similar) lexicon: device Ed25519 identity key, X25519 signed prekey (+signature), prekey rotation timestamps,
  user-signature delegation binding the device to the DID (the spec's device certificate), pointers to the
  device's mailbox address. Also define **revocation** (tombstone record vs deletion) and firehose-consumption
  guidance for caches.

### G9. Sealed sender needs a real design, not a JSON sketch (spec §6)

The construction (HPKE-seal inner-signed payload to recipient's long-term key) is directionally right but
incomplete:

- **Anonymous ingress conflict:** today's worker send paths are sender-authenticated (ES256 JWT over WebSocket).
  Sealed sender requires the provider to accept envelopes **without identifying the sender** — otherwise the
  transport layer un-seals what the crypto sealed. Need an anonymous push endpoint plus **abuse control**:
  rate-limit per target mailbox, proof-of-work, or unlinkable sender tokens (Privacy-Pass-style / Signal
  sealed-sender certificates). This is a protocol+relay design item, not a client detail.
- **`recipient_device_id` in the cleartext envelope** is redundant routing metadata (the mailbox address already
  routes) and leaks device identity to any on-path observer. Drop it; key-trial or mailbox-implied routing.
- **Key separation:** seal to a dedicated X25519 *sealing* key (in the G8 lexicon), not the 2SM/ratchet keys.
  *(Amended 2026-07-22, D10: "dedicated" relaxed — sealed-asym seals to the signed prekey, with a joint-use
  analysis in identity-devices §3.1; still never the 2SM/ratchet/identity keys.)*
- **Padding:** "random bytes" is not a scheme. Specify size buckets (e.g., padmé or fixed classes) so control
  messages, acks, welcomes, and app messages are indistinguishable — the ack traffic pattern (n−1 acks right
  after every update) is otherwise a glaring classifier even with sealing.
- **Envelope-level dedup/replay:** mailboxes redeliver; define envelope IDs and idempotency before decryption.

---

## C. INTEGRATION — making it an atsms-lib replacement

### G10. No relationship to the existing stack is specified

The spec is written as a greenfield system. To be the `atsms-lib` replacement it must define:

- **Identity:** AT Protocol DID (spec has this) + the G8 lexicon + explicit compatibility statement about
  `at.atsms.x509` (architecture.md §6 declares X509/S-MIME the **interop floor that stays**; the decision of
  "replace outright vs. layer above the floor" is flagged in the implementation plan as **D1 — needs sign-off**).
- **Transport mapping:** the spec's "mailbox" ≡ the existing per-(DID, certSerial) inbox DO in `atsms-worker`,
  reachable via `ATSMSTransportLayer` (WS + HTTP). Reuse it; changes needed: anonymous ingress (G9), opaque
  envelope type alongside `atsms|atsms-email|email`, and mailbox-address records (spec §7's
  `DeviceID → MailboxAddress` map) in the G8 lexicon.
- **Dialects:** today's `ATSMSMessagePayload` (contentType `atsms/text`, `atsms/webrtc`, …) becomes the **inner
  plaintext of DCGKA application messages** — the dialect system is orthogonal and survives unchanged. State it.
- **Conversation identity:** `groupId` must be **deterministic and content-derived** (e.g., hash of the signed
  `create` message) — replacing today's sender-chosen random `nanoid` convoIds (a known fragility). DMs: decide
  whether a 2-member DCGKA group replaces `generateDMConvoId` DMs or DMs stay on the pairwise path.
- **API parity surface:** the replacement must (eventually) offer what consumers actually use today —
  `ATSMSStorageManager` (start/send/sync/RxJS streams), `ATSMSClient` (resolution), storage adapters
  (SQLite/IndexedDB), JWT auth for mailbox *fetch* — inventoried in the implementation plan §2.

### G11. Concurrency security caveats must be surfaced (paper §7, App. C)

Not spec'd anywhere: under **concurrent removes** (or concurrent updates by multiple compromised members), healing
is only complete once some later operation **causally dominates** them — e.g., two concurrently-removed members
can **collude to decrypt** messages sent after both removes but before the next dominating update. The paper's
mitigation is behavioral: a client that observes concurrent removes/updates **sends its own update before its next
application message**. This rule must be normative in our spec (it's cheap and closes the gap), and the "sender
always knows exactly who could decrypt, per its own view" property should be surfaced in UX guidance.

### G12. Dumb-mailbox liveness assumptions are stronger than acknowledged (spec §2)

The spec's threat model waves at this ("do not… selectively drop in a targeted way") but the consequences are
unstated: a withholding mailbox can **delay PCS healing indefinitely** (updates that never arrive are never
acked), sustain long-lived group forks, and bloat peers' state (G2). Required: retransmission/repair protocol
(gap detection from seq numbers → re-request from sender or any member), multi-mailbox redundancy option,
operational surfacing of stale members, and an eviction policy (auto-remove members unreachable for N days —
which is a **DGM policy** decision, looping back to G5).

### G13. Wire formats, versioning, and test vectors don't exist

"JSON-like for clarity; serialize to bytes" and "Protocol Buffers or CBOR" is not implementable. Need: exact
canonical serialization (recommend deterministic CBOR), every message schema (control, ack, welcome, 2SM,
app-message, sealed envelope), domain-separation strings for every HKDF invocation (the paper's `"welcome"`/
`"add"` constants and member-secret derivation must be byte-exact), protocol version negotiation, and a
**test-vector suite** — ideally cross-checked against the Java prototype to catch state-machine divergence.

---

## D. HARDENING — production gaps to schedule, not blockers

### G14. Insider attacks / no consistency checking (paper §2.1, §7)

A malicious member can send different seed secrets to different members → permanent ratchet divergence (DoS).
The paper offers no detection (unlike MLS's confirmation tags). Options to evaluate: periodic epoch-hash
comparison (members gossip a transcript/ratchet-state hash; divergence → flag + re-create group), or accept and
document with a recovery procedure (remove offender, re-create). Guarantee we do keep: a malicious member cannot
resist removal, and post-removal it decrypts nothing (no MLS-style double-join).

### G15. Storage/GC policy

Unbounded components: `history`, unacked member secrets, 2SM key stores, skipped app-message keys, mailbox
backlog. Define bounds, pruning (paper §10: prune after full ack), and the App. D cross-layer optimization
(a DCGKA ack proves 2SM key receipt → bound `mySks`).

### G16. Group size & performance envelope

Paper tested to **n=128 devices** (update ≈ 40 kB total traffic, ≤ ~100 ms/op/participant in Java on 2021
hardware; app messages 139 B overhead, <1 ms). Spec's "max 150" is plausible but must be stated as a **device**
cap (G6) with padding overhead (G9) added to the budget. O(n) per op is inherent — follow-ups (CoCoA, DeCAF,
Key Lattice, eprint 2023/1123's lower bounds) confirm you don't get concurrent + decentralized + O(log n)
simultaneously; document the choice and move on.

### G17. Security-model fine print to document

Non-adaptive adversary only; HKDF as random oracle; no post-impersonation security; no deniability treatment; no
post-quantum story (note: 2SM's PKE is the swap point for a PQ KEM later). These go in the spec's §12 as
limitations.

### G18. Formal review pipeline

The spec's "audit all crypto code" needs a plan: internal test-vector + property tests (delivery-order
permutation, FS/PCS game-style tests per the paper's definitions), then external cryptographic review of the
composed system (sealed sender × DCGKA composition is novel enough to warrant it — the paper analyzes neither).

---

## Summary table

| # | Gap | Severity | Owning sub-spec (see implementation plan) |
|---|-----|----------|-------------------------------------------|
| G1 | 2SM recommendation wrong (DR/HPKE don't qualify) | BLOCKER | `../../spec/2sm.md` |
| G2 | Acks treated as optional; PCS + state-GC lifecycle missing | BLOCKER | `../../spec/dcgka-core.md` |
| G3 | App ratchet mis-specified | BLOCKER | `../../spec/dcgka-core.md` |
| G4 | Ordering & authentication layer under-specified | BLOCKER | `../../spec/ordering-auth.md` |
| G5 | **DGM / group management model absent** | DESIGN | `../../spec/dgm.md` |
| G6 | Multi-device model at group layer | DESIGN | `../../spec/identity-devices.md` |
| G7 | Welcome/history growth + metadata exposure | DESIGN | `../../spec/dcgka-core.md` |
| G8 | Prekeys-on-PDS unworkable as written; no lexicon | DESIGN | `../../spec/identity-devices.md` |
| G9 | Sealed sender: anonymous ingress, padding, key separation | DESIGN | `../../spec/sealed-sender.md` |
| G10 | No integration story with atsms-lib/worker/dialects | INTEGRATION | `../../spec/atsms-integration.md` |
| G11 | Concurrent-remove collusion caveat + normative mitigation | INTEGRATION | `../../spec/dcgka-core.md` |
| G12 | Mailbox withholding / liveness / repair | INTEGRATION | `../../spec/ordering-auth.md` |
| G13 | Wire formats, versioning, test vectors | INTEGRATION | `../../spec/wire-format.md` |
| G14 | Insider DoS detection/recovery | HARDENING | `../../spec/dgm.md` + core |
| G15 | Storage/GC bounds | HARDENING | `../../spec/dcgka-core.md` |
| G16 | Size/perf envelope (150 = devices) | HARDENING | spec §Performance |
| G17 | Security-model fine print | HARDENING | spec §Security |
| G18 | Review/audit pipeline | HARDENING | plan Phase 6 |
