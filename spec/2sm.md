# spec/2sm.md — Two-Party Secure Messaging (2SM)

> ## ⚠️ SUPERSEDED (2026-07-22, decision D11) by [`beekem-core.md`](./beekem-core.md)
> BeeKEM has no pairwise channel: admission encrypts to the joiner's published prekey via tree
> path encryption, so 2SM, X3DH, the App-D rotation discipline, the one-time-prekey serve-once
> problem (§5.0.1), and the `retry-signed-only` signal are all **retired with this document**.
> It is retained as the design record of why that complexity existed and what it took to satisfy
> the DCGKA paper's 2SM security notion. The `at.atsms.prekey` record survives with a simplified
> shape (identity-devices.md §4.2 — `identityDh` removed). Do not implement from this document.

> **Status: DRAFT v0.1 (2026-07-15) — for review.** [Protocol] · Phase 0 deliverable.
> Closes gap **G1** from [`../docs/history/gap-analysis.md`](../docs/history/gap-analysis.md) — the original one-page spec's 2SM
> recommendation (X3DH + Double Ratchet, or bare HPKE) does not satisfy the DCGKA proof and is replaced by
> this construction.
> Inputs: DCGKA paper §5.3 + eprint Appendix B (security notion) + Appendix D (construction, Fig. 13);
> p2panda-encryption `two_party/` (the validated X3DH + HPKE instantiation we adopt); spec v1.1 §4/§4.1
> identity model; [`dcgka-core.md`](./dcgka-core.md). MUST/MAY per RFC 2119.

## 1. Role and scope

2SM is the **internal pairwise channel used only by the DCGKA layer** — it carries seed secrets, welcome
material, ratchet-state transfers, and concurrent-add forwards between two devices. It is **not** a
user-facing DM primitive (per decision D6, DMs are 2-member DCGKA groups). Every pair of group members
maintains one 2SM session per direction-pair, created lazily on first need.

**Sessions are strictly per-group — never shared across groups** (made explicit 2026-07-20; the state
already lives inside the per-group γ, dcgka-core §2). If devices A and B co-occur in groups G1 and G2,
they run two independent 2SM sessions, each with its own X3DH bootstrap. This is forced, not stylistic:
(i) the state machine's in-order requirement (§4.3) is supplied by the ordering layer's per-sender FIFO
*within one group* — no cross-group ordering relation exists, so a shared session would desync under
interleaved delivery; (ii) the fresh-Membership rule is a per-group invariant — a re-add in G1 must kill
and re-bootstrap G1's session while leaving G2's untouched; (iii) failure/compromise isolation per group.
Only identity-layer material (the prekey bundle) is shared across groups.

### 1.1 Identity-freeness invariant (normative, 2026-07-20)

The 2SM layer itself carries **no identity and no cleartext**:

- 2SM ciphertexts MUST only ever travel nested inside signed ordering-layer frames inside envelopes
  (`dms`, `AckEntry.dm`, welcome bodies — wire-format §4/§5), and MUST NOT gain cleartext fields. Even
  the header counters (`keyClass`, `usedIndex`) would become linkable sequence markers if a transport
  ever carried 2SM messages bare.
- The single sender-identifying field in the layer — `initiatorIdentityDh` in the X3DH header — exists
  only in bootstrap messages, which MUST ride `sealed-asym` envelopes (the joiner has no group state;
  sealed-sender §1/§11.1). Its confidentiality against outsiders is exactly the HPKE wrap. *(Since D10
  the envelope wrap targets the same `signedPrekey` the X3DH inside consumes — independent ephemerals
  and KDF labels; identity-devices §3.1.)*
- Sender-hiding for 2SM material is therefore a property of *placement*, not of the construction: the
  App. D rotation discipline (§4) is untouched by envelope-mode choices, so its FS/PCS proofs carry.

## 2. Required security notion (why the obvious choices fail)

The DCGKA proof requires a 2SM with **per-message FS and PCS** (eprint App. B: every message counts as a
PCS update; `2SM-safe` predicate). Consequences, recorded so this argument never has to be re-litigated:

- **Signal Double Ratchet does NOT qualify**: it heals only after a full DH round trip; the proof needs
  healing from every single delivered message (paper §5.3 states this explicitly).
- **Bare HPKE does NOT qualify**: no ratcheting — one key compromise is permanent.
- The paper's own construction (App. D) achieves the notion with plain public-key encryption plus an
  aggressive key-rotation discipline; **that discipline is the normative core of this spec** (§4). We
  instantiate the abstract PKE with HPKE and the session bootstrap with X3DH — p2panda's validated
  instantiation, a strict upgrade over the paper's bare PKE.

## 3. Primitives

- **PKE**: HPKE Base mode, `DHKEM(X25519, HKDF-SHA256)` + `HKDF-SHA256` + `ChaCha20-Poly1305` (RFC 9180).
  (IND-CCA2 — stronger than the IND-CPA the Theorem 10 bound needs.)
- **Bootstrap**: X3DH per the Signal spec, adapted to our identity layer (§5).
- **Signatures on published bundles**: ECDSA-P256 under the device identity key (spec v1.1 §4 —
  documented deviation from XEdDSA).
- HPKE `info` strings: `"atsms-2sm:v1:msg"` (steady-state), `"atsms-2sm:v1:x3dh"` (first message); the
  X3DH HKDF itself uses info `"atsms-2sm:v1:x3dh-kdf"` (assigned in the wire-format label registry,
  [`wire-format.md`](./wire-format.md) §7).

## 4. Construction (normative)

### 4.1 State (per session, per party)

```
σ = {
  mySks:          Map<uint64, X25519Priv>,   // my decryption keys, indexed; monotone counter myIndex
  receivedSk:     X25519Priv | ⊥,            // key my peer generated FOR me (latest)
  otherPk:        X25519Pub,                  // peer's current encryption key (what I encrypt to)
  otherPkSender:  "me" | "other",            // who generated otherPk
  otherPkIndex:   uint64,                     // peer's index for otherPk when peer generated it
}
```

### 4.2 Send

On **every** send (no exceptions — this is the rotation discipline):

1. Generate a fresh keypair for **myself**: `(newSk, newPk)`; store `mySks[++myIndex] = newSk`.
2. Generate a fresh keypair **for the peer**: `(peerNewSk, peerNewPk)`.
3. Plaintext tuple `P = (m, peerNewSk, myIndex, newPk)` (deterministic CBOR).
4. `c = HPKE.Seal(otherPk, info, P)`; header records which key was used:
   `(usedKeyClass ∈ {prekey, receivedKey, ownKey}, usedIndex)`.
5. Update local state: `otherPk = peerNewPk`, `otherPkSender = "me"`; **delete `peerNewSk` locally** (only
   the peer may hold its next decryption key).

Every ciphertext is thus encrypted under a never-reused public key (**optimal FS**), and every delivered
message hands both parties fresh keys (**healing on the very next delivered message** — PCS).

### 4.3 Receive

1. Select the decryption key per the header: `receivedSk` if the sender used the key it generated for me;
   `mySks[usedIndex]` otherwise — then **delete every `mySks[i]` with `i ≤ usedIndex`** (FS by deletion).
2. `P = HPKE.Open(...)`; on failure, abort with **no state change** (dcgka-core §9 discipline).
3. Install: `receivedSk = P.peerNewSk`, `otherPk = P.senderNewPk`, `otherPkSender = "other"`,
   `otherPkIndex = P.senderIndex`. Deliver `m` to DCGKA.

**In-order delivery per direction is guaranteed upstream — by the ordering layer, and only there.** The
transport guarantees nothing (mailboxes reorder/duplicate/delay freely); [`ordering-auth.md`](./ordering-auth.md)
is the single layer that repairs this, and 2SM inherits the result:

- Every 2SM payload rides a **control-plane frame** (`dms`, ack `dm` entries, welcome bodies — never
  standalone, §1.1), and each sender's control-plane frames carry a consecutive `ctrlSeq` **inside the
  signed canonical bytes** — unforgeable and un-spliceable (content addressing, ordering-auth §2).
- The receiver's readiness predicate (ordering-auth §4.1) **holds** any frame whose `ctrlSeq` isn't
  exactly `last + 1` (or whose deps are unprocessed) in a bounded buffer; gaps that persist trigger
  repair (§8). Frames are released upward strictly in sequence.
- A total FIFO on sender S's control-plane frames implies FIFO on the subsequence carrying this
  session's payloads — so each 2SM direction sees exactly the order its peer produced.

Given that contract, this state machine is **deliberately not reorder-tolerant**, for two reasons:
tolerance would require retaining superseded decryption keys "in case an earlier message arrives late,"
trading away the delete-on-use discipline that *is* this construction's FS (contrast the inner app
ratchet, which keeps a skipped-key store on purpose — app reorder is a liveness matter, control-plane
order a correctness matter); and intolerance is a **tripwire** — if a readiness bug ever delivers out of
order, the frame references an already-deleted (or not-yet-existing) key index, the open fails, and the
abort-with-no-state-change rule (step 2 above) surfaces the bug immediately at the layer boundary instead
of letting it resurface later as an unexplainable ratchet divergence.

## 5. Session bootstrap (X3DH against the PDS)

First message from `A` to device `B` with no existing session:

### 5.0 The `at.atsms.prekey` record (canonical shape: [`identity-devices.md`](./identity-devices.md) §4.2)

The bundle's record shape, the cert ↔ prekey pairing/verification path, and the rotation mechanics moved
to **identity-devices.md §4.2** (2026-07-16) — that document is the single source of truth. What 2SM
consumes from it:

- **rkey = the device fingerprint** (structural pairing with `at.atsms.x509/<fingerprint>`; re-keyed
  from cert serial 2026-07-17 — identity-devices.md §4.1).
- `identityDh` (X25519, device-lifetime) — X3DH long-term DH key; the X25519 alias of the device identity.
- `signedPrekey` (X25519, rotated **weekly**; grace = one full rotation period, so the device holds
  current + previous secrets and X3DHs against a just-superseded bundle complete for up to a week —
  older fail and the initiator re-fetches). Also the `sealed-asym` envelope recipient key since D10
  (joint use, identity-devices §3.1).
- `bundleSig` (ECDSA-P256 by the device identity key over the deterministic CBOR of all preceding
  fields) — verified against the endpoint cert before any X3DH.

The record is fetched by **every** DCGKA bootstrap (the signed prekey is a mandatory X3DH ingredient —
the future OPK is the optional fourth DH, never a substitute). Reachability lives in the per-DID
`at.atsms.inbox` record, not here (D13 2026-07-25; was per-device `inviteAddress` — inbound-delivery.md §3).

### 5.0.1 One-time prekeys — design deferred (decided 2026-07-16)

The one-time-prekey (OPK) mechanism is **still being formulated — deferred during design and initial
prototyping, to be specified and shipped BEFORE the v1 release** (it is a v1 feature, not a post-v1 one).
The open problem: true one-time semantics require an atomic serve-once dispenser, which a pull-only PDS
does not provide; candidate designs (PDS checkout endpoint with a serve-once index; per-OPK device
signatures for stateless verification) are recorded in the review discussion but not yet specified.
**Interim behavior (normative for prototypes)**: initiators SKIP OPK retrieval entirely and bootstrap
against `at.atsms.prekey/<fingerprint>` directly; the X3DH runs in signed-prekey-only mode (3 DHs, no DH4). The
protocol reserves the OPK slot in the X3DH KDF layout so OPKs land without a version break. Superseded
placeholder constants from the earlier combined-bundle design (batch 20, daily replacement) move with the
deferred design.
- X3DH: standard 3-DH (A's ephemeral × B's identityDh, A's identityDh × B's signedPrekey, A's ephemeral ×
  B's signedPrekey; + A's ephemeral × oneTime when present), HKDF-SHA256 with a 32×0xFF domain-separation
  prefix, AD = `enc(A.Membership ‖ B.Membership)`. Output seeds the first `receivedSk`-equivalent state; the
  first 2SM message carries A's initial `newPk`/`peerNewSk` tuple exactly as §4.2, HPKE-sealed under the
  X3DH-derived key (`info = "atsms-2sm:v1:x3dh"`).
- **Identity-DH key**: a dedicated per-device X25519 key in the bundle — the P-256 endpoint key is never
  used for DH (no cross-algorithm, cross-purpose reuse), and `identityDh` remains X3DH-only. The
  `signedPrekey` is the one deliberate dual-consumer key (X3DH + sealed-asym envelopes — D10,
  identity-devices §3.1; the earlier separate sealing key is deleted).

### 5.1 Bootstrap freshness & healing (interim: signed-prekey-only)

Until the OPK layer lands (pre-v1, §5.0.1) every bootstrap is signed-prekey-only, so first-message forward
secrecy is bounded by the weekly rotation window and initiation replay is possible within it — a
prototype-phase property, not a release property. Both are closed by the healing rule:

- **Healing rule (normative)**: every member MUST send a DCGKA `update` immediately after processing its
  welcome. In the interim mode this is unconditional (all bootstraps are signed-prekey-only); once OPKs
  land, it remains mandatory for any admission whose bootstrap was signed-only or possibly reused
  (Marmot's rule, adapted). The update fully heals the weaker bootstrap for everything that follows; the
  exposure window for the welcome itself is the signed-prekey lifetime.
- **Replay defense**: the ordering layer's MessageID dedup and per-instance welcome-once rule
  (ordering-auth §6) reject re-injected bootstrap messages at the protocol layer even where X3DH-level
  replay is possible.
- The `retry-signed-only` signal is reserved for the OPK layer (a receiver detecting a consumed one-time
  secret fails the X3DH and directs the initiator to signed-only mode); interim initiators are always in
  that mode already. Initiators MUST support bundles with no one-time component — in the interim, all of
  them.

### 5.2 Post-quantum hybrid reservation (phase-1 reservation, 2026-07-20)

v1 is classical (X25519 throughout), but the layout leaves the hybrid door open at zero cost: the X3DH
KDF reserves a trailing `KEM_ss` input slot (wire-format §5) for an ML-KEM-768 encapsulated secret
(PQXDH-style), and the `at.atsms.prekey` record will gain a `suites` hook when hybrid lands (its KEM
prekey addition belongs to identity-devices §4.2). Rationale and sequencing in overview §6.12: 2SM/X3DH
is the harvest-now-decrypt-later funnel — the *entire* asymmetric confidentiality surface of the
protocol — so the hybrid upgrade applies here (and to `sealed-asym` envelopes) and nowhere else. Since
D10 both surfaces share the `signedPrekey`, so the bundle's future hybrid KEM prekey serves the X3DH
`KEM_ss` slot and the envelope `suite` upgrade together — one record addition, two consumers.
Implementations MUST keep PKE/KEM calls behind the injectable `Kem`/`CryptoProvider` seam so the upgrade
is a provider swap.

## 6. Storage bound (cross-layer ack optimization)

`mySks` would grow with unacknowledged sends. Bound it via the paper's App. D observation: 2SM payloads
carrying a DCGKA operation are proven delivered by that operation's **ack** — on processing member `M`'s
ack for op `O`, prune all `mySks` indices for the `M`-session that were superseded at or before `O`'s send.
Per-peer key count is thus bounded by that peer's outstanding unacked operations (same silent-member bound,
same surfacing, as dcgka-core §5/§8).

## 7. Documented caveats (accepted, from the paper)

- **Bad-randomness fragility** (Remark 11): a leaked `Send` coin partially compromises *both* parties (the
  sender generates the peer's next key). Jost et al.'s hardening doesn't port to X25519; mitigation is a
  CSPRNG requirement plus the injectable-RNG test seam — not a protocol change.
- **No post-impersonation security**: authenticity is the ordering layer's job (ordering-auth §5); 2SM
  ciphertexts are not independently signed.
- **Security bound**: ε₂sm = 2q·ε_pke (Theorem 10) with HPKE Base as the PKE.

## 8. Sizes (informative)

Steady-state 2SM direct message ≈ 200–300 bytes (32 B KEM output + sealed tuple + 16 B tag + CBOR); X3DH
first message adds ephemeral/identity refs and prekey ids. At n = 150, one DCGKA update's 2SM fan-out
≈ 35–45 kB total — matching the paper's measured envelope and our G16 budget.

## 9. Test obligations

1. **App. B game tests**: per-message FS (compromise after delivery reveals nothing prior) and PCS (one
   delivered message post-compromise heals), incl. the `2SM-safe` boundary cases.
2. **Differential oracle**: seeded p2panda `two_party` transcripts, byte-compared modulo documented
   deviations (our HPKE info strings, ECDSA-P256 bundle signatures).
3. **Key-hygiene properties**: `mySks[i ≤ used]` deleted on receive; `peerNewSk` never persisted by sender;
   no state change on failed open; §6 pruning exactness.
4. **Bootstrap vectors**: X3DH with/without one-time; reuse → `retry-signed-only` → post-join update
   healing; expired bundle rejection; bad bundle signature rejection.

## 10. Open questions (tracked for review)

- ~~Signed-prekey cadence & grace window~~ **decided 2026-07-16**: weekly rotation; grace = one full
  rotation period — device retains current \+ previous secret (§5.0). The earlier OPK placeholder constants
  (batch 20, daily replacement) travel with the deferred OPK design (§5.0.1).
- **`retry-signed-only` placement — OPEN; revisit together with the OPK design** (only the OPK layer ever
  emits this signal). Trade-offs recorded 2026-07-16 so the discussion needn't restart:
  - *Scenario*: initiator's X3DH used an OPK whose private half the receiver no longer holds → the first
    message is undecryptable and **no 2SM session exists**; the receiver (who still learned and verified
    the sender's identity via the sealed envelope \+ ordering-layer signature) must reply "redo the
    bootstrap signed-only."
  - **(A) 2SM-level frame**: keeps failure semantics inside the 2SM spec, but the NACK cannot be
    session-encrypted (no session), breaking 2SM's every-frame-is-a-rotation-ciphertext invariant — and it
    MUST be authenticated or it becomes a **downgrade attack** (anyone could inject "retry signed-only" to
    strip OPK protection), which drags ordering-layer signature/dedup machinery into the crypto module.
  - **(B) ordering-layer `repair`-class frame** *(recommended)*: authentication and dedup come free (all
    ordering frames are signed); recovery inherently *is* a resend — the failed message carried a DCGKA
    welcome/seed that must be re-sent under the new handshake, which is exactly the repair class's job;
    cost is one opaque reason code crossing the layer boundary. Also preserves the p2panda module split,
    keeping the differential-test oracle clean.
- ~~`inviteAddress` placement/updates~~ **resolved 2026-07-16** — moved to the `at.atsms.x509` endpoint
  record (spec v1.1 §4.1); updates are ordinary record updates there.
- ~~Per-group vs shared sessions~~ **made explicit 2026-07-20**: strictly per-group (§1).
- ~~PQ posture~~ **decided 2026-07-20**: classical v1 with the §5.2 reservations; hybrid
  X25519+ML-KEM-768 on the bootstrap surface in phase 2, before v1 alpha carries real user traffic.
