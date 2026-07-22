# spec/ordering-auth.md — Ordering & Authentication Layer (the ACB substitute)

> **Status: DRAFT v0.2 (2026-07-22) — for review.** *(v0.2: D11 — `ack` frame class retired
> (coverage replaces it, beekem-core §5); epoch anchor is now the establishing `update` op;
> retention re-based on covered-by-all. The layer's job is otherwise unchanged: BeeKEM assumes
> exactly the causal delivery this layer provides.)* [Protocol] · Phase 0 deliverable.
> Closes gaps **G4** (authenticated-causal-broadcast substitute) and **G12** (mailbox liveness/repair) from
> [`../gap-analysis.md`](../gap-analysis.md).
> Inputs: BeeKEM causal-delivery assumption (`beekem/src/cgka.rs` — "We assume that all operations are
> received in causal order"), Cremers et al. signing-key rotation, spec v1.1 §§4, 6, 7.
> This layer sits **below the BeeKEM core** (it feeds `process()` only ready, authenticated messages) and
> **above the sealed envelope** (all signatures live inside the seal). MUST/SHOULD/MAY per RFC 2119.

## 1. What this layer must supply (proof obligations)

The BeeKEM core assumes delivery that cannot forge, replay, or violate causal order of CGKA ops. This
layer MUST provide, per group:

- **A1 Authenticity**: every message verifiably authored by a current member, signature covering content
  *and* ordering metadata, with **PCS for the signing keys** (§5).
- **A2 Control-plane per-sender FIFO**: control-plane messages (`control`, `welcome`) from a member
  are processed in consecutive control-sequence (`ctrlSeq`) order. Application messages are **exempt**
  (§4.1): their out-of-order tolerance is the app ratchet's skipped-key window (beekem-core §7), so an
  app-message gap never head-of-line-blocks later traffic.
- **A3 Causal completeness for CGKA ops** *(replaced the referent-before-ack rule when acks were retired,
  D11)*: a CGKA op is ready only when every op named in its `deps` has been processed — BeeKEM's
  "operations received in causal order" precondition, verbatim.
- **A4 Welcome-first / add-ready**: a joiner processes its welcome before anything else; a *re-added* member
  additionally drains its prior-instance obligations (§4.3).
- **A5 No replay / no duplication**: each MessageID processed at most once.
- **A6 Membership gating**: messages from non-members (in the receiver's view) are rejected (§7).

Full causal order across different senders' **app traffic** is **not** required — except where §3 declares
explicit dependencies. Liveness is explicitly *not* guaranteed (untrusted transports can withhold);
withholding is surfaced (§9), never silently tolerated.

## 2. Message identity

- **Canonical bytes**: deterministic CBOR of
  `(version, groupId, sender: Membership, seq, deps: [MessageID], class, payload)` — field set frozen in
  [`wire-format.md`](./wire-format.md) §3 (which adds `ctrlSeq` and the signed `ext` attachment map).
- **Signature**: over the canonical bytes (§5). **MessageID = SHA-256 of (canonical bytes ‖ signature)** —
  content addressing makes causality metadata tamper-evident: you cannot alter `deps`/`seq` without changing
  every downstream reference.
- `class ∈ {control, welcome, app, repair}` *(the `ack` class was retired 2026-07-22 with D11;
  `coverage` is a `control` opType, wire-format §4.1)*. (The consistency digest is **not** a frame
  class — it rides as an optional signed field on any frame; dgm.md §8, decided 2026-07-16.)

### 2.1 GroupID bootstrap

The `create` message carries `groupId = 0`; **GroupID := MessageID(create)**. All subsequent messages carry
it. This yields the deterministic, content-derived conversation identity required by gap G10 (replacing
sender-chosen random convoIds).

## 3. Dependency rules (what `deps` MUST contain)

| Message class | Required `deps` |
|---|---|
| CGKA control (`create`/`add`/`remove`/`update`) | the sender's current **CGKA-op heads** (frontier of CGKA ops it has processed) — these are BeeKEM's op `predecessors` and the DAG the DGM evaluates; `update` heads additionally bind the path encryption to the tree state it was computed against (beekem-core §4.2 merge validity) |
| role control (`grant`/`revoke`) | sender's CGKA-op heads (role validity is evaluated at a causal position) |
| `coverage` (control opType) | sender's current CGKA-op heads — the deps **are** the payload (beekem-core §5) |
| `welcome` | the `add` op it fulfils |
| first `app` message of an epoch | the **`update` op that established the epoch** (`PcsKey_e`) — a **dedicated single-anchor dep** (see note) |
| subsequent `app` messages | sender's previous `app` message (implied by generation; explicit dep OPTIONAL) |
| `repair` | none required |

Per-sender FIFO (`ctrlSeq`) is implicit in every control-plane row. Anything beyond these rules MAY be added
by implementations but MUST NOT be required for readiness (keeps buffering bounded).

**Epoch-anchor dep (decided 2026-07-16; re-based 2026-07-22)**: the anchor is a **dedicated field** naming
exactly the epoch's establishing `update` op. It lives here (ordering layer) and **only** here — never in
the app message content or AEAD (the per-epoch key already binds the epoch; beekem-core §7). Under BeeKEM
only `update` ops are valid anchors: `create`/`add`/`remove` blank the root and cannot establish a
sendable epoch (beekem-core §10's update-first rule guarantees an anchor always exists before app traffic).

## 4. Readiness predicates & buffering

### 4.1 Ready(m)

Readiness is class-scoped (`seq` remains one per-sender counter across all classes for signature coverage
and replay; control-plane frames additionally carry `ctrlSeq`, consecutively numbering that sender's
control-plane frames):

- **Control-plane frame** (`control`/`welcome`): ready iff `m.ctrlSeq == lastCtrlSeq(S) + 1` (A2),
  every `m.deps` MessageID has been processed (A3 + §3), and the receiver has processed its own welcome
  (A4).
- **Application frame**: ready iff its **epoch-anchor dep** has been processed (§3) and A4 holds — nothing
  else. It is then handed to the app ratchet, which tolerates within-epoch gaps up to
  `OUT_OF_ORDER_TOLERANCE` via the skipped-key store (beekem-core §7); the ordering buffer parks app frames
  only while their epoch anchor is missing.

`process()` drains the buffer to a fixpoint after each newly ready message.

### 4.2 Welcome handling (joiner)

On receiving its `welcome`: validate the embedded DGM state (signatures on ops — dgm.md §6), process it,
then: membership/control messages **concurrent with the add** → buffer and process normally; `app` messages
the joiner is not entitled to (sent under secrets from before its admission) → **discard silently** (they
are not addressed to it under the sender's view; cf. paper's `should-decrypt`).

### 4.3 Add-ready (re-adds)

For a re-added member (same device, fresh Membership): senders MUST NOT address the new Membership until
they have processed the `add`; the re-added member MUST discard anything addressed to its *old* Membership
(old-tenure state was deleted — spec v1.1 §4). The welcome's dep on the `add` op plus Membership-scoped
addressing makes the paper's footnote-4 vector-clock check unnecessary: tenure separation is by identity,
not by counter.

### 4.4 Bounds (DoS)

Per group: `MAX_BUFFERED_PER_SENDER = 200`, `MAX_BUFFERED_TOTAL = 2000` (defaults; SHOULD be configurable).
On overflow: drop newest from the largest per-sender queue and issue a `repair` request (§8) — never drop a
ready message. A message unresolvable for `T_REPAIR_GIVEUP = 30 d` MAY be dropped with a surfaced warning.

## 5. Authentication & signing-key rotation

- **Anchor**: each member's initial **protocol signing key** is declared in the `create`/`welcome` material,
  signed by the device identity key (endpoint cert, spec v1.1 §4.1) — chaining protocol authentication to
  the DID via `DID → verificationKey → at.atsms.x509/<fingerprint> → device key → protocol signing key`.
  The device identity key itself is NOT used per-message (its exposure profile is different, and rotation
  must be cheap).
- **Rotation (PCS for authenticity, Cremers et al.)**: every `update`, `remove`, and `create` the member
  sends includes `nextSigningPubKey`, covered by the current signature. The new key takes effect for that
  sender's messages with **higher `seq`**; the old key is deleted after the rotation message is processed.
  Verifiers maintain `member → (currentKey, effectiveSeq)`; FIFO (A2) makes the handoff unambiguous.
- **Verification**: reject on any failure — wrong key for `seq` range, bad signature, unknown member. A
  rejected message is dropped (not buffered) and counted (§9 telemetry); it MUST NOT advance any state
  (never-mutate-before-verification rule, adopted from the p2panda monorepo fix).
- **Limits (documented, not solved)**: no post-impersonation security — an attacker holding a member's
  current state can sign as it until that member's next processed rotation; and it can suppress the victim's
  updates only via transport withholding, which §9 surfaces.

## 6. Replay & duplicate suppression (A5)

- Processed MessageIDs are recorded per group; duplicates are acknowledged to the transport (if pull-based,
  deletable) and dropped. The seen-set is prunable to `(sender, lastSeq)` watermarks once messages are
  covered-by-all (GC rules in `beekem-core.md` §8, gap G15).
- `groupId` inside the signed bytes prevents cross-group replay; `seq` monotonicity prevents in-group
  re-injection; a `welcome` is processed at most once per Membership.

## 7. Membership gating & the removed-member race (A6)

- Accept a message only if its sender is a member in `members_view(receiver)` **at the message's causal
  position**: messages authored causally *before* the sender's removal (per `deps`/seq) are processed;
  anything by that member after the receiver has processed its removal, and not causally prior to it, is
  rejected. This implements the paper's §2.1 semantics: a removed member can race messages only to peers
  that have not yet processed the removal, and a sender always knows exactly who could decrypt what it sent.
- Messages from wholly unknown Memberships: buffer briefly (they may precede a not-yet-processed `add`,
  bounded by §4.4), else drop.

## 8. Gap detection & repair (G12)

- **Detection**: a control-plane `ctrlSeq` gap, an app-ratchet index gap, or an unresolved dep older than
  `T_REPAIR = 60 s` (online) / on next connect (offline) triggers repair. (Control gaps are the urgent
  case — they stall that sender's group-state progress; app gaps only leave a "message pending" hole while
  later traffic flows.)
- **`repair` request**: sealed direct message to the original sender listing missing `(sender, seq)` ranges
  and/or MessageIDs; if unanswered for `T_REPAIR_FALLBACK = 24 h`, sent to any other member (all members
  store the signed messages they have processed until covered-by-all — the same retention the core's GC
  needs, beekem-core §8, so repair adds no new storage class).
- **Response**: re-send the original sealed envelopes (signatures make them self-authenticating; A5 dedups).
- **Transport note**: repair is end-to-end and transport-agnostic — it works identically over the baseline
  HTTPS mailbox, WebSocket, or P2P paths (spec v1.1 §7), and is the *only* liveness mechanism this spec
  assumes.
- **Non-normative optimization (decided 2026-07-16)**: baseline-profile mailbox providers MAY retain
  delivered envelopes (suggested 30 d, aligned with `T_REPAIR_GIVEUP`) so a client that lost local state
  can re-pull its own copies before issuing member repair requests — note each envelope is sealed
  per-recipient, so a relay can only ever re-serve a device's *own* copies; the group drop-point profile
  (spec v1.1 §9) has re-fetch inherently. Retention length is an operator policy trade-off (longer = more
  provider-side correlation surface); protocol correctness never depends on it — member-served repair
  remains the only normative mechanism.

## 9. Stale-member surfacing

Track per member: last processed message time, oldest own-op not yet covered by them, count of epochs they
have not covered. SHOULD-thresholds: **warn** the application at 7 days silent, **alarm** at 30 days
(feeding the DGM eviction hook, dgm.md §7). Rationale: a silent member is a PCS hole (its own leaf never
rotates) and a state-GC blocker (coverage frontier stalls — beekem-core §5/§8), and a persistently
"losing" member may indicate transport withholding — the alarm text MUST distinguish "no messages from X"
from "X not covering" (different failure modes, same lever).

## 10. Test obligations

1. **Adversarial interleaving fuzz**: random drop/dup/reorder/delay over ≥ 32 members incl. joins,
   removes, re-adds; assert convergence, A1–A6, and bounded buffers.
2. **Rotation vectors**: signing-key handoff across seq boundaries, rotation concurrent with remove,
   rotation message lost-then-repaired.
3. **Removed-member race vectors**: race in both directions per §7.
4. **Repair protocol**: gap under every transport profile; fallback path; give-up surfacing.
5. **Differential**: causal-readiness decisions cross-checked against the `beekem` oracle's
   `merge_concurrent_operation` acceptance behavior (`OutOfOrderOperation` on missing predecessors —
   `cgka.rs`); divergences (welcome-first, add-ready, repair — all above the oracle's layer) are listed
   here as deliberate.

## 11. Open questions (tracked for review)

- ~~Buffer/timeout constants (§4.4, §8)~~ **decided 2026-07-16**: defaults accepted (see
  [`parameters.md`](./parameters.md)).
- ~~Digest packaging~~ **decided 2026-07-16**: piggyback as an optional signed field on **any** outgoing
  frame ("attach if last digest > 7 d"); no standalone digest frames (a quiet group must not emit a
  heartbeat traffic pattern); `digest` removed from the class enum; totally silent members are covered by
  the stale-member machinery, not the digest cadence.
- ~~Relay-served repair~~ **decided 2026-07-16**: member-served repair is the only normative mechanism;
  mailbox retention re-pull is a MAY optimization (§8 note).
- ~~Sender identity encoding~~ **decided 2026-07-17**: `sender` is a `Membership` (`DeviceID` +
  `admittedBy` — dgm.md §2); frame layout in wire-format.md §3.
