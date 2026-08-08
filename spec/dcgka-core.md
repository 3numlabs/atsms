# spec/dcgka-core.md — DCGKA State Machine & Key Schedule

> ## ⚠️ SUPERSEDED (2026-07-22, decision D11) by [`beekem-core.md`](./beekem-core.md)
> The CGKA core is now BeeKEM (concurrent TreeKEM, Ink & Switch — [`../docs/history/beekem-analysis.md`](../docs/history/beekem-analysis.md)).
> This document is retained as the design record of the Weidner-DCGKA phase (through D10): the
> acks-are-PCS mechanism, the outer/inner two-ratchet schedule, and the 2SM seed fan-out it
> specifies are no longer part of the protocol. Constructions that survived — the per-sender
> FS-AEAD application ratchet (§7), the state-mutation discipline (§9), and the skipped-key
> constants — were carried into beekem-core.md §7–§9. Do not implement from this document.

> **Status: DRAFT v0.1 (2026-07-15) — for review.** [Protocol] · Phase 0 deliverable.
> Closes gaps **G2** (ack lifecycle), **G3** (application ratchet), **G7** (welcome contents/compaction),
> **G11** (concurrency mitigations), **G15** (storage/GC) from [`../docs/history/gap-analysis.md`](../docs/history/gap-analysis.md).
> Inputs: DCGKA paper §4–§6 + Fig. 4 (eprint 2020/1281, May 2021 revision), p2panda-encryption
> `message_scheme` (porting reference & differential-test oracle, see
> [`../docs/history/p2panda-analysis.md`](../docs/history/p2panda-analysis.md)), [`dgm.md`](./dgm.md), [`ordering-auth.md`](./ordering-auth.md).
> The ordering layer feeds this machine only **ready, authenticated, deduplicated** messages; the DGM supplies
> `members_view`. MUST/SHOULD/MAY per RFC 2119.

## 1. Two-layer key schedule (overview)

- **Outer ratchet** — one PRF-PRNG chain **per member**, advanced by that member's *update secrets*. An
  update secret for member `M` is produced when `M` initiates create/update/remove (immediately, from the
  seed) or when `M`'s **ack** of someone else's operation is processed (from `M`'s member secret). This is
  why acks are load-bearing (§5).
- **Inner ratchet** — per-sender forward-secure AEAD chain (§7), reseeded by each of that sender's update
  secrets. Application messages are encrypted here; one ciphertext per message, identical for all members.

## 2. State (γ, per device per group)

```
γ = {
  myId:            Membership,                    // (DeviceID, admittedBy) — dgm.md §2
  groupId:         MessageID,                     // ordering-auth §2.1
  dgmState,                                       // processed DGM state (dgm.md §6)
  twoParty:        Map<Membership, TwoPartyState>,  // 2sm.md — one channel per peer
  memberSecret:    Map<(Membership sender, OpID, Membership), bytes32>,
  ratchet:         Map<Membership, bytes32>,      // outer chain state per member
  nextSeed:        bytes32 | ⊥,                   // pending seed for own unbroadcast op
  send:            SenderRatchetState,            // own inner sending chain (§7)
  recv:            Map<Membership, ReceiverRatchetState>,  // inner receive chains + skipped keys
  retained:        processed signed messages until acked-by-all (repair store, ordering-auth §8)
}
```

All of γ is serializable, encrypted at rest, and mutated **copy-on-success only** (§9).

## 3. Key schedule — byte-exact domain separation

All derivations are **HKDF-SHA256**; `Expand(ikm, info, 32)` means HKDF-Extract(salt = 32 zero bytes, ikm)
then HKDF-Expand with the given `info`. `enc(x)` = deterministic CBOR per `wire-format.md`. All info strings
are ASCII, prefixed `atsms-dcgka:v1:`.

| Value | Derivation |
|---|---|
| member secret for `ID` from seed `s` of op `(sender, opId)` | `Expand(s, "atsms-dcgka:v1:member" ‖ enc(ID))` |
| sender's own member secret | same formula with `ID = sender` |
| outer-ratchet step | `updateSecret = Expand(chain ‖ input, "atsms-dcgka:v1:update")`; `chain' = Expand(chain ‖ input, "atsms-dcgka:v1:chain")` (initial `chain` = 32 zero bytes) |
| welcome constant | outer-ratchet `input = "atsms-dcgka:v1:welcome"` |
| add constant | outer-ratchet `input = "atsms-dcgka:v1:add"` |
| inner chain step | `msgKey = Expand(ck, "atsms-dcgka:v1:msgkey")`; `nonce = Expand(ck, "atsms-dcgka:v1:nonce")[0..12]`; `ck' = Expand(ck, "atsms-dcgka:v1:next")` |
| sealed-sym envelope key (per sender-epoch) | `envKey = Expand(updateSecret, "atsms-seal:v1:sym")` (consumed by sealed-sender.md §11; registered in wire-format §7) |

AEAD is **ChaCha20-Poly1305**. Seeds are 32 bytes from a CSPRNG (injectable for deterministic tests —
required by the differential oracle, §11).

## 4. Operations & handlers (semantics)

The algorithm set follows paper Fig. 4 exactly except where a **[deviation]** is marked; deviations are
adopted from p2panda (validated design) or from our layering.

- `create(initialMembers)` → control `create` + per-recipient 2SM direct messages carrying the seed; caller
  ratchets own chain with own member secret → own update secret. **[deviation]** operation IDs are the
  ordering layer's MessageIDs; the state machine never mints IDs (host-supplied, split
  local-op/process-local as in p2panda).
- `update()` / `remove(membership)` → control message + seed 2SM-encrypted to each member of
  `members_view(self)` minus self (and minus the removed member for `remove`).
- `add(deviceID)` → control `add` to the group (the new Membership derives from this op — dgm.md §2) +
  **welcome** to the new member containing: (i) the adder's
  **processed DGM state** incl. op/ack history sufficient for per-member `members_view` (dgm.md §6)
  **[deviation** from the paper's raw-history welcome — this is the G7 compaction**]**, and (ii) the adder's
  outer-ratchet states, 2SM-encrypted. Existing members process `add` by ratcheting the adder's chain twice
  (`welcome` then `add` constants — the first output becomes the new member's initial member secret, the
  second the adder's update secret), then broadcast `add-ack` carrying their own ratchet state 2SM-encrypted
  to the joiner.
- `process(msg)` dispatches on `{create, ack, update, remove, add, add-ack}` per the paper's six handlers,
  with `process-seed`/`process-welcome` helpers. **Normative fix**: in `process-ack`, the acked op is
  recorded into the DGM when it is an add **OR** a remove (the p2panda port's `&&` at `dcgka.rs:359` is a
  known bug — our differential tests exclude that branch from oracle comparison and assert OR behavior).
- **Concurrent-add forwarding** (paper §6.2.5): a member that processed `add(D)` before an update/remove
  from `A` (whose seed did not include `D`) MUST attach its own member secret for that op, 2SM-encrypted to
  `D`, to its ack (`Forward` direct message); `process-ack` consumes forwards when the local member secret
  is absent.

## 5. Ack lifecycle (normative — the PCS mechanism, G2)

- Every member MUST broadcast an `ack` for every processed `create`/`update`/`remove` (and `add-ack` for
  every `add`). Acks are **not optional and not merely causal metadata**: member `X`'s outer chain advances
  — for everyone, including `X` — only when `X`'s ack is processed.
- **Timing**: while online, an ack MUST be sent within `T_ACK = 60 s` of processing; a device coming online
  MUST flush pending acks before sending application messages. Acks MAY be **batched** (one frame acking
  several ops) and MAY be **piggybacked** as an attachment field on any outgoing frame of the same group
  (paper §8.1 permits deferral without weakening security; piggybacking also blunts the ack-storm traffic
  signature — see `sealed-sender.md` padding).
- **On processing an ack**: consume (and **delete**) the stored `memberSecret[op, ackSender]` (or a
  `Forward`), ratchet the ack sender's outer chain → their update secret → reseed their inner receive chain.
- **GC coupling**: member secrets and 2SM keys held for a member are prunable only as that member's acks
  arrive (§8); a silent member therefore blocks both healing and GC — surfaced via ordering-auth §9, acted
  on via dgm.md §7. There is no protocol-level timeout that forges or waives an ack.

## 6. Welcome contents & history compaction (G7)

The welcome carries: `groupId`, the add OpID (the joiner's `admittedBy`), processed DGM state (validated by
the joiner against op signatures — never trusted blindly), the adder's outer-ratchet map, and the delivery
map (`Membership → destination`, spec v1.1 §7). It does **not** carry raw control-message history; the
DGM-state form is O(current members + unpruned ops). Members MUST prune membership ops from retained history
once acked-by-all (paper §10); the digest mechanism (dgm.md §8) detects divergence that pruning could
otherwise mask. In-group metadata disclosure (who added/removed whom) is accepted and documented — sealed
sender protects against outsiders, not members.

## 7. Application-message ratchet (G3)

Per-sender **symmetric FS-AEAD chains** (sender-keys style — *not* a Double Ratchet; there is no pairwise DH
partner in group fan-out):

- **Epochs & anchors (decided 2026-07-16, confirmed against p2panda)**: an **epoch anchor** is the control
  op that last (re)seeded a member's sending chain — `create`/`add` count uniformly (a founding member's
  first anchor is the `create`; a joiner's is the `add` that admitted it), so no message ever lacks one.
  Anchors are **per-member per-chain**, never a group-global epoch number: each member's chain advances on
  its own schedule (yours reseeds when your ack is processed), so two members' concurrent messages may
  legitimately cite different anchors — that is how per-sender ratchets work, not a conflict, and it is what
  lets us avoid the global linearization we rejected MLS to escape. The anchor is expressed **only as the
  ordering-layer dependency** of an epoch's first app message (ordering-auth §3), **not** carried in the
  message content or AEAD: the per-epoch message key already binds the epoch cryptographically (a ciphertext
  decrypts under exactly one epoch's ratchet — wrong epoch → wrong key → AEAD fail), so an in-payload anchor
  would be redundant and would diverge from the p2panda oracle's `(ciphertext, generation)` wire shape.
- Sender: on each new own update secret, reseed `send.ck` (generation resets to 0); per message: derive
  `msgKey`/`nonce` (§3), encrypt with AD = `enc(groupId ‖ senderMembership ‖ generation)` (sender/epoch/
  position are already pinned by the per-sender, per-epoch key + generation-derived nonce; the AD is
  defense-in-depth, not the epoch binding), increment generation, **delete** `msgKey` and the pre-step `ck`
  immediately (forward secrecy is a deletion discipline, not just a derivation).
- Receiver: one chain per (sender, epoch), located by sender then indexed by generation. Out-of-order
  handling via a **skipped-key store**:
  `OUT_OF_ORDER_TOLERANCE = 100` (max backward gap), `MAX_FORWARD_DISTANCE = 1000` (max fast-forward),
  `MAX_SKIPPED_TOTAL = 2000` per group (global DoS cap) — constants adopted from p2panda `GroupConfig` +
  monorepo hardening. Each skipped key is single-use; reuse is an error (`SecretReuse`); skipped keys are
  deleted on use and expire with their epoch once the sender's next epoch is fully caught up.

## 8. Storage & GC (G15)

| Item | Bound / prune rule |
|---|---|
| `memberSecret` entries | deleted when the corresponding ack/forward is consumed (§5); count bounded by (outstanding ops × silent members) — surfaced, not silently capped |
| 2SM states | per-peer key lists pruned via the **cross-layer ack optimization** (a DCGKA ack proves receipt of the 2SM keys carried in that op — paper App. D; details in [`2sm.md`](./2sm.md) §6) |
| retained signed messages (repair store) | until acked-by-all, then pruned with membership-op history (§6) |
| skipped message keys | §7 caps; epoch-expiry |
| outer/inner chain states | O(members); old inner receive chains deleted one epoch after superseded |

All persisted state is encrypted at rest; implementations MUST use best-effort explicit zeroization on
delete and document the JS-runtime limits honestly (GC'd memory cannot be reliably zeroed — accepted
consequence of D3; revisit if a Rust core lands).

## 9. State-mutation discipline (normative)

`process()` MUST NOT mutate persistent state before **all** verification of the message has succeeded
(ordering-layer signature checks are upstream; AEAD/2SM decryption and semantic validation happen here).
Implementations MUST process on a copy (or within a transaction) and commit only on success — a forged or
corrupt frame must not be able to advance chains, stuff skipped-key stores, or perturb DGM state. (Adopted
from the p2panda monorepo `// SECURITY:` fix; their mirror lacked it and was exploitable.)

## 10. Concurrency & healing rules (G11)

- **Dominating-update rule (normative)**: on observing (i) two concurrent `remove`s, (ii) concurrent
  `update`s where at least one sender is not self, or (iii) any retroactive invalidation by the DGM
  (dgm.md §5), a member MUST send its own `update` before its next application message. Rationale: paper
  App. C — concurrently removed members can collude on messages sent before a dominating operation exists;
  this rule manufactures the dominating operation at first opportunity.
- **Sender-view guarantee (documented)**: a sender always knows exactly which member set could decrypt each
  message (its own `members_view` at send time); clients SHOULD expose this in security-sensitive UX
  (e.g., "sent before Bob's removal was known").
- **Healing latency (documented)**: an update heals its sender immediately (own secret applied at once) but
  heals the *group's view of member X* only after X's ack round-trips — with offline members this is the
  dominant PCS latency, which is why stale-member surfacing (ordering-auth §9) is a security feature, not
  telemetry.

## 11. Test obligations

1. **Differential oracle**: seeded p2panda `message_scheme` runs generate transcripts (control messages,
   direct messages, update secrets, message keys) for scripted scenarios; the TS implementation MUST match
   byte-for-byte where our deviations don't apply, with deviation-affected fields excluded by an explicit
   allowlist (deviations: MessageID op-IDs, DGM-state welcomes, OR-fix in process-ack, domain-separation
   labels — for label differences the oracle comparison runs at the *structure* level, and our own frozen
   test vectors pin the bytes).
2. **FS/PCS game tests** translated from paper App. A/B definitions (compromise oracles, `dom-safe`
   predicate cases incl. the concurrent-remove collusion scenario and its §10 mitigation).
3. **§6.2.5 walkthrough vector** (the paper's concurrent add+update example, as p2panda's
   `concurrency.rs` does, quoted step-by-step).
4. **Ack-lifecycle properties**: no chain advance without ack; GC exactness (state size returns to baseline
   after full ack); piggyback/batch equivalence.
5. **Crash-consistency**: kill/restart between receive and commit at every step boundary — no divergence
   (§9 discipline).

## 12. Open questions (tracked for review)

- ~~`T_ACK` and the §7/§8 constants~~ **decided 2026-07-16**: all defaults accepted (see
  [`parameters.md`](./parameters.md)).
- ~~Piggybacked-ack packaging~~ **decided 2026-07-16: attachment-only** — the ack is a sibling field in the
  signed frame bytes, never inside the app-ratchet ciphertext; one ratchet index = one app message always;
  avoids cross-plane hostage-taking (an ack must be processable under control-plane readiness even when the
  app payload's epoch anchor hasn't arrived).
- ~~Epoch anchor / create edge~~ **decided 2026-07-16**: `create`/`add` are uniform per-member epoch
  anchors; the anchor is an ordering-layer dependency only, not an AEAD field (the per-epoch key already
  binds the epoch); AD reduced to `groupId ‖ senderMemberID ‖ generation` (§7). Confirmed against p2panda,
  which carries only `(ciphertext, generation)` and resolves the epoch via out-of-band ratchet state.
