# spec/review-scope.md — what an external security review should focus on

> **Living document.** External cryptographic review is a **gating requirement** before v1 alpha carries
> real traffic (implementation-plan §9, Phase 6 / G18). This is the brief: what we believe is novel, what
> we know is unfinished, and the specific questions we want answered. Add to it whenever a design decision
> creates a new question — that is cheaper than reconstructing the reasoning at review time.
>
> Companion documents: [`../KNOWN-ISSUES.md`](../KNOWN-ISSUES.md) (findings from live testing, numbered
> and referenced below), [`loss-and-reordering.md`](./loss-and-reordering.md) (what survives a lossy
> network), and the spec set in this directory.

## 1. Where the value is highest

**The composition is the novel part, not the pieces.** BeeKEM comes from Ink & Switch, the DCGKA proof
obligations from Weidner et al. (CCS 2021), strong remove from p2panda-auth. What no prior work analyses
is **sealed sender × concurrent DCGKA × a DGM acting as the tree's validity filter**. Effort spent on the
seams between those will find more than effort spent re-checking any one of them.

**BeeKEM has no formal proof.** Our mitigations are a differential oracle (below the `PcsKey` boundary our
TypeScript must be byte-equivalent to the Rust `beekem` crate) and a convergence fuzz harness. Neither is
a proof, and we do not claim otherwise.

**The DGM validity filter is the primary trust boundary.** Every membership and key operation touches the
tree only if the DGM judges it valid at its position in the causal history. Getting an invalid op to
mutate the tree, or a valid op to be filtered out, breaks convergence or authorization outright.

## 2. Malicious insider — the standing focus

Treat a **validly-admitted member running modified client code** as a first-class adversary, not an edge
case. Enumerate how it could: (a) defeat the DGM validity filter in either direction; (b) force
cross-member divergence or break convergence; (c) equivocate, presenting divergent key material or op
histories to different members; (d) escalate its role or authorization; (e) exhaust resources or stall
garbage collection.

## 3. Specific questions, by area

### 3.1 Admission material and re-invitation (`ordering-auth.md` §8.2, built 2026-08-06)

Any member — not only the original adder — may rebuild a joiner's welcome from its retained control log
and send it. This widened a surface that already existed for the adder, and we would like it examined:

- **Selective omission at admission.** A welcome is the rebuilder's control-frame log. A malicious
  rebuilder cannot forge frames (they are signed by their authors), but it can **omit** them — dropping a
  `remove` so the joiner believes an evicted device is still a member, or an admin grant so it
  misjudges authorization. The joiner has no independent frontier to check the log against. How bad is
  this, and what is the cheapest sound defence (a signed frontier commitment in the `add`? a
  post-join reconciliation obligation)?
- **Divergent `admittedBy` under concurrency.** A re-invitation pins to the rebuilder's view of the
  member's admission. If views differ, the joiner gets a membership identity some members do not
  recognise. We expect this heals as the views converge; confirm it cannot be steered into a stable split.
- **Replay of admission material.** A re-sent `create` is a byte-identical replay of a signed frame,
  deliberately. What can an adversary do by replaying admission material at a device whose state has
  changed since — a removed device, or one that has deleted its local state?
- **Amplification and unwanted contact.** Re-invitations are addressed to a target's *public* inbox, and
  any member can emit them. This is a channel by which a member can generate traffic toward someone who
  has stopped answering — including someone who deliberately refused. Where should the bound live: the
  protocol, the relay, or the recipient's admission policy?

### 3.2 The deliberate ambiguity of silence

Nothing at this layer is acknowledged (security properties attach to processing, not to acks), so a lost
invitation, a member who is simply quiet, and a member who **refused** are indistinguishable. We treat
that indistinguishability as a **required privacy property**, since recipient-side admission control
depends on refusal being unobservable. Review question: does anything else in the composition leak the
difference — timing, an automatic protocol reaction, relay-visible behaviour, or a state change a peer
can probe for?

### 3.3 Forward secrecy as implemented, not as specified

**KNOWN-ISSUES 9.** Retained frames are never evicted and nothing calls epoch eviction, so the retention
rules the spec states (covered-by-all, or 30 days) are not enforced anywhere. Old epoch keys stay live.
A claimed property that no code enforces is exactly what a review should catch — please assess it as
built, and tell us what the eviction discipline must actually be.

### 3.4 Delivery, durability and what that costs

- **Ack-before-durable** (KNOWN-ISSUES 3, 8): the transport deletes an envelope from the relay once the
  dispatcher has looked at it, and sealed sender makes "not mine" and "not mine *yet*" indistinguishable,
  so material we could not yet use is discarded. What are the security consequences of the alternatives?
- **Application-message loss** (KNOWN-ISSUES 6): the recovery design (§8.1) has any member serving a
  missing message, which is sound only because the inner ciphertext is identical for every recipient.
  Please check that reasoning before we build on it.

### 3.5 Metadata

Sealed sender hides the sender and the message class; the relay sees destination, arrival time, and a
padded size bucket. Public `at.atsms.inbox` carries first contact only; ongoing endpoints are advertised
in-band. Review the residual correlation surface — bucket boundaries, fan-out patterns per DID, the PDS
read a sender performs before it can seal, and prekey-record lookups.

One asymmetry we want assessed explicitly. An **asym** envelope names no recipient at all (HPKE names
none), so a mailbox holder cannot separate one destination's traffic by device. A **sym** envelope carries
a per-recipient hint tag which is deliberately different per mailbox — defeating cross-mailbox group-graph
reconstruction, §11.3 — but is **stable for a given (epoch, sender, recipient)**. So a relay holding one
DID's mailbox can partition that traffic into per-device streams within an epoch, learning device count
and per-device volume without learning identities, with the partition resetting on each re-key. Is that
residual leak acceptable at the stated threat model, and if not, what is the cheapest fix — per-message
tag derivation, or tag rotation decoupled from epoch rotation?

### 3.6 Concurrency findings already surfaced

KNOWN-ISSUES 1 (concurrent-update epoch divergence, fixed via the sealable-epoch predicate — see
[`concurrent-update-partition.md`](./concurrent-update-partition.md)) is the shape of bug this composition
produces. It was found live, not by the fuzz harness, which is itself worth a comment: what class of
schedule would the harness need to have caught it?

## 4. What we are not asking

Not a review of the primitives themselves (X25519, XChaCha20-Poly1305, P-256 ECDSA, HPKE, BLAKE3) beyond
their composition and domain separation; and not MLS-class scale work — the O(n), n ≤ 128-device design
point is deliberate (implementation-plan §10).
