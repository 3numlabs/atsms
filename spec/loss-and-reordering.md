# spec/loss-and-reordering.md — what survives a lossy, re-ordering network

> **Status: survey of the built system, 2026-08-05.** Every message type the protocol sends, what happens
> when one is lost for good, what happens when one arrives out of order, and whether we recover. Read
> alongside [`ordering-auth.md`](./ordering-auth.md) (§4 buffering, §8 repair) — that document specifies the
> mechanisms; this one audits them against the implementation in `@atsms/dcgka` and its host `@atsms/client`.
> The four holes it identifies are filed as issues 5–8 in [`../KNOWN-ISSUES.md`](../KNOWN-ISSUES.md), and the
> forward-secrecy finding as issue 9. **Updated 2026-08-06:** first-contact recovery (issue 5) is now built —
> see [`ordering-auth.md` §8.2](./ordering-auth.md) — so the `create` and `welcome` entries below record
> both the loss and its recovery.

## Background — enough to read the rest

**Getting bytes across.** A device posts a **sealed envelope** to a relay, which holds it until the
recipient's device fetches it. The relay cannot read it and cannot tell which device it is really for, so it
hands every envelope posted to an account to *all* of that account's devices. The receiving device tries to
open each one; whatever it cannot open, it discards. A device fetches, processes, then tells the relay to
delete — so an envelope the receiver failed to make use of is normally gone from the relay too.

Envelopes come in two forms. **Asymmetric** envelopes are sealed to a device's published one-time key (its
*prekey*) and are how someone who is not yet in a conversation gets their first message — there is no shared
group key yet. **Symmetric** envelopes are sealed with a key every current member of the conversation holds,
and carry everything after that first contact.

**Inside the envelope is a frame.** A frame is a signed message with a class that says what it is:

- **control** — changes who is in the conversation or rotates its keys;
- **welcome** — the bundle that lets a newly added device build the conversation from scratch;
- **application** — an actual user message;
- **repair** — a request to re-send something that went missing.

**Epochs.** Every time the key material changes (someone joins, leaves, or refreshes), the conversation
enters a new **epoch**. Messages are encrypted under the epoch that was current when they were sent, so a
device that missed the change cannot read what follows until it catches up.

**Two ordering lanes.** Control frames carry a per-sender counter, `ctrlSeq`, and must be processed
strictly in order: a receiver holding frame 5 will not process frame 6 until 5 arrives, because group state
changes do not commute. Application and repair frames are deliberately exempt — they carry a sequence
number for reference but may be processed in any order, so one slow user message never stalls the group.

**How a gap is found and filled.** A frame that cannot be processed yet is **buffered**, either because a
frame it explicitly depends on has not arrived or because there is a hole in the sender's `ctrlSeq` run. If
a buffer still holds something 60 seconds later (`T_REPAIR`), the host asks the group to re-send it — a
**repair request** naming the missing message ids and `ctrlSeq` ranges. Every member keeps the signed frames
it has processed, so *any* member can answer, not just the original sender. Answers are the original signed
frames, so they authenticate themselves, and duplicates are ignored. This path is built and has been tested
live against the deployed relay by deliberately destroying a frame in transit.

---

## Message by message

### `create` — founds a conversation

*What it does.* The first frame. It names the founding devices and their keys, and its own id becomes the
conversation's id. It reaches the other party as an asymmetric envelope sealed to their prekey.

*If it is lost.* The recipient never learns the conversation exists. Nothing tells the sender: this layer has
no acknowledgements, by design — security properties are established when a message is *processed*, not when
it is acknowledged. Worse, the recipient cannot recover later on its own: any subsequent group traffic is a
symmetric envelope for a conversation it has never heard of, so it matches nothing, is discarded, and is
deleted from the relay. Repair cannot help — repair belongs to a conversation, and there is no conversation.
**Permanent and silent on both sides.**

*If it arrives out of order.* Not really possible to mis-order in a harmful way: it anchors everything else,
and any later frame depends on it and will wait. The damage is the case above — a recipient that has not
processed the `create` has nowhere to hold what arrives in the meantime.

*Recovery (built 2026-08-06, ordering-auth §8.2).* Any member can re-send the create — **the identical
frame**, because its id is the group id and a second one would found a second group. It is addressed to
that one member, sealed to their prekey, routed to their public inbox exactly as first contact was. The
detection signal is `pendingMembers()`: on the roster, never heard from. Catch-up then rides ordinary
repair, so nothing is bundled with it.

*Status:* **recoverable, by a human decision.** Detection stays inherently ambiguous — silence covers a
lost invitation, a quiet member, and a refusal alike (KNOWN-ISSUES 5).

### `welcome` — admits a new device

*What it does.* When someone is added, the adder sends them a welcome: the conversation's state and key
material, sealed to the joiner's prekey, so they can participate from the current epoch onward. Existing
members see the matching `add` control frame instead.

*If it is lost.* The joiner never joins. Everyone else believes they did — the `add` was processed, so the
group's view already contains them. Nothing is signalled, so the group's only clue is that they never
speak — see the recovery note below.

*If it arrives out of order.* Welcomes deliberately carry no `ctrlSeq` (fixed 2026-08-02 — they used to
consume one, which stalled every other member's control lane behind a frame only the joiner could see).
Traffic that arrives *before* the welcome is the problem: the joiner has no conversation yet, so those
envelopes match nothing and are discarded. Control frames come back later through repair; application
messages do not.

*Recovery (built 2026-08-06, ordering-auth §8.2).* A welcome is **rebuilt**, not re-sent — it is a state
snapshot with no dependents, so a fresh one is free and strictly better: it lands the joiner on the group's
current state rather than the state at the add. It must be pinned to the original `add` op, or the joiner
gets a membership identity nobody else recognizes. Any member can do it, not just the adder, so a group can
re-welcome someone after the adder has gone.

*Status:* **recoverable, by a human decision** — with the same ambiguity, and one hard bound: a joiner
whose prekey rotated past its grace window needs a fresh add, not a welcome (KNOWN-ISSUES 5).

### `add` — admits a member into everyone else's view

*What it does.* Tells existing members that a device has joined, along with the key material needed to
address it.

*If it is lost.* That member does not know the joiner exists and will not address it. The joiner's own
frames then arrive from an apparently unknown sender and are buffered rather than accepted. After
`T_REPAIR` the receiver asks for the missing frame by id, any member re-serves it, and the buffer drains.

*If it arrives out of order.* Buffered on its dependencies and its `ctrlSeq` position, processed when the
run is contiguous.

*Status:* **recovered**, exercised repeatedly in the membership-churn suite.

### `remove` — evicts a member

*What it does.* Removes a device and rotates the keys so the removed device cannot read anything further —
a *strong* remove. Notably, the removal frame is also addressed to the device being removed, so it learns of
its own eviction.

*If it is lost, at a remaining member.* Ordinary control-gap repair recovers it.

*If it is lost, at the removed device.* That device keeps believing it is a member and keeps sending.
Receivers refuse its application frames outright — a membership check that runs before decryption is even
attempted — and each refusal re-queues the removal frame back to it (on the first refusal, then every
eighth: enough to converge, bounded under a flood). Locally, the stranded device notices that nothing it
receives opens any more and, after a quiet period, surfaces a soft "you may have been removed" rather than
asserting it as fact.

*If it arrives out of order.* Strict `ctrlSeq` order; buffered until its turn.

*Status:* **recovered**, and self-healing — this was the 2026-08-03 strong-remove fix.

### `update` — rotates keys, opening a new epoch

*What it does.* Refreshes the conversation's key material, which is what gives the system its recovery
property after a device compromise. It also carries the sender's next signing key.

*If it is lost.* That member never derives the new epoch, so traffic sealed under it will not open; those
envelopes wait in a small in-memory holding area. It is discovered as soon as anyone speaks — application
frames name the epoch they were sent under as a dependency, so the missing `update` shows up as an
unresolved dependency and repair fetches it. Once processed, the waiting envelopes open on the next pass.

*If it arrives out of order.* Buffered like any control frame.

*Status:* **recovered — while somebody is talking.** In a group that has gone quiet there is no traffic to
reveal the hole, and the mechanism designed for exactly that case is not running (KNOWN-ISSUES 7).

### `grantAdmin` and other authorization ops

*What it does.* Changes who may act on others' behalf — adding or removing someone else's device requires
admin rights, while acting on your own devices does not.

*If it is lost.* No effect on decryption; only the authorization view diverges, so a member may reject an op
it would otherwise accept. It heals cleanly: authorization is recomputed over the whole set of known
operations every time one is ingested, so a grant that arrives late retroactively validates what depended on
it. Ordinary control-gap repair brings it in.

*If it arrives out of order.* Buffered by `ctrlSeq`; and per the above, order does not permanently colour the
outcome.

*Status:* **recovered**.

### `coverage` — the idle advert

*What it does.* Announces what a device has seen — its current frontier plus a digest — so peers can notice
that they are missing something and that everyone's view agrees.

*If it is lost.* Nothing breaks; it carries no state of its own. It occupies a `ctrlSeq` slot, so its own
loss is repaired like any control frame.

*If it arrives out of order.* Harmless.

*Status:* implemented in the engine, **never sent** — nothing in the host schedules it (KNOWN-ISSUES 7).

### Application messages — the actual conversation

*What it does.* Carries user content, encrypted under a per-sender, per-epoch ratchet and numbered by a
*generation* counter that advances with each message.

*If it is lost.* Nothing asks for it back. Two shapes, and only one is even visible locally:
an **interior gap** (message 5 arrived, message 4 never did) is detectable, because the receiver keeps the
skipped keys and can see the hole — but no request is issued for it; a **trailing gap** (the sender sent
three more and went quiet) is **undiscoverable**, because nothing advertises how many messages exist.
**Permanently and silently lost**, on both ends.

*If it arrives out of order.* Handled well, and passively: the receiver keeps keys for messages it has
skipped, so a late one still decrypts when it turns up. Application frames are exempt from the control
ordering rule precisely so a slow message cannot stall group state.

*Status:* reordering **met**; loss recovery is **specified and unbuilt** (ordering-auth §8.1, KNOWN-ISSUES 6).

### Repair requests and responses

*What it does.* A request names missing message ids and `ctrlSeq` ranges; any member that holds those frames
re-sends them as-is.

*If a request is lost.* The host re-issues it every window while the gap persists, and requests go to all
members, so losing one copy costs nothing.

*If a response is lost.* The next window asks again. Responses are the original signed frames, addressed by
content, so duplicates are harmless and any member is as good as any other.

*If either arrives out of order.* Irrelevant — requests are stateless and idempotent, responses are
content-addressed.

*Status:* **solid**, and verified end to end against the live relay.

### One-shot messages (the X509 baseline)

*What it does.* A standalone signed-and-encrypted message to a device that is not part of a conversation —
the deliberate "certified mail" surface, and the way to reach peers that do not speak the advanced tier.

*If it is lost.* Gone. No retry, no acknowledgement, by design.

*If it arrives out of order.* Independent of everything; order is meaningless here.

*Status:* by design — though the *sender* gets no signal either, which is worth revisiting for a surface
whose whole point is that the message mattered.

---

## Three things that cut across every type

**Deleting before we have really used it.** The transport hands an envelope to the dispatcher and then tells
the relay to delete it. The dispatcher swallows anything it cannot use — an envelope for an epoch we have
not derived, or for a conversation we have not bootstrapped — so "cannot use *yet*" and "not ours" are
treated identically, and the relay's copy goes either way. Sealed sender is what makes them
indistinguishable: we genuinely cannot tell. This is the durability half of KNOWN-ISSUES 3.

**A restart erases the evidence of a gap.** What we persist is the retained frame log, the secrets and the
counters — deliberately not the buffer of frames waiting on a hole, nor the envelopes waiting for an epoch.
Those envelopes are already deleted at the relay, so after a restart both the data and the *knowledge that
something is missing* are gone: the buffer is empty, so repair never fires. The hole resurfaces only if new
traffic happens to depend on the missing operation (KNOWN-ISSUES 8).

**Nothing is ever discarded, so forward secrecy is not actually enforced.** Retained frames are never
evicted, and nothing calls the engine's epoch eviction. The specified rules — keep until everyone has
covered it, or 30 days — are not implemented. Storage growing without bound is the visible symptom; the
real cost is that old epoch keys stay live, so the forward-secrecy window the spec describes never closes
(KNOWN-ISSUES 9).

---

## Summary

| Message | Lost forever | Out of order | Where it stands |
|---|---|---|---|
| `create` | recipient never learns of the conversation; no signal either side | anchors everything; the damage is having nowhere to hold what follows | re-send the identical frame (§8.2) |
| `welcome` | joiner never joins; group believes it did | no longer stalls others; earlier traffic is discarded | rebuild, pinned to the add (§8.2) |
| `add` | joiner's frames buffer as unknown sender → repair | buffered, drains | recovered |
| `remove` | remaining members repair; removed device refused and re-notified | strict order | recovered, self-healing |
| `update` | traffic under the new epoch waits → repair on next dependency | buffered | recovered while anyone speaks (7) |
| `grantAdmin` | authorization view diverges → repair; recomputed retroactively | order does not colour the outcome | recovered |
| `coverage` | harmless | harmless | built, **never sent** (7) |
| application | silent, permanent; trailing gaps undiscoverable | handled passively by skipped keys | **§8.1 unbuilt** (6) |
| repair req/resp | re-issued next window | stateless / content-addressed | solid |
| one-shot | gone, by design | n/a | by design; no sender signal |

Ordering is in good shape: the control lane is strictly sequenced and buffered, the application lane is
deliberately exempt and recovers reordering passively, and gap repair works end to end. **Loss is the weak
axis.** First contact — the worst of it, because a conversation cannot even begin — now has a recovery
path (§8.2, built 2026-08-06), though detecting that it is needed remains a human judgement over an
ambiguous signal, deliberately so. What is left unbuilt is application-message loss recovery, which has a
finished design and no implementation.
