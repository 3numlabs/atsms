# Proposal 0001 — Group drop point

> **Status: DRAFT (2026-08-11).** Not normative. Nothing in `spec/` depends on this, and nothing should
> until it is ACCEPTED. Supersedes the "profile 2" sketch in the retired v1.1 spec
> ([`../docs/history/atsms-dcgka-spec.md`](../docs/history/atsms-dcgka-spec.md) §9), which was the only
> place it had ever been written down.

## The problem

Without a drop point, a sender pays for the whole group. The engine seals one envelope per recipient
device and the sender uploads all of them, so cost is linear in group size: about 1.06 KiB per device per
message, every message. That is comfortable to roughly 25 devices and uncomfortable well before 128
(`spec/parameters.md`). Nothing about the *protocol* breaks at scale — it is the sender's uplink that
gives out.

## The idea

The sender leaves **one** copy at a shared location and members collect it, instead of pushing a copy to
each member's conversation address.

That requires a **shared ciphertext**: a single envelope every member can open, rather than the
per-recipient sealing of `spec/sealed-sender.md` §11.3, where each copy carries its own tag and nonce
precisely so that two mailboxes cannot be correlated. The reserved `atsms-seal:v1:group` label
(`spec/wire-format.md` §7) is held for this.

**The trade is explicit**: the host learns co-membership. It sees that a particular set of collectors
pulls the same object, which per-recipient delivery hides. In exchange the sender's cost stops scaling
with the group.

## Design sketch

### Addressing needs nothing new

`spec/sealed-sender.md` §12's conversation address is already per-(device, group). A group that adopts a
drop point simply has each device advertise a conversation address at that host, and
`spec/inbound-delivery.md` §5 already collapses a sender's fan-out by destination host.

**This proposal is a sealing change, not a delivery change.** Scoping it as a transport project would be
a mistake.

### Rotate the drop-point address per epoch

Carried over from the v1.1 sketch and worth keeping: derive the drop-point address from group state so
that **only members can compute the next one**, and rotate it each epoch.

This does not stop the host correlating pullers *within* an epoch — that is the trade above, and it is
unavoidable. What it stops is the host accumulating a stable, long-lived identity for the group across
epochs. Since epochs advance on membership change and on every re-key, a group that churns or heals
regularly presents as a succession of unrelated collections.

Open: what an observer learns from the rotation itself, given the same set of addresses pulls the
successor. Rotation may be defeated by simple continuity of client IPs, in which case it is theatre and
should be dropped rather than claimed.

### Collection is by pull, not push

A drop point MUST NOT push the shared ciphertext to members' conversation addresses.

The ciphertext is identical for every member by construction. Pushing it would place byte-identical
envelopes in *n* different mailboxes, letting any two receiving hosts correlate their users as
co-members — exactly the linkage per-recipient sealing exists to prevent, now performed by the drop point
on the group's behalf and scattered across hosts the group never chose. The drop point holds no keys and
cannot re-seal on the way out.

Under pull, the correlation stays at the single host the group knowingly chose.

### Waking a device that cannot hold a subscription

Pull assumes a device can subscribe or poll. Phones cannot, so a device MAY register a **callback** with
the drop point.

- **An opaque URL, one per (device, group), carrying no payload.** Calling it means "this group has
  something". The URL *is* the message, so no group identifier travels in the clear and the token holds
  no DID and no mailbox. A distinct token per group also denies two drop points the ability to correlate
  one device across its groups.
- **The callback need not be hosted by the device's own relay.** Anything that can wake the device will
  do; keep the protocol agnostic.
- **The device sets the nudge policy; the drop point MUST NOT infer it.** Every efficient policy an
  implementer reaches for — "only if they have not collected", "only when they are offline" — requires
  linking a token to a collector, which destroys the opacity that made the token worth having. Instead a
  device MAY register a minimum interval, and MAY declare a pause with a short TTL that lapses on its own
  rather than requiring a clean disconnect.
- **Coalescing is free.** A contentless nudge is idempotent: one and fifty carry identical information.
  Debouncing risks nothing, because the nudge was never the message.

Requirements on a drop point that accepts callbacks:

1. **`https:` only, private address ranges refused.** Accepting a callback makes the drop point an HTTP
   client; an unfiltered one is a request proxy into whatever it can reach.
2. **Rate-limit per token.** An unauthenticated wake-up URL is a battery attack on whoever holds it.
3. **Expire tokens; require periodic re-registration.** A forcibly removed member never deregisters and
   the drop point cannot detect this, since it cannot read group state. Without expiry it holds live
   wake-up URLs for non-members indefinitely. Expiry also bounds a leaked token.
4. **Back off, then expire,** when a token is nudged repeatedly and nothing is collected.
5. The **sender is nudged for its own message** — sealed sender means the drop point cannot identify or
   exclude them. Harmless; stated so it is not read as a bug.

### What a drop point learns, stated plainly

Co-membership of its collectors, collection timing, object sizes, and — if callbacks are used — the
number of registered tokens and when each is called. It does not learn identities: no DID, no mailbox, no
content.

Residual exposure that rotation and opacity do **not** fix: nudge frequency at a callback host traces
group activity to whoever operates it; and a device's own relay sees which hosts nudge it, so it can
infer which hosts carry that device's groups. Weaker than a correspondent graph, the same shape, and
accumulating at the party that already knows who the device is.

## Open questions

Answer these before this could be ACCEPTED.

1. **The sealing itself.** This is the whole substance and it is not designed. What derives the shared
   epoch key, how it relates to §11.2's derivation, and what forward secrecy and post-compromise
   properties survive when every member can open the same ciphertext.
2. **Does epoch rotation buy anything real,** or is it defeated by client-IP continuity and pull timing?
   Measure before claiming.
3. **Who chooses the drop point, and how does a group move?** Changing a conversation address is a
   group-visible event; changing all of them at once is a coordinated migration nobody has specified.
4. **What stops a drop point lying?** It can withhold an object from one collector, or serve stale state.
   Per-recipient delivery has the same weakness per mailbox, but a drop point concentrates it.
5. **Interaction with §8 repair.** Repair re-serves retained frames per recipient. What repair looks like
   when the original delivery was a shared object is unexamined.
6. **Abuse.** An anonymous-write, anonymous-read shared location is an attractive dead drop for traffic
   that has nothing to do with the group.

## Alternatives considered

**Push to conversation addresses instead of pull.** Rejected — see above. It scatters byte-identical
ciphertext across *n* hosts and creates a correlation worse than either profile, by accident rather than
as a trade.

**Nudge by sealed one-shot rather than callback URL.** The drop point sends each member a sealed one-shot
as the wake-up. Its one genuine advantage: a one-shot arrives as an ordinary envelope in an ordinary
inbox, so the member's own relay sees only traffic it already sees, whereas a callback needs a distinct
endpoint its host can always recognise. Rejected because (a) sending one-shots requires each member's
DID, prekey and inbox record, converting the drop point's knowledge from a set of anonymous pullers into
a **named roster** that is publicly linkable and worth compelling; (b) the only address a drop point can
discover is the introduction address, so every nudge would land on the one address deliberately kept
public and quiet, inverting `spec/sealed-sender.md` §12's rationale; (c) one-shots authenticate their
sender, so the drop point would need an identity, making it a named protocol actor contrary to
`spec/inbound-delivery.md` §1; and (d) it recreates the *n* fan-out this profile exists to remove, with
asymmetric crypto per recipient, where a callback is *n* plain POSTs.

**Run the drop point in a trusted execution environment.** Discussed and not pursued here. A TEE would
protect the host's internal state, but the disclosure this profile actually makes — co-membership — is
visible from network traffic regardless, so the claim it appears to support is not the one it delivers.
What it would genuinely change is the cost of *bulk retrospective* disclosure, which is a narrower and
more defensible argument. If revisited, reproducible builds are the prerequisite and the more valuable
half.

## Relationship to the other profiles

The v1.1 sketch named three, and the other two are live rather than proposed:

- **Per-recipient envelopes** — what the protocol does today. Normative, `spec/sealed-sender.md` §11.
- **Blob offload** — orthogonal and already required by `spec/sealed-sender.md` §5's oversize rule.
  Unbuilt, and what closes a group to newcomers once welcomes outgrow the 64 KiB bucket
  ([`../KNOWN-ISSUES.md`](../KNOWN-ISSUES.md) #10). Not part of this proposal.

Note the naming: this document says **drop point** because "relay" already means the store-and-forward
node an individual account uses. Public writing has called the same thing a **group relay**.
