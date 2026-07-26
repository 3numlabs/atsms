# spec/inbound-delivery.md — ATSMS Inbound Delivery Contract

> **Status: DRAFT v0.1 (2026-07-25) — for review.** [Common ATSMS — protocol-neutral, NOT DCGKA-specific]
> The receive half of delivery: *how a message reaches a DID.* It is **payload-agnostic** — it carries a
> stateful DCGKA `SealedEnvelope` ([`sealed-sender.md`](./sealed-sender.md)) and a **stateless one-shot**
> (classic S/MIME / P7M, [`atsms-integration.md`](./atsms-integration.md) §… floor) identically, as opaque
> bytes. Because it serves both semantics, this contract is **common ATSMS** and does not belong to the
> DCGKA spec set alone; its eventual home (this repo vs a shared spec / `atsms-lib`) is an open item (§8).
> MUST/SHOULD/MAY per RFC 2119.

## 1. Role, scope, and the boundary that matters

This contract defines **discovery + delivery bindings + fan-out obligations** for getting bytes to a DID.
It deliberately does **not** define how a receiver *stores* those bytes or *notifies* a device — those are
implementation.

- **"Provider" is not a protocol actor.** The code that receives at an address MAY be helpful (§6), but the
  protocol names only *addresses* and *obligations*, never an operator role. This dissolves the "provider"
  concept: interop is between apps, not between named intermediaries.
- **The common/implementation line (normative).** The **contract** is: the public `at.atsms.inbox`
  discovery record (§3), the SMTP-floor / HTTPS-upgrade bindings and their byte-convergence (§4), and the fan-out-and-forward
  obligation (§6). **Not** the contract, and free to vary per implementation: the per-device inbox as a
  Durable Object, real-time push (WebSocket / push notification), authenticated fetch/JWT — the reference
  worker's choices, one realization among many.
- **Payload opacity.** A receiver MUST treat the delivered unit as opaque bytes and MUST dedup by its
  content identity (DCGKA: `EnvelopeID`, sealed-sender §3; one-shot: content hash). It MUST NOT require
  parsing the payload to route or store it.

## 2. Two reception channels

A DID advertises **two** ways to be reached, because two situations differ in what the sender already knows:

| Channel | When | Sender knows | Discovery | Spec |
|---|---|---|---|---|
| **Welcome** (bootstrap) | Adding a DID to a group it is not yet in | Nothing shared with the recipient | **Public** `at.atsms.inbox` record (§3) | this doc §3 |
| **Non-welcome** (in-conversation) | Between established members | Shared group state | **In-band** advert (`FrameExt.endpoint`) | sealed-sender §12 |

The **welcome** (bootstrap) address MUST be publicly discoverable: a party adding you shares no secret with
you yet, so it can only find you via your DID — that public address is the `at.atsms.inbox` record (§3), which
also serves the stateless one-shot path (§1). The **non-welcome** address need not be public and is advertised
in-band (sealed-sender §12) — it is the high-volume, linkable address, kept off the public record. **This
document specifies the public `at.atsms.inbox` record and the transport/fan-out mechanics both channels share;
it does not redefine the in-band advert.**

## 3. Inbox discovery — `at.atsms.inbox` (per-DID singleton)

A DID publishes a single **`at.atsms.inbox`** record at the conventional ATProto singleton rkey **`self`**
(one logical answer to "where do I reach this DID," like `app.bsky.actor.profile`). It is discovered with one
`getRecord(repo=<did>, collection=at.atsms.inbox, rkey=self)`. *(The name is deliberately neutral — `welcome`
is a DCGKA packet class, and this record also serves the stateless one-shot path, §1.)*

```json
{
  "$type": "at.atsms.inbox",
  "endpoints": [
    { "uri": "https://relay.haiven.mobile/atsms/in/9d2e…" },
    { "uri": "mailto:did!plc!abc123@haiven.mobile" }
  ]
}
```

- **`endpoints` — ordered by preference**, most-preferred first. A sender walks the list and uses the first
  URI **scheme** it understands, so `https:` is the fast path and `mailto:` the universal fallback.
- **The scheme *is* the transport** — no separate `mode`/`transport` field to keep in sync, and nothing
  baked into the NSID. `mailto:` = the SMTP floor (deliver the payload as an email attachment to that
  address); `https:` = POST to that URL. Future transports are new schemes; a consumer ignores schemes it
  does not understand.
- **Floor (normative):** an `at.atsms.inbox` record MUST contain **at least one `mailto:` endpoint** — the
  SMTP interop floor every ATSMS app can hit. `https:` and other schemes are optional upgrades.
- **Endpoints are objects (`{ uri }`)**, not bare strings, to leave room for per-endpoint hints (max size,
  PQ support) without a breaking change; v1 uses only `uri`. Provider-wide capabilities, if ever wanted,
  belong at a domain `.well-known`, not per-user.
- **Per-DID, not per-device.** The inbox is a property of the identity; the receiver fans out to the DID's
  devices (§6). A `mailto:`/`https:` address's **host** is the destination a sender groups on in §5; the
  `mailto:` local-part is opaque to the protocol (encoded-DID for v1, an opaque token later — no schema
  change).
- **Integrity is liveness-only.** An ordinary DID-repo record (DID-signed commit, MST-bound), **not**
  device-signed: a tampered address can only *misroute a sealed envelope*, never break confidentiality (the
  payload is E2E-sealed regardless of transport). Rotation/multi-homing = update the singleton's list.

> **Reconciliation with `inviteAddress` (D13, decided 2026-07-25 — amends 2026-07-16).** This record
> **supersedes and retires** the per-device `inviteAddress` field on the `at.atsms.x509` endpoint record
> ([`identity-devices.md`](./identity-devices.md) §4.1). Its liveness-only integrity model carries over
> unchanged; consumers (classic S/MIME, one-shot sealed, DCGKA welcome) now read `at.atsms.inbox`. A
> per-device override MAY be reintroduced later if a device ever wants a distinct address; not needed for v1.

## 4. Transport bindings (one mailbox, two carriers, identical bytes)

The same message reaches a DID by either binding; both MUST converge on **byte-identical stored content** so
dedup works across transports (a copy that arrived by SMTP and one by HTTPS MUST collide on content identity,
§1).

- **SMTP (floor).** Deliver the opaque payload as a minimal email with the payload as a single attachment of
  media type **`application/atsms-envelope`** (base64 transfer-encoded), to a `mailto:` endpoint's address.
  The receiver extracts the attachment bytes and stores them exactly as the HTTPS path stores its posted
  bytes — so the two bindings byte-converge and dedup collides (content identity is hashed over the decoded
  envelope bytes, not the transfer encoding). Universal, slow, always available.
- **HTTPS (upgrade).** `POST` the opaque payload to an `https:` endpoint (an `at.atsms.inbox` entry for
  welcomes; the in-band `FrameExt.endpoint` for non-welcome, sealed-sender §12). "SMTP without the SMTP
  tax."
- **Anonymous, like SMTP.** SMTP is inherently "anyone can drop." The HTTPS binding SHOULD be equally
  sender-anonymous (no sender auth), consistent with sealed sender; rate-/size-limits (sealed-sender §7) are
  the only abuse control. *(A receiver's fetch side stays authenticated — that is implementation, §1.)*

## 5. Sender-side cross-provider fan-out

A DID MAY be reachable at **several** addresses at once (multi-homing — "try providers simultaneously"). The
**sender** is responsible for cross-address fan-out:

1. Resolve the recipient's reachability (its `at.atsms.inbox` `endpoints`, and for members its in-band endpoints).
2. Group destinations by endpoint **host** (the `mailto:`/`https:` authority).
3. Deliver **one copy per distinct destination** (a `mailto:` floor, or an `https:` upgrade where advertised).

Intra-destination device fan-out is **not** the sender's job (§6). The sender addresses *destinations*, never
individual devices across destinations.

## 6. Receiver-side intake → per-device fan-out (+ forward)

Code receiving at a per-DID `at.atsms.inbox` destination is where the "helpfulness" the protocol declines to name lives:

1. Resolve the DID's `at.atsms.x509` endpoint records (its devices).
2. **Deliver a copy to each device this destination manages** — a device it manages is one whose delivery
   **host** matches this destination's own. *(Reference realization: one per-device inbox keyed by the
   device fingerprint — the worker's `inbox-{did}-{fingerprint}` — one x509 cert = one device.)*
3. **Forward** to any SAN / delivery address it does **not** manage (e.g. a device homed at a different
   destination), over the floor binding. This is what makes multi-homing work without the sender enumerating
   every device.

A non-welcome envelope is already per-device (the engine seals one per recipient device, sealed-sender §11);
such a destination receives one envelope for its device(s) and stores it — devices trial-decrypt by tag
(sealed-sender §11.3). A welcome, addressed per-DID, is fanned to devices here.

## 7. What a receiver learns (privacy budget)

Held to sealed-sender §8: **mailbox + timing + padded size**, nothing more. On the anonymous ingress path a
receiver MUST NOT persist sender-network metadata (source IP, etc.) alongside a stored envelope. Payloads are
opaque; an endpoint's host reveals only what the email address already reveals.

## 8. v1 scope & open questions

**v1 delivers:** the `at.atsms.inbox` record — singleton `self`, ordered `endpoints`, `mailto:` floor +
optional `https:` upgrade, scheme-as-transport (§3); the two bindings with byte-convergence (§4); sender
group-by-destination fan-out (§5); receiver intake→per-device fan-out with forward-to-unmanaged (§6).
Non-welcome addressing is already built in-band (sealed-sender §12).

**Decided (2026-07-25):** record = single `at.atsms.inbox` collection, rkey `self`, transport carried as the
endpoint URI **scheme** (not the NSID, not a field); `inviteAddress` relocated here and retired (§3).

**Open:**
- **Spec home** — this contract is common ATSMS (serves stateless one-shot too); promoting it out of the
  DCGKA spec set (to `atsms-lib` or a shared spec) is tracked, not yet done.
- **Per-endpoint hints** — the `{ uri }` object leaves room for max-size / PQ-support fields; deferred until
  a consumer needs them (provider-wide capability discovery via a domain `.well-known` is the alternative).
- **Reference binding** — BUILT in `atsms-worker` (branch `dcgka-inbound-delivery`): the HTTPS binding
  (`POST /inbox/{did}`) and the SMTP `mailto:` floor (an `application/atsms-envelope` attachment → the same
  `dcgka` per-device inboxes, byte-convergent) both realize §4/§6. Deferred there: managed-cert filtering for
  the multi-provider case (§6), and real anonymous-ingress rate limiting (§4, sealed-sender §7).
