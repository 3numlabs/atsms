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
- **The common/implementation line (normative).** The **contract** is: the public welcome-discovery record
  (§3), the SMTP-floor / HTTPS-upgrade bindings and their byte-convergence (§4), and the fan-out-and-forward
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
| **Welcome** (bootstrap) | Adding a DID to a group it is not yet in | Nothing shared with the recipient | **Public** record on the DID (§3) | this doc §3 |
| **Non-welcome** (in-conversation) | Between established members | Shared group state | **In-band** advert (`FrameExt.endpoint`) | sealed-sender §12 |

The **welcome** address MUST be publicly discoverable: a party adding you shares no secret with you yet, so
it can only find you via your DID. The **non-welcome** address need not be public and is advertised in-band
(sealed-sender §12) — it is the high-volume, linkable address, kept off the public record. **This document
specifies the welcome channel and the transport/fan-out mechanics both channels share; it does not redefine
the in-band advert.**

## 3. Welcome discovery — `at.atsms.welcome.<mode>` (per-DID)

A DID publishes one record per supported **mode**, as a mode-tagged ATProto collection:

```
at.atsms.welcome.smtp   → { email: "<local>@<domain>", ... }     ; REQUIRED — the interop floor
at.atsms.welcome.https  → { url: "https://<host>/<path>", ... }  ; OPTIONAL — a faster upgrade
```

- **`smtp` is the required baseline** every ATSMS implementation can fall back to; additional modes
  (`https`, …) are optional upgrades a sender uses only if it understands them. Absence of a mode simply
  means "use the floor."
- **Per-DID, not per-device.** The welcome address is a property of the identity; the receiver fans a
  welcome out to the DID's devices (§6). The `<domain>` identifies where to deliver; it is the same hint a
  sender groups on in §5.
- **Integrity is liveness-only.** These are ordinary DID-repo records (DID-signed commit, MST-bound); they
  are **not** device-signed. A tampered welcome address can only *misroute a sealed envelope* — never break
  confidentiality (the payload is E2E-sealed regardless of transport). Updates are ordinary record updates.

> **DECISION NEEDED — reconciles with `inviteAddress` (amends 2026-07-16).** Today
> [`identity-devices.md`](./identity-devices.md) §4.1 carries the Welcome/invite destination as a
> **per-device** `inviteAddress` field on each `at.atsms.x509` endpoint record. D13's per-DID
> `at.atsms.welcome.<mode>` supersedes that. **Proposed:** relocate welcome addressing to the per-DID
> welcome record(s) and retire the per-device `inviteAddress` field (its liveness-only integrity model
> carries over unchanged). A per-device override MAY be reintroduced later if a device wants a distinct
> welcome address; not needed for v1. *(Lighter alternative, if per-device welcome addressing is actually
> wanted: keep `inviteAddress` on the x509 record but make it mode-tagged — no new collection. Flagged for
> sign-off because it amends a prior user decision.)*

## 4. Transport bindings (one mailbox, two carriers, identical bytes)

The same message reaches a DID by either binding; both MUST converge on **byte-identical stored content** so
dedup works across transports (a copy that arrived by SMTP and one by HTTPS MUST collide on content identity,
§1).

- **SMTP (floor).** Deliver the opaque payload as a minimal email with the payload as the attachment, to the
  `at.atsms.welcome.smtp` `email`. Universal, slow, always available.
- **HTTPS (upgrade).** `POST` the opaque payload to the advertised endpoint (`at.atsms.welcome.https` `url`
  for welcomes; the in-band `FrameExt.endpoint` for non-welcome, sealed-sender §12). "SMTP without the SMTP
  tax."
- **Anonymous, like SMTP.** SMTP is inherently "anyone can drop." The HTTPS binding SHOULD be equally
  sender-anonymous (no sender auth), consistent with sealed sender; rate-/size-limits (sealed-sender §7) are
  the only abuse control. *(A receiver's fetch side stays authenticated — that is implementation, §1.)*

## 5. Sender-side cross-provider fan-out

A DID MAY be reachable at **several** addresses at once (multi-homing — "try providers simultaneously"). The
**sender** is responsible for cross-address fan-out:

1. Resolve the recipient's reachability (its welcome record(s), and for members its in-band endpoints).
2. Group destinations by **address / domain**.
3. Deliver **one copy per distinct destination** (floor SMTP, or a faster binding where advertised).

Intra-destination device fan-out is **not** the sender's job (§6). The sender addresses *destinations*, never
individual devices across destinations.

## 6. Receiver-side intake → per-device fan-out (+ forward)

Code receiving at a per-DID welcome address is where the "helpfulness" the protocol declines to name lives:

1. Resolve the DID's `at.atsms.x509` endpoint records (its devices).
2. **Deliver a copy to each device this destination manages** — a device it manages is one whose delivery
   `<domain>` matches this destination's own. *(Reference realization: one per-device inbox keyed by the
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
opaque; the welcome `<domain>` reveals only what the email address already reveals.

## 8. v1 scope & open questions

**v1 delivers:** the `smtp` welcome floor + optional `https` upgrade (§3); the two bindings with
byte-convergence (§4); sender group-by-destination fan-out (§5); receiver intake→per-device fan-out with
forward-to-unmanaged (§6). Non-welcome addressing is already built in-band (sealed-sender §12).

**Open:**
- **`inviteAddress` reconciliation** (§3) — the sign-off item above (per-DID welcome record vs per-device
  `inviteAddress`).
- **Welcome record shape** — per-mode collections (`at.atsms.welcome.smtp` / `.https`) as written here, vs a
  single `at.atsms.welcome` collection with a `mode` field. Per-mode makes "does this DID support https?" a
  direct `getRecord`; single-collection makes enumeration one `listRecords`. PROPOSED: per-mode.
- **Spec home** — this contract is common ATSMS (serves stateless one-shot too); promoting it out of the
  DCGKA spec set (to `atsms-lib` or a shared spec) is tracked, not yet done.
- **Reference binding** — realizing §4/§6 in `atsms-worker` (per-DID DCGKA intake fanning to per-device
  inboxes; the HTTPS endpoint the in-band URL points at) is the cross-repo build that follows this spec.
