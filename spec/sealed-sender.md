# spec/sealed-sender.md — Sealed-Sender Envelope Layer

> **Status: DRAFT v0.4 (2026-07-22) — for review.** *(v0.2: two envelope modes — `sealed-sym` added, §11.
> v0.3: D9/D10 — `sealed-asym` targets the signed prekey; sealing cert removed. v0.4: D11 — sym envKey
> derived from `PcsKey_e` with the sender in the info; ack references retired.)* [Protocol] · Phase 0 deliverable.
> Closes gap **G9** (anonymous ingress, padding, key separation, envelope dedup) from
> [`../docs/history/gap-analysis.md`](../docs/history/gap-analysis.md); implements decision **D5** (anonymous relay ingress).
> Inputs: spec v1.1 §6 (construction + envelope-FS and X509-unification design notes), Signal sealed-sender
> design (inspiration only), [`identity-devices.md`](./identity-devices.md) §3.1/§4.2 (signed prekey, joint use),
> [`ordering-auth.md`](./ordering-auth.md) (the signed frame this layer wraps),
> [`wire-format.md`](./wire-format.md) §6 (byte layout). MUST/MAY per RFC 2119.

## 1. Role and scope

The sealed envelope is the **outermost cryptographic layer**: every ATSMS transmission — control
(including coverage), welcome, app, and repair frames — crosses the network and rests
in mailboxes only as a `SealedEnvelope`. Its single job is **metadata protection against outsiders**: an
observer on the wire, a mailbox provider, or anyone who obtains a stored envelope learns neither the
sender's identity nor anything about the payload beyond its size bucket (§5) and arrival time. Recipients
learn the sender only after decryption, from the signed frame inside
([`ordering-auth.md`](./ordering-auth.md) §5 — all signatures live inside the seal).

What this layer does **not** do: authenticate (the inner frame signature does), order (ordering layer),
protect content confidentiality against members (DCGKA/ratchet layers), or hide the recipient *mailbox*
from the provider (inherent to store-and-forward; §8).

**One format across both stacks (normative)**: the same envelope carries either a DCGKA signed frame or a
v1-baseline CMS `SignedData` (the X509 interop floor), discriminated inside the plaintext (§4). The X509
floor thereby gains sealed-sender semantics from the same envelope and key material — see §10 and
[`atsms-integration.md`](./atsms-integration.md).

**Two envelope modes (decided 2026-07-20)**: a KEM is cryptographically necessary only when sender and
recipient share no state yet. The envelope therefore has two modes:

- **`sealed-asym`** (§3–§4, HPKE to the signed prekey) — **bootstrap-class traffic only**: welcomes/invites,
  first-contact `create`, X509-floor one-shots, and any message to a device with no established group
  state. This is the only surface that ever pays KEM costs (including the future post-quantum hybrid,
  overview §6.12).
- **`sealed-sym`** (§11, AEAD under a per-sender-epoch key derived from group state, located via a
  pseudonymous per-recipient tag) — **all in-conversation traffic**: app, control, coverage, and repair
  frames between established members. KEM-free, ~55 B overhead, envelope FS/PCS inherited from the epoch
  schedule, and quantum-safe as-is.

## 2. Keys

*(This section governs `sealed-asym`; `sealed-sym` keys derive from group state — §11.2.)*

- Asym envelopes are sealed to the recipient device's **signed prekey**: the X25519 `signedPrekey` in its
  current `at.atsms.prekey` bundle (identity-devices.md §4.2 — weekly rotation, one-week grace), verified
  via `bundleSig` against the endpoint cert before any seal. *(D10, decided 2026-07-22 — replaces the
  deleted sealing cert; the joint X3DH + HPKE use of this key is the single analyzed exception to strict
  purpose separation, argument in identity-devices.md §3.1.)*
- Senders MUST NOT seal to the endpoint (P-256) key, `identityDh`, or any ratchet key (purpose separation,
  identity-devices.md §3). Domain separation between the signed prekey's two roles is at the KDF-label
  layer: X3DH's `atsms-2sm:v1:x3dh-kdf` vs HPKE's labeled derivation with `info = "atsms-seal:v1"` (§4).
- **No key identifier on the wire.** The envelope names no recipient key (or device — §3); the recipient
  trial-decrypts across its ≤ 2 live signed-prekey secrets (current + grace, identity-devices.md §4.2). A
  key ID would let a provider partition traffic by prekey generation for free.

## 3. Envelope (normative shape; bytes in wire-format.md §6)

```
SealedEnvelope (asym) = [ version = 1, mode = 1, suite = 1, enc, ct ]
  suite: KEM suite id (1 = DHKEM(X25519); reserved values for the PQ hybrid — overview §6.12)
  enc:   HPKE encapsulated key (32 B, X25519)
  ct:    HPKE AEAD ciphertext of the padded plaintext (§4, §5)

SealedEnvelope (sym)  = [ version = 1, mode = 2, tag, nonce, ct ]   — §11
```

- **No cleartext recipient identifier.** The G9 fix: the original sketch's `recipient_device_id` is
  removed — the mailbox address already routes, and naming the device in cleartext leaked device identity
  to every on-path observer. Routing is entirely the transport's mailbox addressing (spec v1.1 §7); a
  device sharing a mailbox discards what it cannot decrypt.
- **No timestamp.** Provider arrival time is unavoidable metadata; a sender-asserted cleartext timestamp
  only adds a correlatable field. Sender time, where needed, lives in the inner payload.
- **EnvelopeID (idempotency)** = SHA-256 of the complete serialized envelope. Mailboxes redeliver;
  receivers MUST dedup on EnvelopeID **before** any decryption attempt (cheap hash vs. HPKE open — this is
  the pre-decryption DoS/redelivery guard; the ordering layer's MessageID dedup (A5) remains the
  authoritative replay defense after unsealing). Providers MAY also use EnvelopeID as their storage key —
  the relay's existing content-hash dedup is compatible.

## 4. Sealing construction (`sealed-asym`)

- **HPKE Base mode** (RFC 9180), `DHKEM(X25519, HKDF-SHA256)` + `HKDF-SHA256` + `ChaCha20-Poly1305`.
  `info = "atsms-seal:v1"`. No PSK, no HPKE Auth mode (sender
  authentication is deliberately *inside* the seal).
- **Sealed plaintext** = deterministic CBOR `[ contentType, body, pad ]`:
  - `contentType = 1` — `body` is a signed ordering-layer frame (wire-format.md §3). The frame's signature,
    verified after unsealing, is what turns "someone sent this" into "member X sent this".
  - `contentType = 2` — `body` is a CMS `SignedData` (X509-floor mode, §10).
  - `pad` — zero bytes to the bucket boundary (§5).
- **Recipient procedure**: dedup (§3) → trial-`Open` with each live signed-prekey secret → on total failure, drop
  silently (count for telemetry; envelopes addressed to a shared mailbox legitimately fail here) → dispatch
  on `contentType` → hand `body` to the ordering layer (or the CMS pipeline). A failed open MUST cause no
  state change.

## 5. Padding (normative)

"Random bytes" is not a scheme (G9). Padding exists so that **message classes are indistinguishable by
size** — otherwise the ack storm after every membership op (n−1 similar-sized envelopes at once) is a
glaring classifier even with sealing. Padding applies identically to **both modes** (the `SealedPlaintext`
structure is shared).

- **Bucket rule**: pad the sealed plaintext (§4) with zero bytes to the smallest bucket ≥ its length.
  Buckets (**PROPOSED**, [`parameters.md`](./parameters.md)): **1, 2, 4, 8, 16, 32, 64 KiB**. The envelope
  on the wire is then bucket + constant HPKE/CBOR overhead (~70 B).
- The 1 KiB floor covers steady-state acks (~300 B), app text messages, updates/removes without large DM
  fan-in, and repair requests — i.e. the overwhelming majority of traffic lands in one indistinguishable
  class. Control ops carrying n 2SM direct messages (wire-format.md §4.1) climb the buckets with group
  size; welcomes typically occupy the top buckets.
- **Oversize rule**: a sealed plaintext that exceeds the largest bucket MUST NOT produce a larger envelope —
  the content moves to **encrypted blob offload** (spec v1.1 §9 profile 3: upload once as an encrypted,
  content-addressed blob; the envelope carries reference + content key) and the envelope re-buckets. This
  applies to media *and* to oversized welcomes.
- Receivers MUST accept any well-formed padding length (tolerant reader, strict writer) but MUST verify
  pad bytes are zero (a covert channel otherwise).

## 6. Traffic-shape mitigations beyond size

Size buckets close only one channel. The spec's other layers already remove the worst timing signatures,
restated here as the envelope layer's dependencies:

- **Protocol acks no longer exist** (retired by D11 — beekem-core §5): the post-op ack storm, the
  single worst traffic classifier this layer had to blunt, is gone. `coverage` frames are the residual
  non-interactive traffic: lazy (≤ `T_COVER` = 24 h), padded like everything else, and SHOULD be
  heavily jittered.
- **No standalone digest frames** (dgm.md §8) — a quiet group emits no heartbeat pattern; digests ride
  coverage or ordinary frames.
- Clients MAY add random send jitter (suggested 0–30 s for non-interactive frames like coverage and
  digest carriers; never for user-visible messages).
- **Residual (documented)**: burst timing correlation across n mailboxes at fan-out time, and sender IP
  visibility to the provider, remain. IP privacy requires Tor/mixnet transport (optional profile,
  spec v1.1 §7); full recipient unlinkability requires a mixnet — out of scope for v1 (spec v1.1 §2).

## 7. Anonymous ingress & abuse control (D5 — the relay contract)

Sealed sender is void if the transport authenticates the sender: today's relay send path over WebSocket
rides an ES256-JWT-authenticated session, which would un-seal at the transport layer exactly what the
crypto sealed. The relay contract for DCGKA traffic ([Node] — changes to `atsms-worker`, detailed in
[`atsms-integration.md`](./atsms-integration.md)):

- **Push (anonymous, normative)**: `POST /envelope/{mailboxId}` — unauthenticated, body = one serialized
  envelope. No sender identity, no session binding; a sender MUST be able to push over a connection that
  carries no credentials (in particular, not its own mailbox WebSocket).
- **Fetch (authenticated, unchanged)**: pulling one's own mailbox stays JWT-authenticated (ES256 against
  the endpoint cert) — the mailbox owner is not anonymous to its own provider, by design.
- **Abuse control (normative minimum for operators)**: per-mailbox rate limit and byte quota
  (**PROPOSED defaults** in [`parameters.md`](./parameters.md): 600 envelopes / 20 MB per mailbox per
  hour), global per-IP limits at the operator's discretion, size cap = largest bucket + overhead (§5).
  Overflow → `429`; the protocol treats a rejected push like any transport failure (retry with backoff,
  ordering-layer repair recovers stragglers).
- **Hardening (post-v1, designed-not-specified)**: unlinkable sender tokens (Privacy-Pass-style, or
  Signal-sealed-sender-style certificates) so operators can rate-limit *senders* without identifying them.
  Tracked as an open item (§14); the v1 position is that per-mailbox caps + the 128-device group envelope
  keep flood damage bounded and local.
- **North star check**: the relay stays dumb — after this change it learns *less* than today (mailbox +
  timing + size bucket; no sender identity on any push).

## 8. What the provider still learns (documented, accepted)

Per envelope: target mailbox, arrival time, size bucket, pusher IP (absent Tor). Across envelopes:
mailbox traffic volume and burst patterns. (A group drop point would additionally expose co-membership
of its pullers; it is a proposal, and that trade is stated there —
[proposals/0001](../proposals/0001-group-drop-point.md).) The provider never learns:
sender identity, message class beyond bucket, group structure (baseline profile), or any content.

## 9. Envelope-layer forward secrecy (bounded, documented)

*(Asym mode only — `sealed-sym` envelopes inherit ratchet-grade FS/PCS directly, §11.5, which is one of
the reasons in-conversation traffic uses it.)*

Sealing to a rotating medium-term key means the envelope layer itself has no per-message FS. The impact is
bounded: the inner payload keeps full FS/PCS from the DCGKA/ratchet layers, so a compromised signed-prekey
secret never exposes message **content** — only the sealed-sender **metadata** (sender identity, frame
structure, causality info) of bootstrap-class envelopes the attacker previously captured, within the
prekey's rotation window + grace (1 week + 1 week, [`parameters.md`](./parameters.md) — tightened from the
deleted sealing cert's 30–97 d by D10; the compromise also yields the X3DH DH1/DH3 legs but no content in
that role either, identity-devices §3.1). Rotation is the mitigation; a later extension MAY derive
per-epoch sealing keys from group state so envelope FS approaches ratchet FS (out of scope for v1).

**Cost note** (spec v1.1 §6): one HPKE seal per recipient per message ≈ 50–100 µs native, ~1 ms JS-class;
at the 128-device max ≲ 0.15 s CPU per send — negligible next to the network fan-out.

## 10. X509-floor unification & SMTP transport

- **D9 (decided 2026-07-22): X509/CMS is the identity + signing floor only.** CMS `EnvelopedData` is not
  an ATSMS encryption mechanism: mainstream MUAs have effectively no RFC 8418 (X25519 CMS) support, and
  self-signed DID certs are untrusted by them regardless — the S/MIME bet's real payoff was library-level
  (`SignedData` + the X509 identity artifact), which stays. Every ATSMS encryption path is HPKE to a raw
  key. Classic S/MIME `EnvelopedData` to the P-256 endpoint cert survives solely for inbound mail from
  external, non-ATSMS senders.
- With `contentType = 2` the envelope carries a CMS `SignedData` — the v1-baseline S/MIME payload —
  HPKE-sealed to the recipient's signed prekey, resolved from `at.atsms.prekey` and verified via
  `bundleSig` (machinery a sealed sender already has: deterministic CBOR for the envelope itself,
  ECDSA-P256 for the endpoint cert). Relative to the old CMS pipeline this fixes: recipient-identifying
  `RecipientInfo` structures (HPKE names no recipient), AES-CBC → AEAD, and unrotated long-lived keys
  (endpoint → weekly prekey). The inner sign-then-encrypt order is unchanged.
- **SMTP is just another baseline store-and-forward transport**: the envelope rides as a MIME part through
  the existing email-bridge extraction path; classic S/MIME to the endpoint cert remains for external,
  non-ATSMS email recipients. **Caveat (MUST document in UX)**: SMTP transport metadata (From, DKIM,
  server IPs) sits outside the envelope's protection — sealed semantics hold against the *storing* mailbox
  provider only; email is a low-anonymity transport.

## 11. Symmetric envelope mode (`sealed-sym`) — decided 2026-07-20

### 11.1 Applicability (normative)

All in-conversation traffic — `app`, `control` (including `coverage`), `repair` frames between
established members — MUST use `sealed-sym`. `sealed-asym` is reserved for bootstrap-class traffic (§1) and MUST NOT be used where a
sym key exists (a KEM there is pure cost). A receiver that cannot yet locate a sym envelope's key buffers
briefly (§11.4); senders never fall back to asym mid-conversation.

### 11.2 Key derivation *(re-based 2026-07-22, D11)*

```
envKey(e, S) = Expand(PcsKey_e, "atsms-seal:v1:sym" ‖ enc(S))      // S = sender Membership
```

where `PcsKey_e` is the group's root secret for epoch `e` (beekem-core §3). The sender moved into the
info string because the ikm is now shared: every member derives `PcsKey_e` by processing epoch `e`'s
`update` op (no ack round-trip), so every member can compute every sender's `envKey` — nobody outside the
group can. Keys remain **per-group** (root secrets are per-group) and **per-sender-epoch** (distinct
`envKey`/tag per sender). Epochs are now group-scoped rather than per-sender — all senders' envelope keys
and tags rotate together on each update; more tag-table churn, no protocol change.

### 11.3 Wire shape, tag, and AEAD

```
[ version = 1, mode = 2, tag, nonce, ct ]
  tag   = Expand(envKey, "atsms-seal:v1:hint" ‖ enc(recipientMembership))[0..8]
  nonce = 24 random bytes (XChaCha20-Poly1305)
  ct    = XChaCha20-Poly1305(envKey, nonce, AAD = enc([version, mode, tag]), padded SealedPlaintext §4/§5)
```

- **Tag properties**: PRF output — pseudorandom to outsiders (sender-hiding); **per-recipient**, so the
  fan-out carries a different tag to every mailbox (no cross-mailbox group-graph reconstruction); rotates
  with the sender's epoch (pseudonym expires on rekey). Residual leak, documented: within one mailbox and
  one sender-epoch, same-stream envelopes share a tag — an observer counts active streams and cadence,
  bounded by epoch length, atop the mailbox+timing baseline it already has. A mod-P truncated-tag variant
  was considered and **rejected 2026-07-20** (adds complexity; at useful P it bought no privacy within a
  mailbox).
- **Fresh nonce per recipient copy (normative)**: the sender MUST re-encrypt per recipient (fresh nonce ⇒
  distinct `ct` bytes). A shared ciphertext across the fan-out would link mailboxes exactly as a shared
  tag would. Cost: n symmetric encryptions, negligible.
- **Lookup**: receiver keeps `tag → (group, sender, epoch, envKey)`; exact hash hit, one AEAD open, O(1)
  in the number of groups/peers. 64-bit tags make table collisions negligible (~K²/2⁶⁵); on a multi-hit,
  trial-open each candidate (Poly1305 rejects false positives), so tag width is not a safety parameter.
- **EnvelopeID dedup (§3) applies unchanged.**

### 11.4 Table maintenance & epoch rules

- Entries (all members' envKeys/tags for epoch `e`) are added the moment `PcsKey_e` is derived — i.e.,
  on processing epoch `e`'s `update` op (beekem-core §4.2). A joiner's first entries come from the first
  post-add update.
- A frame that *establishes* a new epoch (an `update`) rides under the sender's **latest established**
  epoch key — receivers cannot hold the new one yet. The first update after `create` has no prior epoch
  and rides `sealed-asym` (bootstrap-class, §1).
- **Unknown tag** → buffer briefly under the ordering-layer bounds (mirror of the unknown-Membership rule,
  ordering-auth §7) — it may precede the `update` whose processing creates the expected entry — else drop.
- **Grace retention**: superseded epoch `envKey`s are retained while their epoch's messages may still
  legitimately arrive — until the epoch **closes** (covered-by-all, capped at `T_EPOCH_GRACE` = 30 d —
  beekem-core §8, [`parameters.md`](./parameters.md), PROPOSED) — so a receiver offline through several
  epochs still recognizes the missed epochs' envelopes.

### 11.5 Security properties

- **Sender-hiding vs outsiders**: complete — tag and `ct` are pseudorandom; all identity lives inside.
- **Insiders**: any member can mint a well-formed group envelope; sender authenticity was never the
  envelope's job — it is the frame signature (ordering-auth §5). No regression.
- **Compromise scope**: a leaked `envKey` exposes envelope *metadata* of one sender-epoch of one group
  (never content), healed by the next update — strictly narrower than a signed-prekey compromise
  (bootstrap-class envelope metadata across conversations for the ≤ 2-week key window, §9). Envelope
  FS/PCS = epoch-schedule FS/PCS (beekem-core §8 eviction).
- **Post-quantum**: KEM-free — `sealed-sym` is quantum-safe as specified (overview §6, Tier 1), which
  confines the PQ-hybrid cost to the rare `sealed-asym` surface.
- **Identity-freeness preserved** *(the old 2SM invariant, generalized after D11 retired 2SM)*: all key
  material — `PathChange` secret stores included — rides only *inside* signed frames inside envelopes,
  with no cleartext identity fields anywhere in the envelope layer.

### 11.6 The shared-ciphertext variant (proposed, not part of this spec)

A **group drop point** — one shared ciphertext left at a single location and collected by every member,
rather than a sealed copy per recipient — would reuse this section's derivation machinery with a
deliberately *shared* ciphertext, accepting exactly the cross-puller correlation §11.3's per-recipient
tags, nonces and re-encryption exist to prevent. The `atsms-seal:v1:group` label
([`wire-format.md`](./wire-format.md) §7) is reserved for it.

**It is a proposal, not a deferred part of this specification.** The sealing is undesigned, and nothing
here depends on it: [`proposals/0001-group-drop-point.md`](../proposals/0001-group-drop-point.md).

## 12. The conversation address — in-band delivery addressing (decided 2026-07-25, user sign-off)

**Naming (normative).** The two addresses are the **introduction address** (the public
[`at.atsms.inbox`](./inbound-delivery.md) record) and the **conversation address** (the in-band
`FrameExt.endpoint` specified here). Name them for their purpose, not by the packet class that uses them —
"welcome" and "non-welcome" describe a frame, not an address. Do not call the conversation address
*ephemeral*: it is durable last-writer-wins state inside signed group history, merely unpublished.

**The asymmetry that drives this (normative rationale).** A **welcome** is sent by a party that shares
*no* secret with the recipient yet (they are adding the recipient to a group the recipient is not in), so
its delivery address MUST be **publicly discoverable** from the recipient's DID — the per-DID
`at.atsms.inbox` record (singleton rkey `self`; an ordered `endpoints` list where each URI's scheme is its
transport, `https:` = required, `mailto:` = recommended (D15);
[`inbound-delivery.md`](./inbound-delivery.md) §3). Code receiving at that address MAY be helpful — deliver
to the `at.atsms.x509` certs it manages and forward to the SANs it does not — but that helpfulness is an
implementation detail, **not a protocol actor** ("provider" is deliberately *not* a protocol concept).

An **in-conversation** frame, by contrast, is only ever sent by a party that **already shares group state** with
the recipient. Its delivery address therefore need **not** be public: it is advertised **in-band**, inside
the authenticated group channel, so the high-volume/linkable address never appears in a public record. The
public footprint stays exactly one thing — the `at.atsms.inbox` record.

**Mechanism (normative).** A device advertises its conversation address in the **signed frame
`ext`** (wire-format §3.2; `FrameExt.endpoint`) — the same self-authored, last-writer-wins, in-band advert
shape as signing-key rotation (ordering-auth §5). It is authored by the device itself (so the device
controls its own address; the natural first carrier is the joiner's mandatory post-join healing update),
stamped on change and **re-adverted opportunistically on `coverage`** frames so a late/offline joiner
reconverges on every member's address the same way coverage reconciles heads. Receivers keep a
`device → endpoint` table, LWW by the author's own `seq` (a device is a single author, so its seq totally
orders its adverts). The seal/delivery layer resolves each recipient's fingerprint → endpoint locally (no
network lookup — learned in-band exactly as prekeys are, §11.4) and emits `(recipient, url, sealed
envelope)`; the literal `POST url` is the transport's job. Welcome frames carry no in-band url — they are
routed via the recipient's public `at.atsms.inbox` record.

**Granularity is a device policy, not a protocol fork.** Because the advert rides a group-scoped,
self-authored op, the mechanism is inherently **per-(device, group)**. What a device *puts* there is
policy:

- **v1 (reuse policy):** one `https://…` URL per device, reused across all its groups. Simplest; links a
  device's traffic across groups at whoever operates the endpoint. Appropriate when the device trusts its
  endpoint operator.
- **post-v1 (per-group tokens):** a distinct opaque token per (device, group), so the endpoint operator
  cannot correlate a device's group memberships and cross-group members cannot discover each other's
  mailboxes. **No wire change** — purely what the device writes into the same `endpoint` slot.

**Why the split matters for abuse (normative rationale).** The tempting claim — "the conversation address
is unpublished, so it cannot be spammed" — is wrong twice, and implementers should not repeat it.

First, it is not true under the v1 reuse policy: both addresses are the same string, derivable from the
DID, so there is no abuse benefit until per-group tokens land. Second, even then it is *scoping*, not
immunity — every member of a group knows your conversation address for that group, so the property is
"only parties you admitted can reach it," which is admission control rather than anti-abuse.

The real benefit is this: **the split concentrates the anonymous-ingress surface onto one low-volume
address, and low volume is what makes expensive controls affordable.** Proof-of-work, a rate limit that
actually bites, or a micropayment cannot be imposed on every message in a conversation — any control
strong enough to deter spam would tax all legitimate traffic. It can be imposed on *first contact*,
because first contact is rare. So the split does not make spam impossible; it makes spam controls
affordable, by isolating the one channel that must accept traffic from strangers and keeping it quiet
enough to price. Admission-control mechanisms belong on the introduction address for exactly this reason
(§7 ingress quotas; inbound admission control is tracked separately).

**Known gap — a removed member keeps a working conversation address.** Changing the address is a
group-visible event (below), so it does not rotate on removal, and the removed device retains a usable
address for every member. It cannot inject anything: it no longer holds the epoch key, so recipients
fetch and drop. But it can still *make you fetch*. This is the same shape as the callback-token problem
in §11.6 and likely wants the same answer — expiry with re-advertisement, rather than explicit
revocation. Unresolved.

**Accepted tradeoffs.** (1) The endpoint lives in *signed group state*, so changing it is a group-visible
(authenticated) event — normally desirable (the people who message you learn your address changed).
(2) **Recovery** relies on re-`welcome` (a member that loses group state re-bootstraps via the public
`at.atsms.inbox` record), so **no public conversation-address record is required**. (3) `url` may be `null` transiently
(recipient's advert not yet processed); the transport holds/retries — envelopes are never mis-delivered,
only delayed.

## 13. Test obligations

1. **Seal/unseal vectors** (wire-format.md §8): known-key envelopes for both contentTypes, all buckets;
   trial-decrypt across rotation (current key, grace key, neither → silent drop, no state change).
2. **Padding discipline**: writer always lands on a bucket; reader rejects nonzero pad bytes; oversize
   input → blob offload, never an oversized envelope.
3. **Classifier resistance test** (the property, not just the mechanism): generate a scripted mixed
   workload (app chatter, update + ack storm, join with welcome, repair) and assert the provider-visible
   trace (sizes + counts per mailbox) yields no better-than-chance classification of message class within
   a bucket.
4. **EnvelopeID dedup**: redelivered envelope produces exactly one delivery upstream; dedup happens before
   any HPKE operation (assert via instrumented crypto provider).
5. **Anonymous-ingress integration**: push with no credentials succeeds; push exceeding size cap / rate
   limit rejected; JWT still required on fetch.

6. **Sealed-sym vectors**: tag derivation/lookup (incl. multi-hit trial-open); per-recipient nonce/ct
   uniqueness across a fan-out (assert no two recipient copies share bytes); unknown-tag buffering then
   resolution after `update` processing; grace-epoch recognition after simulated offline gap; mode-misuse
   rejection (asym where sym established, and vice versa).

## 14. Open questions (tracked for review)

- **Padding buckets** (§5): 1–64 KiB powers-of-two are PROPOSED — sign-off needed (registered in
  [`parameters.md`](./parameters.md)).
- **A larger top bucket** — deferred, decide before the buckets are signed off. Two things currently
  hit the 64 KiB ceiling and take the oversize path: **welcomes** in a group with any history
  ([`../KNOWN-ISSUES.md`](../KNOWN-ISSUES.md) #10), and any **in-band image** worth looking at. Both
  would fit comfortably under a 128 or 256 KiB top bucket.
  The argument against is the one §5 is built on: every bucket added is an extra size class an observer
  can distinguish, and the top bucket is the emptiest and therefore the most identifying — an envelope
  in it would be close to a label reading *welcome, or a picture*.
  The argument for is that the alternative is not smaller envelopes, it is blob offload, which is a
  second round trip, a second thing to host, and a second place for metadata to leak.
  Note that a larger bucket does **not** fix welcome growth: welcomes grow monotonically, so a bigger
  ceiling buys rounds, not a solution. Checkpointing is the fix; this is about whether the ceiling is
  in the right place for content that is legitimately large.
- **A smaller bottom bucket** — deferred, decide alongside the above; **the recommendation is not to**.
  The floor is measured: an app frame with an *empty* body is **267 B** and `"ok"` is **269 B** — a
  32-byte group id, the sender DID and its 32-byte fingerprint, a 32-byte dep hash, a 64-byte signature,
  the counters, and the sealed body. Content is almost none of it; 500 characters still fits in 770 B.
  So **512 B is the smallest bucket that could exist**, and 256 B cannot hold even an empty message.
  The saving would be real — 1081 B on the wire becomes 569 B, and under profile 1 that is multiplied by
  every recipient device (a 25-device group: 25.3 KiB per message down to ~13.3 KiB).
  The reason not to is §5's own argument. The 1 KiB floor was chosen *because* it is large enough to
  swallow several classes at once: acks (~300 B), reactions (~270 B), short texts, and repair requests
  are today one indistinguishable size on the wire. A 512 B bucket splits that set — reactions and acks
  fall below it, ordinary texts above — and the class it exposes is the worst one to expose. Acks follow
  every membership operation as a burst of n−1 envelopes, which §5 names as the classifier padding
  exists to defeat; make them identifiable by size and an observer reads "the group just changed, and
  here is how big it is" out of traffic it cannot decrypt.
  If this is ever revisited, the question to answer first is whether acks can be made to land in the
  same bucket as short texts by some other means — that, not the bucket boundary, is the property worth
  preserving.
- **Ingress quotas** (§7): 600 envelopes / 20 MB per mailbox-hour are PROPOSED operator defaults.
- **Unlinkable sender tokens** (§7): post-v1 hardening — design not started; revisit after v1 alpha
  traffic data exists.
- **Per-group delivery tokens** (§12): the endpoint slot is per-(device, group) already; v1 ships the
  reuse policy (one https URL per device). Per-group opaque tokens (no wire change) are the post-v1
  tightening for devices that don't trust their endpoint operator — revisit alongside unlinkable sender
  tokens.
- ~~Non-welcome delivery addressing~~ **decided 2026-07-25 (user sign-off)**: advertised **in-band** in
  the signed frame `ext` (§12), not a public record; welcome stays the only public address
  (`at.atsms.inbox`, singleton `self`; its transport floor later inverted to `https:` by D15). "Provider" dropped as a protocol concept.
- ~~**Group drop-point sealing**~~ — moved out of this spec 2026-08-11. It was carried here as a
  "deferred profile" while being defined only in a superseded document, which is how a proposal ends up
  looking decided. It is now [`proposals/0001`](../proposals/0001-group-drop-point.md), status DRAFT, and
  nothing in this specification depends on it.
- ~~Symmetric envelope mode~~ **decided 2026-07-20 (user sign-off)**: `sealed-sym` for all
  in-conversation traffic (§11); asym reserved for bootstrap-class. Per-recipient PRF tags, full-width
  (mod-P truncation dial considered and rejected for simplicity); per-recipient fresh-nonce re-encryption
  mandatory.
- **Sym grace-retention window** (§11.4): covered-by-all capped at 30 d (= `T_EPOCH_GRACE`) is PROPOSED —
  confirm alongside the other repair-aligned constants.
- ~~Sealing key vs signed prekey~~ **decided 2026-07-22 (user sign-off, D9/D10)**: merged — `sealed-asym`
  seals to `at.atsms.prekey.signedPrekey`; the sealing cert type is deleted; the encryption floor is HPKE
  to raw keys (CMS = `SignedData` only, §10). Joint-use security argument in identity-devices §3.1;
  external-review obligation stands (overview §6.13).
