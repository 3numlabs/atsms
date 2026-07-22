# spec/sealed-sender.md — Sealed-Sender Envelope Layer

> **Status: DRAFT v0.3 (2026-07-22) — for review.** *(v0.2: two envelope modes — `sealed-sym` added, §11.
> v0.3: D9/D10 — `sealed-asym` targets the signed prekey; sealing cert removed.)* [Protocol] · Phase 0 deliverable.
> Closes gap **G9** (anonymous ingress, padding, key separation, envelope dedup) from
> [`../gap-analysis.md`](../gap-analysis.md); implements decision **D5** (anonymous relay ingress).
> Inputs: spec v1.1 §6 (construction + envelope-FS and X509-unification design notes), Signal sealed-sender
> design (inspiration only), [`identity-devices.md`](./identity-devices.md) §3.1/§4.2 (signed prekey, joint use),
> [`ordering-auth.md`](./ordering-auth.md) (the signed frame this layer wraps),
> [`wire-format.md`](./wire-format.md) §6 (byte layout). MUST/MAY per RFC 2119.

## 1. Role and scope

The sealed envelope is the **outermost cryptographic layer**: every ATSMS-DCGKA transmission — control,
ack, welcome, app, repair, and the 2SM direct messages riding inside them — crosses the network and rests
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
  pseudonymous per-recipient tag) — **all in-conversation traffic**: app, control, ack, and repair frames
  between established members. KEM-free, ~55 B overhead, envelope FS/PCS inherited from the ratchet, and
  quantum-safe as-is.

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

- **HPKE Base mode** (RFC 9180), `DHKEM(X25519, HKDF-SHA256)` + `HKDF-SHA256` + `ChaCha20-Poly1305` — the
  same suite as 2SM ([`2sm.md`](./2sm.md) §3). `info = "atsms-seal:v1"`. No PSK, no HPKE Auth mode (sender
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

- **Acks piggyback/batch** on outgoing frames (dcgka-core §5) — blunts the post-op ack burst.
- **No standalone digest frames** (dgm.md §8) — a quiet group emits no heartbeat pattern.
- Clients MAY add random send jitter (suggested 0–30 s for non-interactive frames like acks and digests;
  never for user-visible messages).
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
  Tracked as an open item (§13); the v1 position is that per-mailbox caps + the 150-device group envelope
  keep flood damage bounded and local.
- **North star check**: the relay stays dumb — after this change it learns *less* than today (mailbox +
  timing + size bucket; no sender identity on any push).

## 8. What the provider still learns (documented, accepted)

Per envelope: target mailbox, arrival time, size bucket, pusher IP (absent Tor). Across envelopes:
mailbox traffic volume and burst patterns; for the optional group drop-point profile, co-membership of
pullers (spec v1.1 §9 profile 2 — that profile's mitigations live there). The provider never learns:
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
at the 150-device max ≲ 0.15 s CPU per send — negligible next to the network fan-out.

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

All in-conversation traffic — `app`, `control`, `ack`, `repair` frames between established members — MUST
use `sealed-sym`. `sealed-asym` is reserved for bootstrap-class traffic (§1) and MUST NOT be used where a
sym key exists (a KEM there is pure cost). A receiver that cannot yet locate a sym envelope's key buffers
briefly (§11.4); senders never fall back to asym mid-conversation.

### 11.2 Key derivation

```
envKey(sender, epoch) = Expand(I_sender, "atsms-seal:v1:sym")
```

where `I_sender` is that sender's update secret for the epoch (dcgka-core §3). Every member derives every
member's update secrets (that is what acks do), so every member can open every sender's envelopes; nobody
outside the group can. Keys are inherently **per-group** (update secrets are per-group; 2SM meshes are
never shared across groups — 2sm.md §1), and **per-sender-epoch** — there is no group-global epoch, and
none is needed.

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

- Entries are added the moment a sender's new update secret is derived — including a joiner's first epoch,
  derived by existing members when they process the `add` (dcgka-core §4).
- A frame that *establishes* a new epoch (an `update`) rides under the sender's **pre-op** epoch key —
  receivers cannot hold the new one yet.
- **Unknown tag** → buffer briefly under the ordering-layer bounds (mirror of the unknown-Membership rule,
  ordering-auth §7) — it may precede the `add`/ack processing that creates the expected entry — else drop.
- **Grace retention**: superseded epoch `envKey`s are retained while their epoch's messages may still
  legitimately arrive — until that epoch's ops are acked-by-all, capped at `T_REPAIR_GIVEUP` (30 d)
  ([`parameters.md`](./parameters.md), PROPOSED) — so a receiver offline through several of a sender's
  epochs still recognizes the missed epochs' envelopes.

### 11.5 Security properties

- **Sender-hiding vs outsiders**: complete — tag and `ct` are pseudorandom; all identity lives inside.
- **Insiders**: any member can mint a well-formed group envelope; sender authenticity was never the
  envelope's job — it is the frame signature (ordering-auth §5). No regression.
- **Compromise scope**: a leaked `envKey` exposes envelope *metadata* of one sender-epoch of one group
  (never content), healed by the next update+ack — strictly narrower than a signed-prekey compromise
  (bootstrap-class envelope metadata across conversations for the ≤ 2-week key window, §9). Envelope
  FS/PCS = ratchet FS/PCS.
- **Post-quantum**: KEM-free — `sealed-sym` is quantum-safe as specified (overview §6, Tier 1), which
  confines the PQ-hybrid cost to the rare `sealed-asym` surface.
- **2SM invariant preserved**: 2SM ciphertexts continue to ride only *inside* signed frames inside
  envelopes and carry no cleartext fields (2sm.md §1.1) — sealed-sym changes where the wrap key comes
  from, not the nesting.

### 11.6 Relation to the drop-point profile

The reserved `atsms-seal:v1:group` label (wire-format §7) and the drop-point profile (spec v1.1 §9
profile 2) remain deferred; when scheduled, that profile will reuse this section's derivation machinery
with a deliberately *shared* ciphertext — accepting exactly the cross-puller correlation this section's
per-recipient rules exist to avoid. Documented trade, not an accident.

## 12. Test obligations

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
   resolution after `add` processing; grace-epoch recognition after simulated offline gap; mode-misuse
   rejection (asym where sym established, and vice versa).

## 13. Open questions (tracked for review)

- **Padding buckets** (§5): 1–64 KiB powers-of-two are PROPOSED — sign-off needed (registered in
  [`parameters.md`](./parameters.md)).
- **Ingress quotas** (§7): 600 envelopes / 20 MB per mailbox-hour are PROPOSED operator defaults.
- **Unlinkable sender tokens** (§7): post-v1 hardening — design not started; revisit after v1 alpha
  traffic data exists.
- **Group drop-point sealing** (spec v1.1 §9 profile 2, optional post-v1 mode): deferred; will build on
  §11's derivation machinery (see §11.6).
- ~~Symmetric envelope mode~~ **decided 2026-07-20 (user sign-off)**: `sealed-sym` for all
  in-conversation traffic (§11); asym reserved for bootstrap-class. Per-recipient PRF tags, full-width
  (mod-P truncation dial considered and rejected for simplicity); per-recipient fresh-nonce re-encryption
  mandatory.
- **Sym grace-retention window** (§11.4): acked-by-all capped at 30 d is PROPOSED — confirm alongside the
  other repair-aligned constants.
- ~~Sealing key vs signed prekey~~ **decided 2026-07-22 (user sign-off, D9/D10)**: merged — `sealed-asym`
  seals to `at.atsms.prekey.signedPrekey`; the sealing cert type is deleted; the encryption floor is HPKE
  to raw keys (CMS = `SignedData` only, §10). Joint-use security argument in identity-devices §3.1;
  external-review obligation stands (overview §6.13).
