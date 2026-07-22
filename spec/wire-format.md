# spec/wire-format.md — Wire Formats, Versioning & Test Vectors

> **Status: DRAFT v0.1 (2026-07-16) — for review.** [Protocol] · Phase 0 deliverable.
> Closes gap **G13** (wire formats, versioning, test vectors) from [`../gap-analysis.md`](../gap-analysis.md).
> Inputs: [`ordering-auth.md`](./ordering-auth.md) §2 (canonical bytes / MessageID contract),
> [`dcgka-core.md`](./dcgka-core.md) §3 (key-schedule labels), [`2sm.md`](./2sm.md) §4/§5,
> [`sealed-sender.md`](./sealed-sender.md) §3–§5, [`dgm.md`](./dgm.md) §2/§6, p2panda-encryption wire shapes
> (differential-oracle alignment). MUST/MAY per RFC 2119.
> This document **freezes the byte layer**: if a structure is not defined here, it is not on the wire.

## 1. Encoding profile: deterministic CBOR

All protocol structures are **RFC 8949 CBOR under the Core Deterministic Encoding Requirements (§4.2.1)**:

- Integers and lengths in shortest form; **definite lengths only** (no indefinite-length items).
- **No floats, no tags, no `undefined`** anywhere in protocol structures. Absent optional values are `null`.
- Map keys (used only in the `ext` slot, §3) are unsigned integers, sorted by their encoded bytes,
  no duplicates.
- **Frozen structures are fixed-length positional arrays** (compact, order-unambiguous); optionality and
  forward extension live in dedicated `ext` maps, never in variable array length.
- **Never re-encode**: signatures and MessageIDs are computed over, and verified against, the received
  bytes. Implementations MUST store received canonical bytes alongside decoded views (the retained-message
  store, dcgka-core §2, holds bytes). Readers MUST reject non-canonically-encoded signed structures.

Primitive conventions:

| Type | Encoding |
|---|---|
| `MessageID` / `OpID` / `GroupID` / `fingerprint` / hash | `bstr` (32 bytes) |
| public key (X25519 / Ed25519) | `bstr` (32 bytes, raw) |
| signature (Ed25519) | `bstr` (64 bytes) |
| signature (ECDSA-P256, identity layer only) | `bstr` (raw r‖s, 64 bytes) |
| `seq` / `ctrlSeq` / `generation` / counters | `uint` (< 2⁶³; JS implementations MUST use BigInt-safe decoding — no precision loss) |
| `DID` | `tstr` (the full `did:…` string) |
| `DeviceID` | `[ did: tstr, fingerprint: bstr32 ]` (dgm.md §2; fingerprint = SHA-256 of endpoint SPKI = the `at.atsms.x509` rkey) |
| `Membership` | `[ device: DeviceID, admittedBy: bstr32 ]` (dgm.md §2; `admittedBy` = MessageID of the admitting op) |
| `MailboxAddress` | `[ providerUrl: tstr, mailboxId: tstr ]` (spec v1.1 §7) |

## 2. Bootstrap zeroing rule (normative)

Only two fields are **self-referential at signing time** (a message cannot contain its own hash):

- In a `create` frame: `groupId` = 32 zero bytes (ordering-auth §2.1), and the **sender's** `admittedBy`
  = 32 zero bytes (the creator's admission *is* the `create`).
- After the frame's MessageID is computed, processors **normalize** both to that MessageID; all
  *subsequent* frames carry the normalized values.

Membership references never otherwise need zeroing *(simplified 2026-07-17 by the DeviceID/Membership
split)*: `create`/`add` payloads name **DeviceIDs** (§4.1) — the admitted Membership is *derived* as
`(device, this op's MessageID)`, never written on the wire — and a member's first frames always postdate
its admitting op. A zeroed field anywhere else is a validation error.

## 3. Frames (the ordering-layer unit)

```
FrameBody   = [ version: 1,
                groupId:  bstr32,          ; zero in create (§2)
                sender:   Membership,
                seq:      uint,            ; one per-sender counter across ALL classes
                ctrlSeq:  uint / null,     ; consecutive over control-plane classes; null for app/repair
                deps:     [ * bstr32 ],    ; per ordering-auth §3
                class:    uint,            ; §3.1
                payload:  <class-specific, §4>,
                ext:      { * uint => any } ]   ; §3.2; {} when empty

SignedFrame = [ body: bstr(FrameBody), sig: bstr64 ]   ; body embedded as a byte string
MessageID   = SHA-256( body ‖ sig )
```

- `sig` is Ed25519 under the sender's current **protocol signing key** (ordering-auth §5) over the
  embedded `body` bytes. Embedding the body as a `bstr` makes signature input framing unambiguous.
- The signature covers `ext` (it is inside `body`): piggybacked attachments are authenticated, per
  dcgka-core §12's attachment-only decision.

### 3.1 Class registry

| `class` | Name | `ctrlSeq` | Payload → §4 |
|---|---|---|---|
| 1 | `control` | uint | §4.1 |
| 2 | `ack` | uint | §4.2 |
| 3 | `welcome` | uint | §4.3 |
| 4 | `app` | null | §4.4 |
| 5 | `repair` | null | §4.5 |

### 3.2 `ext` key registry

Unknown keys MUST be preserved for signature verification and ignored semantically (forward compatibility).

| Key | Contents | Semantics |
|---|---|---|
| 1 | `[ * AckEntry ]` (§4.2) | piggybacked acks (dcgka-core §5) — processed under control-plane rules regardless of the carrying frame's class |
| 2 | `[ digest: bstr32, heads: [ * bstr32 ] ]` | consistency digest + the sender's valid-op heads it was computed at (dgm.md §8) |

## 4. Class payloads

### 4.1 `control`

```
ControlPayload = [ opType: uint, args, dms: [ * [ recipient: Membership, ct: bstr ] ] ]
```

| `opType` | Name | `args` |
|---|---|---|
| 1 | `create` | `[ initialDevices: [ * DeviceID ], initialAdmins: [ * tstr DID ] ]` |
| 2 | `add` | `[ device: DeviceID ]` (the new Membership = `(device, this op's MessageID)` — §2) |
| 3 | `remove` | `[ membership: Membership ]` |
| 4 | `update` | `[]` |
| 5 | `grantAdmin` | `[ did: tstr ]` |
| 6 | `revokeAdmin` | `[ did: tstr ]` |

**`dms` — direct messages ride inside the signed frame (normative decision, flagged for review §10).**
`create`/`update`/`remove` carry their per-recipient 2SM ciphertexts (seed secrets) as `dms`, sorted by the
recipient Membership's encoded bytes; `add`/`grant`/`revoke` carry `[]`. Rationale:

- **One canonical frame** → one MessageID for all recipients, which the whole ordering/ack design assumes.
- **Authenticity for free**: 2SM ciphertexts are not independently signed (2sm.md §7); inside the frame
  they are covered by the frame signature, exactly the "authenticity is the ordering layer's job" split.
- **Fan-out-profile agnostic**: the identical bytes work for per-recipient envelopes and the future group
  drop-point (spec v1.1 §9).
- Cost: every member downloads all n ciphertexts (~250 B each → ~37 kB at n = 150) — this *is* the paper's
  measured ~40 kB/update envelope (G16 budget); it is not new overhead, only made explicit.

Recipients locate their own entry by Membership match; entries for others are opaque.

### 4.2 `ack`

```
AckPayload = [ * AckEntry ]                      ; one frame MAY ack several ops (batching)
AckEntry   = [ ackedId: bstr32,
               ackType: uint,                     ; 1 = ack, 2 = add-ack
               dm: bstr / null ]                  ; add-ack: 2SM ct to the joiner (own ratchet state,
                                                  ; dcgka-core §4); plain ack: a Forward 2SM ct when the
                                                  ; concurrent-add rule applies (§6.2.5), else null
```

The same `AckEntry` array shape is used for piggybacked acks (`ext` key 1).

### 4.3 `welcome`

```
WelcomePayload  = [ addOpId: bstr32, welcomeCt: bstr ]   ; welcomeCt = TwoSmMessage (§5) to the joiner
```

Decrypted welcome plaintext (deterministic CBOR):

```
WelcomeBody = [ dgmState:      [ ops: [ * SignedFrame ], ackMatrix: [ * [ Membership, [ * bstr32 ] ] ] ],
                ratchetStates: [ * [ Membership, chain: bstr32 ] ],
                deliveryMap:   [ * [ Membership, MailboxAddress ] ],
                profile:       uint ]                     ; fan-out profile, spec v1.1 §9 (1 = baseline)
```

`dgmState.ops` are the retained (not-yet-pruned) membership-op SignedFrames — the joiner re-validates every
signature and evaluates the DGM itself (dgm.md §6). `ackMatrix` (who has acked which OpIDs) is
adder-asserted: its integrity rests on the adder, the same trust the adder already has (it could equally
omit ops); the insider-divergence digest is the detector for abuse (dgm.md §8). A welcome exceeding the
largest padding bucket moves to blob offload (sealed-sender.md §5).

### 4.4 `app`

```
AppPayload = [ generation: uint, ct: bstr ]
```

Matches the p2panda oracle's `(ciphertext, generation)` shape. The epoch anchor is the frame's single
`deps` entry (ordering-auth §3); it appears **nowhere** in the payload or AEAD (dcgka-core §7).
AEAD associated data = `enc(groupId ‖ senderMembership ‖ generation)` where `enc` is this profile's CBOR of
the 3-tuple.

### 4.5 `repair` (requests only)

```
RepairPayload = [ reason: uint,
                  ranges: [ * [ sender: Membership, fromSeq: uint, toSeq: uint ] ],
                  ids:    [ * bstr32 ] ]
```

| `reason` | Meaning |
|---|---|
| 1 | seq gap |
| 2 | unresolved dep |
| 3 | buffer overflow drop (ordering-auth §4.4) |
| 4 | *reserved*: `retry-signed-only` (2sm.md §10 — lands with the OPK design if option B is confirmed) |

**Repair responses are not a class**: the responder re-delivers the requested retained `SignedFrame`s in
fresh sealed envelopes — frames are self-authenticating (author's signature, not the resealer's), and A5
dedup absorbs duplicates (ordering-auth §8).

## 5. 2SM messages

```
TwoSmMessage = [ version: 1,
                 keyClass:  uint,               ; 1 = prekey (X3DH bootstrap), 2 = receivedKey, 3 = ownKey
                 usedIndex: uint,               ; per 2sm.md §4 header
                 bootstrap: X3dhHeader / null,  ; non-null iff keyClass = 1
                 ct:        bstr ]              ; HPKE ct (2sm.md §4.2 tuple, or X3DH first message)

X3dhHeader   = [ ephPk:            bstr32,      ; initiator's ephemeral X25519
                 initiatorIdentityDh: bstr32,   ; initiator's identityDh pub (verifiable against its
                                                ; at.atsms.prekey record; carried so the responder can
                                                ; process offline, verify against PDS opportunistically)
                 usedSignedPrekey: bstr32,      ; the responder prekey pub used (selects current vs grace)
                 usedOpk:          bstr32 / null ]  ; reserved null until the OPK design lands
```

The X3DH KDF layout reserves two trailing slots (both absent in v1 baseline):
`IKM = 0xFF×32 ‖ DH1 ‖ DH2 ‖ DH3 [‖ DH4] [‖ KEM_ss]` — DH4 for the deferred OPK (2sm.md §5.0.1),
`KEM_ss` for the post-quantum hybrid's encapsulated shared secret (2sm.md §5.2 / overview §6.12; the
phase-1 reservation). HKDF-SHA256 with info `atsms-2sm:v1:x3dh-kdf` (§7), salt = 32 zero bytes,
AD = `enc(initiator Membership ‖ responder Membership)`.

## 6. Sealed envelope

```
SealedEnvelope  = AsymEnvelope / SymEnvelope                      ; discriminated by mode (2nd element)

AsymEnvelope    = [ version: 1, mode: 1, suite: uint, enc: bstr32, ct: bstr ]
                  ; sealed-sender.md §3–§4. suite 1 = HPKE DHKEM(X25519); further values reserved
                  ; for the PQ hybrid (overview §6.12) — the phase-1 reservation.

SymEnvelope     = [ version: 1, mode: 2, tag: bstr8, nonce: bstr24, ct: bstr ]
                  ; sealed-sender.md §11: tag = Expand(envKey, "atsms-seal:v1:hint" ‖
                  ; enc(recipientMembership))[0..8]; XChaCha20-Poly1305 under
                  ; envKey = Expand(I_sender, "atsms-seal:v1:sym"); AAD = enc([version, mode, tag]).

SealedPlaintext = [ contentType: uint, body: bstr, pad: bstr ]    ; both modes; padded per sealed-sender.md §5
```

| `contentType` | `body` |
|---|---|
| 1 | a `SignedFrame` (§3) |
| 2 | a CMS `SignedData` (X509-floor mode, sealed-sender.md §10) |
| 3 | *reserved*: blob reference `[ blobUrl: tstr, contentKey: bstr32, contentHash: bstr32, innerType: uint ]` (profile-3 offload of an oversize `body` of type `innerType`) |

`EnvelopeID = SHA-256(serialized envelope)` (pre-decryption dedup, sealed-sender.md §3).

## 7. Domain-separation label registry

Single authoritative list of every derivation label / info string (owners shown; a label change is a
version break):

| Label | Used in |
|---|---|
| `atsms-dcgka:v1:member` / `:update` / `:chain` / `:welcome` / `:add` / `:msgkey` / `:nonce` / `:next` | dcgka-core §3 key schedule |
| `atsms-2sm:v1:msg` | 2SM steady-state HPKE info (2sm.md §3) |
| `atsms-2sm:v1:x3dh` | 2SM first-message HPKE info (2sm.md §3) |
| `atsms-2sm:v1:x3dh-kdf` | X3DH HKDF info (§5 — **assigned here**, flagged §10) |
| `atsms-seal:v1` | sealed-asym HPKE info (sealed-sender.md §4) |
| `atsms-seal:v1:sym` | sealed-sym envelope key from `I_sender` (sealed-sender.md §11.2) |
| `atsms-seal:v1:hint` | sealed-sym per-recipient tag (sealed-sender.md §11.3) |
| `atsms-seal:v1:group` | *reserved* for the group drop-point epoch key (sealed-sender.md §11.6) |

## 8. Versioning & negotiation

- **No in-band negotiation** — store-and-forward has no handshake. The sender chooses formats from the
  recipient's published capability records ([`atsms-integration.md`](./atsms-integration.md): presence of
  `at.atsms.prekey` = DCGKA-capable); `version` fields let receivers fail cleanly, not negotiate.
- v1 receivers MUST reject frames/envelopes with `version ≠ 1` (surfaced, not silent), MUST ignore unknown
  `ext` keys (§3.2), and MUST tolerate any padding length (sealed-sender.md §5). That asymmetry — strict on
  version, tolerant on extensions — is the forward-compat contract.
- A future incompatible version adds a `versions` array to the `at.atsms.prekey` record so senders can
  select; defining that field is deliberately deferred until a v2 exists.

## 9. Test-vector suite (normative deliverable, G13)

Frozen vectors live in `test-vectors/` (this repo), version-controlled, generated once and reviewed —
implementations MUST pass all of them. Format: JSON files, byte fields hex-encoded, each vector carrying a
prose `description`.

| Directory | Contents | Source of truth |
|---|---|---|
| `cbor/` | canonical-encoding cases + **rejection** cases (indefinite length, non-minimal int, float, unsorted/duplicate ext keys) | hand-written |
| `kdf/` | every §7 label: (ikm, info) → output | reference implementation, hand-checked |
| `x3dh/` | bootstrap vectors incl. grace-window prekey, zeroed-OPK slot | reference implementation |
| `2sm/` | seeded multi-message transcripts (rotation discipline, key deletion) | seeded p2panda `two_party` (byte-compare modulo documented deviations, 2sm.md §9) |
| `dcgka/` | scenario transcripts (create/add/remove/update/ack, concurrent §6.2.5 walkthrough) | seeded p2panda `message_scheme` at structure level; **our frozen vectors pin the bytes** (dcgka-core §11 allowlist for deviations) |
| `frames/` | FrameBody → MessageID vectors, incl. bootstrap zeroing (§2) and ext-key preservation | hand-written + reference implementation |
| `envelopes/` | seal/unseal per bucket and contentType; EnvelopeID | reference implementation |

The Java prototype (trvedata/key-agreement) is a **semantic** cross-check for DCGKA state transitions
only — its wire bytes are not authoritative for us (different serialization); p2panda is the byte-level
oracle where our deviations don't apply.

## 10. Sizes (informative)

| Item | Approx. size |
|---|---|
| FrameBody overhead (no payload) | ~120–180 B (the sender Membership dominates: DID string + 64 B of hashes) |
| SignedFrame overhead | + 64 B sig + framing |
| steady-state ack frame (1 entry) | ~250 B → 1 KiB bucket |
| app frame (short text) | ~300–600 B → 1 KiB bucket |
| update/remove at n = 150 (150 dms) | ~40 kB → 64 KiB bucket (the G16 envelope) |
| welcome (n = 150, modest history) | tens of kB → top bucket or blob offload |
| AsymEnvelope overhead | ~70 B over the padded plaintext (X25519; + ~1.1 KB under the future ML-KEM hybrid suite) |
| SymEnvelope overhead | ~55 B over the padded plaintext (tag 8 + nonce 24 + AEAD tag 16 + CBOR) |

## 11. Open questions (tracked for review)

- **`dms` inside the signed control frame** (§4.1) — drafted as normative for the reasons given; needs
  sign-off (the alternative — per-recipient side-cars with an in-frame hash list — re-opens DM
  authenticity and drop-point compatibility for ~37 kB saved per *download*, not per store).
- ~~Bootstrap zeroing rule~~ **shrunk 2026-07-17**: the DeviceID/Membership split removed zeroed member
  references from payloads; only `groupId` + the create-sender's `admittedBy` remain (§2).
- ~~Member identity encoding~~ **decided 2026-07-17**: `MemberID` split into `DeviceID` + `Membership`
  (§1); `create`/`add` payloads name DeviceIDs, `remove` names a Membership.
- **`atsms-2sm:v1:x3dh-kdf` label** (§7) — assigned in this draft; 2sm.md should adopt it on its next
  revision.
- **Numeric enum freeze** — class/opType/reason/contentType/mode/suite assignments freeze when Phase 1
  starts; until then renumbering is free.
- ~~Envelope modes~~ **decided 2026-07-20**: two-mode `SealedEnvelope` (§6) — asym (bootstrap-class, with
  KEM `suite` id reserved for the PQ hybrid) and sym (in-conversation, per-recipient PRF tag lookup); the
  X3DH KDF gains a reserved `KEM_ss` slot (§5). A mod-P truncated-tag variant was considered and rejected
  (sealed-sender §13).
