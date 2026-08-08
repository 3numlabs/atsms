# spec/wire-format.md — Wire Formats, Versioning & Test Vectors

> **Status: DRAFT v0.3 (2026-07-24) — for review.** *(v0.2: D11 — `ack` class and 2SM/X3DH structures
> retired; CGKA op payloads re-drafted around BeeKEM `PathChange`; classes renumbered while renumbering
> is still free. v0.3: **D12** — base wire pinned to the strict deterministic **DRISL** CBOR profile and
> made **map-free**; `ext` is now opaque bytes with a positional `ExtBody` (§1/§1.1/§3.2). Postcard and
> protobuf evaluated and rejected — §1.1.)* [Protocol] · Phase 0 deliverable.
> Closes gap **G13** (wire formats, versioning, test vectors) from [`../docs/history/gap-analysis.md`](../docs/history/gap-analysis.md).
> Inputs: [`ordering-auth.md`](./ordering-auth.md) §2 (canonical bytes / MessageID contract),
> [`beekem-core.md`](./beekem-core.md) §3 (key-schedule labels) + the `beekem` crate's op/tree shapes
> (differential-oracle alignment), [`sealed-sender.md`](./sealed-sender.md) §3–§5, [`dgm.md`](./dgm.md)
> §2/§6. MUST/MAY per RFC 2119.
> This document **freezes the byte layer**: if a structure is not defined here, it is not on the wire.

## 1. Encoding profile: strict deterministic CBOR (DRISL profile, map-free)

*(v0.3 2026-07-24 — profile pinned to DRISL and the base wire made map-free; rationale + alternatives in
§1.1.)*

The base wire is **CBOR restricted to the [DRISL] deterministic profile**, which is itself a subset of
CBOR Core (RFC 8949 §4.2.1), **further constrained here to be map-free**:

- Integers and lengths in shortest form; **definite lengths only** (no indefinite-length items).
- **No floats, no tags** (DRISL permits Tag 42 for CIDs; we do not use it yet and reject all tags), no
  `undefined`. Absent optional values are `null`.
- **No maps anywhere on the signed wire.** DRISL already forbids non-string map keys; we take that to its
  clean conclusion and forbid maps outright. Every structure is a **fixed positional array**, so there is
  no key-ordering or duplicate-key surface to police — the subtlest class of CBOR canonicalization bug is
  removed *by construction*, not by a runtime check. The one former map — `FrameBody.ext` — is now an
  **opaque byte string** with a positional interior (§3.2). Codecs MUST reject a map (major type 5) on the
  base wire.
- **Optionality and forward extension** live in positional slots (`null` when absent) or in the opaque
  `ext` bytes — never in variable array length or dynamic keys.
- **Never re-encode**: signatures and MessageIDs are computed over, and verified against, the received
  bytes. Implementations MUST store received canonical bytes alongside decoded views (the retained-message
  store, beekem-core §2, holds bytes). Readers MUST reject non-canonically-encoded or out-of-profile
  signed structures.

The application-payload layer is **not** bound by this profile (atsms-integration.md §5): an
`ATSMSMessagePayload` is opaque `bytes` to the base — covered by the frame signature as a unit, never
canonicalization-sensitive — so it MAY use self-describing, extensible CBOR (maps and all) freely. Strict
where a hash or signature depends on it; flexible everywhere else.

### 1.1 Framing-format rationale (evaluated 2026-07-24)

The base layer is cryptographically load-bearing: signatures and content-addressed IDs are taken over its
exact bytes, so a format that is **deterministic by construction** matters more than raw compactness.
Three options were weighed:

- **Postcard** (the iroh/serde binary format) — bijective by construction (malformations are
  ungrammatical, not merely rejected), the smallest canonicalization surface. **Rejected** because it is
  non-self-describing and Rust-serde-centric: it raises the bar for third-party/multi-language
  implementers of an open, multi-polar protocol, has no CID/content-addressing story, and still needs a
  language-neutral byte spec anyway. It also bundles a de-facto pull toward a Rust base (reversing D3).
- **Protobuf** — **rejected** outright for the signed base: protobuf serialization is explicitly *not*
  guaranteed deterministic (field ordering, default omission, unknown fields), a well-known footgun under
  signatures.
- **CBOR, strictly profiled (chosen)** — self-describing, multi-language, an IETF standard reviewers know,
  natively content-addressable, and aligned with our ATProto stack (whose repos use dag-cbor). Its one
  weakness — that determinism is *enforced*, not *constructed* — is narrowed two ways: (1) **anchoring the
  strictness to [DRISL]** (a published deterministic-CBOR profile, edited within the ATProto ecosystem)
  rather than a bespoke rule set — a more defensible, conformance-checkable narrative than "our own strict
  CBOR"; and (2) **removing maps from the base wire**, which deletes the largest remaining enforcement
  surface. Size was not a factor: measured framing differences vs Postcard are ~5–8% and are neutralized
  by the padding buckets (sealed-sender §5), which round every envelope to a fixed size regardless.

On DRISL's newness (published 2026-07-17, no conformance suite yet): we depend on it as the **specification
we align our strictness to**, not on any runtime maturity — our frozen test vectors (§9) are the
known-answer tests, and contributing/adopting DRISL's own vectors when they land closes the gap.

Primitive conventions:

| Type | Encoding |
|---|---|
| `MessageID` / `OpID` / `GroupID` / `fingerprint` / hash | `bstr` (32 bytes) |
| public key (X25519 / Ed25519) | `bstr` (32 bytes, raw) |
| signature (Ed25519) | `bstr` (64 bytes) |
| signature (ECDSA-P256, identity layer only) | `bstr` (raw r‖s, 64 bytes) |
| `seq` / `ctrlSeq` / `generation` / counters | `uint` (< 2⁶³; JS implementations MUST use BigInt-safe decoding — no precision loss) |
| `DID` | `tstr` (the full `did:…` string) |
| `DeviceID` | `[ did: tstr, fingerprint: bstr32 ]` (dgm.md §2; fingerprint = SHA-256 of the raw public-key point, identity-devices §2 = the `at.atsms.x509` rkey) |
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
                ext:      bstr ]                ; §3.2; opaque ExtBody bytes, zero-length when empty

SignedFrame = [ body: bstr(FrameBody), sig: bstr64 ]   ; body embedded as a byte string
MessageID   = SHA-256( body ‖ sig )
```

- `sig` is Ed25519 under the sender's current **protocol signing key** (ordering-auth §5) over the
  embedded `body` bytes. Embedding the body as a `bstr` makes signature input framing unambiguous.
- The signature covers `ext` (it is inside `body`): piggybacked attachments (the consistency digest,
  dgm.md §8) are authenticated, per the 2026-07-16 attachment-only decision.

### 3.1 Class registry

*(Renumbered 2026-07-22 — the `ack` class is retired by D11; numbering stays free until the Phase 1
freeze, §11.)*

| `class` | Name | `ctrlSeq` | Payload → §4 |
|---|---|---|---|
| 1 | `control` | uint | §4.1 |
| 2 | `welcome` | uint | §4.3 |
| 3 | `app` | null | §4.4 |
| 4 | `repair` | null | §4.5 |

### 3.2 `ext` — opaque bytes, positional `ExtBody` interior

*(v0.3 2026-07-24 — was an int-keyed CBOR map; now opaque bytes so the base wire stays map-free, §1.)*

`FrameBody.ext` is an **opaque byte string** to the base codec — bijective (minimal length header +
payload), covered by the frame signature, and preserved verbatim by any reader. Empty extensions encode
to a **zero-length** `ext`. Only parties that understand extensions decode the interior:

```
ExtBody = [ version:  uint,                                   ; 1
            digest:   [ bstr32, [ * bstr32 ] ] / null,        ; consistency digest + heads (dgm §8)
            rotation: bstr32 / null,                          ; nextSigningPubKey (ordering-auth §5)
            appHW:    [ * [ epochId: bstr32, hiGen: uint ] ] / null,  ; app high-water (§8.1, DESIGNED)
            endpoint: tstr / null ]                           ; in-band non-welcome delivery URL (sealed-sender §12)
```

- **Fixed positional array** — exactly one encoding per set of extensions, by construction (absent fields
  are `null`; no dynamic keys to sort). `digest` rides on `coverage` frames; `rotation` on
  `create`/`update`/`remove` control frames; `endpoint` on any control frame the device authors when its
  address changed, plus opportunistically on `coverage` (sealed-sender §12); all covered by the frame
  signature.
- **Forward-compat by length tolerance**: new fields are **appended as trailing positional slots** under
  the same `version` — an older reader destructures only the slots it knows and ignores the rest; a newer
  reader treats a shorter (older-encoded) array's missing trailing slots as absent. `endpoint` was added
  this way (no version bump). A `version` bump is reserved for a change that *reinterprets* existing slots;
  an unrecognized `version` leaves the interior unparsed while the raw bytes stay signed (the "unknown
  extensions preserved" property, without a map).
- *(The retired ack attachment (D11) simply does not exist in `ExtBody`.)*

## 4. Class payloads

### 4.1 `control`

```
ControlPayload = [ opType: uint, args ]          ; dms field retired with 2SM (D11) — key material for
                                                 ; the group rides inside PathChange secret stores
```

| `opType` | Name | `args` |
|---|---|---|
| 1 | `create` | `[ initialDevices: [ * [ device: DeviceID, leafPk: bstr32 ] ], initialAdmins: [ * tstr DID ] ]` (leafPk = the device's verified `signedPrekey`, pinned) |
| 2 | `add` | `[ device: DeviceID, leafPk: bstr32, leafIndex: uint ]` (the new Membership = `(device, this op's MessageID)` — §2; leafPk = verified `signedPrekey`, pinned; final position deterministic after concurrent-add re-sort) |
| 3 | `remove` | `[ membership: Membership, removedKeys: [ * bstr32 ] ]` (merge bookkeeping, beekem-core §4.2) |
| 4 | `update` | `[ path: PathChange, rootCommit: bstr32 ]` (beekem-core §4.2/§4.3) |
| 5 | `grantAdmin` | `[ did: tstr ]` |
| 6 | `revokeAdmin` | `[ did: tstr ]` |
| 7 | `coverage` | `[]` (beekem-core §5 — the frame's `deps` are the content; natural digest carrier) |

```
PathChange      = [ leafIndex: uint,
                    newLeafPk:  bstr32,
                    removedKeys: [ * bstr32 ],             ; pks this update superseded (merge bookkeeping)
                    nodes: [ * SecretStoreNode ] ]         ; leaf-parent → root, one per path node
SecretStoreNode = [ nodePk: bstr32,
                    encrypterChildPk: bstr32,
                    secrets: [ * [ idx: uint, pairedPk: bstr32, nonce: bstr, ct: bstr ] ] ]
                                                           ; one entry per sibling-resolution member
                                                           ; (+ the encrypter's own-index copy)
```

*(Field-level layout mirrors `beekem::tree::PathChange` / the secret-store version shape and is frozen
against the ported implementation at Phase 1 — byte-compatibility with the Rust oracle is the design
constraint, beekem-core §3/§11.)*

### 4.2 `ack` — RETIRED (2026-07-22, D11)

Acks are gone (coverage replaces them — beekem-core §5). The class number was reclaimed in the §3.1
renumbering; `AckPayload`/`AckEntry` and ext key 1 MUST NOT be emitted.

### 4.3 `welcome`

```
WelcomePayload  = [ addOpId: bstr32, welcomeCt: bstr ]   ; welcomeCt = the WelcomeBody below, carried in
                                                          ; a sealed-asym envelope to the joiner's prekey
```

Welcome plaintext (deterministic CBOR):

```
WelcomeBody = [ checkpoint:  [ frontier: [ * bstr32 ], treeState: bstr ] / null,
                ops:         [ * SignedFrame ],           ; op suffix since the checkpoint (or since create)
                deliveryMap: [ * [ Membership, MailboxAddress ] ],
                profile:     uint ]                       ; fan-out profile, spec v1.1 §9 (1 = baseline)
```

`ops` are re-validated by the joiner (every signature; DGM evaluated by the joiner itself — dgm.md §6).
`checkpoint` is adder-asserted (pruned history cannot be re-validated — beekem-core §6): the same trust
the adder already has; the digest/`rootCommit` machinery is the abuse detector (dgm.md §8). A welcome
exceeding the largest padding bucket moves to blob offload (sealed-sender.md §5).

### 4.4 `app`

```
AppPayload = [ generation: uint, ct: bstr ]
```

Matches the p2panda oracle's `(ciphertext, generation)` shape. The epoch anchor is the frame's single
`deps` entry (ordering-auth §3); it appears **nowhere** in the payload or AEAD (beekem-core §7).
AEAD associated data = `enc(groupId ‖ senderMembership ‖ generation)` where `enc` is this profile's CBOR of
the 3-tuple.

### 4.5 `repair` (requests only)

```
RepairPayload = [ reason:   uint,
                  ranges:   [ * [ sender: Membership, fromSeq: uint, toSeq: uint ] ],  ; ctrlSeq ranges
                  ids:      [ * bstr32 ],
                  appRanges: [ * [ sender: Membership, epoch: bstr32, fromGen: uint, toGen: uint ] ] ]
                                                ; reason 5 only (§8.1); {} for other reasons
```

*(v0.3 2026-07-23: `appRanges` appended for app-message gap recovery, ordering-auth §8.1 — a trailing
positional field, so `reason 1–4` payloads that omit it stay wire-compatible; the field is DESIGNED, not
yet emitted.)*

| `reason` | Meaning |
|---|---|
| 1 | seq gap |
| 2 | unresolved dep |
| 3 | buffer overflow drop (ordering-auth §4.4) |
| 4 | *unassigned* (was reserved for `retry-signed-only`; retired with the OPK design, D11 — identity-devices §8) |
| 5 | *app-gap* — missing application messages by `(sender, epoch, generation)`, carried in `appRanges` (ordering-auth §8.1, DESIGNED) |

**Repair responses are not a class**: the responder re-delivers the requested retained `SignedFrame`s in
fresh sealed envelopes — frames are self-authenticating (author's signature, not the resealer's), and A5
dedup absorbs duplicates (ordering-auth §8).

## 5. 2SM messages — RETIRED (2026-07-22, D11)

`TwoSmMessage`, `X3dhHeader`, and the X3DH KDF layout (including its `DH4`/`KEM_ss` reserved slots) are
retired with 2sm.md — BeeKEM has no pairwise channel; group key material rides in `PathChange` secret
stores (§4.1) and welcomes ride `sealed-asym` (§4.3). The post-quantum reservation formerly carried by
`KEM_ss` now lives entirely in the envelope `suite` id (§6) — see overview §6.12 for the re-opened D8
position (the tree's DH-based path encryption is the remaining classical surface).

## 6. Sealed envelope

```
SealedEnvelope  = AsymEnvelope / SymEnvelope                      ; discriminated by mode (2nd element)

AsymEnvelope    = [ version: 1, mode: 1, suite: uint, enc: bstr32, ct: bstr ]
                  ; sealed-sender.md §3–§4. suite 1 = HPKE DHKEM(X25519); further values reserved
                  ; for the PQ hybrid (overview §6.12) — the phase-1 reservation.

SymEnvelope     = [ version: 1, mode: 2, tag: bstr8, nonce: bstr24, ct: bstr ]
                  ; sealed-sender.md §11: tag = Expand(envKey, "atsms-seal:v1:hint" ‖
                  ; enc(recipientMembership))[0..8]; XChaCha20-Poly1305 under
                  ; envKey = Expand(PcsKey_e, "atsms-seal:v1:sym" ‖ enc(senderMembership));
                  ; AAD = enc([version, mode, tag]).   (re-based 2026-07-22, D11)

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
| `atsms-beekem:v1:chain` | per-sender chain seed from `PcsKey_e` (beekem-core §3) |
| `atsms-beekem:v1:msgkey` / `:nonce` / `:next` | app-chain steps (beekem-core §3/§7) |
| *(tree-internal BLAKE3 contexts)* | defined by the `beekem` oracle (path ratchet, DH→symmetric key, SIV); adopted verbatim for byte-compatibility — enumerated in the `kdf/` vectors at Phase 1 (beekem-core §3, KDF-split PROPOSED) |
| `atsms-seal:v1` | sealed-asym HPKE info (sealed-sender.md §4) |
| `atsms-seal:v1:sym` | sealed-sym envelope key from `PcsKey_e` ‖ sender (sealed-sender.md §11.2, re-based 2026-07-22) |
| `atsms-seal:v1:hint` | sealed-sym per-recipient tag (sealed-sender.md §11.3) |
| `atsms-seal:v1:group` | *reserved* for the group drop-point epoch key (sealed-sender.md §11.6) |
| ~~`atsms-dcgka:v1:*`~~, ~~`atsms-2sm:v1:*`~~ | **retired 2026-07-22 (D11)** with dcgka-core/2sm; MUST NOT be assigned new meanings |

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
| `kdf/` | every §7 label incl. the oracle's tree-internal BLAKE3 contexts: (ikm, context/info) → output | `beekem` crate + reference implementation, hand-checked |
| `beekem/` | seeded scenario transcripts (create/add/remove/update, concurrent-update merge with conflict keys, membership-change replay, `PathChange` bytes, `PcsKey`s) | seeded `beekem` Rust crate, byte-compared below the seam; profile features on the explicit allowlist (beekem-core §11) |
| `profile/` | chain/eviction/coverage/checkpoint/`rootCommit` vectors (the ATSMS messaging profile above the seam) | reference implementation; **our frozen vectors pin the bytes** |
| `frames/` | FrameBody → MessageID vectors, incl. bootstrap zeroing (§2) and the opaque `ext` bytes (§3.2) | hand-written + reference implementation |
| `envelopes/` | seal/unseal per bucket and contentType; EnvelopeID | reference implementation |

*(Retired 2026-07-22 with D11: `x3dh/`, `2sm/`, and the p2panda/Java-prototype oracle roles — the
`beekem` crate is the sole differential oracle.)*

## 10. Sizes (informative)

| Item | Approx. size |
|---|---|
| FrameBody overhead (no payload) | ~120–180 B (the sender Membership dominates: DID string + 64 B of hashes) |
| SignedFrame overhead | + 64 B sig + framing |
| coverage frame | ~200 B → 1 KiB bucket |
| app frame (short text) | ~300–600 B → 1 KiB bucket |
| `update` at n = 150 (log₂ n ≈ 8 path nodes, single-key siblings) | **~2–3 kB → 4 KiB bucket** (was ~40 kB under DCGKA — the D11 headline; degrades toward O(n) only under heavy blanking/conflicts, healing on the next update) |
| `add` / `remove` | ~300–500 B → 1 KiB bucket (no key material — the following update carries it) |
| welcome (n = 150: checkpoint tree + op suffix) | tens of kB → top bucket or blob offload |
| AsymEnvelope overhead | ~70 B over the padded plaintext (X25519; + ~1.1 KB under the future ML-KEM hybrid suite) |
| SymEnvelope overhead | ~55 B over the padded plaintext (tag 8 + nonce 24 + AEAD tag 16 + CBOR) |

## 11. Open questions (tracked for review)

- ~~`dms` inside the signed control frame~~ **resolved by removal 2026-07-22 (D11)** — 2SM direct
  messages no longer exist; `PathChange` secret stores ride inside the signed `update` frame, keeping
  every property the `dms` design bought (one canonical frame/MessageID, signature-covered key material,
  fan-out-profile agnosticism) at ~1/15th the size.
- **`PathChange`/`SecretStoreNode` field layout** (§4.1) — mirrors the `beekem` crate; byte-frozen
  against the ported implementation when Phase 1 vectors are generated (beekem-core §11).
- ~~Bootstrap zeroing rule~~ **shrunk 2026-07-17**: the DeviceID/Membership split removed zeroed member
  references from payloads; only `groupId` + the create-sender's `admittedBy` remain (§2).
- ~~Member identity encoding~~ **decided 2026-07-17**: `MemberID` split into `DeviceID` + `Membership`
  (§1); `create`/`add` payloads name DeviceIDs, `remove` names a Membership.
- ~~`atsms-2sm:v1:x3dh-kdf` label~~ **retired 2026-07-22 (D11)** with the X3DH layer (§7).
- ~~Numeric enum freeze~~ **FROZEN 2026-07-22** — Phase 1 started (user sign-off): the §3.1/§4.1/§4.5/§6
  class/opType/reason/contentType/mode/suite assignments as printed are final for v1; any change from
  here is a version break.
- ~~Envelope modes~~ **decided 2026-07-20**: two-mode `SealedEnvelope` (§6) — asym (bootstrap-class, with
  KEM `suite` id reserved for the PQ hybrid) and sym (in-conversation, per-recipient PRF tag lookup); the
  X3DH KDF gains a reserved `KEM_ss` slot (§5). A mod-P truncated-tag variant was considered and rejected
  (sealed-sender §14).

<!-- External Links -->
[DRISL]: https://dasl.ing/drisl.html
