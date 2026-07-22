# spec/identity-devices.md — Identity, Devices & Key Material

> **Status: DRAFT v0.2 (2026-07-22) — for review.** *(v0.2: D9/D10 applied — sealing cert type removed;
> the signed prekey is the sealed-asym recipient key, joint-use analysis in §3.1.)* [Protocol] · Phase 0 deliverable.
> Closes gaps **G6** (multi-device model at the group layer) and **G8** (prekeys on a public PDS; lexicon)
> from [`../gap-analysis.md`](../gap-analysis.md).
> Inputs: spec v1.1 §4/§4.1 (identity/device model, cert profiles — normative text consolidated here),
> [`dgm.md`](./dgm.md) §2/§4 (DeviceID/Membership, same-DID authorization), [`2sm.md`](./2sm.md) §5 (X3DH consumption),
> decisions D3/D4, the 2026-07-15/16 lexicon decisions. MUST/SHOULD/MAY per RFC 2119.
> **This document is the canonical home of the `at.atsms.prekey` record shape** (moved from 2sm.md §5.0)
> and of the two-certificate `at.atsms.x509` profile.

## 1. Identity model

- **Identity = the AT Protocol DID.** There is no separate ATSMS account concept. The DID's atproto
  verification key signs the repo commits that publish all ATSMS records; that signature chain is the root
  of every delegation below.
- **Delegation = publication.** A device is delegated by publishing its endpoint certificate as a record in
  the DID's repo. `DID → verificationKey → signed commit → MST inclusion → at.atsms.x509/<fingerprint> →
  cert public key` **is** the cryptographic delegation proof. Verifiers SHOULD check commit signature + MST
  inclusion; the alpha resolver's trust-the-PDS mode is a documented interim relaxation (umbrella
  architecture, multi-polar-trust phase).
- **PDS write access is account-level** — any logged-in device can write or delete any record. Every
  "only this device" property below therefore rests on **signature validity under a device-held key**,
  never on PDS access control. This asymmetry (account-level writes, device-level authority) drives the
  issuance-signature pairing design in §4.1 and the rotation invariant in §6.

## 2. Device model

- **The device identity IS the endpoint-certificate keypair** (`at.atsms.x509`, P-256 — kept for
  S/MIME/WebCrypto interop). No separate device keypair, no `device_id`.
- **Device fingerprint** = SHA-256 of the endpoint cert's SubjectPublicKeyInfo — **the device's sole
  protocol identifier**: it is the `at.atsms.x509` and `at.atsms.prekey` rkey (§4), the cert's SKI, the
  JWT `kid`, and the mailbox key (re-keyed from cert serial 2026-07-17; the serial survives only *inside*
  X509/CMS artifacts).
- **DeviceID** = `(DID, deviceFingerprint)` — the identity-layer handle. **Membership** =
  `(DeviceID, admittedBy)` — the group-layer identifier: one device's tenure in one group, where
  `admittedBy` = the admitting op's MessageID (dgm.md §2). A re-added device is a fresh Membership —
  prior 2SM/ratchet state MUST never be resumed (encoding in [`wire-format.md`](./wire-format.md) §1).
- Each device runs its own independent DCGKA instance per group and holds all of its private key material
  exclusively (nothing in §3 ever leaves the device).

## 3. Per-device key inventory (normative)

Strict purpose separation — a key appears in exactly one row and MUST NOT be used for any other row's
purpose (no cross-protocol reuse; gap G9 key-separation requirement), with **one deliberate, documented
exception**: the signed prekey serves both X3DH and the sealed-asym envelope (§3.1; D10 amends G9's
dedicated-sealing-key recommendation):

| Key | Algorithm | Lifetime | Purpose | Published as |
|---|---|---|---|---|
| Device identity (endpoint) key | ECDSA P-256 | ~10 y (device lifetime) | Device identity; signs all subordinate material; JWT mailbox auth; S/MIME floor | `at.atsms.x509` endpoint record |
| X3DH identity-DH key (`identityDh`) | X25519 | = device lifetime | X3DH long-term DH (the P-256 key cannot DH) | `at.atsms.prekey.identityDh` |
| Signed prekey | X25519 | 1 week (+1 week grace secret) | X3DH medium-term DH **and** sealed-asym HPKE recipient key (joint use, §3.1; [`sealed-sender.md`](./sealed-sender.md) §2) | `at.atsms.prekey.signedPrekey` |
| One-time prekeys | X25519 | single use | X3DH DH4 — **design deferred, ships pre-v1** (§8) | (deferred) |
| Protocol signing key | Ed25519 | per group; rotates on every own `update`/`remove`/`create` | Signs ordering-layer frames (ordering-auth §5) | never published — declared in create/welcome material, signed by the device identity key |
| 2SM / ratchet keys | X25519 / symmetric | per message / per epoch | [`2sm.md`](./2sm.md), dcgka-core §3/§7 | never published |

Trust chain: **DID repo → device identity cert → { prekey bundle, protocol signing keys }**.

### 3.1 Joint use of the signed prekey (D9/D10 — decided 2026-07-22)

The signed prekey is deliberately consumed by two protocols: **X3DH** (the DH1/DH3 legs, 2sm.md §5) and
**HPKE DHKEM** as the `sealed-asym` envelope recipient key (sealed-sender §2). This replaces the earlier
dedicated sealing cert (deleted; §10), under the relaxed encryption floor **D9**: X509/CMS is the
*identity + signing* floor only — every ATSMS encryption path is HPKE to a raw X25519 key resolved from
PDS records, so the sealed-to key never needed to be a certificate. Security argument, recorded so it is
never re-litigated:

- **KDF-label domain separation.** Both usages consume the key solely as X25519 DH input whose raw output
  is immediately bound into a labeled KDF: X3DH under `atsms-2sm:v1:x3dh-kdf` (with the 32×0xFF prefix,
  2sm.md §5), HPKE under RFC 9180's labeled `HPKE-v1`/suite-id derivation with `info = "atsms-seal:v1"`.
  The KDF transcripts cannot collide, and neither protocol ever exposes a raw DH output — so neither acts
  as a DH oracle for the other.
- **Bootstrap coincidence is fine.** An X3DH bootstrap message rides a `sealed-asym` envelope wrapped to
  the *same* signed prekey the X3DH inside it consumes — two independent sender ephemerals, two KDF
  labels; only the recipient static key is shared (2sm.md §1.1).
- **Precedent.** Signal's identity key serves X3DH, sealed sender, *and* XEdDSA signing — a strictly
  stronger reuse, shipped with commissioned analysis.
- **Compromise scope (bounded).** A leaked signed-prekey secret yields (a) sealed-asym envelope
  *metadata* of captured bootstrap-class envelopes and (b) the DH1/DH3 X3DH legs — but message content in
  neither role (DH2 requires the `identityDh` secret; envelope payloads keep ratchet FS/PCS). The window
  is weekly rotation + one-week grace — strictly tighter than the deleted sealing cert's 30–97 days.
- **Review obligation.** No off-the-shelf joint proof covers this exact pair; it is a `[deviation]`-class
  item for the Phase 6 external cryptographic review (overview §6.13).

Every other row remains strictly single-purpose — in particular, senders MUST NOT seal to `identityDh`,
the endpoint P-256 key, or any ratchet key (sealed-sender §2).

## 4. PDS records

### 4.1 `at.atsms.x509` — the endpoint certificate collection

**rkey = the fingerprint (SHA-256 of SPKI, lowercase hex) of the record's own key** — the rkey
self-certifies which key the record serves, and a same-key cert re-issuance updates the record in place
instead of minting a phantom new device. *(Re-keyed from cert serial, decided 2026-07-17: `serialNumber`
remains a required field inside the X509 artifact and CMS structures — `IssuerAndSerialNumber` etc. — but
is no longer a protocol identifier anywhere.)* The record carries `certificateType: "endpoint"` — the
only defined value. *(The second `"sealing"` type was **removed 2026-07-22 by D10**: sealed-asym
envelopes now target the prekey bundle's `signedPrekey` (§3.1, §4.2), so the collection is single-type
again; the ATSMS-sealing EKU OID, the `deviceCert` pairing field, and the AKI/SKI pairing rules are all
retired with it.)*

**Endpoint (device identity) cert** — unchanged from today's atsms-lib profile:

- Self-signed ECDSA P-256, `CN = DID`, SAN routing info, `CA = false`; EKUs unchanged (clientAuth,
  emailProtection, …). Validity ~10 years. The SAN's record-pointer URI follows the rkey change:
  `at://{did}/at.atsms.x509/{fingerprint}`.
- JWT-auth and S/MIME verifiers MUST require `certificateType == "endpoint"` semantics, enforceable from
  the EKU set alone — the EKUs remain the domain-separation guard should a second cert type ever return.
- The endpoint **record** additionally carries **`inviteAddress`** — the Welcome/invite destination
  (spec v1.1 §7) — as a mutable, MST-bound record field (moved here from the prekey bundle 2026-07-16).
  Layering criterion: *who consumes a field*, not its lifetime — classic S/MIME senders and JWT verifiers
  need identity + reachability and nothing else from this layer, so reachability lives in this collection
  (sealed senders additionally fetch the prekey bundle for the envelope key — §4.2, D10).
  `inviteAddress` is deliberately **not** device-signed: its integrity is liveness-only (a
  tampered address can only misroute sealed envelopes, never break confidentiality), so the DID-signed
  commit suffices. Updates are ordinary record updates.

- **SKI = SHA-256 of the public key (RFC 7093 method 1 profile)**, so the cert's SKI *equals* its
  record's rkey = the device fingerprint.

**Why no `CA = true` / PKIX path validation.** Chain semantics are split across two mechanisms:
*DID-level delegation* is proven by the signed-commit/MST chain (§1), and *device-level authority over
subordinate key material* (needed because PDS write access is account-level while the invariant is "a
device rotates only its own keys", §6) is proven by the endpoint key's **`bundleSig`** over the prekey
bundle (§4.2). Verifiers check direct ECDSA signatures — never RFC 5280 path building (the stack already
verifies `checkChain: false`) — so no cert needs the CA bit or `keyCertSign`.

**D9 note (decided 2026-07-22) — the certificate's role is identity + signing only.** The X509 layer
carries device identity, JWT auth, and CMS `SignedData`; it is never an encryption target on any ATSMS
path (the encryption floor is HPKE to raw keys — sealed-sender §10). Classic S/MIME `EnvelopedData` to
the P-256 endpoint cert survives solely for inbound mail from external, non-ATSMS senders.

### 4.2 `at.atsms.prekey` — the X3DH bundle (canonical shape)

One record per device — the always-available bootstrap bundle. **rkey = the device fingerprint**, so the
pairing with `at.atsms.x509/<fingerprint>` is structural (same rkey, two collections) and a DeviceID
resolves to its bundle with a single `getRecord`:

```
at.atsms.prekey (rkey = device fingerprint)
{
  $type:         "at.atsms.prekey",
  identityDh:    X25519Pub,        // device's long-lived X3DH identity-DH key — the X25519 alias of the
                                   // device identity (the P-256 cert key cannot DH); rotates only with
                                   // the device identity itself, constant across re-publishes
  signedPrekey:  X25519Pub,        // rotated WEEKLY (parameters.md)
  createdAt, expiresAt: datetime,
  bundleSig:     bytes             // ECDSA-P256 by the device identity key over the deterministic CBOR
                                   // of ALL preceding fields (prevents cross-generation mix-and-match)
}
```

Contains **only** E2EE bootstrap material (`identityDh` + `signedPrekey` + `bundleSig`). It has two
consumer classes: **every DCGKA bootstrap** (the signed prekey is a mandatory X3DH ingredient; the future
OPK is the optional fourth DH, never a substitute — 2sm.md §5.0.1) and, since **D10**, **every
`sealed-asym` sender** (welcomes, first contact, X509-floor one-shots seal to `signedPrekey` —
sealed-sender §2; joint-use analysis §3.1). `identityDh` stays here despite its long lifetime: only X3DH
consumes it (§4.1 layering criterion).

**Resolution & verification path (cert ↔ prekey pairing, normative)**:

1. `getRecord(repo = DID, collection = "at.atsms.x509", rkey = fingerprint)` → endpoint cert; require
   `certificateType == "endpoint"`, `SHA-256(cert SPKI) == rkey`, valid lifetime, not revoked. (Consumers
   holding a DeviceID resolve **directly** — the list-and-hash-match step the serial scheme required is
   gone.)
2. `getRecord(repo = DID, collection = "at.atsms.prekey", rkey = fingerprint)` → bundle.
3. Verify `bundleSig` against the endpoint cert's public key; check `expiresAt`.
4. (Target state) verify the MST/commit chain for both records; trust-the-PDS is the interim relaxation (§1).

**Rotation**: `signedPrekey` rotates **weekly**; the retained-secret grace window equals one full rotation
period — the device holds exactly two signed-prekey private halves (current + previous); each rotation
promotes current → previous and deletes the old previous. X3DHs computed against a just-superseded bundle
complete for up to a week; older ones fail and the initiator re-fetches ([`parameters.md`](./parameters.md)).
The same two live secrets serve `sealed-asym` trial-decryption — recipients trial-open incoming asym
envelopes against current + previous, unchanged in count from the deleted sealing cert's current + grace
pair (sealed-sender §4).

### 4.3 Record integrity target state

Both collections inherit the same proof discipline: DID-signed commit + MST inclusion (§1). Consumers MUST
treat record contents as attacker-controlled until `bundleSig` / issuance-signature / commit checks pass —
in particular, a hostile PDS can serve stale or mix-and-matched records, which the signatures (not the
transport) reject.

## 5. Multi-device at the group layer (G6)

- **The group-membership unit is the device.** 25 users × 3 devices = 75 DCGKA members; the protocol's
  "max 150" is a **device** budget ([`parameters.md`](./parameters.md)). All O(n) cost statements count
  devices.
- **User-level intents expand client-side into per-device ops** (dgm.md §4): "add user U" = one `add` per
  U-device discovered via U's PDS (`at.atsms.x509` + `at.atsms.prekey`, §4 resolution path); "remove user
  U" = a causally sequential batch of `remove` for every U-device in the author's current view. Batches
  have no atomicity semantics; the DGM validates each op individually.
- **Same-DID authorization**: any member device of a DID may add/remove that DID's *own* devices, regardless
  of role; cross-DID membership change requires admin (dgm.md §4). This is what makes device rotation (§6)
  possible without admin involvement.
- A user adding a device does so **in every group the user participates in** — the client iterates its
  group list and issues the adds; groups where the batch has not yet propagated simply don't include the
  new device yet (no global atomicity, by design).

## 6. Rotation, loss, and compromise — one mechanism, not three

A device identity keypair is **never updated in place** at the group layer:

- **Routine rotation (device rotates itself)**: generate the new endpoint keypair + cert; publish the new
  `at.atsms.x509` endpoint record (+ new `at.atsms.prekey`); in every group, perform a
  DCGKA `remove` of the old device's Membership and `add` of the new DeviceID (same-DID authorization,
  §5); then revoke the old records (§7). The new cert MAY be signed by the old key for continuity when the rotation is routine.
- **Loss / compromise (another device acts)**: any *other* device of the same DID performs the `remove` (no
  `add`) in every group, and revokes the lost device's records (§7). Compromise and loss need no
  protocol-level distinction: both reduce to "remove the device member" — exactly the operation that
  triggers DCGKA's PCS healing (dcgka-core §5/§10).
- **The invariant**: a device can rotate **its own** keypair; it can **remove — but never rotate —** other
  devices' keypairs. Enforced cryptographically, not by PDS ACLs: subordinate material is valid only under
  the owning device's `bundleSig` (§4.2), and same-DID group ops are signed by the acting
  device's protocol key chained to *its* endpoint cert (ordering-auth §5). A hijacked PDS session can
  delete records (a liveness attack, §7) but cannot mint valid key material for another device.

## 7. Revocation & record lifecycle (PROPOSED)

Deletion alone is a poor revocation signal: caches and firehose consumers that miss the delete keep serving
the record, and "absent" is indistinguishable from "never fetched". Revocation is therefore an **in-place
tombstone, then deletion**:

- **Revoke** = update the `at.atsms.x509` record, adding `revokedAt: datetime` (any device of the DID may
  write it — revocation is deliberately account-level: it only *reduces* authority, so the §6 invariant is
  not violated; a malicious co-device "revoking" another device is the same liveness attack as deleting the
  record, recoverable via account control).
- Verifiers MUST treat a cert with `revokedAt ≤ now` as invalid for **new** operations (new bootstraps, new
  sealing, new group adds). Already-established group memberships end via the DCGKA `remove` (§6), not via
  the tombstone — the group layer never consults the PDS for liveness of existing members.
- Revoking an endpoint record implicitly revokes everything it signed (the prekey bundle, via rkey
  pairing + `bundleSig`). The device's `at.atsms.prekey` record SHOULD be deleted at the same time.
- The tombstoned record is retained for a grace period (**30 d PROPOSED**, [`parameters.md`](./parameters.md))
  and MAY then be deleted.
- **Cache / firehose guidance**: consumers maintaining cert caches MUST process record updates and deletes
  (not only creates); SHOULD bound cache staleness for cert records (**≤ 24 h PROPOSED** without
  re-validation); and SHOULD re-fetch the live record before failing hard on a signature/pairing mismatch
  (the mismatch may be rotation, not attack).

## 8. One-time prekeys — deferred (pointer)

The OPK layer (X3DH DH4) is **deferred during prototyping and ships before v1**; the open serve-once
dispenser problem, the interim signed-prekey-only mode, and the mandatory post-join healing update are
specified in [`2sm.md`](./2sm.md) §5.0.1/§5.1. Whatever design lands (PDS checkout endpoint is the
candidate), the record/lexicon changes belong to this document and MUST preserve the §3 purpose-separation
rule and the §4.2 pairing discipline.

## 9. Test obligations

1. **Endpoint-record vectors**: valid endpoint cert accepted; wrong EKU / expired / revoked — rejected
   for JWT auth, S/MIME, and as the `bundleSig` verification parent.
2. **Bundle vectors**: valid bundle; `bundleSig` over reordered fields rejected (deterministic-CBOR
   coverage); expired bundle; bundle signed by a *different* valid device of the same DID rejected
   (cross-device mix-and-match); sealed-asym seal/unseal against current vs grace `signedPrekey`, and a
   seal attempt against an expired or revoked bundle rejected sender-side (envelope vectors proper in
   sealed-sender §12).
3. **Rotation flows**: routine self-rotation end-to-end (records + per-group remove/add + old-record
   revocation); loss flow driven from a second device; verify old-instance state is unreachable afterward
   (fresh Membership, dgm.md §2).
4. **Fingerprint/Membership vectors**: SPKI hashing (fingerprint == rkey == SKI), DeviceID/Membership
   encoding (wire-format §1), re-add produces a distinct Membership.
5. **Revocation propagation**: verifier honors `revokedAt` from a stale cache after re-fetch; new bootstrap
   against a revoked device fails.

## 10. Open questions (tracked for review)

- **Revocation grace + cache staleness values** (§7) — 30 d / 24 h are PROPOSED defaults awaiting sign-off.
- **OPK design** — deferred, tracked in 2sm.md §5.0.1 (ships pre-v1); its lexicon additions land here.
- ~~`inviteAddress` placement~~ **resolved 2026-07-16** — on the `at.atsms.x509` endpoint record (§4.1).
- ~~Prekey record name/rkey~~ **resolved 2026-07-16** — `at.atsms.prekey` (singular); rkey originally the
  endpoint-cert serial, **re-keyed 2026-07-17 to the device fingerprint** (below).
- ~~Serial vs fingerprint~~ **decided 2026-07-17 (user sign-off)**: the fingerprint is the sole protocol
  identifier — rkeys of both collections, the `deviceCert` pairing field, SKI/AKI, JWT `kid`/`sub`, and
  mailbox keys; the serial is demoted to X509/CMS internals (§4.1). Rationale: self-certifying,
  same-key re-issuance stays the same identity, and DeviceID→record resolution becomes a direct
  `getRecord`.
- ~~MemberID shape~~ **decided 2026-07-17**: split into `DeviceID` + `Membership(admittedBy)` (§2,
  dgm.md §2).
- ~~Sealing cert / dedicated sealing key~~ **removed 2026-07-22 (user sign-off, D9/D10)**: the encryption
  floor is HPKE to raw keys — X509/CMS is identity + signing only (D9), and `sealed-asym` seals to
  `at.atsms.prekey.signedPrekey` (D10; joint-use analysis §3.1). The `"sealing"` certificate type, its
  EKU OID, the `deviceCert` field, the AKI/SKI pairing rules, and its parameters rows are deleted.
  Amends G9's "dedicated sealing key" recommendation; external-review obligation recorded in
  overview §6.13.
