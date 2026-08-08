**Decentralized Sealed-Sender Group Messaging Protocol Specification**

**Version**: 1.1 (2026-07-15 — transport generalized; identity/device model clarified; prekey-reuse TODO; envelope-FS, addressing, and fan-out design notes)  
**Based on**: DCGKA (Weidner, Kleppmann et al., CCS 2021 – eprint.iacr.org/2020/1281)  
**Target group size**: Typical 25, maximum 150  
**Key properties**: End-to-end encryption with forward secrecy (FS) and post-compromise security (PCS), decentralized delivery (no central ordering server), multi-device support, sealed sender metadata protection, store-and-forward via untrusted dumb mailboxes reachable over any suitable transport (WebSocket is one valid implementation path, not a protocol requirement).

This specification is self-contained and detailed enough for an AI coding agent (or team) to implement a production-ready system. It references the DCGKA paper for the core cryptographic construction while providing the integration layers, message formats, flows, and adaptations required for your transport model and sealed sender requirement.

### 1\. Overview and Goals

The protocol enables secure group messaging where:

- Any participant can send messages directly (or via mailboxes).  
- Messages may arrive out of order.  
- No central server enforces ordering or consistency.  
- Strong cryptographic security (FS \+ PCS) like Signal.  
- Metadata protection via **sealed sender**: An observer seeing a message on the wire, in a mailbox, or at a provider cannot determine the sender’s identity or the intended recipient(s) from the message contents/headers.  
- Supports users with multiple devices (each device has independent encryption/ratchet keys; user-level identity is authenticated via delegated signing keys).  
- Transport uses untrusted “dumb mailbox” providers for offline storage \+ WebSocket for online send/receive.

**High-level components**:

- **DCGKA Core**: Decentralized continuous group key agreement (key material evolution, membership, FS/PCS).  
- **Sealed Sender Layer**: Cryptographic hiding of sender identity (and partial recipient hiding).  
- **Delivery Layer**: Mailbox push/pull over whatever transport(s) the client supports — HTTPS store-and-forward, WebSocket, or P2P network protocols (with optional Tor/mixnet for stronger anonymity). Every client MUST implement the baseline fallback transport profile (§7); richer transports are negotiated upgrades.  
- **Application Ratchet Layer**: Per-sender message encryption.  
- **Identity Layer**: Identity **is** the AT Protocol DID. The identity issues/signs longer-lived device identity keypairs; these signed device identity records live in the identity's PDS (§4).  
- **Per-device prekeys**: Are stored in the user's PDS and broadcast via the AT Protocol firehose. Each device holds read-write PDS access and adds its own prekeys; only the owning device can produce *valid* prekeys because they are signed by the device identity key that never leaves the device (note: PDS write access itself is account-level — see §4). The X3DH bundle is **`at.atsms.prekey`** (rkey \= the device's endpoint-cert serial; long-lived X3DH identity-DH key \+ weekly-rotated signed prekey, one `bundleSig` — full shape in `../../spec/2sm.md` §5.0; it is fetched by **every** DCGKA bootstrap, since the signed prekey is a mandatory X3DH ingredient and the OPK only an optional fourth DH). Reachability (`inviteAddress`) lives on the `at.atsms.x509` endpoint record instead (§4.1). **One-time prekeys: design still being formulated — deferred during prototyping, ships before the v1 release** (a pull-only PDS cannot dispense keys atomically; a serve-once checkout endpoint is under consideration). Interim clients skip OPK retrieval and bootstrap in signed-prekey-only mode; the mandatory post-join key update heals the weaker bootstrap, and the OPK layer lands without a version break.

### 2\. Threat Model and Security Properties

**Adversary capabilities**:

- Passive network observers and mailbox providers (see all ciphertext and delivery metadata).  
- Active compromise of individual devices (with recovery via PCS).  
- Malicious but “dumb” mailbox providers (they store/forward but do not alter or selectively drop in a targeted way; they learn which mailbox receives what, but not content or true sender via sealing).  
- No trusted central PKI or ordering service.

**Guaranteed properties** (inherited from DCGKA \+ layering):

- **Confidentiality & Integrity**: Only current group members can decrypt messages.  
- **Forward Secrecy**: Compromised state does not reveal past messages.  
- **Post-Compromise Security**: Regular updates heal the group after compromise.  
- **Sealed Sender Metadata Protection**: Sender identity is cryptographically hidden from observers and providers until the legitimate recipient decrypts. Intended recipient is hidden from network observers (provider sees the target mailbox by design).  
- **Decentralized Consistency**: Eventual agreement on group state and key sequence via causal ordering (no total order required).  
- **Multi-device**: Each device participates independently with its own keys.

**Limitations** (document explicitly):

- Traffic analysis and timing attacks remain possible (mitigate with padding, Tor, and infrequent updates).  
- Provider learns mailbox → device mapping (inherent to the model).  
- Full recipient anonymity from the provider requires additional mixnet layers (optional future extension).

### 3\. Cryptographic Primitives and Recommendations

Use modern, audited libraries (libsodium, Rust `ring`/`dalek`, or Go `crypto`):

- **Key exchange / encryption**: X25519 (Curve25519)  
- **Signatures**: Ed25519  
- **Key derivation**: HKDF-SHA256  
- **Authenticated encryption**: ChaCha20-Poly1305 (or AES-GCM)  
- **Hash**: SHA-256  
- **2SM (pairwise secure messaging)**: Implement a minimal Signal-like protocol (X3DH \+ Double Ratchet) or use HPKE (RFC 9180\) for simplicity.  
- **Randomness**: Cryptographically secure RNG.

All long-term keys are generated per device/user. Never reuse keys across purposes.

### 4\. Identity and Multi-Device Model

- **Identity (user)**: The identity *is* the AT Protocol DID. The DID's signing authority (its long-term signing keypair) authenticates operations "as this identity" and issues/signs device identity keypairs.  
- **Device**: The per-device identity **is the device's endpoint-certificate keypair** (`at.atsms.x509`; P-256 today, kept for S/MIME/WebCrypto interop) — the same X509 identity atsms-lib already publishes. There is **no separate device identity keypair and no separate `device_id`**: the cert-key fingerprint *is* the device identifier, and DCGKA member IDs are `(DID, cert-key fingerprint, instance nonce)` — the nonce makes any re-add a fresh protocol instance. The device additionally generates X25519 material (prekeys, sealing key) for encryption/ratchets, all signed by the device identity key. (Deliberate deviation to document: prekey signatures are therefore ECDSA-P256, not Signal-style XEdDSA.)  
- **Delegation**: Publication of the device's endpoint certificate as a record in the DID's repo *is* the delegation — the repo, signed by the account's signing key, binds cert → DID (exactly how atsms-lib/atsms-worker verify devices today). All subordinate key material — prekeys (`at.atsms.prekey`) and the medium-lived sealing certificate (§6) — is signed by the device identity key, giving one trust chain: **DID repo → device identity cert → {sealing cert, prekeys}**. Note: PDS write access is account-level — any logged-in device can write or delete records — so the "only this device" property for prekeys and device records comes from **signature validity under the device identity key**, not from PDS access control.  
- **Rotation, loss, and compromise — one mechanism, not three**: a device identity keypair is never updated in place at the group layer. Rotation \= the device performs a DCGKA **remove** of its old member identity and an **add** of the new keypair, in every conversation the identity participates in, plus the corresponding PDS record replacement (the new key MAY be signed by the old one for continuity when the rotation is routine). For **lost or compromised** devices, *another* device of the same identity performs the remove (no add). The invariant: the current device can rotate **its own** keypair; it can **remove — but never rotate —** other devices' keypairs. Compromise and loss therefore need no protocol-level distinction: both reduce to "remove the device member," which is exactly the operation that triggers DCGKA's PCS healing.  
- Each device runs its own independent DCGKA instance and maintains its own ratchet state.

This satisfies “user delegates keys to each device for identity auth, but each device generates its own encryption keys and ratchet.”

**4.1 Certificate & PDS record shapes (ID cert ↔ sealing cert pairing)**

Both certificate types live in the **same collection**, `at.atsms.x509`, rkey \= serialNumber (existing 16-byte scheme). The record adds `certificateType: "endpoint" | "sealing"` and, on sealing records only, `deviceCertSerial` (the rkey of the issuing endpoint record). One `listRecords` call fetches a device's full cert set.

**Delegation proof**: every record is committed into the repo's MST and the commit is signed by the DID's atproto verification key. `DID → verificationKey → at.atsms.x509/<serial> → cert public key` **is** the cryptographic proof that the DID delegated identity authority to that key; verifiers SHOULD check the commit signature \+ MST inclusion proof (the alpha resolver's trust-the-PDS mode is an explicit interim relaxation, per the umbrella architecture's multi-polar-trust phase). Note the proof attests the *account signing key's* endorsement — exactly as self-sovereign as that key's custody (user-held in the Bourbon model).

**EKUs are domain separation, not forgery defense**: both cert types are honestly DID-delegated; the EKUs guarantee a validator can never accept a genuine sealing cert where an endpoint cert is required (JWT auth, S/MIME) or vice versa — enforceable from the certificate artifact alone, even by validators that never consult the PDS.

- **Endpoint (device identity) cert** — **unchanged from today's atsms-lib profile** (self-signed P-256, CN\=DID, SAN routing info, `CA=false`). EKUs unchanged (clientAuth, emailProtection, …). JWT auth verifiers MUST require an endpoint cert (enforceable from EKU alone). The endpoint **record** additionally carries **`inviteAddress`** (the Welcome/invite destination, §7) as a mutable, MST-bound field — the identity-layer parallel of the cert's SAN email: reachability lives with identity so that S/MIME and one-shot sealed-message senders need only this collection. It is deliberately *not* device-signed: its integrity is liveness-only (a tampered address can only misroute sealed envelopes, never break confidentiality), so the DID-signed commit suffices.
- **Sealing cert** — X25519 SPKI (RFC 8410) **issued/signed by the endpoint key** (ECDSA-P256 signature; mixed-algorithm certs are standard). `CA=false`; KeyUsage `keyAgreement` only; EKU \= a dedicated ATSMS-sealing OID **only** (use the registration-free UUID arc `2.25.<uuid>` until/unless a 3NUM PEN exists). **AKI \= the endpoint cert's SKI** — since SKI derives from the public key, this is the device fingerprint, so pairing is unambiguous even though all of a DID's certs share Subject CN\=DID. Validity ~30–90 days.
- **Why no `CA=true` / PKIX path validation**: chain semantics are split across two mechanisms — **DID-level delegation** of *both* certs is proven by the signed-commit/MST chain (above), and **device-level pairing** (needed because PDS write access is account-level while the invariant is "a device rotates only its own keys") is proven by the endpoint key's **issuance signature** over the sealing cert. Verifiers check that as a direct ECDSA signature \+ AKI/SKI match — never RFC 5280 path building (the stack already verifies `checkChain:false`) — so no cert needs the CA bit or `keyCertSign`.
- **Pairing verification (sender side)**: list records → validate endpoint certs → for each sealing record, locate the endpoint via `deviceCertSerial`, verify issuance signature \+ AKI/SKI match \+ EKU \+ lifetime → `device fingerprint → current sealing key`. Multiple valid sealing certs per device are permitted during rotation overlap; senders use the newest.
- **Rotation**: publish the new sealing record before deleting the old; the device retains the previous sealing secret for a grace window (~7 days) to decrypt in-flight envelopes; recipients trial-decrypt across their (≤2) live sealing secrets — which is also why the SealedEnvelope carries no key identifier.

### 5\. DCGKA Core Layer

**Reference**: Study the full paper (eprint.iacr.org/2020/1281) and prototype (github.com/trvedata/key-agreement) for exact algorithms and proofs. The spec below describes the integration.

**DCGKA State (`γ` per device)** (high-level from paper):

- Counters, update secrets array `I[]`, history of control messages, member list/view (via DGM), ratchet states, needsResponse flags, delivered set, etc.  
- Persistent across restarts; store securely (encrypted at rest).

**Core Algorithms** (adapt from paper):

- `init(user_id, device_id, long_term_keys)` → initial state `γ`  
- `create(group_id, initial_members)` → (control\_message, update\_secret)  
- `add(γ, new_member_device_info)` → (control\_message, direct\_messages via 2SM)  
- `remove(γ, member_to_remove)` → (control\_message, seeds)  
- `update(γ)` → (control\_message)  // for PCS healing  
- `process(γ, incoming_control_or_direct_message)` → updated `γ`, possibly new update\_secrets, responses

**Decentralized Delivery Adaptation (Critical)**:

- The paper assumes **Authenticated Causal Broadcast (ACB)** for control messages.  
- **Implementation**: Replace centralized broadcast with **per-recipient sealed delivery** (see Section 7).  
  - Every control message and application message is sent as a sealed envelope to *each current group member’s mailbox*.  
  - Each message carries:  
    - Predecessor hashes (or vector clock) for causality.  
    - Sequence number per sender.  
    - Signature (device or user level).  
  - Recipient buffers messages in a local queue. `process()` only applies a message when all causal predecessors have been processed (enforce via DGM and history checks).  
- **DGM (Decentralized Group Membership)**: Recompute current member view from the causally ordered history of add/remove/create messages.  
- **2SM (pairwise)**: Use for initial secrets/welcomes during add/create. Deliver via sealed envelopes to the target device’s mailbox.

This preserves all security properties while working over unordered mailbox delivery.

### 6\. Sealed Sender Layer

**Goal**: Hide sender identity from mailbox providers and network observers.

**SealedEnvelope Structure** (JSON-like for clarity; serialize to bytes):

{

  "version": 1,

  "recipient\_device\_id": "uuid",

  "ciphertext": "base64( HPKE\_Seal(recipient\_x25519\_pub, plaintext) )",

  "timestamp": "...",

  "padding": "random bytes for size hiding"

}

**Sealed Sender Construction** (adapted from Signal sealed sender idea):

1. **Inner plaintext** (only recipient can decrypt):  
   - `sender_device_id`  
   - `sender_user_id` (optional, for user-level view)  
   - `sender_signature` (over the inner content using sender’s device or user signing key)  
   - `inner_payload` (DCGKA control message, application ciphertext, or 2SM message)  
   - `causality_info` (predecessor hashes / vector clock)  
2. Encrypt inner plaintext to the recipient’s long-term X25519 public key using HPKE (or X25519 \+ HKDF \+ AEAD).  
3. The resulting `ciphertext` goes into the `SealedEnvelope`.  
4. Push the envelope to the recipient’s mailbox over any supported transport (§7).

**Recipient side**:

- Receive envelope from mailbox.  
- Decrypt using private key → verify signature → learn true sender → feed `inner_payload` into DCGKA `process()` or application ratchet.

This hides the sender from everyone except the legitimate recipient. The provider only sees “someone pushed ciphertext to this mailbox.”

**Envelope-layer forward secrecy (design note)**: Sealing to the recipient's long-term X25519 key means the *envelope* layer itself has no FS — but the impact is bounded, because the inner payload retains full FS/PCS from the DCGKA/ratchet layers. A compromised sealing key therefore never exposes message **content**, only the sealed-sender **metadata** (sender identity, causality info, signature) of envelopes the attacker previously captured. Mitigations: make the sealing key a dedicated, medium-lived key published in the PDS and rotated on a schedule (never reuse the identity or ratchet keys for sealing); a later extension MAY derive per-epoch sealing keys from group state so envelope FS approaches ratchet FS. **Cost note**: one HPKE seal (ephemeral X25519 keygen \+ DH \+ HKDF \+ AEAD) per recipient per message costs ~50–100 µs native, ~1 ms in JS-class runtimes — at the 150-device maximum that is ≲ 0.15 s of CPU per send worst-case, negligible next to the network fan-out itself. Realistic.

**Key publication & reuse of the atsms-lib X509 pattern (design note)**: The sealing key reuses atsms-lib's existing capability as a *pattern*, not as a keypair. Each device publishes **two certificates** under the same PDS record mechanics (X509 wrapper, serial \= rkey): (1) the existing **long-lived P-256 endpoint cert** — S/MIME interop floor, SMTP bridge routing (SAN email), JWT auth; (2) a new **medium-lived X25519 sealing cert** (RFC 8410 SPKI, ~30–90-day rotation), marked with a distinct ATSMS EKU. Never seal to the endpoint key itself — cross-protocol reuse of one keypair between CMS key-agreement and HPKE is unanalyzed and defeats rotation. The **SealedEnvelope is one format across both stacks**: HPKE to the sealing cert, inner payload either a DCGKA control/application message or a v1-baseline CMS SignedData — so the X509 floor gains sealed-sender semantics from the same envelope and key material. Note the current CMS pipeline is already sign-*inside*-encrypt; what this design fixes relative to it: recipient-identifying `RecipientInfo` (HPKE carries no recipient identifier), CBC → AEAD, and unrotated long-lived keys. **SMTP secure email** is then just another baseline store-and-forward transport: the SealedEnvelope rides as a MIME part through the existing email-bridge extraction path (classic S/MIME to the endpoint cert remains for external, non-ATSMS email recipients). Caveat: SMTP transport metadata (From, DKIM, server IPs) is outside the envelope's protection — sealed semantics hold against the storing mailbox provider, but email is a low-anonymity transport and MUST be labeled as such.

**Optional strengthening**:

- Connect to mailbox providers over Tor (or a mixnet) so even the provider does not see the sender’s IP.

### 7\. Delivery and Transport Layer

**Two logical delivery channels** (transport-abstract — HTTPS store-and-forward, WebSocket, or P2P network protocols are all valid carriers; none is prescribed):

- **Welcome/invite channel** — how a device receives Welcome messages inviting its identity into a conversation. The recipient's **PDS specifies where Welcome messages are to be sent** for that identity's devices (the invite inbox address in each device record). Senders resolve DID → PDS → invite address.  
- **In-conversation channel** — how all non-Welcome messages (control \+ application) are delivered. The conversation itself carries the delivery map: either each member device's destination address (published at join time, updated in-band), OR a shared drop-point keyed by an opaque, rotating **group-ID** (see the fan-out design note in §9). Which profile a group uses is negotiated at creation.

**Core delivery requirement**: every message MUST be durably stored somewhere until each end device has received it — devices are routinely offline at send time. Providers offer dumb store-and-forward only.

**Baseline fallback profile (MANDATORY for v1 interop)**: every client MUST implement plain HTTPS store-and-forward push/pull against a mailbox provider, addressed as `MailboxAddress` \= `{provider_url, mailbox_id, auth_token?}`. Richer transports (persistent WebSocket push, P2P/overlay delivery, Tor) are OPTIONAL upgrades negotiated per device; a sender that cannot reach a device by any richer path falls back to the baseline.

**Client Operations**:

- `push_sealed_envelope(destination, sealed_envelope)` → deliver over any mutually supported transport.  
- `receive()` → obtain pending sealed envelopes (push preferred when a live connection exists; pull otherwise).

**Flows**:

- Online device: Maintain a live path to its own mailbox (or a P2P subscription); push sealed messages to other members’ destinations.  
- Offline: Messages accumulate at the destination (mailbox/drop-point).  
- Coming online: Pull all pending sealed envelopes, decrypt, process causally.

**Addressing**:

- `MailboxAddress` is logically **per-device**, matching DCGKA membership (every member is a device that must independently receive and process). Deployments MAY point several of an identity's devices at one shared physical mailbox — envelopes are opaque and devices discard what they cannot decrypt — trading extra downloads for hiding the device-level recipient from the provider.  
- Devices publish their invite address on their `at.atsms.x509` endpoint record (Welcome channel, §4.1); in-conversation destinations travel in welcome material or signed announcements, and group state maintains a mapping `DeviceID → current destination` (updated on changes).

### 8\. Message Types (High-Level)

- **ControlMessage**: DCGKA create/add/remove/update/ack \+ causality data \+ signature.  
- **ApplicationMessage**: `sender_ratchet_key` \+ `ciphertext` (encrypted under per-sender ratchet) \+ metadata.  
- **SealedEnvelope**: As above (wraps any of the above).  
- **DirectMessage** (for 2SM): Similar to ApplicationMessage but pairwise.

All messages are serialized deterministically (e.g., Protocol Buffers or CBOR).

### 9\. Key Protocol Flows

**Group Creation**:

1. Creator runs `create()`.  
2. Broadcasts create control message \+ sends welcome seeds via sealed 2SM to initial members.  
3. Each recipient processes the create message.

**Add Member**:

1. Sender runs `add()`.  
2. Sends add control message (sealed) to all current members.  
3. Sends welcome material (ratchet state \+ history) via sealed 2SM to the new member.  
4. New member processes and joins.

**Remove Member** & **Key Update (PCS)**: Similar — sealed broadcast of control message \+ necessary direct secrets.

**Send Application Message**:

1. Derive message key from per-sender ratchet (DCGKA provides update secrets).  
2. Encrypt plaintext with AEAD.  
3. Create `ApplicationMessage`.  
4. For each current group member: wrap in `SealedEnvelope` and push to their mailbox.  
5. (Optional) Send a lightweight ack if needed for causality.

**Fan-out design note (open discussion)**: the application ciphertext is identical for every member (it is encrypted once under the per-sender ratchet), so the O(n) in step 4 is **delivery duplication, not encryption cost**. Three profiles, trading efficiency against what providers learn:

1. **Per-recipient envelopes (baseline)** — metadata-optimal: no provider ever sees group structure, only fan-in to individual mailboxes. Cost: the sender uploads n copies.  
2. **Group drop-point** — the sender pushes ONE envelope to a destination keyed by an opaque group-ID; members pull. The cost moves to metadata: the provider hosting the drop-point can correlate all pullers as co-members. Mitigate by rotating the group-ID per epoch (derived from group state, so only members can compute the next ID) and pulling via Tor.  
3. **Encrypted blob offload (always, orthogonal)** — media and large content are uploaded once as an encrypted, content-addressed blob; the fan-out envelope carries only the reference \+ content key. This removes the dominant bandwidth cost from profile 1 regardless of profile choice.

v1 baseline: profiles 1 \+ 3 mandatory; profile 2 an optional per-group negotiated mode.

**Receiving**:

1. Pull sealed envelope from own mailbox.  
2. Decrypt seal → verify signature → extract inner payload.  
3. If control: feed to `process(γ)`.  
4. If application: decrypt with recipient’s per-sender ratchet state → deliver to UI.

### 10\. State Management & Persistence

- Persist per-device: DCGKA `γ`, ratchet states (delete old keys for FS), message history (bounded), mailbox addresses.  
- On startup or reconnect: Pull all pending envelopes from mailbox, process in causal order.  
- Prune old history once a sufficient number of acks have been received (as in the paper).

### 11\. Implementation Guidance for AI Builder

**Modular Architecture** (recommended):

- `DCGKACore` module — implement algorithms from the paper (study prototype).  
- `SealedSender` module — HPKE sealing \+ signature logic.  
- `DeliveryClient` module — WebSocket \+ mailbox logic (Tor optional via socks proxy).  
- `Ratchet` module — per-sender Double Ratchet or HKDF chain for app messages.  
- `IdentityManager` — key generation, certificates, delegation.  
- `CausalityManager` — vector clocks / predecessor tracking.  
- `GroupState` — wraps DCGKA \+ membership view.

**Concurrency**: Use async (Tokio in Rust, asyncio in Python, etc.). Process incoming messages in a queue with causal readiness checks.

**Error Handling**:

- Retry failed pushes with exponential backoff.  
- On causality violation or signature failure: drop or flag as malicious.  
- Handle duplicate messages (idempotent processing via sequence numbers).

**Testing**:

- Unit test each module.  
- Integration tests with simulated mailboxes and out-of-order delivery.  
- Security tests for FS/PCS (using the paper’s game definitions).

**Performance**:

- At n=150, updates are acceptable. Batch acks where possible.  
- Use padding in sealed envelopes to hide message type/size.

**Dependencies**:

- Study the DCGKA paper in detail for exact state transitions and security proofs.  
- Adapt the Java prototype as a reference implementation.

### 12\. Security Considerations & Future Work

- The combination achieves the stated properties.  
- Mitigate traffic analysis with message padding and random delays.  
- For stronger anonymity: Add a mixnet frontend in front of mailbox providers.  
- Formal verification of the sealed sender \+ DCGKA composition is recommended for high-assurance use.  
- Audit all crypto code.

### References

- Primary paper: “Key Agreement for Decentralized Secure Group Messaging with Strong Security Guarantees” (Weidner et al., 2021).  
- Prototype: github.com/trvedata/key-agreement  
- Sealed sender inspiration: Signal’s sealed sender design (signal.org/blog/sealed-sender) and related analyses.  
- Primitives: HPKE (RFC 9180), libsodium documentation.

This specification provides a complete, buildable blueprint. An AI agent can implement it module-by-module, starting with the DCGKA core (following the paper), then adding the sealed sender and delivery layers exactly as described.

If you need expansions (e.g., full pseudocode for a specific flow, Protocol Buffer schemas, or Rust/Go skeleton code outlines), provide the priority and I will generate it.  