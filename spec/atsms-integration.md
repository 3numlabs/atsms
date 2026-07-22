# spec/atsms-integration.md — Integration with the ATSMS Stack

> **Status: DRAFT v0.1 (2026-07-16) — for review.** [Protocol] with flagged [Node] items · Phase 0
> deliverable. Closes gap **G10** (no integration story) from [`../gap-analysis.md`](../gap-analysis.md);
> applies decisions **D1** (layer over the X509 floor), **D2** (`@atsms/dcgka` consumed by `@atsms/sms`),
> **D5** (anonymous relay ingress — relay side in [`sealed-sender.md`](./sealed-sender.md) §7), **D6**
> (DMs = 2-member groups).
> Inputs: atsms-lib survey 2026-07-16 (file:line refs below are to `atsms-lib`/`atsms-worker` at that
> date), implementation plan §2 parity inventory. MUST/MAY per RFC 2119.

## 1. Shape of the integration (D1/D2/D6 applied)

- **Layer, then deprecate by attrition** (D1): DCGKA becomes the default for DM + group traffic between
  capable endpoints; X509/S-MIME stays as the interop floor (email dialect, legacy endpoints) behind the
  same facade, selected per-conversation by capability discovery (§3). No flag day, no floor removal.
- **Package boundary** (D2): this repo ships **`@atsms/dcgka`** — the protocol engine (2SM, DGM, DCGKA
  core, ordering, sealing) behind a **serialize-in/serialize-out boundary** (bytes and JSON-safe state in,
  bytes and events out; no I/O, no storage, injectable RNG/clock — the p2panda-style seam that keeps a
  later Rust core swappable and the simulation harness trivial). `@atsms/sms` consumes it and keeps
  everything app-facing: `ATSMSStorageManager`, storage adapters, transport clients, PDS resolution.
  Consumers (`atsms-demo`, future Haiven app) keep importing `@atsms/sms`.
- **DMs are 2-member DCGKA groups** (D6): one code path; bare 2SM remains engine-internal.

## 2. Engine ↔ host contract (the `@atsms/dcgka` API shape)

The engine exposes, per group: `create/add/remove/update/leave` (op builders returning frames + envelopes
to send), `ingest(envelopeBytes)` (returns readiness-resolved events: decrypted app payloads, membership
changes, acks needed, repair requests due), `sendApp(plaintextBytes)`, and serializable state
(γ + ordering buffers + 2SM stores — dcgka-core §2). The host (`@atsms/sms`) owns: persistence of engine
state and retained frames (encrypted at rest), all network I/O, PDS resolution
([`identity-devices.md`](./identity-devices.md) §4), timers (`T_ACK`, `T_REPAIR`, staleness — the engine
reports *deadlines*, the host schedules them), and the UX surfacing duties (stale members, digest
mismatches, "sent before removal was known").

## 3. Capability discovery & path selection (normative)

- A recipient **device** is DCGKA-capable iff its `at.atsms.prekey/<fingerprint>` record resolves and
  verifies (identity-devices §4; since D10 the bundle's `signedPrekey` is also the sealed-asym envelope
  target, so one record proves both capabilities). A recipient **DID** is capable iff ≥ 1 of its
  devices is.
- **Per-conversation, not per-message**: a conversation is either a DCGKA group or an X509-floor
  conversation. Mixing paths inside one conversation is forbidden — it would silently strip FS/PCS for
  some members while the UX shows one thread.
- New DM: peer DID capable → create a 2-member group; else → floor DM (today's path). New group: **all**
  member DIDs capable → DCGKA group; else → floor group (naive fan-out), and the client SHOULD surface
  which participants hold it back.
- Capability is re-evaluated when adding members (an incapable invitee to a DCGKA group is a UX error, not
  a silent downgrade) and MAY be re-checked opportunistically to propose **upgrading** a floor
  conversation: upgrade = create a fresh DCGKA group with the same participants; the floor conversation is
  closed for sending, retained for history. History is NOT migrated into the group (it predates the
  group's key material by construction).
- **No protocol-level downgrade**: an established DCGKA group never falls back to the floor. Loss of a
  member's records is handled inside the group (remove/re-add, identity-devices §6).

## 4. Conversation identity

- DCGKA conversations: `LocalConversation.id` = lowercase-hex **GroupID** (= MessageID of `create`,
  ordering-auth §2.1) — deterministic and content-derived, closing the G10 fragility where a group's
  convoId is the creator's random `nanoid(13)` riding inside the payload and trusted verbatim on receipt
  (manager.ts:356, 803-847).
- Floor conversations keep today's scheme (`dm_<16hex>` via `generateDMConvoId`, messages.ts:28; nanoid
  groups). The two id spaces are disjoint by construction; `isDMConvoId` remains floor-only.
- The storage layer maps both into the existing `conversations`/`messages` tables (sqlite-adapter.ts:33-97)
  unchanged; a `protocol: "dcgka" | "x509"` field in `LocalConversation.metadata` records the path.

## 5. Dialect layering (unchanged by design)

- The dialect system is orthogonal and survives whole: an `ATSMSMessagePayload` (types.ts:35 — `version`,
  `contentType` `atsms/text` | `atsms/webrtc` | …, `content` JSON string, ids) serialized as compact JSON
  is the **plaintext handed to `sendApp()`** — i.e. the inner-ratchet plaintext of an `app` frame
  (wire-format §4.4). WebRTC signaling, facets, future dialects need zero changes.
- Redundant-field validation replaces today's signer-CN check (manager.ts:771-778): on receive,
  `payload.senderId` MUST equal the frame sender's DID and `payload.convoId` MUST equal the GroupID —
  mismatch = drop (defense-in-depth; the frame signature is the authority).
- `payload.recipientIds` is informational only under DCGKA (membership is the DGM's, not the payload's);
  writers SHOULD still populate it for floor-code compatibility.
- The CMS steps (`signMessage` → `encryptMessage`, crypto.ts:41/116) do **not** run on the DCGKA path —
  signing is the frame signature, encryption is ratchet + seal. They remain untouched for floor traffic.

## 6. `ATSMSStorageManager` surface (parity + growth)

Per the implementation-plan §2 inventory, with the concrete surface from the survey:

| Today (manager.ts) | Under DCGKA |
|---|---|
| `startConversation` / `sendMessage` / `sendWebRTC` | **Kept** — internally route to `createGroup`+`sendApp` / `sendApp` when the conversation is DCGKA (§3) |
| `processIncomingTransportMessage` (:744) | **Kept** as the floor inbound path; a sibling `processIncomingEnvelope` feeds `engine.ingest()` |
| `syncMessages` (:888), WS client (:955) | **Kept** — transports carry opaque envelopes (§7) |
| `messageAdded$` / `conversationUpdated$` / `syncCompleted$` (:314-322) | **Kept**; joined by `membershipChanged$` and `securityEvent$` (stale member, digest mismatch, "who could decrypt") |
| — | **New**: `createGroup(dids)`, `addMember(convoId, did)`, `removeMember(convoId, did)`, `updateKeys(convoId)`, `leaveGroup(convoId)` — user-level ops expanding to per-device ops (dgm.md §4) |
| `getCachedOrFetchCertificatesForDID` (:1084) | **Extended** — resolves prekey bundles too (identity-devices §4); gains the §7-cache rules (revocation honoring) |

New persistence (adapter schema additions, encrypted at rest, key-deletion verified — FS depends on it):
engine state per group, retained SignedFrames (repair store), 2SM sessions, pending-envelope buffer,
processed-EnvelopeID window.

## 7. Transport mapping

- The spec's "mailbox" ≡ the existing per-`(DID, certSerial)` **Inbox Durable Object** (`atsms-worker`
  inbox.js:19, DO name today `inbox-{did}-{serialNumber}`, re-keyed per §8 item 5). `MailboxAddress`
  (wire-format §1) binds as `providerUrl` = the worker base URL, `mailboxId` =
  `{did}/{deviceFingerprint}` (lowercase hex; re-keyed from certSerial 2026-07-17 —
  identity-devices §4.1).
- A new transport message type **`atsms-sealed`** joins `atsms | atsms-email | email` (types.ts:19):
  content = the serialized `SealedEnvelope`, base64 in the existing `encryptedContent` field. Both
  envelope modes (asym/sym — sealed-sender §11, decided 2026-07-20) are equally opaque blobs here: the
  mode split is invisible to the relay and requires no additional worker changes. Existing
  list/get/delete/stats and WS push (`new_message` broadcast, inbox.js:309) work unchanged — envelopes are
  opaque blobs to the relay, exactly like PKCS#7 today.
- **Push MUST NOT ride an authenticated session** (sealed-sender §7): even when the device's own-mailbox
  WebSocket is connected, envelope pushes to *other* mailboxes go over the anonymous HTTP path. The WS
  `send` command (websocket-client.ts:558) is floor-only; DCGKA never uses it. (Today's HTTP
  `/send-message` is already sender-JWT-free — atsms-api.ts:187 — so the trust model barely moves; see §8.)
- SMTP transport: the envelope rides as a MIME part through the existing email-bridge extraction
  (classifier §8 item 4), giving the email dialect a sealed path; low-anonymity caveat per
  sealed-sender §10.

## 8. `atsms-worker` change list ([Node] — cross-repo, contract versioned here)

1. **Anonymous envelope ingress** (D5): public `POST /envelope/{did}/{fingerprint}` → recipient's Inbox DO
   `/store` with `messageType: "atsms-sealed"`. The DO's `/store` is already unauthenticated
   (inbox.js:177) and keyed by recipient only — the change is exposing a public route + the abuse controls
   (rate/byte quotas + size cap per sealed-sender §7, [`parameters.md`](../spec/parameters.md)). Fetch
   stays ES256-JWT (inbox.js:80-160).
2. **Dedup compatibility**: the DO's content-hash id (`computeMessageHash`, inbox.js:326) over the base64
   envelope is consistent with EnvelopeID dedup (sealed-sender §3); keep, but treat client-side
   EnvelopeID dedup as the normative check.
3. **Retention**: today's hard 1000-message cap with oldest-eviction (inbox.js:297) becomes
   policy-configurable; a relay MAY retain delivered envelopes ~30 d to serve self re-pulls
   (ordering-auth §8 non-normative optimization). Eviction of an *undelivered* envelope is a liveness
   event the protocol repairs around, but operators SHOULD size caps above the 64 KiB × backlog
   worst case.
4. **Email worker**: classify the new MIME part type for sealed envelopes (alongside the pkcs7 paths,
   email-worker.js:390-415) → `/store` as `atsms-sealed`.
5. **Fingerprint re-keying (breaking change, pre-alpha)**: DO names, `mailboxId`, JWT `kid`/`sub` rkey,
   and record rkeys move from cert serial to the **device fingerprint**, lowercase hex (decided
   2026-07-17 — identity-devices §4.1). Touches `atsms-lib` (`generateJWT` claims, `ATSMSClient` record
   writes, SAN URI) and the worker (DO naming, JWT verification's record fetch by fingerprint rkey).
   This also closes the old serial-case drift (API worker lowercases DO names, email worker doesn't —
   email-worker.js:174 vs cloudflare-api-worker.js:191): the **lowercase-hex rule now applies to
   fingerprints**, and mixed case splitting a mailbox in two gets a regression test (§11).
6. **Non-blockers noted**: the JWT verifier's PEM-as-key placeholder (jwt-verification.js:145-157) and the
   API worker's decode-without-verify routing (real verification is in the DO) are unchanged by DCGKA;
   TURN credentials path untouched.

The envelope ingress contract (route, size cap, quotas, error codes) is **versioned in
sealed-sender.md §7** so lib and worker ship independently (implementation-plan §10 risk item).

## 9. Pre-existing defects this integration touches (recorded, not silently fixed)

- **HTTP multi-recipient send is broken today**: `ATSMSTransportLayer.sendMessage` passes
  `(recipients, content)` into `ATSMSApiClient.sendMessage(did, content, type)`
  (transport-layer.ts:177 vs atsms-api.ts:193) — multi-recipient send only actually works over WebSocket.
  The DCGKA path sidesteps it (per-recipient anonymous pushes), but the floor path should be fixed or the
  HTTP send documented as single-recipient.
- **Group convoId trusted from sender payload** (manager.ts:803-847) — closed for DCGKA by §4; floor
  behavior unchanged (documented fragility).
- **Doc/code drift**: worker CLAUDE.md's per-DID `email-{did}` inbox vs actual per-cert storage
  (email-worker.js:174) — flag to the worker repo; this spec assumes the *actual* per-cert keying.
- **Payload serialization drift**: `prepareMessageForSending` pretty-prints (`JSON.stringify(p, null, 2)`,
  messages.ts:141) while the manager path is compact — harmless today (bytes ride signed), but the DCGKA
  path standardizes on **compact** JSON for payload plaintext (§5).

## 10. Migration & coexistence sequencing

Aligned with implementation-plan Phases 1–5; the coexistence invariants:

1. **Ship dark** (lib): `@atsms/dcgka` lands inside `@atsms/sms` behind capability discovery that finds no
   capable peers (no prekey records published yet) — zero behavior change, floor untouched.
2. **Relay ingress** (worker): anonymous `POST /envelope` + `atsms-sealed` type deploy independently
   (contract §8.1) — inert until clients push. The §8 item-5 fingerprint re-keying completes across
   stages 1–2 (lib records/JWT in 1, worker DO naming here), before any capability is published.
3. **Publish capability**: clients begin publishing `at.atsms.prekey` records on onboarding/rotation
   (identity-devices §4); from here, *new* DMs between updated clients become 2-member groups.
4. **Groups + demo**: group lifecycle UI in `atsms-demo` (proving ground; unblocks demo Phase 3) — adds,
   removes, device rotation, stale-member surfacing.
5. **Upgrade prompts**: existing floor conversations offer §3 upgrades once all participants are capable.
   Floor remains fully functional throughout and indefinitely for email/legacy (D1 — attrition, no
   removal).

Rollback safety: every stage is additive; disabling capability publication reverts new conversations to
the floor without touching existing DCGKA groups (which keep working — the engine has no server-side
dependency beyond dumb mailboxes, D0).

## 11. Test obligations

1. **Path selection matrix**: capable/incapable × DM/group × new/upgrade — correct path chosen, no silent
   downgrade, upgrade closes the floor conversation for sending.
2. **End-to-end over the real worker contract**: two engine instances over a local `atsms-worker`
   (anonymous push + JWT fetch + WS notify), including the §8 quotas and the 64 KiB envelope cap.
3. **Coexistence**: floor and DCGKA conversations interleaved in one store; floor regression suite
   unchanged (email dialect, WebRTC signaling on both paths).
4. **Migration drill**: stage 1→5 sequence on a fixture pair, with rollback at each stage.
5. **Defect guards**: §9 items get regression tests as they're fixed (HTTP multi-recipient send;
   serial-case mailbox splitting).

## 12. Open questions (tracked for review)

- **`mailboxId` format** (§7): now `{did}/{deviceFingerprint}` (re-keyed 2026-07-17); still confirm
  against fidis/gateway addressing conventions before Phase 3 (relay work) freezes it.
- **Ingress route shape** (§8): dedicated `POST /envelope/{did}/{fingerprint}` vs generalizing
  `/send-message` — drafted as dedicated (keeps floor and sealed contracts separately versionable).
- **Floor-upgrade UX policy** (§3): automatic vs user-prompted upgrade of floor conversations — product
  decision (Haiven-side for the consumer app; the protocol supports both).
- **Mixed-capability groups** (§3): drafted as all-or-nothing with UX surfacing; sign-off needed (the
  alternative — capable-subset DCGKA + floor side-channel — was rejected as a silent-downgrade trap).
