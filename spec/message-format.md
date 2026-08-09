<!-- cSpell:words CBOR DCGKA bstr tstr uint CDDL BLOBREF blurhash renderable refinable ciphertext prekey oneshot unforgeable franking Telnyx -->

# ATSMS message format v2 — application-message structure

> **Status: ACCEPTED (2026-07-31, rev 3) — cut-over in progress per §11.** Clean-slate redesign of the
> application-level message payload before v1 alpha. Ground rules set 2026-07-31: **no backward
> compatibility** (v1 was never released — the current format is input to learning, not a
> constraint), **CBOR on the wire** (consistent with the DCGKA frame layer), **the one-shot path is
> redesigned too** (same content format, same sealed transport), and the bar is *a clean protocol
> built for the future*, not a patch.
>
> Scope: the **plaintext application content** that rides inside both encryption paths (X509
> one-shot CMS and DCGKA sealed frames), plus the one-shot framing changes needed to make the two
> paths symmetric. Remaining out of scope, listed as adjacent work in §9: relay blob storage,
> membership events in the feed.

---

## 1. What we learned from v1

The prototype format is one JSON object per message:

```ts
// atsms/packages/client/src/lib/types.ts — the v1 shape, kept here as the "what we learned" record
interface ATSMSMessagePayload {
  version: string;        // "1.0", hardcoded, never checked
  contentType: string;    // "atsms/text" | "atsms/webrtc" — only two ever existed
  id: string;             // nanoid(13), sender-chosen
  content: string;        // JSON *string* inside JSON (double-encoded)
  senderId: string;
  recipientIds: string[]; // load-bearing on one-shot, informational on DCGKA
  convoId: string;
  createdAt: string;      // sender-asserted; used as the ordering key
}
```

One thing it got right: **the one-shot and DCGKA paths share the same inner content** (verified in
code — both build this payload), and v2 keeps that property. Everything else is a lesson (full
audit, 2026-07-31):

1. No fields for replies, threads, reactions, edits, deletes/retraction, or expiring messages.
   (Storage grew vestigial `reactions`/`edited` columns that nothing on the wire ever populated.)
2. No delivery/read receipts, no typing indicators.
3. Attachments structurally blocked: one JSON string means base64-inline binary, against a 64 KiB
   sealed-envelope cap. The envelope layer reserved `CONTENT_BLOBREF` for blob offload, unused.
4. No ephemeral class — WebRTC signaling was persisted like chat and filtered at render time;
   every lesson in [`webrtc-over-atsms.md`](../docs/history/webrtc-over-atsms.md) (own-echo filtering, the
   30-second staleness window, replay on reload) is a workaround for this.
5. No unknown-type policy — the three clients each invented one (raw JSON, `[type]` placeholder,
   silent hide).
6. Integrity gaps: sender-chosen `id` + `INSERT OR REPLACE` let one group member overwrite
   another's stored message; sender-asserted `createdAt` was the sort key while DCGKA's real
   causal order was discarded; the same `recipientIds` field meant two different things on the two
   paths; the paths were told apart by **byte-sniffing** (CBOR vs DER) because the one-shot CMS
   traveled bare, outside the sealed-sender layer.
7. No group-metadata messages (name/topic/avatar), no membership events in the message feed.

## 2. Prior art — what we take from whom

Surveyed 2026-07: IETF **MIMI** content format (`draft-ietf-mimi-content-09`, July 2026 — the IETF
working group is "More Instant Messaging Interoperability"; active, **not near RFC**), XMTP content
types (v3/MLS era), Matrix relations, Signal's `DataMessage` protobuf.

**From MIMI (our main source — structure *and* encoding):**
- **Deterministic CBOR** as the wire encoding, for the same reasons MIMI chose it: no base64 for
  binary, no boundary-scanning, and — decisive for us — deterministic serialization makes
  **content-derived message IDs** practical (§6). It also matches the DCGKA frame layer, so the
  whole stack speaks one encoding.
- Replies, threads, edits, and deletes are **fields on a common envelope**, not new message
  shapes: `inReplyTo` (reply), `topicId` (thread), `replaces` (edit = full replacement body;
  delete = `replaces` + null body). One mechanism each, composable with any body.
- A reaction is a message with `inReplyTo` = target and a reaction body part; removing a reaction
  reuses the delete mechanism.
- Attachments are **encrypted external blobs**: upload AEAD-encrypted bytes anywhere, carry
  `{url, key, nonce, hash, size}` in the message. (Signal and XMTP use the same pattern.)
- Salted, hash-derived message IDs; per-message expiration; receiver-side authorization of
  edits/deletes (original authenticated sender only).

We adopt MIMI's **field names** (`inReplyTo`, `topicId`, `replaces`, `expires`, `salt`) and its
external-part and message-ID constructions outright, so a future transcode to
`application/mimi-content` — or a gateway to a MIMI network — is mechanical. We do **not** adopt
the draft wholesale yet: it is pre-RFC and still moving, and it doesn't cover receipts (split into
a separate draft), typing, or call signaling, all of which we need (§10).

**From XMTP (packaging discipline):**
- Every render-class message with a non-universal type carries **fallback text**; background
  operations (receipts) carry none and clients silently skip what they can't decode — never
  "unsupported content" boxes. XMTP's newest direction (XIP-63) is itself to adopt the MIMI
  content format — the industry is converging there.

**Cautionary tales:**
- **Matrix** retrofitted threads onto reply relations → the `is_falling_back` machinery and
  unresolvable thread/edit/redaction interactions. Lesson: `inReplyTo` and `topicId` are
  **independent fields from day one**, even though thread UI ships later.
- **Signal** addresses messages by `(sender, sent-timestamp)` and embeds a *copy* of quoted
  content in replies — a known dedupe/reference sore spot. Lesson: real, derived message IDs.

## 3. Product modality inventory

The target range is plain SMS → Slack-grade UX:

| Modality | Mechanism (→ section) | Phase |
|---|---|---|
| Plain text | `text` part | **alpha** |
| Rich text: mentions, links, formatting | `text` part + facets | **alpha** |
| Reply / quote | envelope `inReplyTo` | **alpha** |
| Emoji reactions (Slack-style, add/remove) | `reaction` part + `inReplyTo`; removal via `replaces` | **alpha** |
| Edit message | envelope `replaces` + full new body | **alpha** |
| Delete / retract | envelope `replaces` + `body: null` | **alpha** |
| Images, video, documents | external encrypted blob parts | **alpha if blob endpoint lands**, else next |
| Voice notes | external blob, `audio/*` + duration | next |
| Audio/video calls (signaling) | `call` part, ephemeral | **alpha** (replaces `atsms/webrtc`) |
| Call transcript events (missed/ended) | `call-event` part | next |
| Link previews | `preview` part alongside text | next |
| Delivery/read receipts | `receipt` part (state, not rendered) | next |
| Typing indicators | `typing` part, ephemeral | next |
| Threads (Slack-style) | envelope `topicId` (+ client store work, §7) | **field present now**, UI post-alpha |
| Disappearing messages | envelope `expires` | field present now |
| Group name/topic/avatar | `group-update` part (state) | next (needed for groups UX) |
| Membership events in feed | surfaced from the DCGKA layer as synthetic rows | next |
| SMS/MMS bridge dialect | `sms` part (gateway ↔ app) | roadmap Phase 10 |
| Location, contacts, polls, payments | future part kinds — the registry absorbs them | post-v1 |

## 4. The v2 content format

One format for every message on both paths. **Wire encoding: deterministic CBOR** (RFC 8949 —
shortest-form integers/lengths, no indefinite-length items, definite map ordering), reusing the
exact encoding rules the DCGKA wire format already specifies so the stack has one CBOR dialect.
Like MIMI, the top level is a **fixed-position array** (every field always present; `null` for
absent), which keeps the deterministic encoding trivial and the size honest.

```cddl
; deterministic CBOR, same encoding rules as atsms spec/wire-format.md
AtsmsContent = [
  v: 2,
  salt: bstr .size 16,          ; random per message; feeds message-id derivation (§6)
  convoId: ConvoId,             ; §8 — context byte + 32-byte id, one collision-free space
  createdAt: uint,              ; ms since Unix epoch, sender clock — display/tiebreak only (§6)

  ; relations — independent, composable (the Matrix lesson):
  replaces: null / MessageId,   ; FIRST version of the message this edits or retracts
  topicId: null / bstr,         ; thread key; convention: MessageId of the thread's first message
  inReplyTo: null / MessageId,  ; message being quoted / reacted to
  expires: null / [relative: bool, time: uint],   ; cooperative disappearing-messages hint

  ephemeral: bool,              ; signaling class: never persist, drop if stale (§8)
  fallback: tstr,               ; plain-text stand-in when no part is understood ("" = none)
  extensions: { * (int / tstr) => any },   ; int keys = registered below; tstr = private use
  body: null / [* Part]         ; null = retraction tombstone (only meaningful with `replaces`)
]

MessageId = bstr .size 32       ; derived, not carried — §6
ConvoId   = bstr .size 33       ; §8
```

Registered extension keys (so the core array stays stable): `1` = `recipients: [* tstr]` —
**one-shot path only**, the intended recipient DIDs, bound into the signed plaintext to prevent
surreptitious forwarding and to let receivers verify the derived `convoId`. On the DCGKA path the
group's membership is authoritative and this key is absent. (This retires v1's dual-meaning
`recipientIds` field.)

Notably absent, on purpose: **`senderId` and `id` are not in the content.** The sender is whatever
the seal layer cryptographically proves (the CMS signer certificate resolved via `at.atsms.x509`,
or the DCGKA frame signature) — carrying a copy invited the v1 cross-check-or-trust confusion.
The message ID is derived from the authenticated sender, the conversation, the content, and the
salt (§6), so it cannot be chosen — or forged — by anyone.

### 4.1 Parts

```cddl
Part = [
  kind: uint,                   ; ATSMS part-kind registry, §5
  content: InlineContent / ExternalContent
]

InlineContent = [ 0, body: { * tstr => any } ]      ; CBOR map, schema per kind — no
                                                    ; string-in-string double encoding
ExternalContent = [ 1,
  contentType: tstr,            ; IANA media type of the *plaintext*, e.g. "image/jpeg"
  url: tstr,                    ; where the encrypted bytes live
  size: uint,                   ; plaintext octets
  encAlg: uint,                 ; IANA AEAD registry; 1 = AES-128-GCM (mandatory to implement)
  key: bstr,  nonce: bstr,      ; decryption material (MIMI ExternalPart construction)
  hashAlg: uint,                ; IANA named-hash registry; 1 = SHA-256
  contentHash: bstr,            ; over the *encrypted* bytes at url
  meta: { ? filename: tstr, ? description: tstr,    ; description = alt text
          ? dims: [w: uint, h: uint], ? durationMs: uint,
          ? thumb: bstr,        ; tiny inline preview (blurhash-scale, ≤ ~2 KiB)
          ? urlExpires: uint }
]
```

Multipart semantics are MIMI's `processAll` only: receivers handle every part they understand, in
order, and skip the rest. (MIMI's `chooseOne` alternative-representations mode is deliberately
deferred; revisit when interop with a second implementation is real.)

The SDK never exposes CBOR to app developers: `@atsms/client` gains a `format/` module owning the
CDDL, the codec, constructors (`text()`, `reply()`, `reaction()`, `attachment()` …), and typed
TypeScript views of decoded messages. Test vectors (CBOR hex ↔ decoded form) live next to the
codec, MIMI-style.

## 5. Part-kind registry

Kinds are small integers. Each kind declares a **handling class**, which is what makes independent
clients behave identically:

| Handling | Meaning |
|---|---|
| **render** | Appears as a bubble in the transcript. |
| **apply** | Mutates conversation/message state; never its own bubble. Persisted. |
| **signal** | Real-time only; processed then discarded; sent with `ephemeral: true`. |

| kind | name | handling | inline body schema | notes |
|---|---|---|---|---|
| 1 | `text` | render | `{ text, ? facets }` | Facets: the existing atproto-style `mention`/`link`/`tag` byte-range annotations, finally produced and rendered; formatting (bold etc.) extends facets later. |
| 2 | `reaction` | apply | `{ emoji }` | Envelope `inReplyTo` = target. One emoji per part; multiple reactions = multiple parts. Removal: new message with `replaces` = the reaction message's ID, `body: null`. Aggregated Slack-style on the target. |
| 3 | `file` | render | external content (§4.1); tiny files MAY inline as `{ data: bstr, contentType, filename }` ≤ 32 KiB plaintext | Images/video/audio/documents are all `file` — the media type differentiates. |
| 4 | `call` | signal | promoted call-control contract: `{ callId, type: "offer"/"answer"/"ice"/"hangup"/…, ? sdp, ? candidate, ? mediaTypes }` | Replaces `atsms/webrtc`; absorbs the designed 8-verb gateway contract (`haiven-call-control.md`) **minus its private mini-envelope** — its `v`/`ts` duplication is deleted; the envelope owns those. Roadmap Phase 2. |
| 5 | `call-event` | render | `{ callId, event: "missed"/"ended"/"declined", ? durationMs }` | The durable transcript record of a call; signaling itself is ephemeral. |
| 6 | `receipt` | apply | `{ status: "delivered"/"read", ids: [* MessageId] }` | Batched. Persisted (offline devices catch up), never a bubble. |
| 7 | `typing` | signal | `{ state: "start"/"stop" }` | |
| 8 | `preview` | render | `{ url, ? title, ? description, ? image: ExternalContent }` | Sender-generated link preview, after a `text` part. |
| 9 | `group-update` | apply | `{ ? title, ? description, ? avatar: ExternalContent }` | Group metadata over the wire at last (closes the `product-architecture.md` group-info gap). Membership *events* stay at the DCGKA layer; clients surface them as synthetic feed rows. |
| 10 | `sms` | render | `{ text, ? from: e164, ? to: e164, ? mms: [* ExternalContent] }` | Gateway bridge dialect (roadmap Phase 10). |

Kinds ≥ 1024 are private-use. New standard kinds are additive; body maps ignore unknown keys, so
per-kind evolution is additive-field-only until a new kind is warranted.

### 5.1 Composition examples

- **Reply with a photo and caption:** envelope `inReplyTo` = target, body =
  `[file(image/jpeg external), text("this one?")]`.
- **Edit:** envelope `replaces` = *first* version's MessageId (MIMI's rule — maximizes correlation
  when intermediate edits were missed), body = the complete replacement parts. Receivers show the
  newest accepted version + an "edited" marker.
- **Delete:** `replaces` = first version's MessageId, `body: null` → placeholder bubble.
- **Thread reply that also posts to the channel** (Slack's "also send to #channel"): `topicId` set;
  the boolean rides a registered extension key when thread UI ships (§7).

**Authorization rule (edits, deletes, reaction removal):** receivers accept a `replaces` only when
the seal-layer-authenticated sender equals the target message's authenticated sender. Group-admin
deletion is deferred with group governance policy.

### 5.2 Unknown-kind policy (normative for all clients)

1. Process every part whose kind you know, per its handling class.
2. If at least one render part was understood, ignore unknown parts silently.
3. If nothing renderable was understood and `fallback` is non-empty → render `fallback` as plain
   text with an "unsupported message" affordance.
4. Otherwise → store but don't render, don't bump unread. Never render raw structures, never show
   `[kind]` placeholders.

Senders MUST set `fallback` on any render-class message using non-universal kinds, and MUST leave
it empty on pure apply/signal messages.

## 6. Message identity, ordering, integrity

**MessageId is derived, not carried** — MIMI's construction, adapted:

```
content  = deterministic-CBOR(AtsmsContent)          ; includes the salt
sender   = UTF-8 DID of the seal-layer-authenticated sender
id       = 0x01 || SHA-256( len16(sender) || sender ||
                            len16(convoId) || convoId ||
                            content || salt )[0..30]
```

`len16` = big-endian uint16 octet count (MIMI's fix for concatenation ambiguity); the salt appears
twice (inside `content` and appended) per MIMI's length-extension defense; the `0x01` prefix names
the hash (SHA-256) so it can be swapped later. Sender and receivers compute the same 32 bytes
independently.

What this buys:
- **No overwrite hazard.** An ID binds sender + conversation + content; a malicious group member
  cannot mint a message that collides with someone else's. Local storage keys on the derived ID.
- **Unforgeable references.** `inReplyTo`/`replaces`/receipt `ids` point at IDs nobody could have
  chosen; the `replaces` same-sender check (§5.1) stacks on top.
- **Franking-ready.** Abuse reporting against a sealed-sender relay needs exactly this shape of
  ID; MIMI's franking design slots in later without reshaping anything (§10).
- **One ID space.** The relay's ciphertext hash and the DCGKA frame MessageID remain transport- and
  engine-internal; the app layer sees only derived content IDs.

**Ordering:** DCGKA conversations sort by the engine's causal order — the frame layer's
`(seq, deps)` finally gets surfaced into `LocalMessage` as a `causalOrder` key — with `createdAt`
then lexicographic ID as tie-breakers. One-shot messages (no causal layer) sort by `createdAt`.
`createdAt` is otherwise display-only and understood to be sender-asserted.

## 7. Threads: what actually changes

Threads cost more than a field — but the cost lands **entirely in the client data model, not the
wire format**. This is MIMI's design and it holds up:

- **Wire:** `topicId` on the envelope. Done. It is present from day one and composes independently
  with `inReplyTo`/`replaces` — a message can be an edit of a reply inside a thread with no
  special cases (the Matrix failure mode, designed out).
- **Client store (the real work, post-alpha):**
  - thread summaries per root: reply count, participant set, last-reply time (a `GROUP BY topicId`,
    worth materializing);
  - per-thread read state and unread counts, separate from the conversation's;
  - notification policy: thread subscription (participated → subscribed), distinct badge rules;
  - "also send to channel" = one registered extension key when thread UI ships — old clients just
    render the message in the main flow anyway;
  - main-transcript policy: "N replies" affordance (Slack) vs inline (Matrix) — pure UI.

Recommendation: **ship the field in alpha, ship the UX later.** No stored message ever needs
migrating when threads arrive.

## 8. Path symmetry, ephemeral class, conversation IDs

**One-shot redone for symmetry.** The plaintext handed to CMS becomes the same deterministic-CBOR
`AtsmsContent` (v1's pretty-printed JSON inside DER is gone), and the CMS output travels **inside
the sealed-sender envelope** using the already-reserved `CONTENT_CMS` slot — no more bare DER on
the wire, no more telling the paths apart by byte-sniffing; dispatch reads the declared sealed
content type. Limitation: sealing requires a recipient sealing key (a published prekey);
for recipients that expose only an X509 certificate, the bare-CMS form remains as the explicit
legacy floor, and that privacy gap is a property of the floor, documented rather than sniffed
around.

**Ephemeral class.** `ephemeral: true` messages (all signal-handling kinds) are never written to
message storage, dropped on receipt when `createdAt` is older than 30 seconds, and excluded from
unread counts. This deletes the WebRTC replay-bug class at the root ([`webrtc-over-atsms.md`](../docs/history/webrtc-over-atsms.md)'s
lessons 1–4 become obsolete rather than worked around). Limitation, worth writing down:
end-to-end encryption means the relay cannot see the flag — ephemeral messages occupy inbox slots
until fetched or TTL'd. Letting the relay expire signaling faster would need a hint on the outer
transport envelope, leaking one bit of traffic metadata ("this is signaling"); default is not to
leak it.

**Conversation IDs: one space, no collisions.** v1 grew two indistinguishable 64-hex ID spaces
(one-shot participant hashes and DCGKA GroupIDs — the spec's "disjoint by construction" claim is
stale). v2 defines:

```cddl
ConvoId = bstr .size 33   ; context byte || 32-byte id
; 0x01 = one-shot: SHA-256("atsms/convo/oneshot/v2" || sorted, deduped participant DIDs,
;                          each length-prefixed)
; 0x02 = conversation: the DCGKA GroupID (MessageID of the create frame)
```

Structurally disjoint, domain-separated, and self-describing — no local metadata needed to know
which kind of conversation an ID names.

## 9. Adjacent work (not this doc, but sequenced with it)

1. **Blob storage endpoint** — external parts need somewhere to PUT/GET encrypted blobs. Natural
   home: the relay worker (R2 behind `POST /blob`), plus wiring the reserved `CONTENT_BLOBREF`
   envelope slot for oversize *messages* (distinct feature, same storage).
2. **Membership events → feed** — surface DCGKA join/leave/create as synthetic apply-class rows so
   clients can render "Alice added Bob" without a wire message.
3. **Spec/code name drift** — `atsms-sealed` (spec) vs `atsms-envelope` (shipped); align the spec
   while touching this layer.

## 10. Decisions (resolved 2026-07-31)

Formerly the open-questions list; each now has a recorded decision.

1. **Full `application/mimi-content` adoption — NO for v1; stay congruent, revisit at RFC.** v2 is
   deliberately congruent (same encoding discipline, field names, ID and external-part
   constructions), so transcoding — or swapping the container outright — stays mechanical. The
   gaps MIMI doesn't cover (receipts, typing, calls) are exactly our part registry's job either
   way. Trigger to revisit: the draft reaching RFC, or a real MIMI-network gateway requirement.
2. **Franking — DEFERRED to the abuse-reporting design.** The derived-ID construction is the
   prerequisite and is adopted now; the franking tag itself (relay-verifiable abuse reports under
   sealed sender) is designed alongside `draft-ietf-mimi-protocol`'s version when we do abuse
   reporting.
3. **Receipts privacy — sender-side setting; the format always carries receipts.** Whether a
   client *sends* read receipts is a per-conversation setting defaulting to an account-level
   setting (default: on). Enforcement is purely sender-side — you protect your privacy by not
   sending, never by asking others not to process. The SDK exposes the setting
   (`conversation.settings.sendReadReceipts` shape, exact API per `sdk-shape.md` conventions);
   surfacing the toggle in UI is operator/product territory (Haiven). Delivered receipts are not
   privacy-gated.
4. **Group-admin delete/edit authority — same-sender only for v1.** Receivers enforce the §5.1
   rule (authenticated sender must equal the target's authenticated sender) and nothing else.
   Admin/moderator retraction is deferred with group governance policy; when it lands it will be a
   receiver-side authorization extension, not a format change.
5. **`chooseOne` multipart — DEFERRED.** Only needed for multi-vendor alternative representations;
   revisit when interop with a second independent implementation is real.

## 11. Cut-over plan

> **Status (2026-08-01): FULLY EXECUTED** — `atsms/packages/client` + all three reference clients
> (`atsms-cli`, `atsms-web`, `atsms-demo`) run on v2; 238 lib tests green; the legacy
> `ATSMSStorageManager`/client vertical is deleted and **no v1 format code remains anywhere**.
> The demo's call signaling now rides ephemeral `call` parts (§8), retiring the
> `webrtc-over-atsms.md` replay workarounds. Remaining: the §9 adjacent work (blob endpoint
> first: external file parts encode but have nowhere to upload yet) and a live smoke over the
> deployed worker (`atsms-cli/scripts/smoke.ts` + the demo).

No wire migration — v1 was never released; it is deleted, not bridged.

1. Land the `format/` module in `atsms/packages/client`: CDDL file, deterministic-CBOR codec (shared rules
   with `@atsms/dcgka` — consider extracting a tiny common CBOR helper), MessageId derivation,
   constructors, typed decode views, §5.2 policy in one shared render-model helper, test vectors.
2. Cut over the DCGKA path: `convo.send()` accepts structured payloads
   (`send({text})`, `send({parts, inReplyTo})`); `handleDecrypted` decodes CBOR, derives IDs,
   routes by handling class (reactions/edits/deletes folded into message rows — the vestigial
   storage columns finally get producers).
3. Cut over the one-shot path: CBOR plaintext into CMS, CMS into the sealed envelope
   (`CONTENT_CMS`), declared-type dispatch replacing byte-sniffing, `ConvoId` derivation with the
   context byte, `recipients` extension check.
4. Storage: key on derived MessageId; add `causalOrder`; add thread/receipt/reaction projections.
5. Update the three reference clients; delete v1 (`ATSMSMessagePayload`, `atsms/text`,
   `atsms/webrtc`, `generateDMConvoId`) once nothing constructs it.
6. Stale-doc sweep: `architecture.md` §5 wording, `README-NPM`/browser guides (`atsms/image`
   examples), `atsms-integration.md` §5 and its "disjoint by construction" claim.
