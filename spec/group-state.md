# spec/group-state.md — shared group state (`setState`)

> **Status: `setState` op + the `group.name` convention BUILT 2026-08-06; the `group.info` document and
> its push/pull exchange DESIGNED, not built.** [Protocol] for §§1–4, **app-level convention** for §5
> onward — the split is the point of the design and is called out per section.

## 0. The problem

A group has state everyone should agree on — its name, later a description and an icon — and today it has
none: the creator names a conversation locally and nobody else ever sees it.

Three properties make this harder than a settings blob:

1. **A joiner must get it at admission.** A welcome carries the retained *control log* and nothing else, so
   anything living in application messages is invisible to someone admitted after it was sent — and they
   are not entitled to pre-admission app traffic anyway (ordering-auth §4.2).
2. **The log is forever, and welcomes carry all of it.** Every control op is re-sent inside every future
   welcome, and welcomes already outgrow the seal bucket after a few dozen membership changes
   (KNOWN-ISSUES 10). Anything that people change casually must not fatten that log.
3. **We do not want to freeze a schema.** Naming fields in the protocol means every future addition is a
   wire change and an interop obligation across implementations.

## 1. Shape: the protocol carries a pointer, the application carries the meaning

The op says **which** state is current. The application says **what it is**.

```
setState { ns: text, value: bytes | null }
```

- **`ns`** — a namespace, UTF-8, **≤64 bytes**. Convention is NSID-style (`at.atsms.group.name`), but the
  engine never interprets it: an implementation may mint namespaces without touching this spec or
  coordinating with anyone.
- **`value`** — opaque bytes, **≤128 bytes**, or `null` to clear. The engine never interprets these either.
  By convention a value is either a short inline datum or a 33-byte v2 message ID pointing at a document
  (§5).

Because the value is capped and opaque, adding new shared state later costs no protocol change: a new
namespace, a new app-level document format, nothing else.

**One namespace per op, deliberately.** Each namespace is its own register, so two admins setting different
namespaces concurrently never conflict, and only same-namespace writes need a tie-break. A map-valued op
would reintroduce cross-field clobbering unless every entry carried its own causal position.

## 2. Authorization (normative)

`setState` is **admin-only**, enforced by the DGM exactly like `grantAdmin` (dgm §4). A non-admin's
`setState` is filtered out and never changes any register — the same validity filter that governs
membership.

Small groups that want SMS-like informality make everyone an admin; that is a product decision, not a
protocol one.

*Widening this later costs no wire change.* Frames already carry their author, so a future rule — say a
`member.*` prefix each member may write about itself — is an engine change, not a format change.

## 3. Convergence (normative)

Per namespace, the current value is the one set by the **causally-latest** `setState` op for that
namespace. Concurrent writes (neither op an ancestor of the other) are broken by **lowest op id**,
compared as bytes.

This is deterministic over the same op set, which is all the DGM's convergence obligation requires, and it
is the same shape as the maximal-epoch selection the engine already performs.

An op whose `ns` or `value` exceeds its bound is **invalid**: ignored for state, never fatal.

## 4. Initial values on `create` (normative)

The `create` op MAY carry initial `(ns, value)` pairs, subject to the same bounds. They take effect as
though set by the create op itself, so a group is **born** with its state: every founding member and every
later joiner has it the moment they process their admission material, with no round trip and no
application message.

This is why the name is an inline value rather than a pointer (§5): a pointer cannot be seeded at genesis,
since a message's ConvoId derives from the GroupID, which *is* the create op's id.

## 5. Conventions (NOT protocol — app-level, changeable without a wire change)

| Namespace | Value | Fetch needed |
|---|---|---|
| `at.atsms.group.name` | the group's name, UTF-8, **≤64 bytes** | never |
| `at.atsms.group.info` | a 33-byte v2 message ID → the group-info document | yes, once |

Splitting them keeps the common case free: a group with only a name never needs a document, a fetch, or a
single application message, and a rename is one tiny op. The two do not overlap — the name is always
authoritative in `group.name`, and the document carries only the richer material — so there is no
precedence rule to get wrong.

**64 bytes is a byte cap, not a character cap.** That is ~64 Latin characters but ~21 CJK characters or
~16 emoji; clients SHOULD count bytes in their input UI rather than showing a character counter that lies
to some users.

### 5.1 The group-info document (DESIGNED)

An ordinary v2 message (docs/message-format.md) whose content carries a group-info part: description, and
an **inline icon**, capped at **16 KiB encoded** and sized for avatar display (96–128 px WebP/AVIF is
typically 3–8 KB). Inline rather than a blob reference because at that size it fits a seal bucket, needs no
blob store, and keeps v1 free of an availability dependency; when attachments land, the same document can
carry a reference instead for anything larger — an app-level change, invisible to the protocol.

The pointer is the message's **derived ID** (`sha256(senderDid ‖ convoId ‖ contentBytes ‖ salt)`), so a
recipient **recomputes the ID from served content and checks it against the pointer the admin signed**.
Serving is therefore unprivileged and tamper-evident: a member can withhold the document but cannot
substitute it. A response MUST carry the original author's DID and the original content bytes verbatim —
re-authoring changes the derived ID and fails verification. The responder is a courier, not a signer.

### 5.2 Getting the document to a joiner (DESIGNED)

A joiner has the pointer (it is in the welcome's control log) but not the content (it rode an epoch the
joiner was not in). The pointer is what makes the fetch reliable and terminating: the joiner knows exactly
what is missing, knows when it is satisfied, and can verify what arrives.

- **Push** — on processing an `add`, the **author of that add op** re-sends the current document content as
  an ordinary application message under the post-add epoch. Deterministic, no election.
- **Pull** — a joiner that cannot resolve a pointer after a short grace period (the push may be in flight)
  requests it by message ID.
- **Answer** — the **author of the `setState` op** answers; anyone else answers only after a short
  randomized delay if no answer has appeared.
- **Address answers to the group**, not to the requester: they are small, everyone dedups by derived ID,
  others observe and suppress their own answer, and any other member who was missing it is healed too.
- A client that has pruned the content MUST be able to say so rather than stay silent, or a requester
  cannot distinguish absence from refusal.
- If nobody answers, clients fall back to rendering participant names — today's behaviour, so the failure
  mode is the status quo rather than a regression.

Note this rides application messages, so it inherits their loss profile (KNOWN-ISSUES 6): a lost answer is
not automatically re-requested. The pull is the recovery, and it is idempotent.

## 6. Policy fields are deliberately out of scope

Disappearing-message timers, who-may-post and similar **behaviour-bearing** settings are NOT part of this
design. A client that silently ignores an unknown presentation field shows a plain group name; one that
silently ignores an unknown *policy* field misleads its user about protection. Those need either engine
enforcement or a required-capability mechanism (as MLS has, for the same reason), and they should be
designed with that in mind rather than smuggled in as another namespace.

## 7. Growth and compaction

Each set is one retained control op (~100–200 bytes), so a rename is cheap — but the log is forever and
welcomes carry all of it (KNOWN-ISSUES 10).

**`setState` history is the cleanest compaction case in the protocol**: unlike membership ops, superseded
values carry no causal meaning, so only the latest op per namespace is semantically needed. Welcome
checkpointing SHOULD treat them as such — this is design intent, recorded now so the checkpoint work can
rely on it.
