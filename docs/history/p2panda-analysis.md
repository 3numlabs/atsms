# p2panda-encryption vs. the DCGKA plan

> Fourth research note (see [`q-channel-analysis.md`](q-channel-analysis.md),
> [`mls-analysis.md`](mls-analysis.md)). Evaluates **p2panda-encryption** — the only shipped DCGKA
> implementation besides the academic Java prototype — for **adopt (bind via WASM) vs. port-as-reference vs.
> ignore**, against [`implementation-plan.md`](implementation-plan.md). Context: the per-group-sequencer
> question (D0) is now resolved — **sequencers are rejected; transport varies; local-first is a hard
> constraint** — which rules out MLS-with-sequencer and confirms the DCGKA family. p2panda made the same call
> for the same reason.
>
> Based on a full read of the `p2panda/p2panda` monorepo at v0.7.0 (HEAD 2026-07-07): `p2panda-encryption`
> (~14k LOC incl. tests), `p2panda-auth`, the `p2panda-spaces` bridge, plus crates.io history, the Feb 2025
> design blog post, and audit-status verification. Written 2026-07-14. **[Protocol] research note.**

## Verdict up front

**Port-as-reference — emphatically not ignore, and not bind (yet).** The `message_scheme` module is the most
faithful implementation of Weidner et al. in existence — a near line-by-line port of the paper with sensible,
well-documented upgrades — and it resolves precisely the ambiguities we would otherwise hit implementing from
the paper. But the half we need (the message scheme) is the **unproductized** half: no production DGM, no
production orderer, no app ships it (including p2panda's own), no WASM/JS story, and the announced Radically
Open Security audit **was never published** (README at v0.7.0 still says "not yet received a security
audit"). Binding it would buy only the code that's easiest to port while leaving every hard, product-shaped
piece for us anyway — around a pre-1.0 WASM core we'd have to patch and be the first to ship in JS runtimes.

## What it is

- `p2panda-encryption` in the `p2panda/p2panda` monorepo; crates.io 0.4.0 (Jul 2025) → **0.7.0 (Jul 2026)**;
  ~700 total downloads, no external consumers beyond p2panda's own crates. MIT OR Apache-2.0 (license-clean
  for us, unlike Q-channel). Three maintainers (Berlin collective), EU NGI grant-funded, **bus factor ≈ 2**.
- Consumer reality: **Reflection** (GNOME local-first editor, alpha) uses only the **Data Encryption** mode
  via `p2panda-spaces`. **Nobody anywhere ships the Message Encryption (DCGKA) scheme in production.**
- Two modes:
  - **Data Encryption** (default, productized): long-lived reused group secret, full secret history shipped
    to new members (late joiners read everything), FS only if the app deletes old secrets. Built for
    wikis/CRDT documents. **Wrong for messaging** — not our path.
  - **Message Encryption** (`message_scheme`, what we need): the paper's DCGKA + per-member hash ratchets.
    Signal-grade FS; ack-driven PCS exactly per the paper.

## Fidelity to the paper — and the upgrades worth copying

- **DCGKA core** (`message_scheme/dcgka.rs`, 1,570 lines): state maps 1:1 to the paper's γ (2SM sessions,
  `member_secrets[(sender, seq, id)]`, per-member outer ratchets, `next_seed`, DGM). All six control types,
  welcome/add-ack handling, and **concurrent-add member-secret forwarding** (§6.2.5) implemented — doc
  comments quote the paper inline. PCS is ack-driven with FS-motivated deletes exactly as specified.
- **2SM** (`two_party/`): the paper's App. D rotating-key discipline, but with the abstract PKE instantiated
  as **X3DH for the first round + RFC 9180 HPKE (X25519/HKDF-SHA256/ChaCha20-Poly1305) for subsequent
  rounds**, XEdDSA-signed prekeys. A strict upgrade over the paper's bare PKE — exactly what our
  `../../spec/2sm.md` should specify (this supersedes the plan's "implement App. D exactly" wording).
- **App ratchet** (`message_scheme/ratchet.rs`): sender-keys-style HKDF chains with single-use keys and a
  bounded out-of-order window (`GroupConfig { maximum_forward_distance: 1000, out_of_order_tolerance: 100 }`)
  — a concrete answer to our G3, worth adopting numbers and all.
- **Useful deviations to keep**: host-supplied operation IDs/seq (fits our envelope layer), local-op/process
  split, welcome carries **processed DGM state instead of raw history** — which is also a ready-made answer
  to our G7 history-compaction question.
- **One real bug found** (`dcgka.rs:359`, `process_ack`): the condition reads `is_add(op) && is_remove(op)`
  where the paper (and Java reference) require **OR** — with any sane DGM the branch is dead code, so
  remove-acks are never recorded and a remote member's view can over-approximate after removals. It survives
  their tests because add-acks flow through a different path. Two lessons: (a) fix it in our port; (b) this
  is direct evidence the crate has **not been adversarially reviewed** — reinforcing "reference, not
  dependency."

## The three holes that decide adopt-vs-port

1. **No production DGM.** The message scheme ships only `AckedTestDgm` — self-described as test-only, no
   re-add support, "will be soon replaced" (12+ months old). The real membership CRDT — `p2panda-auth`, an
   operation-DAG with `Pull/Read/Write/Manage` roles and a ~1,000-line **StrongRemove resolver** (manager
   removal invalidates their concurrent ops, mutual removes both apply, re-adds allowed, transitive
   invalidation) — is genuinely good design **but implements a different trait and has never been bridged to
   the message scheme**. The only bridge (`p2panda-spaces`) is a data-scheme-only `HashSet` placeholder. Our
   G5 design work remains ours; `p2panda-auth`'s resolver rules are the best available input to
   `../../spec/dgm.md` (better documented than the Java `StrongRemoveDgm`).
2. **No production orderer.** The crate requires the host to deliver control messages causally ordered; the
   `ForwardSecureOrdering` trait's rustdoc is an excellent **ordering spec** (dependency rules for control
   messages, acks, epoch-first app messages, welcome semantics — directly usable input to our
   `../../spec/ordering-auth.md`), but the shipped orderers are test-only (one literally makes every message depend
   on all prior messages). Our G4/G12 work remains ours.
3. **No JS/WASM path.** No bindings exist (their FFI work targets uniffi/GObject, not JS; "WASM planned, not
   the priority" — June 2026). The crate is sync, pure-Rust, and should compile to wasm32, but
   `SystemTime::now()` calls in key-bundle lifetime checks **panic at runtime on wasm32-unknown-unknown**,
   getrandom needs configuring, and we'd be the first-ever JS-runtime consumer across browser + RN + Workers,
   tracking a churning pre-1.0 API we can't fix in-tree. That's a worse position than owning a TS
   implementation validated against their code.

Also noteworthy: **transport-agnosticism is real** (no networking, no async, no p2panda-store dependency;
pure functions `f(state, input) → (state, output)` with fully serializable state) — it validates both our
local-first constraint and our planned architecture. Metadata protection is absent by design (control
messages currently plaintext; sender/recipient of direct messages visible) — our sealed-sender envelope
(G9) wraps it cleanly since the crate never inspects transport metadata. Prekeys: pluggable registry traits
map onto a PDS, but the message scheme hard-types one-time bundles and `PreKeyReuse` is a hard failure with
no fallback — confirming our D4 design (signed-prekey/last-resort semantics + explicit retry path) must be
handled in our layer. Multi-device: member = device key throughout; user→devices modeling exists only in
auth-layer nested groups, data-scheme only — our G6 remains ours.

## What this changes in the implementation plan

The plan's shape survives; its contents get significantly de-risked:

- **D3 (TypeScript) is reinforced**, with a twist: keep the p2panda clone as a **differential-testing
  oracle**. Their RNG is seedable, making whole-protocol runs deterministic — we can generate cross-
  implementation test vectors (2SM transcripts, ratchet chains, full group scenarios) from the Rust side and
  assert byte-equality in TS. That is a far stronger Phase 1–2 quality gate than the Java prototype
  (which was our previous plan for test vectors) — supersedes that reference.
- **Phase 0 spec inputs upgraded**: `../../spec/2sm.md` specifies X3DH + HPKE with rotating-key discipline (their
  instantiation) rather than bare App. D PKE; `../../spec/ordering-auth.md` starts from their
  `ForwardSecureOrdering` rustdoc spec; `../../spec/dgm.md` draws on `p2panda-auth`'s StrongRemove resolver rules
  (with our authorization model on top); `../../spec/dcgka-core.md` adopts welcome-carries-DGM-state (G7) and their
  out-of-order window config (G3). Port their module boundaries (`two_party` / `dcgka` / `ratchet` / `group`
  + host-supplied DGM/Orderer/PKI/KeyManager traits) as our module architecture — it's exactly the
  decomposition our plan sketched, now proven in code.
- **Known-bug list for the port**: the `process_ack` AND→OR fix. Worth filing upstream too — cheap goodwill
  and a live test of their responsiveness (a data point for any future adopt decision).
- **Re-evaluate triggers** (adopt/bind becomes plausible if): the ROS audit actually publishes; the message
  scheme gets a real DGM bridge + production orderer; v1.0 lands with a JS/WASM story. Until then: reference.

## Bottom line

p2panda-encryption is the strongest possible validation of the path we're on: an independent, well-run team
with the same local-first constraint evaluated MLS, chose DCGKA, and implemented the same paper — arriving at
essentially the architecture our plan describes (host-supplied ordering, swappable DGM, sealed transport as a
separate layer). It doesn't change the destination; it substantially de-risks the journey: our two BLOCKER
crypto ambiguities (G1, G3) now have working, inspectable answers, our three hardest specs get concrete
prior-art inputs, and we gain a deterministic oracle for differential testing. What it is not — yet — is a
dependency: the messaging half is unproductized, unaudited (with at least one found paper-deviation bug),
and has no JS path. **Port, validate against it, watch it.** *(Superseded in part by the Addendum below.)*

## Addendum (2026-07-14): fork-and-contribute-back reconsidered

Follow-up question: rather than porting to TS, should we fork the repo, add WASM, and contribute back?
**Revised answer: yes — structured as "depend + thin patch fork," conditional on Rust capacity.** This
revises the verdict above and D3 in the implementation plan (now D3-a/D3-b).

The technical fact that reframes the choice: the crate's DGM/orderer/PKI are **Rust generic type
parameters**, not injectable from JS across a wasm boundary. So "bind the crate" ⇒ our DGM, orderer, and
PDS key-registry are written in Rust too ⇒ the real decision is *protocol language: Rust vs TS*. Seen that
way:

- **For the Rust path:** one crypto implementation instead of two (the reimplementation-bug class — our
  biggest plan risk — disappears; we found a real bug even in p2panda's faithful port); the
  libsignal / Wire-core-crypto precedent (Rust core + per-platform bindings is how every serious messenger
  does this); real `zeroize` memory hygiene (impossible in GC'd JS); any future upstream audit covers the
  shared core if our delta stays thin; contribute-back fits the 3NUM Labs open-source posture.
- **Structure — no hard fork needed:** the trait design means our components are separate crates *depending
  on* `p2panda-encryption`. The fork is only a patch queue while PRs are pending upstream: `process_ack`
  `&&`→`||`, injectable clock (kills the `SystemTime::now()` wasm panic), getrandom `wasm_js` config —
  all small, all things upstream has signaled wanting. The PRs double as a responsiveness probe: merged
  fast → the model works; rotting → we already hold the fork.
- **Platform caveat:** React Native has no WASM (Hermes). "Use WASM" therefore means **dual bindings**:
  wasm-bindgen for browser/Workers/node-bun (the crate is sync, pure-Rust, ideal for wasm32) + **uniffi**
  for iOS/Android — which is upstream's own v1.0 FFI direction, so we swim with their current.
- **The condition:** all protocol work moves to Rust (TS keeps the `@atsms/sms` facade + envelope/transport
  layer), plus a multi-target build pipeline to own. If Rust capacity is thin, fall back to the TS port
  with the crate as differential-test oracle (D3-b). Pre-1.0 churn is managed by pinning and deliberate
  upgrades.

**Decision (2026-07-15): D3-b — TypeScript for v1.** The first app is React Native-based; RN's lack of WASM
means the Rust path would lead with its weakest binding (uniffi native modules) on the primary platform.
The crate remains the porting reference and differential-testing oracle; D3-a is shelved, to be revisited if
p2panda ships a JS/WASM story, publishes the audit, or the RN platform picture changes.
