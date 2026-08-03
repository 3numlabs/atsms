# spec/add-member-flow.md — Adding a member: the end-to-end flow

> **Status: DOCUMENTATION v1 (2026-08-02)** — an operational walkthrough of the BUILT flow
> (`ATSMS.addMember` in atsms-lib + `ConversationSession.addMember` here), written after the live
> add-flow debugging arc. Normative material lives in the referenced specs; this doc records **what
> actually happens, in order**, flags **every network fetch and whether it is cacheable**, and analyzes
> **how multi-device DIDs and multi-user adds scale**. §6 lists optimization candidates (PROPOSED);
> nothing in this doc changes wire behavior.

Actors: the **adder** (an existing member device running the client), the **existing members** (every
other device already in the group), the **joiner devices** (the added DID's devices), the **relay**
(dumb store-and-forward worker), and the **PDSes** (each DID's AT Protocol data server, found via PLC).

---

## 1. Phase A — naming: handle → DID → PDS

| # | Step | Network | Cacheable? |
|---|------|---------|-----------|
| A1 | Handle → DID (`resolveHandle`) — client UX input only; the protocol deals in DIDs | 1 × XRPC | Yes — hours; handles remap rarely, and a wrong hit fails loudly at capability discovery |
| A2 | DID → PDS service endpoint (PLC directory lookup, `readAgentFor`) | 1 × HTTPS per *new* DID | **Already cached** per-process (read-agent map, `pds-client.ts`) — but not persisted across runs |

## 2. Phase B — capability discovery (`capableDevices`, capability §3)

The adder enumerates the added DID's devices and verifies each one is DCGKA-capable. A device counts
iff its cert parses, the fingerprint derives, and its prekey record verifies against the cert identity
key and is unexpired (identity-devices §4).

| # | Step | Network | Cacheable? |
|---|------|---------|-----------|
| B1 | `listRecords(did, at.atsms.x509)` — the device list | 1 × XRPC | Yes — minutes; devices appear/re-key rarely. Staleness cost: a *missed brand-new device* (it catches up later via `reconcileDevices`) |
| B2 | Per device: `getRecord(at.atsms.prekey/<fingerprint>)` | **1 × XRPC × N devices, currently sequential** | Yes — minutes, BUT freshness matters more than A/B1: sealing a welcome to a superseded prekey is undecryptable-by-design (`drop-admission-keys`). Rule: cache short, and **invalidate + refetch on admission failure signals** |
| B3 | Cert parse, fingerprint derivation, prekey signature + expiry checks | none (local) | — |

> **Hotspot (BUILT):** B2 runs in a `for` loop — N devices = N sequential round trips. The fetches are
> independent; parallelizing is safe.

## 3. Phase C — per-device group operation (local; this package, §4b orchestration)

For **each** joiner device, `ConversationSession.addMember` mints, in one atomic local pass:

1. **`add`** — DGM op admitting the device (leafPk = its signed prekey; signingPk pinned). Blanks the
   tree root (correct BeeKEM behavior: no shared secret may survive a resolution change).
2. **`update`** — the adder immediately establishes the **post-add epoch**, path secrets encrypted to
   resolutions that include the new leaf. Built *before* the welcome so the welcome's log carries it —
   the joiner derives the epoch on replay instead of racing a heal (concurrent-update-partition §4b).
3. **`welcome`** — the retained frame log, point-to-point for the joiner. **`ctrlSeq: null`** — it must
   not occupy the sender's broadcast contiguity lane, since existing members never receive it
   (the 2026-08-02 partition fix; ordering-auth §4.1 order-exempt lanes).

Then the seal pass (sealed-sender §11): the `add` and `update` frames are sealed **sym under the
PARENT epoch** (`sealEpochFor(deps)` — receivers hold it and derive the new epoch by processing these
very frames; falls back to asym-to-prekeys when no sealable epoch exists), **one envelope per recipient
device**. The welcome is sealed **asym to the joiner's signed prekey**, one envelope.

> **When does an add find no sealable epoch?** Three cases. (1) *Genesis window*: the adder is a
> founding member that bootstrapped from the create but has not yet processed the first
> epoch-establishing update — the add's ancestry reaches only the create. (2) *Mid-heal*: a concurrent-
> update merge blanked the root, so every reachable epoch is orphaned and disqualified by the §4.1
> sealable rule (note every `addMember` mints an update, so two members concurrently adding different
> people is sufficient to get here). (3) *Degenerate*: an epochless half-built group (interrupted
> `open()`; now repaired on reopen) racing that repair. The fallback is self-extinguishing — the frames
> inside the asym envelopes are the ones that re-establish a sealable epoch — and costs per-recipient
> HPKE, larger envelopes, and reliance on prekey-secret grace (asym opens only while the recipient
> still holds the prekey secret) instead of epoch grace.

No network in Phase C. Envelope count per added device: `2 × (current members − 1) + 1`.

## 4. Phase D — delivery (`ATSMS.route` + `ATSMSWorkerEnvelopeTransport`)

Per envelope, in a **sequential** `for`-await loop (BUILT hotspot):

| # | Step | Network | Cacheable? |
|---|------|---------|-----------|
| D1 | If the recipient device advertised an in-band endpoint (`ext.endpoint`, sealed-sender §12): direct POST | 1 × POST | The *endpoint* is already known in-band — no lookup. POST itself: no |
| D2 | Else `deliverToDid`: resolve the recipient DID's `at.atsms.inbox` record | **1 × XRPC per envelope — currently UNCACHED** | Yes — ~60 s TTL. The record is a per-DID singleton (last-writer-wins), so short TTL + invalidate-on-delivery-failure preserves semantics. **This is the single largest waste**: every envelope to the same DID re-fetches the same record |
| D3 | POST `{envelope}` → relay ingress `/inbox/{did}` | 1 × POST | No (the actual delivery) |
| D4 | **Relay-side, per ingress POST**: `getActiveClientCertificates(did)` → PLC resolve + `listRecords(x509)` to fan one copy per device DO | 2 × HTTPS *on the relay*, **currently uncached** | Yes — relay MAY cache the device list per DID for minutes; staleness only delays fan-out to a brand-new device, which §8 repair / reconcile covers |

Ordering constraint on parallelizing D: envelopes to the **same recipient device** SHOULD stay FIFO
(the ordering buffer + §8 repair absorb violations, but in-order is free goodwill); envelopes to
**different recipients** are fully independent.

## 5. Phase E — receive side

- **Existing members**: open the sym envelopes under the parent epoch → ordering layer (deps/ctrlSeq)
  → engine: `add` blanks the root, `update` derives the post-add epoch. No action, no round trips.
  A lost frame becomes a discoverable gap; the §8 repair trigger re-fetches it from any member
  (T_REPAIR = 60 s).
- **Joiner**: opens the asym welcome with its prekey secret → `Session.fromWelcome` replays the log →
  holds the post-add epoch immediately (no self-heal update — §4b). Its first outbound frames advertise
  its in-band endpoint, upgrading future traffic to D1 routing.
- **Non-added devices of the joiner DID** (relay fan-out gives every device of a DID a copy of
  everything): AEAD-fail and drop the copies not sealed for them. Normal noise.

## 6. Scaling: multi-device DIDs and multi-user adds

**BUILT shape:** `ATSMS.addMember(convo, did)` loops Phase C+D **once per capable device**. Adding a
DID with K devices to a group with M existing member devices:

- **Ops**: 3K frames (K adds, K updates, K welcomes) — and **K epochs** minted where one would do.
- **Envelopes**: Σₖ [2·(M+k−1) + 1] ≈ **2KM + K² + K** — the recipient set grows as each device joins.
- **Round trips** (with today's uncached D2 + sequential D): ~2 per envelope + Phase B.

Live datapoint (2026-08-02): K=4 devices, M=4 existing → ~48 envelopes ≈ **85–90 sequential HTTPS
round trips ≈ 4–13 s** for one `/add`. Adding multiple *users* is the same loop over the union of
their devices — cost is linear in total device count with the same per-device constants, plus the K²
recipient-growth term.

**PROPOSED batched shape** (protocol-visible, needs its own change + regression pass): for one
`addMember` call covering K devices — mint **K adds, then ONE update, then K welcomes**. The §4b
invariant ("the joiner derives the post-add epoch on replay") holds: every welcome's log contains all
K adds and the single epoch-establishing update. Effects: K epochs → 1; frames 3K → 2K+1; every
existing member processes K+1 control ops instead of 3K; envelope count drops the same way. Partial-
failure semantics must match today's resumability: a crash mid-batch is healed by `reconcileDevices`
on next open (it admits any capable device not yet in the group), same as today.

## 7. Cacheability summary (the client-side fix list, impact order)

1. **D2 — inbox-record resolution**: memoize per DID, ~60 s TTL, invalidate on delivery failure.
   Removes ~40 redundant XRPC fetches from the live datapoint.
2. **D — parallelize route()**: FIFO per recipient device, concurrent across recipients.
3. **B2 — parallelize prekey fetches** (K round trips → 1 RTT).
4. **D4 — relay-side device-list cache** (minutes TTL) — separate repo (atsms-worker).
5. **§6 batched add** — the only item that changes protocol-visible behavior; do last, separately.

Items 1–4 change *when* data is fetched, never *what* is trusted: every cached artifact is either
self-authenticating (certs, prekeys verify against the cert identity key) or fails loudly and
refetchably (inbox record → delivery failure; stale device list → reconcile/repair catch-up).
