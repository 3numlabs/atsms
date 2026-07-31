# spec/dgm.md — Decentralized Group Membership for ATSMS-DCGKA

> **Status: DRAFT v0.2 (2026-07-22) — for review.** *(v0.2: D11 reconciliation — the key-agreement
> executor is now the BeeKEM tree; the DGM is unchanged as policy and additionally acts as the
> validity filter gating tree application ([`../spike-b-dgm-reconciliation.md`](../spike-b-dgm-reconciliation.md));
> ack-tracking in §6 re-based on coverage; §8 digests narrowed by `rootCommit`.)*
> [Protocol] · Phase 0 deliverable.
> Closes gaps **G5** (group-management model) and **G14** (insider-divergence detection) from
> [`../gap-analysis.md`](../gap-analysis.md).
> Inputs: DCGKA paper §5.2/§6.2 (required DGM properties), prototype `StrongRemoveDgm.java`,
> p2panda-auth `StrongRemove` resolver semantics, spec v1.1 §4 identity/device model.
> Terminology: MUST/SHOULD/MAY per RFC 2119. "Ordering layer" = [`ordering-auth.md`](./ordering-auth.md).

## 1. Role in the stack

The DGM is a **pure, deterministic function** from a set of membership operations plus their causal relation
(the op DAG supplied by the ordering layer) to a membership view:

```
members_view(history, viewer) → { membership → role }
```

It holds **no state of its own** beyond what is derivable from `history`; it performs **no I/O**; it consults
**no clocks**. The core calls it for welcome contents and message-acceptance gating, and — since D11 — as the
**validity filter for the BeeKEM tree**: a CGKA op (`create`/`add`/`remove`/`update`) is applied to the tree
iff this function judges it valid at its causal position in the full frame DAG; invalid ops remain causal
history but never touch tree state (beekem-core §4.1, PR-1/PR-2). Because validity is deterministic over the
op set + causal order, all honest members apply the same subset and BeeKEM's deterministic merge/replay
yields identical trees (P5 lifts through). Implementations MAY cache/evaluate incrementally, but incremental
evaluation MUST be extensionally equal to batch re-evaluation from scratch (test obligation, §9).

## 2. Identifiers

- **DeviceID** `= (DID, deviceFingerprint)` — the identity-layer device handle
  ([`identity-devices.md`](./identity-devices.md) §2). `deviceFingerprint` is the SHA-256 of the device's
  endpoint-cert SubjectPublicKeyInfo (also the `at.atsms.x509` rkey).
- **Membership** `= (DeviceID, admittedBy)` — the group-layer member identifier: one device's tenure in
  one group. **`admittedBy` = the MessageID of the op that admitted this member** (the `create` for
  founding members, the `add` otherwise; identical construction to BeeKEM's
  `Digest<Signed<CgkaOperation>>`) — derived data, never client-chosen. Re-adding a device
  therefore yields a fresh Membership with no coordination — prior chain/envelope-key state MUST never be
  resumed (all profile keys are Membership-keyed, beekem-core §3, so resumption is structurally impossible). *(Renamed 2026-07-17 from the earlier `MemberID = (DID, fingerprint, instanceNonce)` triple:
  the split separates who the device is from which admission is speaking.)*
- **OpID** = the MessageID (content hash of the signed message, per ordering-auth §2) of a membership
  operation.
- **GroupID** = the MessageID of the `create` operation (ordering-auth §2.1).

## 3. Required properties (from the DCGKA proof — all normative)

- **P1 Determinism**: output depends only on the *set* of valid ops and their causal partial order — never on
  local arrival order, wall-clock time, or any tie-break derived from them.
- **P2 Sequential self-consistency**: from each sender's own vantage, its ops apply with ordinary sequential
  semantics.
- **P3 Add-only entry**: a member enters the group **only** via a `create`/`add` naming its DeviceID (the
  resulting Membership is derived from the admitting op). No conflict-resolution rule may (re)admit a
  member as a side effect.
- **P4 No remove-undo**: a processed remove is never negated by a concurrent or later op (re-entry only via
  P3 with a fresh Membership). Matrix-style "remove undoes concurrent remove" is explicitly excluded.
- **P5 Convergence**: any two evaluators holding the same op set compute identical views (follows from P1;
  stated separately as the property the test harness asserts).

## 4. Roles and authorization

Two roles: **admin** and **member**. Authorization is evaluated **inside the pure function**, from history
alone, at the op's causal position (an op's validity depends on the authorizer's role *in the view formed by
the op's causal predecessors*).

| Op | Authorized when author is… |
|---|---|
| `create(initialMembers, initialAdmins)` | n/a — the creator's devices are admins; other founding members as listed |
| `add(deviceID)` — cross-DID | admin |
| `remove(membership)` — cross-DID | admin, or the target itself (self-leave, any device of the target DID) |
| `add(deviceID)` / `remove(membership)` — **same-DID** (author DID == target DID) | **any member device of that DID**, regardless of role (device rotation/loss, spec v1.1 §4) |
| `grantAdmin(DID)` / `revokeAdmin(DID)` | admin |

Notes:
- Roles attach to **DIDs**, not devices: every device of an admin DID authors admin ops. `grantAdmin`/
  `revokeAdmin` target DIDs; `add` targets a DeviceID (the new Membership is derived from the op), `remove` targets a Membership. **`grantAdmin` is valid only if the
  grantee DID has at least one current member device in the author's view at the op's causal position**
  (decided 2026-07-16).
- **User-level intents expand client-side** into per-device ops: "remove user U" = a causally sequential
  batch of `remove` for every U-device in the author's current view (strong removal, §5, catches devices
  added concurrently); "add user U" = `add` per U-device discovered via U's PDS (`at.atsms.x509` +
  `at.atsms.prekey`). The DGM validates each op individually; batches have no atomicity semantics.
- An admin DID whose last device is removed loses admin trivially (no members left to act). A group whose
  last admin leaves is frozen for cross-DID membership change; clients SHOULD warn before allowing the last
  admin to leave (an admin MUST `grantAdmin` first). Same-DID device ops and PCS updates remain possible.
- `revokeAdmin` on the last admin DID is **invalid** (prevents adminless-by-malice; adminless-by-departure
  is handled above).

## 5. Conflict resolution: strong remove

Let `R` be a valid `remove` (or `revokeAdmin`) and `M` its target. Definitions use the ordering layer's
happens-before (`≺`); "concurrent" = neither `≺` direction holds.

- **SR1 (invalidate the removed member's concurrent ops)**: every op authored by `M` that is concurrent with
  `R`, and every op authored by `M` after `R` in `M`'s own sequence, is **invalid**. (For `revokeAdmin`,
  only ops *requiring admin* become invalid; the demoted DID's ordinary membership continues.)
- **SR2 (transitive cascade)**: if an invalid op is an `add`, the added member is treated as never admitted:
  all of its ops are invalid, recursively. Invalidation MUST NOT remove ops that merely *causally follow* a
  valid op by an invalidated member (only authorship matters, per SR1's authorship test applied recursively).
- **SR3 (mutual removes)**: two admins concurrently removing each other — **both removes are valid** (both
  DIDs' devices are out); each party's *other* concurrent ops are invalid per SR1.
- **SR4 (no resurrection)**: cascades only shrink the member set (P3/P4). In particular a cascade never
  restores a member that an invalidated op had removed — instead, a remove authored by a *later-invalidated*
  member is itself invalid, and the target's membership is decided by the remaining valid ops alone.
- **SR5 (self-leave priority)**: a self-leave is valid regardless of any concurrent remove targeting the
  same member (both yield "out"; recorded independently for audit).

**Evaluation algorithm (reference)**: iterate ops in any topological order of `≺`; maintain
`(members, roles, invalid)`. For each op: (i) skip if author ∉ members at its causal position or
authorization (§4) fails — mark invalid; (ii) apply SR1–SR5 retroactively when a remove/revoke arrives that
is concurrent with already-applied ops — implementations MAY re-evaluate from the nearest checkpoint; the
result MUST equal batch evaluation (P5).

**Core interaction note**: ops invalidated retroactively may already have contributed key material (an
invalidated `add`'s leaf may sit in a surviving root's resolutions). After any retroactive invalidation the
client MUST schedule a PCS `update` before its next application message (beekem-core §10 — the one case the
no-root-→-update rule does not absorb). Mechanically, retroactive invalidation rides the replay BeeKEM
already performs on concurrent membership changes (PR-3, [`../spike-b-dgm-reconciliation.md`](../spike-b-dgm-reconciliation.md) §4).

## 6. Coverage tracking and `members_view(viewer)` *(re-based 2026-07-22 — acks retired by D11)*

The core still needs membership **as another member sees it**. With acks retired (beekem-core §5), the
signal is **coverage**: op `X` is in `viewer`'s vantage iff `viewer` authored `X` or authored any frame
causally descending from `X` (the ordering layer's `deps`). `members_view(history, viewer)` = the §5
evaluation restricted to ops the viewer has authored or covered, plus their causal predecessors — same
shape as before, different (and cheaper) signal: coverage is implicit in all ordinary traffic, topped up
by `coverage` frames within `T_COVER` (beekem-core §5). Welcome messages carry a **checkpoint + op
suffix** (beekem-core §6) instead of the old processed-DGM-state form: the joiner re-validates every
suffix signature and evaluates the DGM itself; the checkpoint portion is adder-asserted — the same trust
the adder already held under the old `ackMatrix`.

## 7. Eviction policy hook (stale members)

The DGM defines **no timers** (P1). Staleness is detected by the ordering layer (ordering-auth §9) and
surfaced to the application; an application/operator policy MAY respond by issuing an **ordinary authorized
`remove`** (nothing else — auto-eviction has no special status in the DGM). Recommended default policy
(SHOULD): warn the group UI at 7 days of a member neither sending nor acking; propose eviction to admins at
30 days. Rationale: unacked members block PCS healing and state GC (gap G2/G15).

## 8. Insider-divergence detection & recovery (G14)

*(Narrowed 2026-07-22 by D11.)* The worst insider attack of the DCGKA era — one signed op delivering
**different key material to different members** — is now **rejected at processing time** by the
`rootCommit` check (beekem-core §4.3): a single root secret per epoch makes divergent derivation
detectable by every member individually, no comparison protocol needed. What remains for the digest is
**op-set equivocation** (showing different signed-op histories to different members):

- **Consistency digest**: `H(groupId ‖ sorted valid-op OpIDs at the sender's heads ‖ H(tree public
  state))`. No secret inputs remain (ratchet-state hashes are retired with the outer ratchet) — but the
  digest stays inside the sealed envelope like everything else. Carried as an optional signed field on
  **any** outgoing frame (decided 2026-07-16; no standalone digest frames) — attach if the last one is
  older than 7 days, at least every `K = 50` own messages; `coverage` frames are natural carriers
  (beekem-core §5). Silent members are the stale-member machinery's job (§7), not the digest's.
- **Mismatch procedure**: head-set differences resolve through ordinary `repair` (someone is missing
  ops — liveness, not attack). Equal head-sets with unequal digests means disagreement on op *validity*
  or tree state — deterministic from the op set, so it isolates to a missing/withheld op or an
  implementation fault; exchange the op lists via repair and re-evaluate. A member persistently
  presenting signed, conflicting head-sets **is** the equivocator → any admin SHOULD `remove` it
  (ordinary op); if no admin acts, clients MUST surface a persistent security warning; the fallback
  remains group re-creation (fresh `create`) excluding the suspect.
- Guarantee preserved: the equivocator cannot resist removal, and post-removal it decrypts nothing.

## 9. Test obligations (normative for the implementation)

1. **Permutation determinism**: randomized op schedules (≥ 32 members, adds/removes/grants/leaves incl.
   same-DID device ops), evaluated under many delivery interleavings — identical views (P1/P5) **and
   identical filtered-tree hashes** (the D11 filter composed with BeeKEM merge/replay; Spike B §9).
2. **Strong-remove vectors** (fixed, reviewable): add∥remove-of-adder; mutual admin remove; revoke∥admin-op;
   remove-user∥target-adds-device; re-add after remove (fresh Membership — new `admittedBy` — no state
   resumption); cascade depth ≥ 3;
   last-admin rules.
3. **Cross-check** against p2panda-auth's `StrongRemove` resolver on the scenario subset where semantics
   coincide (documented divergences: our role model, self-leave, last-admin rule).
4. **Incremental ≡ batch**: property test that cached evaluation equals from-scratch evaluation after every
   op.

## 10. Open questions (tracked for review)

- ~~grantAdmin target~~ **decided 2026-07-16: yes** — grantee DID must be a current member (normative in §4).
- ~~Digest cadence~~ **decided 2026-07-16**: `K` = 50 own messages / 7 d backstop (§8; registered in
  [`parameters.md`](./parameters.md)).
- ~~Third role (e.g., read-only)~~ **decided 2026-07-16**: v1 ships admin/member only.
- ~~MemberID shape~~ **decided 2026-07-17**: split into `DeviceID` + `Membership(admittedBy)` (§2);
  `add` targets DeviceIDs, `remove` targets Memberships; the device fingerprint (not cert serial) is the
  sole protocol identifier (identity-devices.md §4).
- **Ban-on-remove (compromised-device re-add veto)** — discussed 2026-07-17, **parked by user** pending
  the MemberID-shape resolution above; revisit: same-DID re-adds need no admin, so a group-level,
  history-derived ban is the deterministic complement to identity-layer revocation.
- **Versioned authorization policy at `create`** — raised 2026-07-31, **open**. Today the authorization
  model (roles, who-can-do-what — §4) is fixed by this spec; `create` selects only the initial roster/admins,
  not a *policy*. Should `create` instead pin a **policy identifier** (e.g. `authPolicy: 1`) naming one of a
  set of spec-defined policies, so the ruleset can evolve without breaking existing groups (old groups keep
  policy 1; new groups opt into policy N)? The policy definitions live in the spec, not in the op — the op
  carries only the version tag, evaluated identically by every member (determinism/P1 preserved). Motivation:
  future changes like a third role (read-only, cut from v1 above), configurable "who can add" (admin-only vs
  any-member), or per-group invite rules would otherwise be un-negotiable across a group's lifetime. Decide
  whether v1 reserves the field now (cheap forward-compat) even if it only ever defines policy 1.
