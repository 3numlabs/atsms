# Proposals

A place for protocol ideas that are **not yet part of the protocol**.

`spec/` is normative: everything in it is decided, and an implementation that disagrees with it is wrong.
`docs/history/` is the opposite end — how we got here, superseded. This directory is the missing middle: a
design worked out in enough detail to argue about, deliberately not yet binding on anyone.

We added it because we needed it. The group drop point had been carried for months as a "deferred
profile", referenced from five normative documents, defined only in a superseded one — and at one point
recorded in `spec/parameters.md` as **DECIDED**, because there was no other status to give it. An idea
with nowhere to live ends up in the specification by default, which is the failure this directory exists
to prevent.

## The rule that matters

**Nothing in `spec/` may depend on a proposal.** The protocol has to be implementable, and correct, with
this directory deleted. The spec may *mention* a proposal — "a group drop point is proposed, see
[0001](./0001-group-drop-point.md)" — but never build on one, never reserve required behaviour for one,
and never mark a proposal's properties as decided.

Cross-references run one way. Proposals cite the spec freely; the spec points at proposals only to say
that an idea exists and is not settled.

## Status

Each proposal carries one, at the top:

| Status | Meaning |
|---|---|
| **DRAFT** | Being worked out. May be wrong, may be abandoned. The default |
| **REVIEW** | The author thinks it is complete enough to argue about |
| **ACCEPTED** | Agreed in principle; the normative text has not landed yet |
| **LANDED** | The normative text is in `spec/`. The proposal stays as the record of the reasoning |
| **REJECTED** | Decided against. **Stays, with the reasoning** — a rejected idea nobody wrote down gets reproposed |
| **WITHDRAWN** | The author stopped pursuing it. Not the same as rejected |

## Landing one

When a proposal is accepted, the normative text moves into `spec/`, the decision gets a **D-number**
alongside the others, and the proposal is marked LANDED with a pointer to where the text went. The
proposal is not deleted: the specification says what the protocol does, and the proposal says why, which
is the part that is expensive to reconstruct.

## Writing one

Number sequentially, `NNNN-short-name.md`. Follow the spec's own conventions — RFC 2119 keywords where
you mean them, and state what you are *not* addressing as plainly as what you are. Two sections earn
their place beyond the design itself:

- **Open questions.** What would have to be answered before this could be ACCEPTED. Be specific enough
  that someone else could answer one.
- **Alternatives considered.** Including the ones you rejected and why. We keep finding that the rejected
  option is the one someone proposes again a year later.

## Index

| | Status | What |
|---|---|---|
| [0001](./0001-group-drop-point.md) | DRAFT | Group drop point — one shared ciphertext collected by many, instead of a sealed copy per recipient |
