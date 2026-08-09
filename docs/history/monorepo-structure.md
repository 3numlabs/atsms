# How this repository came to hold the protocol and both packages

*Design history. This describes a decision that has since been carried out — the structure it proposes is
the structure you are reading it in. Not normative; kept for the reasoning.*

Written while the code lived in three repositories: `atsms-dcgka` (engine and specs), `atsms-lib` (the
client SDK), and the clients. Carried out on 2026-08-08, when `atsms-dcgka` was renamed `atsms` and
`atsms-lib` moved in as `packages/client` with its history rewritten to match.

The open items at the end were all settled: the demo and the CLI stayed in their own repositories, the
package is `@atsms/client` under the `@atsms` scope, the lexicons sit at the repository root rather than
as a package, and the workspace is bun.

---

## The proposal, as written

### The governing constraint

The **open-source boundary** (north star): the Protocol + node reference impls are open (3NUM Labs); the
Haiven operator product (app, billing, AI-screening) is private. **No repo may straddle that line** — so "one
monorepo for everything" is out. Within the open half, the deciding factor is coupling: `@atsms/dcgka` and the
client library are co-developed, co-versioned, differentially tested — the `file:` links between them are a
symptom that they belong in one workspace. Node services and the operator are loosely coupled *consumers* and
stay independent.

### The tree (LANDED 2026-08-08)

Built as described below, with three deviations decided at the time: the lexicons sit at the repo root
rather than as a package, since they are the protocol's source of truth and a non-TypeScript implementer
should not have to look inside `packages/` for them; and the CLI and demo stayed in their own
repositories rather than becoming `examples/`, so the monorepo remains protocol plus packages. The
former `atsms-dcgka` repo was renamed `atsms` and `atsms-lib` moved in as `packages/client`, history
preserved.

### Proposed tree (as written)

```
atsms/  ← SDK monorepo · OPEN SOURCE (3NUM Labs) · "the smart core" = the product
  packages/
    lexicons/   @atsms/lexicons   all at.atsms.* schemas — single source of truth
                                   (x509 + prekey + inbox + e164, today scattered across 3 repos)
    dcgka/      @atsms/dcgka       advanced E2EE engine (BeeKEM)
    client/     @atsms/client      app-facing library  ← renamed from @atsms/client
  spec/                            the protocol specs (moved out of atsms/spec)
  examples/
    demo/                          reference client (from atsms-demo)   [refinable: examples/ vs own repo]
  docs/                            architecture.md, roadmap.md, this doc (the ecosystem picture)

atsms-worker/         Relay Node reference impl    ┐ separate repos — deployable services,
atsms-voip-gateway/   Gateway Node reference impl  ┤ own lifecycle, "anyone runs a node,"
fidis/                Identity/PDS infra           ┤ each depends on published @atsms/* packages
atsms-atproto-user/   Infra POC                    ┘

haiven/  (private)    Operator: consumer app, AI-screening, AgentConfig, billing
```

### Rationale

- **SDK monorepo** (bun/pnpm workspace): removes the `file:` links; one toolchain / CI / test runner; atomic
  cross-package changes; a single home for the wire contracts (`@atsms/lexicons`) and specs. This *is* the
  "smart core, swappable dumb gateway" north star made concrete — the SDK is the product.
- **Node impls stay separate**: reference implementations of a dumb, swappable role (D0). A relay operator
  forks `atsms-worker` alone and shouldn't clone the SDK. Bundling would couple release cadence and blur the
  boundary.
- **Haiven stays private + separate** — the open/closed line, non-negotiable.
- **The umbrella** (`/localdev/atsms`) stops being a phantom non-repo: cross-cutting docs move into the SDK
  monorepo's `docs/` (the protocol's natural home); the top level is just a dev workspace holding sibling repos.

### Not yet — the migration is its own effort

Consolidating three repos into a workspace touches git history, `file:` links, every import path, CI, and the
worker's dependency on the lib. It is a deliberate, sequenced migration with its own plan — **not** part of
Phase 5. **Until then we build in place**: keep the existing repos and `file:` links, but write new
`atsms/packages/client` code in the Part A shape (modules named `send` / `conversations` / `identity`) so the eventual move
is a relocation, not a rewrite.

### Open items to refine before committing

- `examples/demo` inside the monorepo vs `atsms-demo` staying its own repo.
- Exact package names (`@atsms/client` vs `@atsms/messaging`; scope `@atsms` vs a Bourbon-branded scope).
- Where `atsms-brand` (assets) lives.
- Whether `fidis` / `atsms-atproto-user` fold together as one "infra" repo.
- Monorepo tooling (bun workspaces vs pnpm) and release/versioning (independent vs fixed).
