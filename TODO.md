# Outstanding work

Work on this repository that is not a protocol defect. Engine and protocol findings from live testing
live in [`KNOWN-ISSUES.md`](./KNOWN-ISSUES.md), and the questions we want an outside eye on are in
[`spec/review-scope.md`](./spec/review-scope.md).

## 1. The packages are not publishable yet

**Status**: Blocking any `npm publish`. Not blocking the announcement, which points at GitHub.

Nothing is on npm. The `@atsms` scope is reserved and empty. `publishConfig`, licence files, and
repository metadata are in place — but publishing today would put a broken package on the registry.

### What is wrong

**`@atsms/client` depends on `"@atsms/dcgka": "file:../dcgka"`.** That is correct inside this workspace
and fatal outside it: npm would publish the manifest verbatim, and every consumer's install would fail
trying to resolve a relative path that exists only on our disks.

The obvious fixes are both wrong, because the two packages are coupled in two different ways at once:

- **The JS is bundled.** `packages/client/dist/index.js` inlines dcgka's code, so at runtime a consumer
  of `@atsms/client` needs nothing from the dcgka package. That argues for dropping the dependency.
- **The types are not bundled.** Thirteen shipped `.d.ts` files still `import` from `@atsms/dcgka`, so a
  TypeScript consumer needs those types resolvable. That argues for keeping it.

So dcgka is simultaneously inlined and externally referenced. Neither dropping the dependency nor
leaving it as-is produces a working package.

**`@atsms/dcgka` sets `main` to `./src/index.ts`** and ships raw TypeScript. This works today only
because bun executes TypeScript natively and the client consumes it as a sibling. For anyone else it is
broken: plain Node cannot require a `.ts` file, and Vite and most bundlers do not transpile inside
`node_modules`.

### What to do

Publish both, and make `@atsms/dcgka` a real package.

1. Give dcgka a JS build like the client's. Point `main` at `dist/index.js`, keep `types` at
   `dist/index.d.ts`, and add an `exports` map.
2. Change the client's dependency from `file:../dcgka` to `^0.1.0`. Keep the workspace resolution
   working for local development — bun resolves a workspace sibling ahead of the registry.
3. Publish dcgka first, then the client.
4. Verify by installing the tarballs into a scratch project outside this repository — `npm pack` then
   `npm install ./atsms-dcgka-0.1.0.tgz`, in plain Node and in a Vite app. A dry run inside the
   workspace proves nothing, because the workspace is what hides the problem.

The alternatives are worse. Bundling the type declarations hides an engine we deliberately document and
tell people to read. Marking dcgka private contradicts the README, which presents it as one of the two
things this repository provides.

### Also worth settling before a first publish

- **Version numbers.** Both packages sit at `0.1.0` and nothing has ever shipped. Decide whether the
  first publish is `0.1.0` or `0.0.1`, and whether the two version in lockstep.
- **The `README-NPM` question.** Both packages ship their own `README.md`, which is what npm renders.
  Check that each reads sensibly to someone who arrived from a package page rather than from the
  repository root.
- **Provenance.** `npm publish --provenance` from a GitHub Action gives a verifiable link between the
  tarball and the commit that produced it. Cheap, and worth having for a package whose entire pitch is
  that you can check what it does.
