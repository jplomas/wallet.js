# Contributing to wallet.js

Thanks for contributing. This document covers the development workflow and
the repository conventions that CI enforces.

## Setup

- Node.js ≥ 20.19 (`.nvmrc` says 22 — `nvm use` and go). CI tests 20.x,
  22.x, and 24.x.
- `npm ci` to install from the lockfile.

## Commands

| Command | What it does |
|---|---|
| `npm test` | Node test suite (mocha) |
| `npm run coverage` | Same suite under c8 — **fails below 100%** statements/branches/functions/lines (this is what CI runs) |
| `npm run test:browser` | Browser suite in Chromium via Playwright (`npx playwright install chromium` first time) |
| `npm run lint-check` / `npm run lint` | ESLint over the whole repo (src, tests, scripts, browser shims, configs) |
| `npm run typecheck` | `checkJs` validation of the JSDoc annotations that generate the published types |
| `npm run build` | Rollup dual ESM/CJS build into `dist/` + type declarations into `types/` |

## Things that surprise newcomers

### `dist/` and `types/` are committed

The built artifacts are checked in, and the CI `dist-check` job rebuilds
from scratch and fails on any diff. **If you change anything under `src/`,
run `npm run build` and commit the resulting `dist/` and `types/` changes
in the same PR.**

### Tests must keep coverage at 100%

The c8 gate requires 100% on every metric. New branches need tests for
both sides. Use `/* c8 ignore */` only with a comment explaining why the
path is unreachable (see existing examples in `src/`).

The flat-100% baseline exists for **drift visibility** — any drop points
directly at the new untested branch, which is why unreachable paths are
excluded with rationale instead of letting the number sit below the
ceiling. This repo is past the 100% milestone and the gate is locked in:
**lowering it is a maintainer decision**, made as an explicit, reviewed
change to the c8/Codecov thresholds with its reasoning in the PR — never
a status check everyone learns to ignore.

### The browser suite uses hand-rolled shims

`browser-tests/` runs shared suites from `test/unit/` in a real browser
with **minimal local shims** for chai, mocha, and Buffer (no bundler).
Consequences for test authors:

- In any suite imported by `browser-tests/tests.js`, only use assertions
  the shim implements: `equal`, `deep.equal`, `not`, `instanceOf`, `a`/`an`,
  `match`, `throw`, `have.property`, `undefined`. If you need a richer chai
  API, either extend `browser-tests/chai.js` (keeping chai semantics) or
  keep the test Node-only.
- Node-only suites and the reason they are excluded are listed at the
  bottom of `browser-tests/tests.js` — keep that list annotated.
- Bare imports used by browser-run suites must be mapped in
  `browser-tests/runner.html`'s import map.

### Test suite map

| Suite | Purpose |
|---|---|
| `*.wallet`, `seed`, `descriptor`, `address`, `context`, `mnemonic`, `factory`, `wallettype`, `utils.bytes`, `random` | Unit tests per module |
| `edge-cases` | Boundary inputs and validation paths |
| `fuzz` | Property-based tests (fast-check, Node-only) |
| `metamorphic` | Bit-flip mauling + descriptor-binding properties (ToB-derived) |
| `cross-implementation` | go-qrllib-matched fixtures (KATs) |
| `seed-ownership` | Wallet/caller lifecycle isolation |
| `secret-enumeration` | Secrets stay out of JSON/inspect/enumeration |
| `verify-with-reason` | Discriminated verification failures + error-code contract |
| `public-api` | Locks the export surface of `src/index.js` |
| `dist-bundle`, `types-build`, `types-consumer` | Built-artifact and declaration regression tests |

## Pinned verification inputs

Anything CI resolves and then *executes or trusts* is a pin, not just the
`git clone` SHAs — a pin matrix is only as strong as its most creative
resolver. The full list, with bump semantics:

| Pin | Where | Bump semantics |
|---|---|---|
| go-qrllib `6f99783…` (= v0.9.0) | `cross-verify.yml` env `GO_QRLLIB_PIN` | Routine: update SHA + dated comment, run the workflow via `workflow_dispatch` on the branch, merge. Never bump past a failure silently. |
| Go module context of the cross-verify harness | structural | The harness Go programs run from *inside* the pinned go-qrllib clone, so `go run` resolves through the clone's own `go.mod`/`go.sum` at the pinned commit. There is deliberately **no `go.mod` under `.github/cross-verify/`** — a harness-local module file would resolve go-qrllib from the registry and silently shadow the clone pin. Adding one is a reviewed change to this table. |
| `npm@11.16.0` | `release.yml` "Use npm 11" step; `package.json` `overrides` + lockfile | Exact-pinned in the publish-privileged job (a `^range` would resolve at run time). Bump the workflow and the override together. |
| actionlint `1.7.10` | `actionlint.yml` `version:` input | The engine inside the SHA-pinned action (defaults to `latest` otherwise). Keep in step with the brew-installed version used locally. |
| zizmor engine | `zizmor-action` SHA pin | The action digest-pins its own engine — pinned transitively; bumping the action SHA bumps the engine. |
| `codecov-action` `fb8b358… # v7.0.0` | `coverage.yml` | House pin, aligned across the QRL JS repos — bump in step. |
| GitHub SSH host keys | `release.yml` known_hosts | Published keys from `api.github.com/meta` (not run-time `ssh-keyscan`). Refresh when GitHub rotates. |
| `slsa-github-generator@v2.1.0` | `release.yml` | Tag-pinned **by requirement** (provenance verification needs the tag); documented zizmor exception in `.github/zizmor.yml`. |
| Playwright Chromium build | lockfile | `npx playwright install` fetches the browser build mapped to the locked `@playwright/test` version — governed by `package-lock.json`. |
| Everything `uses:` | all workflows | Actions are SHA-pinned with a `# vX.Y.Z` comment. |
| npm dependency tree | `package-lock.json` | All installs are `npm ci`; the release job never runs a bare `npm install`. |

## CI shape

`ci.yml` is the push/PR battery; `release.yml`'s preflight job re-runs the
release-blocking subset (lint, tests, build, dist-clean) inline before the
publish path starts. The playbook's preferred single-package shape — one
reusable `workflow_call` CI consumed by push/PR and the release pipeline —
is noted and **deferred** (optional, no forced migration); adopt it the
next time the two job lists are caught drifting apart. Per-module Codecov
`components` are adopted in `.codecov.yml` for drift visibility; the
gates remain the project/patch 100% targets plus the c8 `check-coverage`
run in CI.

## Commit messages

Releases are fully automated with semantic-release on push to `main` —
commit types determine version bumps (`fix:` → patch, `feat:` → minor,
`feat!:`/`BREAKING CHANGE:` → major). See [RELEASE.md](RELEASE.md) for
the format and examples. `chore:`, `docs:`, `test:`, `ci:`, `refactor:`
do not trigger releases.

## Security

Never log, serialize, or commit secret material (seeds, secret keys,
mnemonics) — including in test fixtures, which must use published,
throwaway vectors only. Security vulnerabilities go to
**security@theqrl.org**, not the issue tracker. See
[SECURITY.md](SECURITY.md) for the security model, the wallet lifecycle
contract, and the dependency-patch playbook.
