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
