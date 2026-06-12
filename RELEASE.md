# Release Process

This project automates versioning through **semantic-release**, which analyzes commit messages to determine version bumps and publish releases automatically.

## How It Works

The system uses **Conventional Commits** format to trigger different version changes:

- `fix:` triggers patch versions (1.0.0 → 1.0.1)
- `feat:` triggers minor versions (1.0.0 → 1.1.0)
- `BREAKING CHANGE:` or `!` triggers major versions (1.0.0 → 2.0.0)

Other prefixes (`chore:`, `docs:`, `test:`, `refactor:`) do not trigger releases.

## Commit Message Format

Messages follow this template:

```
type(scope): description

[optional body]

[optional footer]
```

Examples:

```
fix: correct address validation

feat(wallet): add SPHINCS+ support

feat!: change signature format

feat: update API response structure

BREAKING CHANGE: response now returns object instead of array
```

## Workflow

1. Create feature branches with properly formatted commits
2. Submit pull requests to `main`
3. Upon merge, GitHub Actions automatically:
   - Analyzes commits since the last release
   - Calculates the appropriate version number
   - Updates `package.json` version
   - Generates changelog from commit messages
   - Builds and publishes to npm
   - Creates a Git tag and GitHub release

## Best Practices

- Write atomic commits (one logical change per commit)
- Use clear, imperative-mood subjects under 72 characters
- Include detailed explanations in commit bodies when needed
- Reference relevant issues in footers (e.g., `Fixes #123`)
- Use consistent scope labels like `(crypto)`, `(wallet)`, `(api)` for organization

## Publish ordering & failure semantics

`npm publish` runs **inside** semantic-release's publish phase
(`@semantic-release/exec` `publishCmd` → `scripts/release-publish.sh`),
which executes before `@semantic-release/github` creates the GitHub
release. Consequences:

- A GitHub release existing for a version means that version **is** on npm.
- If npm publish fails, semantic-release aborts: no GitHub release is
  created. The **git tag is still pushed** (semantic-release core tags
  before the publish phase), and semantic-release will not retry a version
  whose tag exists.

## Recovering an orphaned release

State: tag `vX.Y.Z` exists, npm does not serve `X.Y.Z` (the release job
failed at or after publish). Historical example: v6.2.0 was tagged and
GitHub-released but never reached npm under the old step ordering; it was
superseded by v6.2.1 rather than recovered.

Preferred recovery — **supersede, don't backfill**: land a trivial `fix:`
commit and let the pipeline cut the next patch version end-to-end. The
orphaned version number stays burned (semver ranges skip the gap
harmlessly). Never move or delete the existing tag.

Manual backfill (only if the exact version must exist, and you hold
publish rights on `@theqrl`): check out the tag, `npm ci && npm run build`,
verify `git status` is clean (committed `dist/` must match), then
`npm publish --access public`. A manual publish lacks the workflow's
provenance attestation — note that in the GitHub release. Verify with
`npm view @theqrl/wallet.js@X.Y.Z version`.
