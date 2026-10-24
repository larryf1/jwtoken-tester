# Proposal

## Why

The repository's CI, publish, and release workflows depend on a Node.js toolchain (semantic-release, commitlint, the npm dependency tree and its audit gates) that exists solely to run those workflows and ships no runtime code. It is an outsized supply-chain surface — a private `package.json`, a 180 KB lockfile, an npm stub override, and dedicated audit jobs — for two behaviors that a small native Go tool can own with fewer dependencies and one shared parser. Separately, the release version scheme (`git describe` → `X.Y.Z` or `X.Y.Z-<n>-<sha>`) is hand-implemented three times (Makefile twice, publish workflow once), and CI audits the JavaScript tree while the Go module that actually ships has no vulnerability gate at all.

## What Changes

- Add two off-the-shelf Go tools to own commit linting and release cutting: `github.com/go-semantic-release/semantic-release` (analysis, changelog via a committed template, tagging, GitHub release, dry-run) and the `github.com/conventionalcommit/commitlint` CLI (PR gate, same rules as the old `@commitlint/config-conventional`). No custom release/lint code is added to this repository.
- **BREAKING** Remove the entire Node.js footprint: `package.json`, `package-lock.json`, `.npmrc`, `.nvmrc`, `commitlint.config.js`, `node_modules/`, `tools/npm-stub{,.tgz}`, the `npm-deps` and `commitlint` CI jobs, the Node setup in `release.yml`, and the dependabot npm entry. Local contribution docs change from `npx commitlint ...` to `make lint-commits`.
- Pre-release version derivation stays the existing `git describe` shell expression (Makefile `build`/`docs-openapi`, publish workflow), which is now only used for non-release builds; formal releases are `vX.Y.Z` tags produced by go-semantic-release. The version-scheme *behavior* is unchanged; only the duplicated implementation detail of running it three times remains, which is accepted as flexible shell.
- Replace the `npm-deps` CI job with a `govulncheck` job, extending the vulnerability gate from the (now deleted) JS tree to the Go module that ships.
- Keep externally visible release behavior identical: same conventional-commit release rules, same `CHANGELOG.md` format, same `VERSION`/`.release-version`/`docs/openapi.yaml` updates, same `chore(release): X [skip ci]` commit, same `vX.Y.Z` tag, same `workflow_dispatch` trigger, same GoReleaser/Docker publish steps.
- Add a `dry_run` input to the release workflow's manual trigger: it runs `citool release --dry-run` and forces the publish jobs off, giving the only workflow that pushes to `main` a no-write dispatch mode for validation.

## Capabilities

### New Capabilities

- `release-pipeline`: How the repository derives version numbers (single implementation of the describe scheme) and cuts releases (commit analysis, changelog generation, version-file updates, tagging, and publish gating).
- `commit-linting`: Enforcement of Conventional Commits on pull requests and locally via `citool lint-commits`, with a fixed rule set.
- `supply-chain`: CI gates protecting the repository's supply chain — SHA-pinned actions, Go module vulnerability scanning, and the absence of a Node.js/npm toolchain from the build and release path.

### Modified Capabilities

(none — the product specs `cli`, `container`, etc. are unaffected; the `cli` version-resolution requirement keeps its `VERSION` file, which `citool release` continues to write)

## Impact

- **Deleted files**: `package.json`, `package-lock.json`, `.npmrc`, `.nvmrc`, `commitlint.config.js`, `node_modules/`, `tools/npm-stub/`, `tools/npm-stub.tgz`
- **New config**: `.semrelrc` (or equivalent) + `changelog.tmpl` matching the existing CHANGELOG.md format, `.commitlint.yaml` matching the old JS rule set
- **No new Go source or module dependency for tooling** — both tools run via `go run`/`go install` in CI and locally
- **Workflows**: `.github/workflows/ci.yml` (drop `npm-deps` + `commitlint` jobs, add `govulncheck` + Go-based `lint-commits` jobs; `dco`, `supply-chain`, `lint`, `build-test`, `coverage` unchanged), `.github/workflows/release.yml` (Node/semantic-release steps → go-semantic-release + one git commit/tag/push step), `.github/workflows/publish.yml` (version step unchanged shell, still `git describe`-based)
- **Build**: `Makefile` (new `lint-commits` target running the commitlint CLI; `COVER_PKGS` unchanged — no `internal/citool`)
- **Config/docs**: `.github/dependabot.yml` (remove npm entry), `.gitignore` (remove `/node_modules/`), `.goreleaser.yaml` unchanged, `README.md` and `CONTRIBUTING.md` rewritten around go-semantic-release, the commitlint CLI and `make lint-commits`
- **Contributor workflow**: `npx commitlint --from origin/main --to HEAD` → `make lint-commits`; no Node.js required to contribute
