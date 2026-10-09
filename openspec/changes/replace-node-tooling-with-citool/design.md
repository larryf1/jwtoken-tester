# Design

## Context

CI/release today runs two Node tools — commitlint (PR gate) and semantic-release (release cutting) — behind a private `package.json` tree that ships no runtime code, plus an `npm-deps` job that audits that tree while the shipped Go module has no vulnerability gate. The release version scheme (`git describe` → `X.Y.Z` or `X.Y.Z-<n>-<7sha>`, fallback `0.0.0`) is hand-implemented three times (Makefile twice, publish.yml once) and is used for *pre-release* builds only; formal releases are always `vX.Y.Z` tags. See proposal.md for motivation; specs/release-pipeline, specs/commit-linting, and specs/supply-chain state the required behavior.

Existing constraints that shape this design:

- The repo already has an in-repo Go tool precedent: `cmd/coverage/main.go` invoked from the Makefile.
- `go.mod` is lean (3 direct runtime deps) and the repo is visibly supply-chain-conscious (SHA-pinned actions, `ignore-scripts`, DCO).
- Release publishing is split: semantic-release only computes/commits/tags/pushes; GoReleaser builds from the tag; Docker steps push images. That split stays.
- Coverage gate: `COVER_PKGS` + 90% threshold, enforced by `make coverage-check` in CI.

## Goals / Non-Goals

**Goals:**

- Replace Node tooling with off-the-shelf Go tools; add zero custom Go source for lint/release.
- Zero Node.js/npm footprint in the repository's build, CI, release, and contribution path.
- Formal releases are computed, changelogged, tagged, and pushed by go-semantic-release; PR lint stays conventional-commit rules via the commitlint CLI.
- The shipped Go module behind a vulnerability gate (`govulncheck`).
- Behavior parity for everything externally observable: version format (pre-release describe scheme kept), changelog format (via committed template), release rules, commit/tag messages, workflow triggers.

**Non-Goals:**

- Changing the pre-release version scheme, release trigger (`workflow_dispatch`), or branch policy (`main` only).
- Writing a custom release/lint/version tool — tooling is upstream, not in-repo source.
- Touching GoReleaser, Docker publish steps, or GitHub Release creation.
- Replacing the `dco` job (shell), the SHA-pinning check (shell), or the copilot-setup/openspec agent's `npm install -g` (different toolchain, out of scope).
- Prerelease channels, semantic-release plugin extensibility, or npm publishing (package is `private: true`, never published).

## Decisions

### 1. Off-the-shelf Go tools, zero custom source

`github.com/go-semantic-release/semantic-release` owns release analysis, changelog generation (via a committed `.tmpl` reproducing the existing CHANGELOG.md format), version tagging, GitHub release creation, and dry-run. `github.com/conventionalcommit/commitlint` (CLI entrypoint at the module root) owns commit linting via a committed `.commitlint.yaml` replicating the old JS rule set (100-char header, lowercase 11-type enum, subject rules, 200-char body/footer lines).

- **Why**: the rule/parity burden moves upstream; we configure rather than own the logic. `go-semantic-release` has first-class `dry`, changelog, and update-file modes matching the former semantic-release's role; commitlint v0.12.0 ships a CLI we run via `go run`, so Makefile and CI need no wrapper code.
- **Alternative**: bespoke `citool` (rejected by user decision — custom code in this repo is unwanted; anything kept belongs in a standalone CLI project).
- **Pre-release version scheme** stays the existing `git describe` shell expression in Makefile (`build`, `docs-openapi`) and `publish.yml`; formal releases are always the `vX.Y.Z` tags go-semantic-release creates, so the scheme never affects a release artifact.
- **Accepted cost**: go-semantic-release's commit-analyzer defaults are a Go port of semantic-release rules; the changelog template must be verified to render byte-near-identical sections to the current file.

### 2. Git commit/tag/push of release artifacts stays one explicit shell step

`chore(release): X [skip ci]` commit (with notes body) and `vX.Y.Z` annotated tag are created in one `git` step in `release.yml`, with go-semantic-release handling analysis/version computation/GitHub release. The publish job keys its `if:` on the tool's `version` output (`''` means no release).

- **Why**: go-semantic-release tags/releases on its own; committing the changelog + VERSION + openapi.yaml back to `main` needs one deterministic git step either way (`update-file` for a single file is configured, but openapi.yaml's targeted sed-equivalent edit is simpler as an existing `sed` step).

### 3. Lint gate shares semantics with release analysis through config, not code

`.commitlint.yaml` (lint) and go-semantic-release's analyzer preset both parse conventional commits (angular preset); the spec scenario "gate commits are analyzable" is satisfied because both consume the same message format.

### 4. Release authentication via checkout credentials

`release.yml`'s version job persists the `RELEASE_TOKEN` checkout credential (`persist-credentials: true`) so the git commit/tag/push step is authenticated. go-semantic-release's `version` output keys the publish job's `if:` (replacing the `.release-version` sentinel file); dry-run reports analysis without writes.

### 5. Workflow-level dry-run input

`release.yml` gains a boolean `dry_run` input on `workflow_dispatch`. When true, the version job runs go-semantic-release in its dry mode (`--dry` / `dry: true`), the publish job's `if:` additionally requires `dry_run == false`, so publishing cannot fire regardless of the tool's output.

- **Why**: the tool flag alone is unreachable from the Actions UI — without a workflow input there is no way to exercise the live job wiring (`$GITHUB_OUTPUT`, credential persistence, gating) short of performing a real release. This is the lowest-confidence layer (see Risks) and the workflow that pushes to `main`.
- **Alternative**: a separate `release-dry-run.yml` workflow (rejected — duplicates the job wiring that most needs testing, and the two copies would drift).

### 6. Testing strategy

No new Go packages join `COVER_PKGS` (no custom code). Verification shifts to: go-semantic-release's analyzer reproducing the real history (dry-run over `v1.0.0..HEAD` yields versions 1.0.1→1.3.0), the changelog template rendering against a golden section, `make lint-commits` exit-code checks, and workflow YAML parsing.

### 7. Workflows consume the tools, YAML stays thin

- `ci.yml`: `commitlint` job → `lint-commits` job (setup-go + `go run` commitlint CLI with `--from`/`--to` over `fetch-depth: 0`); `npm-deps` job → `govulncheck` job (setup-go + pinned `govulncheck ./...`).
- `publish.yml`: version stays the existing `git describe` shell expression (pre-release only).
- `release.yml`: Node setup + `npx semantic-release` + `.release-version` → setup-go + go-semantic-release (dry mode on `dry_run`) + one git commit/tag/push step; publish gating on the tool's `version` output; everything downstream (GoReleaser, Docker) untouched.
- Makefile: `lint-commits` target runs the commitlint CLI; `VERSION`/`docs-openapi` shell expressions unchanged.

## Risks / Trade-offs

- [go-semantic-release parity gaps (revert handling, merge commits, changelog format drift)] → Run it dry over the repository's real history (`git log v1.0.0..HEAD`) and verify it yields 1.0.1 → 1.1.0 → 1.2.0 → 1.3.0 and a changelog section matching the committed template before wiring CI. Accept cosmetic gaps; block on mis-bumps.
- [First release after the switch fails or mis-bumps] → `dry_run` validated on the real workflow before merging; the change lands before the next planned release; rollback is a plain revert (Node files and old workflows restore from git).
- [Push auth regression in `release.yml` (credential persistence change)] → Test via `workflow_dispatch` dry-run first; `RELEASE_TOKEN` scope is unchanged.
- [New `govulncheck` gate fails immediately on pre-existing vulns] → Run `govulncheck ./...` locally before writing the job; decide with evidence.
- [Changelog template drifts from the tool's default] → The `.tmpl` is committed and verified against the current CHANGELOG.md format in CI (a golden-section comparison on a dry run).
- [`docs/openapi.yaml` sed remains shell] → Kept as-is; duplication is accepted in favor of flexibility.

## Migration Plan

1. Add tool config files (`.commitlint.yaml`, `.semrelrc`/changelog template) and parity-check go-semantic-release dry runs against real history (pure addition, CI untouched).
2. Swap workflow steps and Makefile consumers to the tools (one PR, both directions verified by CI on the PR itself).
3. Delete the Node footprint and stale docs references; `openspec validate` clean.
4. Validate the release path with a `dry_run` dispatch in the real workflow, then the next genuine release is the end-to-end confirmation.

Rollback: revert the merge commit — workflows, Node tree, and docs all return to the last known-good state.

## Open Questions

None blocking. Two items resolve during implementation with evidence, without changing specs or task order: the exact upstream rule/defaults extraction (Decision 2) and any pre-existing `govulncheck` findings (Risks).
