# Tasks

## 1. Foundation

- [~] 1.1 ~~Add `github.com/leodido/go-conventionalcommits` to `go.mod` and scaffold `cmd/citool`~~ *(Superseded: no custom citool; tools run off-the-shelf via `go run`. The `internal/citool` code added under 1.1/1.2/2.1/2.2/3.1 will be deleted in task 6.0.)*
- [~] 1.2 ~~Extract rules into `internal/citool/commits`~~ *(Superseded: `.commitlint.yaml` replicates the JS rule set; go-semantic-release provides release rules.)*
- [x] 1.3 Add tool configuration: `.commitlint.yaml` (header ≤ 100, lowercase 11-type enum, subject rules, blank-line rules, body/footer ≤ 200) and `.semrelrc` / changelog template reproducing the current CHANGELOG.md format; verify `go run github.com/conventionalcommit/commitlint` exits 0 on the current branch and the changelog template renders a golden section identical to the current file.

## 2. Commit rules and release analysis

- [~] 2.1 ~~Implement lint rule set in `internal/citool/commits`~~ *(Superseded by 1.3.)*
- [~] 2.2 ~~Implement release-bump analysis in `internal/citool/commits`~~ *(Superseded by go-semantic-release.)*
- [x] 2.3 Run go-semantic-release in dry mode over the repository's real history (`v1.0.0..HEAD`); verify it reproduces the released versions 1.0.1, 1.1.0, 1.2.0, and 1.3.0 in order.

## 3. Version subcommand

- [~] 3.1 ~~Describe-based version scheme in `internal/citool/version`~~ *(Superseded: pre-release versions keep the existing `git describe` shell expression.)*
- [~] 3.2 ~~Byte-identical check vs legacy bash~~ *(Covered by 5.5/publish.yml unchanged shell.)*

## 4. Release subcommand

- [~] 4.1 ~~Release-notes rendering~~ *(Superseded: go-semantic-release + committed changelog template; parity checked in 2.3.)*
- [~] 4.2 ~~Version-file updates~~ *(Handled by go-semantic-release `update-file` for `VERSION` plus the existing sed step for `docs/openapi.yaml`.)*
- [~] 4.3 ~~Git operations behind runner seam~~ *(Handled by one explicit git step in release.yml.)*
- [~] 4.4 ~~`--dry-run`, `$GITHUB_OUTPUT`, no-release reporting~~ *(Handled by go-semantic-release dry mode + its `version` output gating publish.)*
- [~] 4.5 ~~End-to-end custom release test~~ *(Superseded: dry-run dispatch in 7.4 exercises the real path.)*

## 5. Consumers: Makefile and workflows

- [x] 5.1 Run `govulncheck ./...` locally before writing the CI job; verify findings are recorded — bump vulnerable deps in this change if any exist, or note zero findings.
- [x] 5.2 Makefile: add a `lint-commits` target running the commitlint CLI (`git log origin/main..HEAD` piped per-commit into `go run github.com/conventionalcommit/commitlint@v0.12.0 lint`, since the CLI has no `--from`/`--to` range flags); verify `make lint-commits` exits 0 on the current branch (and non-zero when pointed at a known-bad commit).
- [x] 5.3 `ci.yml`: replace the `commitlint`/`lint-commits` job with a setup-go `lint-commits` job running the same per-commit commitlint loop and replace `npm-deps` with a `govulncheck` job; verify the workflow parses (actionlint/yamllint) and both commands run green locally.
- [x] 5.4 `release.yml`: swap the version job to setup-go + go-semantic-release with persisted `RELEASE_TOKEN` checkout credentials, add a `dry_run` workflow_dispatch input that enables the tool's dry mode and forces the publish job off, commit `chore(release): X [skip ci]` + tag + push in one git step, and key the publish job's `if:` on the tool's `version` output; verify the workflow parses (actionlint) and the gating condition and `dry_run` plumbing are present in the YAML — live dispatch exercised in 7.4.
- [~] 5.5 ~~publish.yml version step~~ *(Unchanged: existing `git describe` shell expression retained.)*

## 6. Remove the Node footprint and update docs

- [x] 6.0 Delete `cmd/citool/`, `internal/citool/`, and the conventionalcommit deps from `go.mod`/`go.sum` (`go mod tidy`); verify `go build ./...` and `go test ./...` pass.
- [x] 6.1 Delete `package.json`, `package-lock.json`, `.npmrc`, `.nvmrc`, `commitlint.config.js`, `node_modules/`, `tools/npm-stub/`, `tools/npm-stub.tgz`; drop `/node_modules/` from `.gitignore` and the npm entry from `.github/dependabot.yml`; verify `git status` shows only intended deletions and a grep over the repo finds no remaining references to `package.json` or `node_modules` outside CHANGELOG.md and openspec/.
- [x] 6.2 Rewrite README.md and CONTRIBUTING.md release/commit sections around go-semantic-release and `make lint-commits`; verify a repo-wide grep finds no `npx`, `semantic-release`, `commitlint`, or `npm` references outside CHANGELOG.md, openspec/, and the out-of-scope copilot/openspec-agent files, and that every command printed in CONTRIBUTING runs as written.
- [x] 6.3 Verify no Node setup remains in `.github/workflows/`: grep `setup-node`, `npm`, `npx`, `semantic-release`, `commitlint` across all workflow files returns only the untouched copilot-setup-steps.yml.

## 7. Integration gates

- [x] 7.1 `COVER_PKGS` unchanged (no new custom packages); verify `make coverage-check` still reports >= 90%.
- [x] 7.2 Run the full local gate: `make lint`, `make fmt-check`, `go vet ./...`, `go test ./...`; verify all pass with no warnings.
- [x] 7.3 Validate the change artifacts with `openspec validate "replace-node-tooling-with-citool"`; verify the command reports the change valid.
- [x] 7.4 Exercise the release workflow end-to-end on the branch: dispatch it with `dry_run=true`; verify the version job reports the analysis (would-be version and notes on a release-worthy range), the publish jobs are skipped, and no commit or tag is created.

## Workflow follow-up

- Archive the change after the project's review requirements are satisfied.
- Verify the archived result.
