# Tasks

## 1. Configure Semrel release metadata

- [x] 1.1 Replace go-semantic-release configuration with pinned Go-native Semrel in `.semrel.yaml` and `.semrel.lock`; verify plugin restoration and the configured release rules.
- [x] 1.2 Configure changelog retention and replacement updates for `VERSION` and `docs/openapi.yaml`; verify the generated format preserves existing history and each target has exactly one expected match.

## 2. Orchestrate verified release and publication

- [x] 2.1 Add the read-only updater preflight that parses configured replacement patterns and checks target match counts; verify with `go test ./tools/semrel-preflight` and a live preflight run.
- [x] 2.2 Update `.github/workflows/release.yml` to consume Semrel release metadata, verify the local tag and its metadata commit, and atomically push the branch and tag; verify workflow syntax and the controlled release path.
- [x] 2.3 Gate GoReleaser and GHCR publication on a real non-dry-run release and check out Semrel's reported tag; verify dry-run and no-release paths skip publication without publishing production artifacts.

## 3. Update contracts and validate release safety

- [x] 3.1 Update the `release-pipeline` and `commit-linting` contracts for Semrel bump rules, metadata ordering, dry-run, and publication behavior; verify the OpenSpec specs validate.
- [x] 3.2 Confirm the active GitHub ruleset targets `refs/tags/v*`, blocks updates and deletion, and has no bypass actors; record it as an external prerequisite.
- [x] 3.3 Run Semrel dry-run and a controlled non-publishing release simulation; verify dry-run leaves the checkout unchanged and the local version tag points to a commit containing `CHANGELOG.md`, `VERSION`, and `docs/openapi.yaml`.