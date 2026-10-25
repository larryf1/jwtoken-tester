# Proposal

## Why

The existing go-semantic-release flow can create the version tag before its generated changelog and version-file changes are committed, leaving the tagged source inconsistent with the release metadata. Replace that flow so a successful release tags a verified metadata commit, while retaining the existing publishers and a safe dry-run path.

## What Changes

- Replace go-semantic-release configuration and invocation with pinned Go-native Semrel and plugins; do not introduce JavaScript or npm.
- Generate and retain changelog history, update `VERSION` and `docs/openapi.yaml`, and commit those changes before creating the version tag.
- Keep the current release workflow as orchestrator, with GoReleaser publishing the GitHub Release and the existing Docker action publishing multi-architecture GHCR images.
- Use Semrel release metadata to gate publication; verify tag contents before atomically pushing the release commit and tag.
- Make dry-run and no-release outcomes side-effect free, including a read-only preflight for updater patterns; require an external GitHub ruleset to protect `v*` tags from updates and deletion.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `release-pipeline`: Change release analysis, changelog/version preparation, tag ordering, dry-run, and publication requirements to use Semrel and verified release metadata.
- `commit-linting`: Require Semrel release analysis to agree with the Conventional Commit types and breaking-change markers accepted by the existing lint gate.

## Impact

The change affects `.semrelrc`/`.semrel.yaml`, `.semrel.lock`, `.github/workflows/release.yml`, the `tools/semrel-preflight` validator, and the two listed OpenSpec capabilities. GoReleaser and the existing GHCR publication action remain in place. Immutable version tags depend on GitHub repository ruleset configuration outside the source tree.