# Spec Delta

## Purpose

Owns how this repository derives version numbers and cuts releases: conventional-commit release analysis by go-semantic-release, changelog generation, version-file updates, tagging, and publish gating. Pre-release version strings come from the existing `git describe` shell expression.

## ADDED Requirements

### Requirement: Version scheme matches the git-describe form for pre-release builds
For non-release builds the version SHALL be `X.Y.Z` on a release tag, otherwise `<base>-<n>-<short-sha>`: `<base>` is the nearest reachable release tag, or `0.0.0` when none exists; `<n>` is the number of commits since that tag; `<short-sha>` is the 7-character abbreviated commit SHA without the leading `g`. Formal releases SHALL always be the exact `vX.Y.Z` tags produced by go-semantic-release.

#### Scenario: All consumers agree on pre-release versions
- **WHEN** the Makefile and the publish workflow compute a pre-release version for the same commit
- **THEN** they produce the identical string, because both use the same `git describe` expression

#### Scenario: Build from a release tag
- **WHEN** the version is computed on the commit tagged `v1.2.3`
- **THEN** the version is `1.2.3`

#### Scenario: Development build after a tag
- **WHEN** the version is computed on `main`, 5 commits after `v1.2.3`, at commit `4fa184eff...`
- **THEN** the version is `1.2.3-5-4fa184e`

#### Scenario: Repository with no tags
- **WHEN** the version is computed and no tag matching `v*` is reachable
- **THEN** the version is `0.0.0-<n>-<short-sha>`

### Requirement: Release version calculated from conventional commits
`go-semantic-release` SHALL determine the next version by analyzing commits since the last release tag: a `feat` commit requires a minor bump, a `fix` commit requires a patch bump, and a breaking change (a `BREAKING CHANGE:` footer or a `!` type marker) requires a major bump. Commits of any other type SHALL NOT trigger a release.

#### Scenario: Feature commits produce a minor release
- **WHEN** the commits since the last tag include `feat(server): add rotation`
- **THEN** the next version increments the minor component

#### Scenario: Fix commits produce a patch release
- **WHEN** the commits since the last tag include `fix(keyring): correct rotation edge case` and no `feat` commits
- **THEN** the next version increments the patch component

#### Scenario: Breaking change produces a major release
- **WHEN** a commit carries a `BREAKING CHANGE:` footer or uses the `fix!:` marker
- **THEN** the next version increments the major component

#### Scenario: Non-release commits produce no release
- **WHEN** the commits since the last tag are only `docs`, `chore`, `refactor`, `test`, `ci`, or merge commits
- **THEN** no new version is calculated and no release is cut

### Requirement: Changelog preserves existing format
On a release, `go-semantic-release` SHALL append release notes to `CHANGELOG.md` in the format the repository already uses: a `# [X.Y.Z](<compare url>)` header, grouped sections such as `Bug Fixes` and `Features`, and per-commit links to the repository.

#### Scenario: Notes appended on release
- **WHEN** a release of `1.4.0` is cut from `v1.3.0`
- **THEN** `CHANGELOG.md` gains a `# [1.4.0](...compare/v1.3.0...v1.4.0...)` section above the previous entries, listing the release's commits grouped by type with commit links, and all prior history is unchanged

### Requirement: Version files updated on release
On a release, go-semantic-release SHALL update the tracked version files — `VERSION` (via its `update-file` support run as needed) and the `version` field in `docs/openapi.yaml` — and its step output SHALL carry the new version for the workflow.

#### Scenario: All version surfaces updated
- **WHEN** a release of `1.4.0` is prepared
- **THEN** `VERSION` contains `1.4.0` and the `docs/openapi.yaml` version field contains `1.4.0`

### Requirement: Release commit, tag, and push
On a release, go-semantic-release SHALL compute the version, render the changelog, and create the GitHub release from the tag; a single explicit git step SHALL commit the updated files (changelog, `VERSION`, `docs/openapi.yaml`) as `chore(release): <version> [skip ci]` with the release notes as the commit body, create the annotated tag `v<version>` on that commit, and push the commit and tag to the origin remote using the configured release credentials.

#### Scenario: Release pushed to origin
- **WHEN** a release of `1.4.0` completes
- **THEN** `origin` receives a commit whose subject is `chore(release): 1.4.0 [skip ci]` and a tag `v1.4.0` pointing at it

### Requirement: No release leaves the repository untouched
When no release-worthy commits exist, `go-semantic-release` SHALL NOT modify any file, create any commit or tag, or contact the remote, and SHALL report that no release is being cut.

#### Scenario: Only chore commits since last tag
- **WHEN** `go-semantic-release` runs and the range contains only non-release commit types
- **THEN** the working tree, local history, and remote are all unchanged

### Requirement: Dry-run performs no writes
When run in dry mode, go-semantic-release SHALL perform the full analysis and report the version and notes it would produce, without writing files, committing, tagging, pushing, or creating a GitHub release.

#### Scenario: Dry-run on a release-worthy range
- **WHEN** go-semantic-release runs in dry mode on a range containing `feat` commits
- **THEN** it prints the would-be next version and release notes, and the repository is unchanged

### Requirement: Release workflow accepts a dry-run dispatch
The release workflow SHALL declare a `dry_run` input on `workflow_dispatch`. When true, the version job SHALL run go-semantic-release in dry mode, the publish jobs SHALL be skipped regardless of the analysis result, and no file, commit, tag, or remote write SHALL occur.

#### Scenario: Dry-run dispatch on a release-worthy range
- **WHEN** the release workflow is dispatched with `dry_run` set true on a range containing `feat` commits
- **THEN** the version job reports the would-be version and notes, the publish jobs are skipped, and the repository and remote are unchanged

#### Scenario: Dry-run dispatch with no release-worthy commits
- **WHEN** the release workflow is dispatched with `dry_run` set true and the range contains only non-release commit types
- **THEN** the job reports that no release would be cut and nothing is written or pushed

### Requirement: Publish jobs gated on a new version
The release workflow SHALL run GoReleaser, build the container image, and push to GHCR only when `go-semantic-release` reports that a new version was cut; when no version is cut, those jobs SHALL be skipped.

#### Scenario: No release means no publish
- **WHEN** the release workflow runs and no release-worthy commits exist
- **THEN** the publish job is skipped and no GitHub Release or image is produced

#### Scenario: Release triggers publish
- **WHEN** the release workflow runs and a new version is cut
- **THEN** GoReleaser builds from the pushed tag and the image is pushed with that version

