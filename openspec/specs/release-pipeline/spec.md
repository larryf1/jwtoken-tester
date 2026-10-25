# release-pipeline Specification

## Purpose
Owns how this repository derives version numbers and cuts releases: conventional-commit analysis by Semrel, changelog and version-file preparation, release commit/tag creation, and publish gating. Pre-release version strings continue to come from the existing `git describe` shell expression.

## Requirements

### Requirement: Version scheme matches the git-describe form for pre-release builds
For non-release builds the version SHALL be `X.Y.Z` on a release tag, otherwise `<base>-<n>-<short-sha>`: `<base>` is the nearest reachable release tag, or `0.0.0` when none exists; `<n>` is the number of commits since that tag; `<short-sha>` is the 7-character abbreviated commit SHA without the leading `g`. Formal releases SHALL always be the exact `vX.Y.Z` tags produced by Semrel.

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
Semrel SHALL determine the next version by analyzing commits since the last release tag: a `feat` commit requires a minor bump, `fix`, `perf`, and `revert` commits require a patch bump, and a breaking change (a `BREAKING CHANGE:` footer or a `!` type marker) requires a major bump. Commits of any other type, including merge commits, SHALL NOT trigger a release.

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

### Requirement: Changelog retains history and adds Semrel release notes
On a release, `@semrel/generator-changelog-md` SHALL prepend a dated `## vX.Y.Z (YYYY-MM-DD)` entry with `###` groups such as `Features`, `Bug Fixes`, and `Other Changes`. The configured retention SHALL preserve all existing release entries and bodies; new heading levels may differ from the legacy compare-link headings.

#### Scenario: Notes appended on release
- **WHEN** a release of `1.4.0` is cut from `v1.3.0`
- **THEN** `CHANGELOG.md` gains a dated `## v1.4.0 (...)` section above prior entries with commits grouped by type, and all prior history remains unchanged

### Requirement: Version files updated on release
On a release, `@semrel/updater-replace` SHALL update `VERSION` and the `info.version` field in `docs/openapi.yaml` before tagging. Its configured match and replacement counts SHALL require exactly one version match in each file. During dry-run, a standalone read-only preflight SHALL validate those configured patterns and counts because Semrel skips pre-tag plugins in its dry-run mode.

#### Scenario: All version surfaces updated
- **WHEN** a release of `1.4.0` is prepared
- **THEN** `VERSION` contains `1.4.0` and the `docs/openapi.yaml` version field contains `1.4.0`

### Requirement: Release commit, tag, and push
On a release, Semrel SHALL run the changelog generator and version updater before creating a local tag, then commit their tracked-file changes as `chore(release): set version to v<version> [skip ci]`. The local `v<version>` tag SHALL point to that commit. The workflow SHALL verify the tagged metadata and atomically push the release branch and tag using the configured release credentials; it SHALL NOT push the tag before verification. GoReleaser remains the sole GitHub Release publisher.

#### Scenario: Release pushed to origin
- **WHEN** a release of `1.4.0` completes
- **THEN** `origin` receives a commit whose subject is `chore(release): set version to v1.4.0 [skip ci]`, containing `CHANGELOG.md`, `VERSION`, and `docs/openapi.yaml`, and a tag `v1.4.0` pointing at it after the workflow verifies the tag contents

### Requirement: No release leaves the repository untouched
When no release-worthy commits exist, Semrel SHALL NOT modify any tracked file, create any commit or tag, or push to the remote, and SHALL report that no release is being cut.

#### Scenario: Only chore commits since last tag
- **WHEN** Semrel runs and the range contains only non-release commit types
- **THEN** the working tree, local history, and remote are all unchanged

### Requirement: Dry-run performs no writes
When run in dry-run mode, Semrel SHALL analyze commits and report the candidate version and notes without modifying files, running pre-tag or release plugins, committing, tagging, pushing, or creating a GitHub Release. The release workflow SHALL run the standalone updater preflight, which reads the configured replacement rules and target files without writing.

#### Scenario: Dry-run on a release-worthy range
- **WHEN** Semrel runs in dry-run mode on a range containing `feat` commits
- **THEN** it prints the candidate version and release notes, the updater preflight confirms both version patterns, and the repository remains unchanged

### Requirement: Release workflow accepts a dry-run dispatch
The release workflow SHALL declare a `dry_run` input on `workflow_dispatch`. When true, the version job SHALL run Semrel in dry-run mode and the read-only updater preflight, the publish job SHALL be skipped regardless of the analysis result, and no file, commit, tag, or remote write SHALL occur.

#### Scenario: Dry-run dispatch on a release-worthy range
- **WHEN** the release workflow is dispatched with `dry_run` set true on a range containing `feat` commits
- **THEN** the version job reports the candidate version and notes, validates the updater patterns without writing, skips publication, and leaves the repository and remote unchanged

#### Scenario: Dry-run dispatch with no release-worthy commits
- **WHEN** the release workflow is dispatched with `dry_run` set true and the range contains only non-release commit types
- **THEN** the job reports that no release would be cut, the updater preflight still validates both version patterns, and nothing is written or pushed

### Requirement: Publish jobs gated on a new version
The release workflow SHALL run GoReleaser and publish the multi-architecture container image only when Semrel reports a real release and the dispatch is not a dry-run. The publish job SHALL check out Semrel's reported `v<version>` tag; GoReleaser SHALL be the sole GitHub Release publisher.

#### Scenario: No release means no publish
- **WHEN** the release workflow runs and no release-worthy commits exist
- **THEN** the publish job is skipped and no GitHub Release or image is produced

#### Scenario: Release triggers publish
- **WHEN** the release workflow runs and a new version is cut
- **THEN** the publish job checks out the reported version tag, GoReleaser creates the GitHub Release, and the image is pushed with that version

### Requirement: Version tags are immutable
The GitHub repository SHALL maintain an active tag-targeted ruleset for `refs/tags/v*` with `update` and `deletion` rules and no bypass actors. This policy is external to the workflow, which SHALL NOT claim to enforce tag immutability itself.

#### Scenario: Release tag cannot be rewritten
- **WHEN** a user attempts to update or delete an existing `vX.Y.Z` tag without an explicit bypass
- **THEN** GitHub rejects the operation because the active ruleset has no bypass actors
