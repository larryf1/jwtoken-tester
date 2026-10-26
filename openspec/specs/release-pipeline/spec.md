# release-pipeline Specification

## Purpose
Owns how this repository derives version numbers and cuts releases: conventional-commit analysis by Semrel, changelog and version-file preparation, the release commit/tag, and the Semrel release-phase plugins that push refs, build Go binaries, publish the GitHub Release, and publish the container image. Pre-release version strings continue to come from the existing `git describe` shell expression.

## Requirements

### Requirement: Version scheme matches the git-describe form for pre-release builds
For non-release builds the version SHALL be `X.Y.Z` on a release tag, otherwise `<base>-<n>-<short-sha>`: `<base>` is the nearest reachable release tag, or `0.0.0` when none exists; `<n>` is the number of commits since that tag; `<short-sha>` is the 7-character abbreviated commit SHA without the leading `g`. Formal releases SHALL always be the exact `vX.Y.Z` tags produced by the release workflow.

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

### Requirement: Manual release runs from main with release credentials
The release SHALL be triggered only by manual `workflow_dispatch`. The release job SHALL check out `main` explicitly, require a clean working tree, and use the repository's `RELEASE_TOKEN` secret for the checkout and Semrel's providers so the release commit can be written to `main`. The workflow SHALL NOT rely on the dispatch ref or infer the release branch from `github.ref_name`.

#### Scenario: Dispatch from a non-main ref still releases main
- **WHEN** the release workflow is dispatched while selecting a feature branch
- **THEN** the release job checks out `main`, analyzes `main`, and pushes the release to `main`

#### Scenario: Dirty checkout stops the release
- **WHEN** the checked-out `main` working tree has modified tracked files before Semrel runs
- **THEN** the release job fails instead of committing unrelated changes

### Requirement: Changelog retains history and adds one Semrel release entry
On a release, `@semrel/generator-changelog-md` SHALL prepend a dated `## vX.Y.Z (YYYY-MM-DD)` entry with `###` groups such as `Features`, `Bug Fixes`, and `Other Changes`. The configured retention SHALL preserve all existing release entries and bodies. Semrel's built-in changelog writer SHALL be disabled with `commit_changelog: false` so exactly one entry is generated per release.

#### Scenario: Notes prepended on release
- **WHEN** a release of `1.4.0` is cut from `v1.3.0`
- **THEN** `CHANGELOG.md` gains exactly one dated `## v1.4.0 (...)` section above prior entries with commits grouped by type, and all prior history remains unchanged

### Requirement: Version files updated on release
On a release, `@semrel/updater-replace` SHALL update `VERSION` and the `info.version` field in `docs/openapi.yaml` before tagging. Its configured match and replacement counts SHALL require exactly one version match in each file, so a stale pattern fails the release before any commit, tag, or publication.

#### Scenario: All version surfaces updated
- **WHEN** a release of `1.4.0` is prepared
- **THEN** `VERSION` contains `1.4.0` and the `docs/openapi.yaml` version field contains `1.4.0`

#### Scenario: Invalid updater pattern blocks the release
- **WHEN** an updater pattern or expected match count no longer matches the repository files
- **THEN** the updater fails before Semrel commits or tags, and no publication occurs

### Requirement: Semrel providers publish the release commit, tag, and GitHub Release
On a release, Semrel SHALL run the changelog generator and version updater before creating a local tag, then commit their tracked-file changes as `chore(release): set version to v<version> [skip ci]` and create the local `v<version>` tag on that commit. In the release phase, `@semrel/provider-git` SHALL push the tag and the `main` branch using `RELEASE_TOKEN` (`push_branch: true`), and `@semrel/provider-github` SHALL create the GitHub Release for the tag with the generated changelog as its notes. Only after the release exists SHALL GoReleaser run, with its own release publishing disabled (`release.disable: true`), and a following hook SHALL attach `dist/*.tar.gz`, `dist/*.zip`, and `dist/checksums.txt` to that release. The workflow SHALL NOT perform post-commit verification or an independent `git push`.

#### Scenario: Release commit and tag reach origin
- **WHEN** a release of `1.4.0` completes
- **THEN** `origin/main` receives a commit whose subject is `chore(release): set version to v1.4.0 [skip ci]`, containing exactly `CHANGELOG.md`, `VERSION`, and `docs/openapi.yaml`, and a tag `v1.4.0` pointing at it

#### Scenario: GitHub Release is created before artifacts are built
- **WHEN** the release plugins finish for `1.4.0`
- **THEN** the GitHub Release `v1.4.0` contains the generated changelog, and the GoReleaser archives and checksums are attached to it after the build

### Requirement: No release leaves the repository untouched
When no release-worthy commits exist, Semrel SHALL NOT modify any tracked file, create any commit or tag, or push to the remote, and SHALL report that no release is being cut.

#### Scenario: Only chore commits since last tag
- **WHEN** Semrel runs and the range contains only non-release commit types
- **THEN** the working tree, local history, and remote are all unchanged

### Requirement: Dry-run performs no writes
When run in dry-run mode, Semrel SHALL analyze commits and report the candidate version and notes without modifying files, running pre-tag or release plugins, committing, tagging, pushing, or creating a GitHub Release.

#### Scenario: Dry-run on a release-worthy range
- **WHEN** Semrel runs in dry-run mode on a range containing `feat` commits
- **THEN** it prints the candidate version and release notes, lists the plugins it would run, and the repository remains unchanged

### Requirement: Release workflow accepts a dry-run dispatch
The release workflow SHALL declare a `dry_run` input on `workflow_dispatch`. When true, the release job SHALL run Semrel in dry-run mode, skip all release-phase plugins, and make no file, commit, tag, remote, or registry write.

#### Scenario: Dry-run dispatch on a release-worthy range
- **WHEN** the release workflow is dispatched with `dry_run` set true on a range containing `feat` commits
- **THEN** the release job reports the candidate version and notes, skips publication, and leaves the repository and remote unchanged

#### Scenario: Dry-run dispatch with no release-worthy commits
- **WHEN** the release workflow is dispatched with `dry_run` set true and the range contains only non-release commit types
- **THEN** the job reports that no release would be cut and nothing is written or pushed

### Requirement: Release-phase plugins build and publish all artifacts
When Semrel cuts a release, the same release job SHALL run release-phase plugins that push the release refs, create the GitHub Release, build and attach the Go binaries, and publish the container image; there SHALL be no separate publish job. GoReleaser SHALL run after the release exists, from the tag Semrel created, and build the configured Go target matrix (linux, darwin, and windows on amd64 and arm64, excluding windows/arm64) with its own GitHub Release publishing disabled. The container image SHALL be built and pushed in one `docker buildx build --push` for `linux/amd64` and `linux/arm64` with both the `X.Y.Z` and `latest` tags.

#### Scenario: No release means no publish
- **WHEN** the release workflow runs and no release-worthy commits exist
- **THEN** no release plugin runs and no GitHub Release or image is produced

#### Scenario: Release triggers full publication
- **WHEN** the release workflow runs and a new version is cut
- **THEN** the Git provider pushes the tag, the GitHub provider creates the release, GoReleaser builds the configured Go binaries and they are attached to the release, and the `linux/amd64` and `linux/arm64` images are pushed as `X.Y.Z` and `latest`

### Requirement: Release refs are protected externally
The GitHub repository SHALL maintain an active tag-targeted ruleset for `refs/tags/v*` with `update` and `deletion` rules and no bypass actors. Any branch protection or ruleset configured for `main` SHALL allow `RELEASE_TOKEN` to push the release commit and tag. These policies are external to the workflow, which SHALL NOT claim to enforce them itself.

#### Scenario: Release tag cannot be rewritten
- **WHEN** a user attempts to update or delete an existing `vX.Y.Z` tag without an explicit bypass
- **THEN** GitHub rejects the operation because the active ruleset has no bypass actors

#### Scenario: Release token can write the release commit
- **WHEN** Semrel's Git provider pushes the release commit and tag to `main`
- **THEN** GitHub accepts the push because `RELEASE_TOKEN` is allowed by the `main` branch protection configuration
