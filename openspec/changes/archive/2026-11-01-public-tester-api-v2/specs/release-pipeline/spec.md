# Spec Delta

## MODIFIED Requirements

### Requirement: Release version calculated from conventional commits
Semrel SHALL determine the next version by analyzing commits since the last release tag: a `feat` commit requires a minor bump, `fix`, `perf`, and `revert` commits require a patch bump, and a breaking change (a `BREAKING CHANGE:` footer or a `!` type marker) requires a major bump when the module path has no major-version suffix. For a module path carrying a `/vN` suffix, a breaking change SHALL NOT produce a major bump; the release SHALL fail until a deliberate module-path migration to `/v(N+1)` lands. Commits of any other type, including merge commits, SHALL NOT trigger a release.

#### Scenario: Feature commits produce a minor release
- **WHEN** the commits since the last tag include `feat(server): add rotation`
- **THEN** the next version increments the minor component

#### Scenario: Fix commits produce a patch release
- **WHEN** the commits since the last tag include `fix(keyring): correct rotation edge case` and no `feat` commits
- **THEN** the next version increments the patch component

#### Scenario: Breaking change produces a major release
- **WHEN** a commit carries a `BREAKING CHANGE:` footer or uses the `fix!:` marker and the module path has no major-version suffix
- **THEN** the next version increments the major component

#### Scenario: Breaking change cannot escape the module major
- **WHEN** a commit carries a `BREAKING CHANGE:` footer or uses the `fix!:` marker and the module path ends in `/v2`
- **THEN** the release fails before committing, tagging, pushing, or publishing, and the failure names the required module-path migration

#### Scenario: Non-release commits produce no release
- **WHEN** the commits since the last tag are only `docs`, `chore`, `refactor`, `test`, `ci`, or merge commits
- **THEN** no new version is calculated and no release is cut

## ADDED Requirements

### Requirement: Release version major matches the module path
The release SHALL derive the major version from the module path's `/vN` suffix (or `1` when there is no suffix) and SHALL compare it with the major of the computed next version. On a mismatch the release SHALL fail before any version-file update, release commit, tag, push, GitHub Release, binary publication, or image push.

#### Scenario: Matching major proceeds
- **WHEN** the module path ends in `/v2` and the computed next version is `v2.4.0`
- **THEN** the release proceeds normally

#### Scenario: Mismatched major stops the release
- **WHEN** the module path ends in `/v2` and the computed next version is `v3.0.0`
- **THEN** the release fails before writing any file or creating any commit, tag, or publication

#### Scenario: Unsuffixed path is treated as major one
- **WHEN** the module path has no major-version suffix and the computed next version is `v1.5.0`
- **THEN** the release proceeds normally

### Requirement: Published tags are fetchable for the module path
Every published tag SHALL be a valid Go module version for the repository's module path, so the Go module proxy resolves it. A release tag whose major does not match the path suffix SHALL NOT be published.

#### Scenario: New tag resolves through the module proxy
- **WHEN** a `/v2` release of `v2.4.0` is published
- **THEN** `go list -m -versions` for the `/v2` path includes `v2.4.0`

#### Scenario: Command install resolves from the release
- **WHEN** a `/v2` release is published
- **THEN** `go install <module>/v2/cmd/jwtoken-tester@latest` resolves to that release

#### Scenario: Invalid-major tag is never published
- **WHEN** the computed version's major does not match the module path suffix
- **THEN** no tag is created and the module proxy never sees that version
