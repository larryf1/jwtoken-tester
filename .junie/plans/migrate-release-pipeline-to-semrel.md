---
sessionId: session-261024-222203-uovo
---

# Requirements

### Overview & Goals
Replace go-semantic-release with `SemRels/semrel` for release analysis and metadata preparation, without introducing JavaScript or npm. A successful release must put generated changelog and version-file changes in the release commit before the `vX.Y.Z` tag is created.

### Scope
- Replace the release analyzer/configuration with pinned Go-native Semrel and its required plugins.
- Update `VERSION`, `docs/openapi.yaml`, and `CHANGELOG.md` before committing/tagging; retain historical changelog content and the repository’s release-note conventions.
- Keep `.github/workflows/release.yml` as the orchestrator. GoReleaser remains responsible for the GitHub Release and binary assets; the existing multi-architecture Docker action remains responsible for GHCR images.
- Preserve manual dispatch and dry-run: dry-run reports the candidate release and validates updater patterns without changing files, committing, tagging, releasing, or publishing images.
- Ensure version tags cannot be moved or deleted through GitHub tag protection/rulesets; this repository-level policy is an operational prerequisite, not something the workflow can guarantee by itself.

### Functional Requirements
- Conventional Commit bump behavior remains compatible with the lint gate: breaking change → major, `feat` → minor, `fix`/`perf`/`revert` → patch, and non-release commits → no release.
- The release commit contains the generated changelog and both tracked version updates, and `v<version>` points to that commit.
- The workflow obtains the release version from Semrel’s release metadata rather than relying on a local exact-`HEAD` tag lookup.
- Only a real release proceeds to GoReleaser and Docker publication; dry-run and no-release cases publish nothing.

### Out of Scope
- Replacing GoReleaser or changing the product’s pre-release `git describe` version calculation.
- Adding JavaScript/npm tooling or moving publication to a separate workflow.

### Acceptance Criteria
- A Semrel dry-run previews release analysis, while a standalone preflight validates both configured updater patterns and match counts without modifying or publishing anything.
- A controlled release run commits changelog/version updates before tagging, then publishes from the resulting version tag.
- No-release and dry-run paths skip GitHub Release and GHCR publication.

# Technical Design

### Current Implementation
`.github/workflows/release.yml` runs `go-semantic-release`, then attempts to gate the publish job by checking for an exact tag on `HEAD`. Its `dry_run` input skips publication. The current `.semrelrc` configures the default analyzer/generator, npm file updater for `VERSION` and `docs/openapi.yaml`, and GitHub provider; the workflow currently invokes none of the configured file updates. The existing `openspec/specs/release-pipeline/spec.md` and `openspec/specs/commit-linting/spec.md` encode go-semantic-release-specific requirements and need deltas. `CHANGELOG.md` contains legacy generated releases as well as Keep-a-Changelog sections.

### Decisions
- Use the Go-native Semrel CLI pinned in the workflow and pin plugin versions/checksums in `.semrel.lock`; replace `.semrelrc` with Semrel’s YAML configuration. Do not add Node/npm.
- Let Semrel prepare the release commit and create the local version tag. The workflow SHALL verify that the tag contains all updated metadata before atomically pushing the release branch and tag. Use the pinned changelog generator’s built-in dated `## vX.Y.Z` entries and `###` type groups, with retention configured to preserve all existing history, plus a replace updater for `VERSION` and `docs/openapi.yaml`.
- Keep the current single workflow. Export Semrel’s release version/tag metadata to the publish job, which checks out that tag; do not infer the version from a possibly stale local `HEAD` ref.
- Do not configure Semrel’s GitHub Release provider alongside GoReleaser. GoReleaser remains the sole GitHub Release publisher; retain the existing Docker build/push action.
- Keep dry-run as a no-side-effects preview and explicitly gate all publish actions off when requested.
- Because Semrel skips pre-tag plugins in dry-run, use a separate non-writing validator that reads the configured updater rules and checks their match counts against `VERSION` and `docs/openapi.yaml`.
- Enforce immutable `v*` tags with a GitHub repository ruleset/tag protection policy, because workflow configuration alone cannot prevent administrators or credentials from rewriting a tag.

### Components / Files
- `.semrelrc` → `.semrel.yaml` and `.semrel.lock`: configure release rules, changelog/version updates, and pinned plugin integrity; omit the Git push provider.
- `.github/workflows/release.yml`: install/run Semrel, verify release metadata before atomically pushing the tag and branch, and retain the GoReleaser/GHCR downstream flow with dry-run/no-release gates.
- `tools/semrel-preflight/main.go`: validate the configured replacement regexes and match counts without writing files.
- `openspec/specs/release-pipeline/spec.md`: replace obsolete analyzer/ordering contracts while retaining `git describe` pre-release behavior.
- `openspec/specs/commit-linting/spec.md`: require Semrel’s analyzer to agree with accepted Conventional Commits.
- GitHub repository ruleset: protect version tags against update and deletion.

### Risks / Trade-offs
- Plugin lifecycle/order could leave generated files out of the release commit; test the pinned versions’ pre-tag update/commit behavior before enabling production publishing.
- Semrel may still create a local tag after a metadata commit failure; the workflow must verify the tag before pushing any release refs.
- The pinned Markdown generator does not read a custom template; the accepted built-in heading style differs slightly from older entries, so validate that existing release blocks are retained and none are archived.
- Semrel's standalone `lint` command rejects one historical merge commit and has no ignore option; keep the existing PR linter as the commit-format gate unless that history or tool behavior changes.
- The active tag ruleset (ID `25809020`) is external to repository source; keep it enabled and without bypass actors.

# Testing

### Validation Approach
- Run Semrel dry-run on a controlled release-worthy range and the standalone updater preflight; confirm release metadata and replacement matches while the working tree and remote remain unchanged. Semrel lint flags one historical merge commit and offers no ignore option, so it is not used as the PR gate.
- Validate the GitHub Actions workflow’s branches for dry-run, no release, and actual release, including that publish checks out the Semrel version tag and that no Semrel GitHub Release provider duplicates GoReleaser.
- In a disposable repository or controlled test branch, exercise a real release preparation and verify the release commit contains the changelog and version-file updates before the tag is created.
- Confirm the active GitHub ruleset targets `refs/tags/v*` and blocks updates/deletion; do not attempt destructive remote tag operations or publish Docker images to production.

### Key Scenarios
- `feat`, `fix`, breaking-change, and non-release commit ranges produce the expected version decision.
- Dry-run with a candidate release reports metadata, validates both updater rules, and produces no file changes, commit, tag, GitHub Release, or Docker image.
- No release-worthy commits leave the remote unchanged and skip the publish job.
- Successful release tags the metadata commit, and GoReleaser/GHCR publish artifacts for that exact version.

# Delivery Steps

### ✓ Step 1: Replace release metadata tooling with pinned Semrel configuration
Semrel is configured as the Go-native release analyzer and prepares changelog/version metadata before tagging.
- Replace `.semrelrc` with `.semrel.yaml`, pin the CLI version in the workflow, and pin plugin versions/checksums in `.semrel.lock`.
- Configure Conventional Commit rules consistent with `openspec/specs/commit-linting/spec.md`.
- Configure changelog generation to retain historical entries and project release-note conventions.
- Configure the updater for `VERSION` and `docs/openapi.yaml`; the workflow task adds a separate non-writing check of both replacement patterns because Semrel dry-run skips pre-tag plugins.

### ✓ Step 2: Rework the single release workflow around Semrel outputs
`.github/workflows/release.yml` uses Semrel for release preparation and gates existing publication on Semrel’s reported version.
- Replace go-semantic-release invocation and capture Semrel’s version/release output instead of checking for a local exact-`HEAD` tag.
- Add and run a standalone validator for both configured updater patterns on dry-run, without modifying the checked-out files.
- Ensure Semrel commits changelog/version updates before creating local `v<version>`, verify the tag contents, then atomically push the release branch and tag without a Git push provider.
- Keep GoReleaser as the GitHub Release publisher and preserve the existing multi-architecture GHCR build/push step.
- Gate all publication off for dry-run and no-release outcomes; validate the branches without publishing production images.

### ✓ Step 3: Update release contracts and verify tag immutability
The OpenSpec release contracts describe the new Semrel flow and its validation requirements.
- Update `openspec/specs/release-pipeline/spec.md` for Semrel analysis, metadata commit-before-tag ordering, release output, and dry-run behavior while preserving pre-release version rules.
- Update `openspec/specs/commit-linting/spec.md` so accepted commit messages are analyzable by Semrel.
- Verified active ruleset `25809020` targets `refs/tags/v*`, blocks updates/deletion, and lists no bypass actors; document it as an external release prerequisite.
- Exercise Semrel dry-run and a non-publishing controlled release path, checking release commit contents and tag target.