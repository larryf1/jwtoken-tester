# Design

## Context

See `proposal.md` for motivation. The release path is a Go project with an existing Conventional Commit lint gate, `VERSION` and OpenAPI version fields, a mixed-format historical `CHANGELOG.md`, and a single GitHub Actions workflow that owns release and image publication. Preserve the existing pre-release `git describe` behavior, GoReleaser, and the multi-architecture GHCR action.

## Goals / Non-Goals

**Goals:**
- Prepare and commit changelog and version-file updates before creating the version tag.
- Ensure only a verified tag and its release commit reach the remote, and publish from Semrel's reported tag.
- Keep dry-run and no-release outcomes free of repository writes and publication.

**Non-Goals:**
- Replace GoReleaser or the existing Docker publication action.
- Add JavaScript/npm tooling, change pre-release version calculation, or move publishing into another workflow.
- Make tag immutability a workflow responsibility; it is enforced by GitHub repository policy.

## Decisions

1. **Use pinned Go-native Semrel and plugins.** Pin the Semrel CLI in the workflow and pin plugin versions and checksums in `.semrel.lock`; configure the release branch, `v` tag prefix, and Conventional Commit bump rules in `.semrel.yaml`. This avoids a JavaScript toolchain and makes plugin restoration reproducible. The existing go-semantic-release configuration and invocation are replaced.

2. **Use the Markdown generator's built-in output and preserve the existing history.** Configure dated `## vX.Y.Z` headings and `###` type groups, with retention high enough to preserve every current release entry and body. The generator's custom-template option is not implemented by the pinned executable, so a repository-specific generator is not added; validate the built-in format and confirm no existing changelog content is archived or removed.

3. **Update the two tracked version surfaces with configured replacement rules.** The replace updater changes `VERSION` and the `info.version` field in `docs/openapi.yaml`, with one expected match and replacement per file. Semrel dry-run skips pre-tag plugins, so a separate read-only preflight parses those rules, compiles their patterns, and checks target-file match counts without writing. A disposable local release test is not used as the updater preflight because the standalone checker avoids temporary commits and tags while directly validating the configured patterns.

4. **Verify local release metadata before any remote push.** Semrel runs the changelog and updater plugins, commits their tracked changes, and creates a local `v<version>` tag. Do not configure a Git push provider: it could push a tag before the workflow verifies its contents. Instead, the workflow checks that the tag points to the expected commit and that the tagged `VERSION`, OpenAPI version, and changelog entry match the reported release; only then does it atomically push the release branch and tag. Atomic push prevents the branch and tag from being updated separately.

5. **Keep one workflow and make Semrel metadata the publication contract.** The version job exports Semrel's release state, version, and tag. The publish job runs only for a real non-dry-run release and checks out that exact tag. GoReleaser remains the sole GitHub Release publisher; the existing Docker action publishes the versioned and `latest` GHCR images. This retains the current orchestration and avoids cross-workflow tag-trigger and credential coordination.

6. **Treat tag protection as an external prerequisite.** Keep the active GitHub ruleset targeting `refs/tags/v*`, blocking updates and deletion, with no bypass actors. Workflow checks protect the release ordering but cannot prevent an authorized repository actor from rewriting a tag if repository policy permits it.

## Risks / Trade-offs

- **A plugin failure can leave a local tag that does not include prepared metadata** → Verify the tag target and all three tagged metadata files before pushing; perform branch and tag publication atomically.
- **The built-in changelog headings differ from legacy entries** → Accept the documented heading style, retain the existing content with the configured release retention, and verify the generated top section and full historical tail in a controlled release test.
- **Updater patterns can drift from target-file formats** → Run the standalone preflight in dry-run and assert exactly one match and replacement for each configured target.
- **Semrel lint rejects a historical merge commit** → Keep the existing PR commit-lint gate as the format gate and ensure Semrel's configured release rules do not assign merge commits a bump.
- **GitHub ruleset configuration is outside source control** → Confirm the active `v*` ruleset remains enabled and has no bypass actors before production release use.
- **A release tag cannot be safely rolled back by rewriting it** → Do not push until verification succeeds; if publication fails after a verified tag is pushed, retry publication from that tag or make a forward-fix release rather than moving or deleting the tag.

## Migration Plan

1. Install the pinned Semrel CLI and restore plugins from the lock file; run the dry-run analysis and read-only updater preflight.
2. Validate release/no-release/dry-run workflow paths without publishing production images. In a disposable repository or controlled branch, run actual release preparation and confirm the metadata commit precedes the local tag and contains all expected files.
3. Confirm the active GitHub `v*` tag ruleset and then enable normal workflow publication. The workflow must verify the local tag before its atomic branch-and-tag push.
4. If preparation or verification fails before the atomic push, stop with no remote release refs changed and correct the configuration. If publication fails after the push, retry GoReleaser/GHCR publication from the reported tag; do not rewrite or delete the tag.

## Open Questions

None. The workflow boundary, changelog format, preflight method, and tag-push ordering have been selected.