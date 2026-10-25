# Spec Delta

## MODIFIED Requirements

### Requirement: Linter and release analysis agree
The pull-request linter and Semrel release analysis SHALL agree on the supported Conventional Commit types and breaking-change markers. Semrel SHALL apply the configured release rules to accepted messages: breaking change → major, `feat` → minor, and `fix`, `perf`, or `revert` → patch; other types SHALL NOT trigger a release. The PR linter's existing default ignores for merge messages SHALL remain enabled.

#### Scenario: Gate commits are analyzable
- **WHEN** a pull request passes the lint gate and is merged to `main`
- **THEN** Semrel can analyze each accepted Conventional Commit in the release range using the same type and breaking-change conventions

#### Scenario: Merge messages do not trigger a release
- **WHEN** a merge commit message is present in a release range
- **THEN** the PR lint gate continues to ignore the merge message by its default ignore rule, and Semrel's configured release rules do not assign it a version bump