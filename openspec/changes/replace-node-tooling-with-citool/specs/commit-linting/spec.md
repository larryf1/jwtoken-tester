# Spec Delta

## Purpose

Enforces the Conventional Commits format on pull request commits and locally, so that release versions and changelogs can be derived from commit messages.

## ADDED Requirements

### Requirement: Pull requests are gated on commit format
CI SHALL reject a pull request when any commit in its range fails the commitlint check, and SHALL pass when every commit in the range conforms.

#### Scenario: Conforming pull request passes
- **WHEN** a pull request's commits are `feat(server): add X`, `fix(keyring): correct rotation edge case`, and `docs(readme): clarify TTL parsing`
- **THEN** the lint job succeeds

#### Scenario: Non-conforming commit fails the build
- **WHEN** a pull request contains a commit with subject `Add new feature` (no type)
- **THEN** the lint job fails and reports the offending commit and rule

### Requirement: Conventional commit rules are enforced
The linter SHALL enforce: a header of at most 100 characters; a type from the set `build`, `chore`, `ci`, `docs`, `feat`, `fix`, `perf`, `refactor`, `revert`, `style`, `test`, written in lowercase; a non-empty subject that does not end with a period and does not use sentence, start, or pascal case; a blank line between header and body; and body and footer lines of at most 200 characters.

#### Scenario: Header over the limit is rejected
- **WHEN** a commit header exceeds 100 characters
- **THEN** the linter reports a header-max-length violation

#### Scenario: Body line over the project limit is rejected
- **WHEN** a commit body contains a line longer than 200 characters
- **THEN** the linter reports a body-max-line-length violation

#### Scenario: Unknown type is rejected
- **WHEN** a commit starts with `wip: do the thing`
- **THEN** the linter reports that the type is not in the allowed set

#### Scenario: Trailing period in subject is rejected
- **WHEN** a commit subject ends with `.`
- **THEN** the linter reports a subject-full-stop violation

### Requirement: Linting is runnable locally
The check SHALL be runnable locally without installing any non-Go toolchain, both as `make lint-commits` and as the commitlint CLI directly (`go run github.com/conventionalcommit/commitlint` with `--from <ref>`/`--to <ref>`), using the same rules as CI.

#### Scenario: Contributor checks their branch locally
- **WHEN** a contributor runs `make lint-commits` with conforming commits above `origin/main`
- **THEN** the command exits zero

#### Scenario: Contributor sees failures before pushing
- **WHEN** a contributor runs `make lint-commits` (or the commitlint CLI with `--from origin/main --to HEAD`) on a branch with a malformed commit
- **THEN** the command exits non-zero and names the rule violated

### Requirement: Linter and release analysis agree
The linter and go-semantic-release SHALL both parse conventional-commit messages, so that any commit accepted by the lint gate can be analyzed for release without parse errors.

#### Scenario: Gate commits are analyzable
- **WHEN** a pull request passes the lint gate and is merged to `main`
- **THEN** go-semantic-release can parse every commit in the range during version analysis


