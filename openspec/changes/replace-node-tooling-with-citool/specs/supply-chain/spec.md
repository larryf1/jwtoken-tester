# Spec Delta

## Purpose

Protects the repository's supply chain in CI: pinned third-party actions, a vulnerability gate over the shipped Go module, and freedom from a Node.js/npm toolchain in the build, CI, and release path.

## ADDED Requirements

### Requirement: GitHub Actions are SHA-pinned
Every `uses:` reference in `.github/workflows/` SHALL be pinned to a full 40-character commit SHA with the version retained in a trailing comment, and CI SHALL fail when any reference is unpinned.

#### Scenario: Unpinned action fails CI
- **WHEN** a workflow adds `uses: actions/checkout@v4` (a mutable tag)
- **THEN** the supply-chain job fails and names the unpinned reference

#### Scenario: Pinned action passes CI
- **WHEN** all workflow references use the `actions/checkout@<40-hex-sha> # vX.Y.Z` form
- **THEN** the supply-chain job succeeds

### Requirement: Go module vulnerability gate
CI SHALL include a job that scans the repository's Go module for known vulnerabilities and fails the build when a vulnerability affecting the module's packages is reported.

#### Scenario: Vulnerable dependency fails the build
- **WHEN** a dependency version with a known vulnerability is introduced
- **THEN** the vulnerability job fails and names the vulnerable package

#### Scenario: Clean module passes
- **WHEN** the module has no known vulnerabilities in its dependencies
- **THEN** the vulnerability job succeeds

### Requirement: No Node.js toolchain in the repository's build path
The repository SHALL NOT contain a Node.js/npm toolchain for its build, CI, release, or contribution workflows: no `package.json`, `package-lock.json`, `.npmrc`, `.nvmrc`, or `node_modules` tree, no Node setup or npm execution in `.github/workflows/`, and no npm entry in dependabot configuration. The Release, Publish, and CI workflows SHALL run with only Go, shell, and pinned actions.

#### Scenario: No Node in workflows
- **WHEN** `.github/workflows/*.yml` is inspected
- **THEN** no step installs Node.js or runs `npm`, `npx`, `semantic-release`, or `commitlint`

#### Scenario: No npm dependency tree
- **WHEN** the repository root is inspected
- **THEN** `package.json` and `package-lock.json` are absent and dependabot has no `npm` ecosystem entry

#### Scenario: Contribution without Node
- **WHEN** a contributor follows CONTRIBUTING.md to lint commits and cut a release
- **THEN** no step requires installing Node.js or npm
