# Contributing to jwtoken-tester

Thanks for helping out! This project is small on purpose — keep changes focused
and documented.

## Getting started

Requirements:

- Go 1.27+
- `golangci-lint` (install with `make lint-install`)
- Docker (only for the container/demo-service targets)

Fork the repo, clone it, then build and test:

```sh
make all          # lint, test, build in one pass
make test         # go test ./...
make lint         # go vet + gofmt formatting check
make coverage     # measure coverage (threshold: 90%)
go run ./cmd/jwtoken-tester   # run the server locally
```

## What to know first

The whole point of this tool is **ephemeral, spec-compliant tokens with zero
persisted secrets**. When you change it, keep that invariant: private keys must
never touch disk, env vars, logs, or HTTP responses.

- Every minted token is cross-validated in the test suite against an independent
  JWT library (`github.com/golang-jwt/jwt/v5`). New signing behaviour must keep a
  test that does the same.
- Key `kid`s are RFC 7638 thumbprints. Do not introduce a divergent `kid` scheme
  unless you can justify it.
- Test tooling only, no TLS, no users. Keep it that way.

## Conventional commits

Release automation (`semantic-release`) derives versions and the changelog from
commit messages, so the format is **enforced, not just requested**: the PR CI
job `commitlint` rejects any commit that does not follow the
[Conventional Commits](https://www.conventionalcommits.org/) spec (run it
locally with `npx commitlint --from origin/main --to HEAD`).

```
feat(server): add X
fix(keyring): correct rotation edge case
docs(readme): clarify TTL parsing
```

Type keywords that cut a release: `feat` → minor, `fix` → patch. `docs`,
`chore`, `refactor`, `test` do not. Put `BREAKING CHANGE:` in the body when a
change is breaking (→ major).

## Releases

Releases are cut automatically from `main` by `semantic-release`. Versions are
calculated from the merged conventional commits:

- `feat` → **minor** (e.g. `1.0.0` → `1.1.0`)
- `fix` → **patch** (e.g. `1.0.0` → `1.0.1`)
- `BREAKING CHANGE:` → **major** (e.g. `1.0.0` → `2.0.0`)

There is no manual version number step — the version is always derived. To cut
a release, run the [Release](.github/workflows/release.yml) workflow
(interactively, or with `gh workflow run release.yml`). It bumps the version in
`VERSION`/`package.json`, updates `CHANGELOG.md`, tags the commit, pushes, and
publishes binaries + the Docker image. Releases from the tag push flow through
the [Publish](.github/workflows/publish.yml) workflow.

## Developer Certificate of Origin (DCO)

By contributing you certify that you wrote the code (or have the right to submit
it) under the [MIT license](LICENSE) — the
[Developer Certificate of Origin, version 1.1](https://developercertificate.org/).
Sign off every commit with `git commit -s` (adds a `Signed-off-by:` trailer with
your name and email). The PR CI job `dco` rejects the PR unless **every** commit
carries the trailer.

## Before you open a PR

1. `make fmt` then `make lint` and `make test` locally — all green.
2. Keep coverage at or above the project threshold where feasible.
3. Update `README.md` if behaviour or flags/env vars change (there is a config
   table that must match the code).
4. Write a conventional-commit summary in the PR title so it can be squashed
   cleanly.
5. One logical change per PR. Small, reviewable diffs get merged faster.

## Project layout

```
cmd/jwtoken-tester/     main binary, flag/env configuration
internal/keyring/       key generation, rotation, RFC 7638 kids, zeroization
internal/tokenfactory/  claim templating, TTL parsing, signing
internal/server/        HTTP handlers, JWKS, discovery document
pkg/tester/             embeddable Go library mode (httptest helper)
docker/                 container + docker-compose demo
```

`internal/*` is intentionally internal. Shared public API lives under `pkg/`.

## Reporting bugs / security issues

- Security vulnerabilities: do **not** open a public issue. Follow
  [`SECURITY.md`](SECURITY.md).
- Everything else: open an issue with repro steps (e.g. a curl snippet) and the
  Go version you used.