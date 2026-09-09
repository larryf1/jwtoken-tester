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
commit messages, so:

```
feat(server): add X
fix(keyring): correct rotation edge case
docs(readme): clarify TTL parsing
```

Type keywords that cut a release: `feat` and `fix`. `docs`, `chore`, `refactor`,
`test` do not. Put `BREAKING CHANGE:` in the body when a change is breaking.

## Developer Certificate of Origin (DCO)

By contributing you certify that you wrote the code (or have the right to submit
it) under the [MIT license](LICENSE) — the [Developer Certificate of Origin,
version 1.1](https://developercertificate.org/). Sign off every commit with
`git commit -s` (adds a `Signed-off-by:` trailer with your name and email).
Commits without the trailer will be rejected. (Internal CI checks for the
trailer on all branches that gate merges to `main`.)

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