# Proposal

## Why

The project is adopting OpenSpec but `openspec/specs/` is empty, so there is no spec-driven record of what the existing system does. This change captures the entire shipped behavior of jwtoken-tester as baseline specs so that future changes have a stable, reviewable contract to build on.

## What Changes

- Adds the first OpenSpec capability inventory for the project, covering all existing runtime functionality:
  - Runtime configuration via environment variables and flags
  - In-memory signing key management (generation, rotation, grace period, pruning, RFC 7638 kids)
  - Token minting via `POST /token` (claims, time-value parsing, TTL caps, algorithms, JOSE headers, responses, errors, audit logging)
  - HTTP surface: service index, version, health, OIDC discovery, JWKS, single JWK by kid
  - HTTP middleware: security headers, per-IP rate limiting, request IDs
  - CLI commands (`serve`, `print-token`, `help`)
  - Embeddable Go library mode (`pkg/tester`)
  - Container image and docker-compose demo
- Creates the specification files only. No application code changes.
- **Out of scope**: the current CI, publish, and release workflows (`.github/workflows`, `semantic-release`, GoReleaser) are intentionally not captured; they are being re-implemented soon. Developer-only `make` targets and test/coverage tooling are also not captured.

## Capabilities

### New Capabilities

- `configuration`: Runtime configuration of the server and one-shot token mode from environment variables and CLI flags, including defaults, precedence, and duration semantics.
- `key-management`: Lifecycle of in-memory signing keys — generation per algorithm, RFC 7638 thumbprint-derived `kid`s, rotation, grace period for retired keys, pruning with private-key zeroization, algorithm enablement, and JWKS/JWK access.
- `token-minting`: Observable behavior of the `POST /token` endpoint — request shape, claim handling, time-value parsing, TTL defaults and caps, signing algorithms, custom JOSE headers, response format, and error mapping.
- `http-api/service-metadata`: The service index (`GET /`) and version (`GET /version`) endpoints.
- `http-api/health`: The liveness endpoint (`GET /healthz`) and its payload.
- `http-api/discovery`: The OpenID Connect discovery document (`GET /.well-known/openid-configuration`).
- `http-api/jwks`: The JWKS endpoint (`GET /.well-known/jwks.json`) and single-key lookup (`GET /.well-known/jwks.json/{kid}`).
- `http-api/security`: Cross-cutting HTTP guards — security headers, per-IP rate limiting, and request-ID correlation.
- `cli`: The `jwtoken-tester` command-line entrypoint — subcommands, usage output, and exit behavior.
- `embedding`: The embeddable `tester` Go package that spins up an in-process test issuer via `httptest`.
- `container`: The Docker image runtime contract (distroless, non-root, `serve` entrypoint) and the docker-compose demo with a token-protected sample service.

### Modified Capabilities

_(none — first spec inventory on an empty `openspec/specs/`)_

## Impact

- Adds ~11 new spec files under `openspec/specs/`.
- No source code, APIs, dependencies, or build artifacts change.
- The archived result becomes the baseline contract for all future OpenSpec changes to this project.