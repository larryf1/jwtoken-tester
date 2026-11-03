# jwtoken-tester

[![CI](https://github.com/larryf1/jwtoken-tester/actions/workflows/ci.yml/badge.svg)](https://github.com/larryf1/jwtoken-tester/actions/workflows/ci.yml)
[![Go Version](https://img.shields.io/badge/Go-1.27%2B-blue?logo=go&logoColor=white)](https://go.dev/dl/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Latest Release](https://img.shields.io/github/v/release/larryf1/jwtoken-tester?sort=semver)](https://github.com/larryf1/jwtoken-tester/releases)

An **ephemeral JWT/JWKS issuer** for integration-testing JWT-aware services.

It behaves like a tiny OpenID Connect-style identity provider whose public keys your app can
fetch and verify against — but it holds **zero persisted secrets**: keypairs are generated
in memory at startup and discarded on shutdown. Real IdPs bring secrets, configuration, and
network dependencies; this is the throwaway replacement you point a test environment at instead
of hacking basic-auth shortcuts into your middleware.

> **Test tooling only.** Not a production IdP: no users, no consent, no refresh tokens, **no TLS**.
> Binds to loopback by default and warns loudly if bound elsewhere.
> 
> **TLS/HTTPS:** This tool does not implement TLS. In test environments requiring HTTPS,
> terminate TLS at a reverse proxy (nginx, Caddy, Traefik, etc.) in front of this service.

## How it works

```
┌──────────────────────────────────────────────────┐
│                jwtoken-tester                    │
│                                                  │
│  In-memory KeyRing                               │
│   ├─ active key(s): RSA2048 / P-256 / Ed25519    │
│   ├─ retiring keys (grace window)                │
│   └─ rotation goroutine                          │
│                                                  │
│  HTTP API                                        │
│   GET  /                                         │
│   GET  /healthz                                  │
│   GET  /version                                  │
│   GET  /.well-known/jwks.json                    │
│   GET  /.well-known/jwks.json/{kid}              │
│   GET  /.well-known/openid-configuration         │
│   GET  /.well-known/oauth-authorization-server   │
│   POST /token          ← mint arbitrary JWTs     │
│   POST /oauth/token    ← OAuth client credentials│
│   POST /introspect     ← RFC 7662 introspection  │
│   POST /v2/oauth/token ← legacy v2-style JWTs    │
│   POST /verify         ← self-check a token      │
└──────────────────────────────────────────────────┘
```

Tokens are standards-compliant JWS compact serializations (RS256, ES256, EdDSA), so real-world
JWT middleware (Spring Security, go-jose, golang-jwt, jsonwebtoken, …) accepts them unchanged —
most libraries auto-configure from the discovery document alone.

Each signing key's `kid` is the unpadded base64url SHA-256 [RFC 7638](https://datatracker.ietf.org/doc/html/rfc7638)
thumbprint of its public JWK, so JWKS consumers can match keys without special-casing.

### Key lifecycle

1. On boot keypairs are generated from `crypto/rand`. Private keys never touch disk, env vars,
   logs, or HTTP responses.
2. Every `ROTATION_INTERVAL` (default `30m`) a fresh key becomes active. The previous key stays
   published in the JWKS for `GRACE_PERIOD` so outstanding tokens keep validating, then it is
   zeroized in memory and dropped from the set.
3. Set `ROTATION_INTERVAL=0` when tests need long-lived key stability.

## Installation

Prebuilt binaries for Linux, macOS, and Windows (amd64 + arm64) are attached to
every [release](https://github.com/larryf1/jwtoken-tester/releases). Or install
from source (Go 1.27+):

```sh
go install github.com/larryf1/jwtoken-tester/v2/cmd/jwtoken-tester@latest
```

A released Docker image is also published:

```sh
docker pull ghcr.io/larryf1/jwtoken-tester:latest
docker run --rm -p 8080:8080 ghcr.io/larryf1/jwtoken-tester
```

## Releases

Versions are derived automatically from [Conventional Commits](https://www.conventionalcommits.org/)
and cut with [Semrel](https://semrel.io/):
`feat` → minor, `fix` → patch, `BREAKING CHANGE:` → major on an unsuffixed
module path. Every PR merge to `main` is gated by CI that enforces the commit
format (`commitlint`, run it locally with `make lint-commits`) and the DCO
`Signed-off-by:` trailer. There is no manual version to pick.

The **Release** workflow does everything in one manual run from `main`:
1. A dry run computes the candidate version, then `cmd/releaseguard` compares its
   major with the major encoded in the module path. A mismatch stops the run
   before anything is written.
2. Semrel analyzes the history and determines the next version.
3. It updates `CHANGELOG.md`, `VERSION`, and `docs/openapi.yaml`, commits them as
   `chore(release): set version to vX.Y.Z [skip ci]`, and tags that commit.
4. Its release plugins push the commit and `vX.Y.Z` tag to `main` with
   `RELEASE_TOKEN` and create the GitHub Release with the changelog.
5. GoReleaser then builds the binary archives and attaches them to the release,
   and the multi-architecture Docker image is built and pushed to GHCR as
   `X.Y.Z` and `latest` in the same run.

### Module major versions and `/vN` releases

The module path ends in `/v2` (`github.com/larryf1/jwtoken-tester/v2`). Because a
`/vN` module cannot publish a `v(N+1)` tag, the Release workflow runs
`cmd/releaseguard` as a preflight. It reads the module path from `go.mod`,
derives the required major from the final `/vN` segment (or `1` when there is
no suffix), and rejects a computed version whose major differs. The guard runs
before any version-file update, release commit, tag, push, GitHub Release, or
image push, and its error names the module path that must be migrated.

To ship a deliberate breaking change:

1. Change `go.mod` to `/v(N+1)` and rewrite every internal import plus the
   install/import paths in the README.
2. Land the migration together with the breaking change so Semrel computes
   `v(N+1).0.0`; the guard then sees matching majors. Do not tag the new path
   with an old-major version.
3. Never rewrite or delete a published tag.

This `/v2` introduction is the one deliberate exception to the major-bump rule:
it must land as a `feat:` commit with no `!` type marker and no
`BREAKING CHANGE:` footer, so Semrel computes `v2.4.0` — the first tag the Go
module proxy can resolve for the `/v2` path. The older `v2.0.0`–`v2.3.0` tags
remain valid only for the unsuffixed path.

The **Publish (development build)** workflow is for ad-hoc image pushes from any
branch; it uses the development-build version scheme below.

### Versioning

A version is always a plain, unambiguous version number derived from git,
following the [`git describe`][git-describe] scheme:

- **Release** — a tag `vX.Y.Z` on the release commit produces the exact
  version `X.Y.Z` (the `v` prefix is stripped). Every artifact (binary, Docker
  image, GitHub Release) is tagged with just `X.Y.Z`.
- **Development build** — a build from any non-tag ref (e.g. a manual
  *Publish* run on `main`) is labeled
  `X.Y.Z-<n>-<short-sha>`, where `X.Y.Z` is the most recent reachable release
  tag, `<n>` is the number of commits since that tag, and `<short-sha>` is the
  7-character abbreviated commit SHA (the leading `g` that `git describe`
  emits is stripped). If no release tag exists yet, the base is `0.0.0`.

  | Source ref | Image tag |
  |-----------|-----------|
  | tag `v1.2.3` | `1.2.3` |
  | `main`, 5 commits after `v1.2.3` | `1.2.3-5-4fa184e` |
  | no tags yet | `0.0.0-<n>-<short-sha>` |

The image is published to
[`ghcr.io/larryf1/jwtoken-tester`](https://github.com/larryf1/jwtoken-tester/pkgs/container/jwtoken-tester);
the **Release** workflow also tags the release image `latest`. `make docker-build`
tags both the computed version and `latest`, and passes the same version to the
binary and the OCI `version` label.

Images carry OCI label metadata ([`org.opencontainers.image.*`][oci-labels])
— `version`, `revision` (commit SHA), `source`, and `created` — so the exact
code a container runs is inspectable with `docker inspect`.

`make build`, `make run`, `make docker-build`, and the **Publish** workflow all
use the same `scripts/version.sh`: the version is derived from `git describe`,
baked into the binary via `-ldflags "-X main.Version=…"`, and used for the image
tag and OCI label. Running the binary through `go run` (no build flags) falls
back to the `VERSION` file updated by Semrel, then to Go build metadata; it never
reports a placeholder `dev` version.

[git-describe]: https://git-scm.com/docs/git-describe
[oci-labels]: https://github.com/opencontainers/image-spec/blob/main/annotations.md#pre-defined-annotation-keys

## Quick start

Requires Go 1.27+.

```sh
go run ./cmd/jwtoken-tester serve
# INFO listening addr=127.0.0.1:8080 issuer=http://127.0.0.1:8080 ...
# WARN TEST ISSUER ONLY: keys are generated in memory and never persisted
```

Mint a token:

```sh
curl -s http://127.0.0.1:8080/token -d '{
  "claims": {
    "sub": "user-123",
    "aud": ["my-service"],
    "roles": ["admin"],
    "tenant": "acme"
  }
}'
```

```json
{
  "access_token": "eyJhbGciOiJSUzI1NiIsImtpZCI6Ii4uLiJ9...",
  "token_type": "Bearer",
  "expires_in": 3600
}
```

Use it:

```sh
curl -H "Authorization: Bearer $ACCESS_TOKEN" http://localhost:3000/api/things
```

Point the app under test at the issuer (e.g. env `ISSUER_URL=http://127.0.0.1:8080`) and it will
pull the JWKS from `/.well-known/jwks.json` like any other IdP.

### CLI commands

The binary has these modes:

- `serve` — run the HTTP issuer (used by the container and `make run`).
- `print-token` — mint one token and print only the `access_token` to stdout, useful in shell
  scripts that cannot reach a running server:
  `jwtoken-tester print-token --claims '{"sub":"user-1","aud":["my-service"]}' --alg ES256`
- `decode` — print a token's JOSE header and claims without keys, network access, or trust.
- `verify` — verify a token against a JWKS URL, a JWKS file, or a discovered issuer.
- `healthcheck` — probe `/healthz` using the binary itself, so distroless containers do not need
  `curl` or `wget`.

Run `jwtoken-tester help` for the full flag list.

#### `decode`

`decode` prints the JOSE header and payload as indented JSON. It needs no keys, makes no network
request, and does not validate the signature, time claims, issuer, or audience, so it works on
expired and foreign tokens too. It exits `0` for any structurally decodable three-segment compact
JWS and non-zero otherwise (including missing input).

```sh
jwtoken-tester decode "$ACCESS_TOKEN"
jwtoken-tester decode < token.txt
```

#### `verify`

`verify` checks a token against keys from `--jwks <url|file>` or discovered from
`--issuer <url>`. Key retrieval happens in the client process; the local server is not involved.
Exactly one of `--jwks` or `--issuer` is required.

- `--jwks` accepts an `http(s)` URL or a file path. `--jwks` alone does not check `iss`, because a
  JWKS carries no issuer identity.
- `--issuer` fetches `<issuer>/.well-known/openid-configuration`, loads its `jwks_uri`, and checks
  `iss` against the discovery document's `issuer` (falling back to the flag value).
- `--aud`, repeatable `--alg`, and `--leeway` add consumer expectations. `--json` prints the same
  verdict envelope that `POST /verify` returns.
- Exit codes are `0` valid, `1` invalid verdict, and `2` for operational failures such as an
  unreadable key source, a failed fetch, or a usage error.

Flags must precede the positional token because the command uses Go's standard flag parsing. Pipe
the token on stdin to avoid that ordering or to keep it out of the process list:

```sh
TOKEN=$(curl -s http://127.0.0.1:8080/token | jq -r .access_token)

jwtoken-tester verify --jwks http://127.0.0.1:8080/.well-known/jwks.json "$TOKEN"
jwtoken-tester verify --issuer http://127.0.0.1:8080 --aud my-service --json "$TOKEN"
jwtoken-tester verify --jwks ./jwks.json --alg RS256 --leeway 30s < token.txt
```

Tokens minted by `print-token` use a throwaway in-memory keyring, so they cannot verify against a
running `serve` process, and restarting `serve` discards its keys. When the verdict is
`kid`/`unknown`, `verify` prints a hint explaining this. Mint the token from the same server whose
JWKS you verify against, or use the keyring that signed it.

### Verifying tokens on jwt.io

The `/token` endpoint returns JSON, so paste **only** the `access_token` value into jwt.io —
not the whole JSON response and not a `Bearer ...` prefix. jwt.io's
*"This tool only supports a JWT that uses the JWS Compact Serialization…"* error means the pasted
text did not split into exactly three dot-separated segments; with this tool that is almost always
a copy-paste artifact (a terminal line-wrap, a stray quote, or the JSON envelope), not a bad token.
Every minted token is cross-validated in the test suite against an independent JWT library, so if
you hit that message, re-copy the raw token first.

To check the signature:

1. Paste the token. jwt.io selects `alg` from the token header automatically.
2. Fetch the matching public key — either an entry from `GET /.well-known/jwks.json`, or, simpler,
   the single key `GET /.well-known/jwks.json/{kid}` whose `kid` matches the token header.
3. Paste that JWK into jwt.io's key field (it accepts a JWK or a PEM public key) and confirm the
   `kid`s match. RS256 and ES256 verify this way.

jwt.io does not support EdDSA/Ed25519 — an EdDSA token can't be signature-verified there. Use
`/.well-known/jwks.json/{kid}` plus any JWT library (e.g. `golang-jwt`) for those.

## API

### `POST /token`

Request body is JSON (empty body mints an anonymous token with defaults):

| Field     | Type             | Description                                                        |
|-----------|------------------|--------------------------------------------------------------------|
| `claims`  | object           | Arbitrary claim set; standard claims included                       |
| `alg`     | string, optional | One of `RS256`, `ES256`, `EdDSA` (must be enabled); anything else → `400` |
| `headers` | object, optional | Extra protected JOSE header parameters to embed                     |

Rules:

- `iss`, `iat`, `nbf` are injected automatically; explicit values in `claims` win
  (overriding `iss` enables negative-path issuer-mismatch tests).
- `exp`, `iat`, and `nbf` accept epoch seconds (`1800000000`, `"1800000000"`), durations
  (`"90m"`, `"in 1h"`, negative for already-expired), or RFC 3339 timestamps.
- Omitted `exp` means now + `DEFAULT_TTL`. Lifetimes beyond `MAX_TTL` are refused with `400`.
  Tokens that are *already expired* are minted happily — handy for negative tests.
- Empty body ⇒ anonymous token carrying just the injected defaults; good smoke test.

Error responses are `{"error": "<message>"}` with status `400` (bad JSON, unsupported alg,
lifetime cap exceeded), `405` (wrong method), or `503` (no active signing key).

### `POST /oauth/token`

Standards-shaped OAuth 2.0 client-credentials endpoint for generic OAuth clients. The request
body must be `application/x-www-form-urlencoded`:

```sh
curl -s http://127.0.0.1:8080/oauth/token \
  -d 'grant_type=client_credentials&client_id=test-client&scope=read write'
```

| Form field      | Required | Description                                                        |
|-----------------|----------|--------------------------------------------------------------------|
| `grant_type`    | yes      | Must be `client_credentials`; anything else is `unsupported_grant_type` |
| `client_id`     | yes*     | Client identifier used for `sub` and `client_id`; also accepted via HTTP Basic |
| `client_secret` | no       | Accepted but never validated (test issuer)                          |
| `scope`         | no       | Space-delimited scopes; whitespace is normalized and echoed back    |
| `alg`           | no       | Enabled algorithm; defaults to RS256 when enabled, else the first enabled |
| `ttl`           | no       | Non-negative Go duration such as `5m`; capped by `MAX_TTL`          |

\* The client identifier may come from HTTP Basic (`Authorization: Basic ...`) instead of the form
body. A missing identifier returns `400 invalid_request`. Secrets are ignored.

The minted token contains `iss`, `sub` and `client_id` set to the client identifier, `iat`, `nbf`,
`exp`, `jti`, a normalized `scope` when requested, and `aud` only when `AUDIENCE` is configured. It
does **not** carry the legacy `capabilities`, `idtyp`, `allowedResources`, or `version` claims.
`SCOPES` only advertises supported scopes in discovery; it does not restrict what a client may
request.

Success responses use the standard envelope and include `scope` when one was requested:

```json
{
  "access_token": "eyJhbGciOiJSUzI1NiIsImtpZCI6Ii4uLiJ9...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "scope": "read write"
}
```

Token responses send `Cache-Control: no-store` and `Pragma: no-cache`. Errors use the standard OAuth
shape `{"error": "<code>", "error_description": "<message>"}`: `400 invalid_request` or
`unsupported_grant_type`, `405` for non-POST methods, `503 temporarily_unavailable` when no signing
key is active, and `500 server_error` for internal failures. Request bodies larger than 1 MiB are
rejected with `400 invalid_request`.

### `POST /introspect`

RFC 7662 token introspection over a form body. The endpoint verifies the token against this
server's live keyring and configured issuer:

```sh
curl -s http://127.0.0.1:8080/introspect -d "token=$ACCESS_TOKEN"
```

| Form field        | Required | Description                                      |
|-------------------|----------|--------------------------------------------------|
| `token`           | yes      | JWT in JWS Compact Serialization                 |
| `token_type_hint` | no       | Accepted and ignored                            |

The endpoint uses the same permissive authentication as `/oauth/token`: it does not require a client
identifier and ignores client secrets. An active token returns `200` with every claim from the token
plus authoritative `active: true` and `token_type: "Bearer"`. Expired, not-yet-valid, wrong-issuer,
unknown-key, bad-signature, and malformed tokens return `200` with exactly `{"active": false}` and no
claim fields. A missing `token` returns `400 invalid_request`; non-POST methods return `405`, and
bodies larger than 1 MiB are rejected. Responses send `Cache-Control: no-store` and
`Pragma: no-cache`.

### `POST /verify`

Self-check a token against the running issuer's own live keyring. This is deliberately **not** a
general-purpose verifier: the request may not carry key material or key locations (`jwks`,
`jwks_url`, or `issuer` are rejected with `400`), and the endpoint never makes an outbound request.
Use it to confirm what this issuer would accept without wiring up your own verification stack.

```sh
curl -s http://127.0.0.1:8080/verify -d "{\"token\":\"$ACCESS_TOKEN\"}"
```

Request body:

| Field    | Type             | Description                                                          |
|----------|------------------|----------------------------------------------------------------------|
| `token`  | string, required | JWT in JWS Compact Serialization                                     |
| `aud`    | string or array  | Expected audience; matching any member passes                        |
| `alg`    | array, optional  | Non-empty subset of enabled algorithms to accept (default: all enabled) |
| `leeway` | string, optional | Go duration widening the `exp`/`nbf`/`iat` window, e.g. `30s`        |

Unknown fields are rejected with `400`. The response is always `200` when a verdict was reached;
inspect `valid` and `reason`:

```json
{
  "valid": false,
  "reason": "audience",
  "error": "token audience does not match",
  "header": {"alg": "RS256", "kid": "..."},
  "claims": {"iss": "http://127.0.0.1:8080", "aud": ["my-service"]},
  "kid": "...",
  "kid_status": "active",
  "alg": "RS256"
}
```

- `reason` is one of `malformed`, `alg`, `kid`, `signature`, `expired`, `not_yet_valid`,
  `issuer`, or `audience`, checked in that order. Exactly one reason is reported.
- Claims appear under `claims` only after the signature verified, under `unverified_claims`
  before it, and under neither for `malformed` input. Never trust `unverified_claims`.
- `kid_status` is `active`, `retired` (still inside its grace window), or `unknown`.
- `iss` is always checked against this server's configured issuer.
- Verification responses carry `Cache-Control: no-store`.

A `500` means verification failed outside the closed reason set; correct requests never produce it.

### `POST /v2/oauth/token`

Legacy bespoke endpoint retained for compatibility. Discovery no longer points here; it advertises
`/oauth/token` instead. Mints a v2-style token from a client ID and comma-separated capability
scope:

```sh
curl --request POST \
  --url 'http://127.0.0.1:8080/v2/oauth/token?Scope=capability1,capability2' \
  --header 'X-Client-Id: client-id' \
  --header 'X-Client-Secret: REDACTED' \
  --header 'accept: application/json'
```

The response uses the same `{access_token, token_type, expires_in}` envelope as `POST /token`.
The signed token includes `sub`, `client_id`, `aud: ["client"]`, `idtyp: "app"`, `version: "2.0"`,
the requested `capabilities`, and standard `iss`, `iat`, `nbf`, `exp`, and unique `jti` claims.
`allowedResources.allowedPartners` currently contains the example value `partner`.

Optional query extensions select the signing algorithm and lifetime:

| Query | Description                                                                 |
|-------|-----------------------------------------------------------------------------|
| `alg` | Enabled algorithm; defaults to RS256 when enabled, else the first enabled   |
| `ttl` | Non-negative Go duration such as `5m`; capped by `MAX_TTL`                  |

```sh
curl --request POST \
  --url 'http://127.0.0.1:8080/v2/oauth/token?Scope=read&alg=ES256&ttl=5m' \
  --header 'X-Client-Id: client-id'
```

Invalid, negative, disabled, or over-cap values return `400` using this endpoint's legacy
`{"error": "<message>"}` shape. The bespoke claims above are unchanged.

This is test tooling, not client authentication: `X-Client-Secret` is accepted but not validated,
requested capabilities are not checked against a registry, and partner policy is not configurable.
Do not expose this endpoint as a production OAuth service.

Example — deliberately broken token for a rejection test:

```sh
curl -s http://127.0.0.1:8080/token -d '{"claims":{"iss":"https://attacker.example","exp":"-5m"}}'
```

### `GET /.well-known/openid-configuration` and `GET /.well-known/oauth-authorization-server`

Both paths serve the same metadata document. It advertises:

- `issuer`, `jwks_uri`, `token_endpoint` (`<issuer>/oauth/token`), and `introspection_endpoint`
  (`<issuer>/introspect`), all derived from `ISSUER`
- `grant_types_supported: ["client_credentials"]`
- `token_endpoint_auth_methods_supported: ["client_secret_basic", "client_secret_post", "none"]`
- `response_types_supported: ["token"]`, `subject_types_supported: ["public"]`, and
  `id_token_signing_alg_values_supported` listing all enabled algorithms
- `claims_supported` for the generic OAuth claim profile
- `scopes_supported` only when `SCOPES` is set

The document deliberately omits `authorization_endpoint`, `code_challenge_methods_supported`, and
`userinfo_endpoint`, because this issuer does not implement those flows. `/v2/oauth/token` is not
advertised; use it directly only for the legacy claim profile.

`DISCOVERY_EXTRA_JSON` merges additional JSON-object members into both documents. The derived core
fields `issuer`, `jwks_uri`, `token_endpoint`, and `introspection_endpoint` always win over supplied
values. Invalid JSON or a non-object value fails startup.

### `GET /.well-known/jwks.json`

The live public key set: active key plus retired keys still inside their grace window,
each tagged `use=sig`, `alg` (RS256/ES256/EdDSA), and thumbprint-derived `kid`.

### `GET /.well-known/jwks.json/{kid}`

Fetch a single public key from the live key set by its thumbprint-derived `kid`. Returns just
that key's JWK — the same shape as one entry of the JWKS set — which is handy when a consumer
needs the exact key that signed a token instead of downloading the whole set. Retired keys still
inside their grace window are reachable too. An unknown or cleaned-up kid returns `404`; a missing
`kid` in the path returns `400`.

### `GET /healthz`

Liveness plus the current `active_kids` per algorithm, and an explicit reminder that this is a test issuer.

### `GET /version`

Returns the resolved build version as `{"version":"X.Y.Z"}`. The value comes from the build-time
`-X main.Version` injection, then the `VERSION` file, then Go build metadata — it never reports a
placeholder `dev` value.

## Configuration

Every setting can be passed as an environment variable or the equivalent flag (flag wins):

| Env                  | Flag                  | Default                 | Meaning                                |
|----------------------|-----------------------|-------------------------|----------------------------------------|
| `LISTEN`             | `--listen`            | `127.0.0.1:8080`        | bind address                           |
| `ISSUER`             | `--issuer`            | `http://127.0.0.1:8080` | external base URL used as `iss`        |
| `DEFAULT_TTL`        | `--default-ttl`       | `1h`                    | token lifetime when `exp` omitted      |
| `MAX_TTL`            | `--max-ttl`           | `24h`                   | lifetime cap, `0` disables             |
| `ROTATION_INTERVAL`  | `--rotation-interval` | `30m`                   | key rotation cadence, `0` disables     |
| `GRACE_PERIOD`       | `--grace-period`      | `25h`                   | retired keys stay published this long  |
| `ALGORITHMS`         | `--algorithms`        | `RS256,ES256,EdDSA`     | comma-separated algorithms to enable   |
| `RATE_LIMIT_RPS`     | `--rate-limit-rps`    | `100`                   | per-IP requests per second             |
| `RATE_LIMIT_BURST`   | `--rate-limit-burst`  | `200`                   | per-IP burst allowance                 |
| `AUDIENCE`           | `--audience`          | *(unset)*               | `aud` claim on `/oauth/token` tokens   |
| `SCOPES`             | `--scopes`            | *(unset)*               | comma-separated scopes advertised in discovery |
| `DISCOVERY_EXTRA_JSON` | `--discovery-extra-json` | *(unset)*         | JSON object merged into discovery metadata |

Durations use Go syntax: `30s`, `45m`, `12h`. Keep `GRACE_PERIOD ≥ MAX_TTL` so tokens minted
just before a rotation stay verifiable until they expire.

Per-IP rate limiting honors the first `X-Forwarded-For` entry when present, so run this behind a
proxy only if you trust that header. Non-positive rate-limit values fall back to the defaults above.

## Embedding in Go tests

`pkg/tester` starts an in-process issuer over `httptest`, registers cleanup
automatically, and returns a leak-free server handle. No binary, port
reservation, or external process is required.

```go
package auth_test

import (
	"testing"

	"github.com/larryf1/jwtoken-tester/v2/pkg/tester"
)

func TestProtectedEndpoint(t *testing.T) {
	srv := tester.NewServer(t, tester.WithAlgorithms(tester.RS256))

	token, err := srv.Mint(tester.MintRequest{
		Claims: map[string]any{
			"sub": "user-123",
			"aud": []string{"my-service"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	// Point the service under test at srv.Issuer(), and send token.AccessToken
	// as a Bearer credential exactly as you would with a real IdP. The service
	// can fetch srv.URL()+"/.well-known/jwks.json", or the test can use
	// srv.JWKSJSON(), srv.PublicKey(kid), or srv.PublicKeyPEM(kid).
}
```

Options mirror the server settings: `WithAlgorithms`, `WithIssuer`, `WithDefaultTTL`,
`WithMaxTTL`, `WithRotationInterval`, `WithGracePeriod`, `WithRateLimit`, `WithLogger`,
`WithAudience`, `WithScopes`, and `WithDiscoveryExtra`. An empty issuer selects the bound server URL.
Enabled algorithms use
`tester.RS256`, `tester.ES256`, and `tester.EdDSA`; `Mint` returns `ErrUnsupportedAlgorithm`,
`ErrTTLTooLong`, or `ErrInvalidRequest` for rejected requests.

`NewServer` is the testing wrapper: it panics if startup fails and registers
`t.Cleanup(srv.Close)`. For `TestMain`, benchmarks, or non-`testing` callers, use
`Start(opts...)` and call `Close` yourself. `Close` stops the listener, rotation, and
internal cleanup, waits for those goroutines, and is safe to call more than once.
Minting and key accessors keep working after `Close` because they use in-memory state.

The exported surface uses only standard-library and `pkg/tester` types: `Mint`,
`Keys`, `ActiveKeyID`, `PublicKey`, `PublicKeyPEM`, `JWKSJSON`, `Rotate`, `PruneAt`,
`Handler`, `URL`, `Issuer`, `Client`, and `Close`. No private key material is reachable.

## Development

```sh
make build   # compile to bin/jwtoken-tester(.exe)
make test    # go test ./...
make lint    # golangci-lint + gofmt formatting check (make fmt fixes)
make coverage-check  # enforce the 90% coverage threshold
make govulncheck     # scan dependencies for known vulnerabilities
make all     # lint, test, build in one pass
```

Tests cross-validate every minted token with `github.com/golang-jwt/jwt/v5` — an independent
library from the signer (`github.com/lestrrat-go/jwx/v4`) — proving the output is not just
self-consistent but genuinely spec-compliant.

Project layout:

```
cmd/jwtoken-tester/     main binary, flag/env configuration, CLI commands
cmd/coverage/           coverage-threshold helper used by make coverage-check
internal/keyring/       key generation, rotation, RFC 7638 kids, zeroization
internal/tokenfactory/  claim templating, TTL parsing, signing
internal/server/        HTTP handlers, JWKS, discovery document
pkg/tester/             embeddable Go test helper (httptest server)
docker/                 distroless image, compose stack, demo protected service
docs/                   OpenAPI specification
openspec/               behavior specs and archived change history
scripts/                shared version derivation
```

## Roadmap

Shipped:

- [x] Keyring + `/token` + JWKS + discovery, RS256, validated against golang-jwt
- [x] ES256 / EdDSA support alongside RS256
- [x] Embeddable Go library mode (`httptest` server helper) and CLI one-shot mode
- [x] Distroless Docker image + docker-compose example wired to a demo protected service
- [x] Public, leak-free `pkg/tester` API (neutral algorithm/request types, JWKS/PEM helpers,
      deterministic keys, and a resource-only `Close`)
- [x] Token verification and debugging: `POST /verify` self-check endpoint and `decode` /
      `verify` CLI commands
- [x] Standards-compliant `POST /oauth/token` (client credentials), RFC 7662 `POST /introspect`,
      richer shared discovery metadata, RFC 8414 metadata, and `alg`/`ttl` selection

Candidate enhancements below are **not commitments**. See [`FUTURE.md`](FUTURE.md) for effort,
value, design notes, and open questions.

- [ ] Authorization-code + PKCE flow, `id_token`/`/userinfo`, and claim/IdP profiles
- [ ] More algorithms (PS256/PS384/PS512, RS384/RS512, ES384/ES512, optional HMAC) and
      negative-token controls (`alg: none`, malformed tokens, `kid`/`typ`/`x5c` overrides)
- [ ] Claim profiles for common IdPs (Entra ID, Auth0, Keycloak, Okta, Cognito) and
      configurable default claims
- [ ] JWKS caching headers (ETag/304, `Cache-Control`) and `no-store` on token responses
- [ ] Operability: JSON logs, Prometheus metrics, `/readyz`, configurable HTTP timeouts,
      trusted-proxy handling, optional CORS, and loopback-protected admin rotation
- [ ] Developer experience: serve the OpenAPI spec, CI examples (GitHub Actions, GitLab,
      Kubernetes/Helm, Testcontainers), and `make bench`
- [ ] Supply chain: SBOMs, image signing/provenance, Scorecard/CodeQL, dependency review,
      a race-enabled CI job, and a container smoke test

Exploratory — design questions need answering first:

- [ ] Opt-in fixture keys (`keygen` + `--keys-file`, or a deterministic seed) for shared
      cross-process fixtures
- [ ] `x5c` certificate chains, JWE, DPoP, and an authorization-code + PKCE flow
- [ ] Multiple active keys per algorithm and multiple issuers