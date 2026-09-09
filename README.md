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

> **Test tooling only.** Not a production IdP: no users, no consent, no refresh tokens, no TLS.
> Binds to loopback by default and warns loudly if bound elsewhere.

## How it works

```
┌──────────────────────────────────────────────┐
│                jwtoken-tester                │
│                                              │
│  In-memory KeyRing                           │
│   ├─ active key(s): RSA2048 / P-256 / Ed25519│
│   ├─ retiring keys (grace window)            │
│   └─ rotation goroutine                      │
│                                              │
│  HTTP API                                    │
│   GET  /                                     │
│   GET  /healthz                              │
│   GET  /.well-known/jwks.json                │
│   GET  /.well-known/jwks.json/{kid}          │
│   GET  /.well-known/openid-configuration     │
│   POST /token        ← mint arbitrary JWTs   │
└──────────────────────────────────────────────┘
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
go install github.com/larryf1/jwtoken-tester/cmd/jwtoken-tester@latest
```

A released Docker image is also published:

```sh
docker pull gcr.io/larryf1/jwtoken-tester:latest
docker run --rm -p 8080:8080 gcr.io/larryf1/jwtoken-tester
```

## Quick start

Requires Go 1.27+.

```sh
go run ./cmd/jwtoken-tester
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

Example — deliberately broken token for a rejection test:

```sh
curl -s http://127.0.0.1:8080/token -d '{"claims":{"iss":"https://attacker.example","exp":"-5m"}}'
```

### `GET /.well-known/openid-configuration`

OIDC-style discovery document advertising `issuer`, `jwks_uri`, `token_endpoint`, and
`id_token_signing_alg_values_supported` listing all enabled algorithms.

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

Durations use Go syntax: `30s`, `45m`, `12h`. Keep `GRACE_PERIOD ≥ MAX_TTL` so tokens minted
just before a rotation stay verifiable until they expire.

## Development

```sh
make build   # compile to bin/jwtoken-tester(.exe)
make test    # go test ./...
make lint    # go vet + gofmt formatting check (make fmt fixes)
make all     # lint, test, build in one pass
```

Tests cross-validate every minted token with `github.com/golang-jwt/jwt/v5` — an independent
library from the signer (`github.com/lestrrat-go/jwx/v4`) — proving the output is not just
self-consistent but genuinely spec-compliant.

Project layout:

```
cmd/jwtoken-tester/     main binary, flag/env configuration
internal/keyring/       key generation, rotation, RFC 7638 kids, zeroization
internal/tokenfactory/  claim templating, TTL parsing, signing
internal/server/        HTTP handlers, JWKS, discovery document
```

## Roadmap

- [x] Keyring + `/token` + JWKS + discovery, RS256, validated against golang-jwt
- [x] ES256 / EdDSA support alongside RS256
- [x] Embeddable Go library mode (`httptest` server helper) and CLI one-shot mode
- [x] Distroless Docker image + docker-compose example wired to a demo protected service