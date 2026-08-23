# jwtoken-tester — ephemeral JWT/JWKS test double

## Problem

Integration-testing a JWT-aware service requires a token issuer whose public keys the app can
fetch. Real IdPs bring secrets, configuration, and network dependencies. This project is a
throwaway OpenID Connect-style issuer that is standards-compliant but holds **zero persisted
secrets**: keypairs are generated in memory at startup and discarded on shutdown.

## Goals

- Fully RFC-compliant tokens and JWKS so real-world JWT middleware accepts them unchanged.
- No secrets on disk, in env vars, or in config files. Nothing survives process exit.
- Usable three ways: docker sidecar, embeddable Go library, CLI one-shot.
- Removes the need for basic-auth shortcuts in integration environments.

## Non-goals

- Not a production IdP: no user database, no consent, no refresh tokens, no TLS termination
  (put it behind the test-env proxy or use plain HTTP between containers).
- Not hardened against hostile traffic; bind loopback by default.

## Compliance targets

| RFC / spec             | What we implement                                                        |
|------------------------|--------------------------------------------------------------------------|
| RFC 7519 (JWT)         | `iss`, `sub`, `aud`, `exp`, `nbf`, `iat`, `jti` + arbitrary custom claims |
| RFC 7515 (JWS)         | Compact serialization, correct `alg`/`kid`/`typ` headers                 |
| RFC 7517 (JWK/JWKS)    | JWKS document at `/.well-known/jwks.json`                                 |
| RFC 7518 (JWA)         | RS256, ES256, EdDSA (Ed25519); `alg=none` always rejected                 |
| RFC 7638 (thumbprint)  | `kid` = SHA-256 JWK thumbprint, base64url unpadded                        |
| OIDC Discovery / RFC 8414 | `/.well-known/openid-configuration` with `issuer` + `jwks_uri`         |

The discovery document matters most in practice: Spring Security, go-jose middleware, and
jsonwebtoken-style libraries auto-configure from it, so the app under test needs zero
special-casing.

## Architecture

Single Go binary, one in-process key ring, four HTTP endpoints.

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
│   GET /.well-known/jwks.json                 │
│   GET /.well-known/openid-configuration      │
│   POST /token        ← mint arbitrary JWTs   │
│   GET /healthz                               │
└──────────────────────────────────────────────┘
```

### Key lifecycle (the "no secrets" core)

1. On boot, generate keypairs from `crypto/rand`. Private keys never touch disk, env,
   logs, or HTTP responses.
2. Rotation every N minutes (default 30): a fresh key becomes active; the previous key stays
   published in the JWKS for a grace period ≥ max token TTL so outstanding tokens keep
   validating, then it is zeroed in memory and dropped from the JWKS.
3. Tests that need long-lived stability can disable rotation (`ROTATION_INTERVAL=0`).

### Token endpoint contract

Replaces basic auth in test setups:

```http
POST /token
Content-Type: application/json

{
  "claims": {
    "sub": "user-123",
    "aud": ["my-service"],
    "roles": ["admin"],
    "exp": "in 1h"
  },
  "alg": "RS256",
  "headers": {}
}
```

```json
{
  "access_token": "eyJhbGciOiJSUzI1NiIsImtpZCI6Ii4uLiJ9...",
  "token_type": "Bearer",
  "expires_in": 3600
}
```

Rules:

- `iss`, `iat`, `nbf` are injected automatically; explicit values in `claims` win
  (overriding `iss` enables negative-path issuer-mismatch tests).
- `exp` accepts epoch seconds, RFC3339, `"90m"`, or `"in 1h"`; omitted means the server
  default TTL. Tokens already expired are minted happily for negative tests.
- Lifetimes beyond `MAX_TTL` (default 24h) are refused with HTTP 400.
- Unsupported `alg` values are refused; only algorithms enabled at the server are honored.
- Empty body mints an anonymous token with defaults — handy smoke test.

Optional escape hatch for exotic tests: `GET /keys/private?confirm=yes`, disabled by default,
enabled only with an explicit flag, for tests that want to sign locally.

## Integration patterns

1. **Docker sidecar (primary)** — compose adds `jwtoken-tester`; the app under test gets
   `ISSUER_URL=http://jwtoken-tester:8080`. Test setup calls `POST /token` and uses the
   string as `Authorization: Bearer ...`.
2. **Go library** — `pkg/tester.NewServer(t)` returns `(baseURL, TokenFactory)` on an
   `httptest` port; no container needed for Go-native suites.
3. **CLI one-shot** — `jwtoken-tester print-token --sub x --aud y` for manual curl poking.

## Tech choices

- `github.com/lestrrat-go/jwx/v4` for JOSE primitives (thumbprints, signing, JWKS).
- Standard library `net/http` (Go 1.22+ method routing); no web framework.
- `github.com/golang-jwt/jwt/v5` as an independent validator in tests (cross-library proof).
- Distroless static Docker image, non-root, single exposed port.

## Safety rails (test-only tool)

- Startup banner and `/healthz` field: `THIS IS A TEST ISSUER — DO NOT USE IN PRODUCTION`.
- Binds `127.0.0.1` by default; non-loopback bind logs a loud warning.
- Refuses token lifetimes over `MAX_TTL` unless the cap is explicitly raised.

## Configuration (env or equivalent flag)

| Env                  | Flag                | Default               | Meaning                          |
|----------------------|---------------------|-----------------------|----------------------------------|
| `LISTEN`             | `--listen`          | `127.0.0.1:8080`      | bind address                     |
| `ISSUER`             | `--issuer`          | `http://127.0.0.1:8080` | external base URL / `iss`      |
| `DEFAULT_TTL`        | `--default-ttl`     | `1h`                  | lifetime when `exp` omitted      |
| `MAX_TTL`            | `--max-ttl`         | `24h`                 | lifetime cap (0 = uncapped)      |
| `ROTATION_INTERVAL`  | `--rotation-interval` | `30m`               | key rotation cadence (0 = off)   |
| `GRACE_PERIOD`       | `--grace-period`    | `25h`                 | retired keys stay published this long |

## Project layout

```
cmd/jwtoken-tester/     main, flags/env config
internal/keyring/       generation, rotation, RFC 7638 kids, zeroization
internal/tokenfactory/  claim templating, TTL parsing, signing
internal/server/        handlers, discovery docs
pkg/tester/             embeddable library API
docker/Dockerfile       distroless build
```

## Milestones

- [ ] **M1** — Keyring + `/token` + JWKS endpoint, RS256 only, validated against
      golang-jwt in tests ← *current*
- [ ] **M2** — Discovery doc hardening, ES256/EdDSA, rotation with grace window
- [ ] **M3** — Library mode (`pkg/tester`) + CLI mode
- [ ] **M4** — Docker image + docker-compose example wired to a demo protected service
