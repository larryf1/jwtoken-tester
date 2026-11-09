# Future Work / Candidate Enhancements

This document tracks intentionally deferred work and candidate enhancements that
could make jwtoken-tester more useful. It is **not** a roadmap or a commitment:
items are prompts for design discussion. Shipped behavior belongs in
[`README.md`](README.md) and [`CHANGELOG.md`](CHANGELOG.md).

Effort is approximate: **S** = hours to a day, **M** = a few days, **L** = a week
or more. Value is judged against the project's test-tooling use case, not against
production IdP requirements.

## Guardrails

Every candidate should preserve the project's core promise:

- **Ephemeral by default** — signing keys are generated in memory and never
  persisted, logged, or returned over HTTP.
- **Test-only scope** — no users, consent, refresh-token lifecycle, or claims of
  production readiness.
- **Self-contained** — no external IdP, database, or network dependency.
- **Small surface** — three direct Go dependencies and a Go-only toolchain; new
  dependencies need a clear payoff.
- **Predictable configuration** — every setting has an env var and flag; flags
  win; defaults stay safe.

Ideas that conflict with these guardrails (private-key import/export, HMAC secret
exposure, native TLS) are explicitly opt-in and must be labeled loudly.

## Priority snapshot

| # | Candidate | Effort | Value | Why it matters |
|---|-----------|--------|-------|----------------|
| 1 | Public `pkg/tester` API + leak-free lifecycle | — | Shipped | Delivered in v2.4.0 with a neutral surface and resource-only `Close`. |
| 2 | Verification and `decode`/`verify` CLI | — | Shipped | `POST /verify` and both CLI commands shipped; introspection shipped with #3. |
| 3 | Standards-compliant OAuth token endpoint + richer discovery | — | Shipped | Delivered in the unreleased release; authorization-code/PKCE remains deferred to #12. |
| 4 | More algorithms + negative-token controls | M | High | Broadens consumer compatibility and negative-path coverage. |
| 5 | Claim/IdP profiles + `id_token`/`/userinfo` | M | High | Makes tokens resemble real gateways instead of hand-built maps. |
| 6 | JWKS caching headers | S | Medium | Cuts polling and enables realistic cache/rotation tests. |
| 7 | Operability: logs, metrics, readiness, timeouts | S–M | Medium | Better CI/container behavior and incident debugging. |
| 8 | Developer experience: served OpenAPI, CI examples, Helm/Testcontainers | S–M | Medium–High | Lowers adoption cost. |
| 9 | Startup/config validation | S | Medium | Fewer confusing misconfigurations. |
| 10 | Supply chain: SBOM, signing, provenance, race job | S–M | Medium | Keeps release trust aligned with the existing SHA-pinning discipline. |
| 11 | Importable or reproducible fixture keys | M | Medium | Shared fixtures and cross-process tests need stable keys. |
| 12 | x5c / JWE / DPoP / authorization-code flow | M–L | Low–Medium | Niche, but occasionally blocking for specific consumers. |

---

## 1. Public, leak-free `pkg/tester` API

- **Status:** ✅ Shipped in v2.4.0
- **Effort:** Small–Medium
- **Value:** High

**Delivered.** `pkg/tester` now exposes only standard-library and `pkg/tester` types:
`Algorithm` constants, `MintRequest`, `Token`, `KeyInfo`, public error sentinels,
`Start`/`NewServer`, `Mint`, `Keys`, `ActiveKeyID`, `PublicKey`, `PublicKeyPEM`,
`JWKSJSON`, `Rotate`, `PruneAt`, `Handler`, `URL`, `Issuer`, `Client`, `Close`, and
`WithLogger`. `TokenFactory()` and `KeyRing()` are gone, so no private key material
or internal package is reachable.

`NewServer` returns only `*Server`; `URL()` replaces the old second return value.
Startup binds the listener before deriving the issuer, so nothing is mutated after
serving begins. `Close` stops the listener, cancels rotation, stops internal cleanup,
waits for those goroutines, and is idempotent. Keys are sorted by `kid`, and retired
keys stay listed until `PruneAt` removes them.

The original problem statement is retained below for historical context.

**Problem.** The embeddable mode is advertised as complete, but its public surface
leaks internal packages. `Server.TokenFactory()` returns
`*tokenfactory.Factory` and `Server.KeyRing()` returns `*keyring.KeyRing`, both
from `internal/`. Another module can call methods on those values, but cannot
construct a `tokenfactory.Request` to pass to `Mint`. That leaves the raw HTTP
endpoint as the only practical API.

`NewServer` also has lifecycle rough edges:

- `server.New` starts a visitor-cleanup goroutine that `Server.Close()` never
  stops; `t.Cleanup(ts.Close)` does not cancel it.
- Rotation is stopped by the test cleanup context, not by an explicit `Close()`.
- The factory is replaced on the running server after `httptest.NewServer`
  starts, so an early request can observe the placeholder issuer.

**Proposal.**

- Add public request/option types in `pkg/tester`, for example
  `tester.MintRequest{Claims, Alg, Headers}` and `tester.Algorithm` constants,
  plus `Server.Mint(...) (*tester.Token, error)`.
- Add helpers for common external use cases: `JWKS()`, `PublicKey(kid)`, PEM
  export, `Handler()`, and a documented `NewServer` example.
- Make `Server` own a context: `Close()` cancels rotation and the cleanup
  goroutine, and is safe to call more than once. Keep `t.Cleanup` automatic.
- Build the final server and factory once the listener URL is known, or hold the
  factory behind an atomic pointer.
- Add `ExampleNewServer` so pkg.go.dev renders a working snippet.

**Open questions.** Should `TokenFactory()`/`KeyRing()` remain as escape hatches
for internal tests, or be replaced by stable public wrappers? Does `pkg/tester`
get the same semantic-versioning guarantee as the binary?

## 2. Verification and debugging CLI

- **Status:** ✅ Shipped (verification and CLI); introspection deferred to #3
- **Effort:** Medium
- **Value:** High

**Delivered.** `POST /verify` self-checks a token against the running issuer's live
keyring and returns `valid`, a closed `reason` (`malformed`, `alg`, `kid`,
`signature`, `expired`, `not_yet_valid`, `issuer`, `audience`), the parsed header,
claims labeled as `claims` or `unverified_claims`, and `kid_status`. It accepts no
caller-supplied keys or key locations and never makes an outbound request.
`jwtoken-tester decode` prints a token without keys or trust, and
`jwtoken-tester verify --jwks|--issuer` checks any issuer's token with `--aud`,
repeatable `--alg`, `--leeway`, stdin, `--json`, and exit codes `0`/`1`/`2`. The
README documents the API and CLI contracts.

**Remaining.** None; RFC 7662 `POST /introspect` shipped with the OAuth/discovery work in #3.

## 3. Standards-compliant OAuth token endpoint and discovery

- **Status:** ✅ Shipped (client credentials and introspection); authorization-code/PKCE deferred
- **Effort:** Medium
- **Value:** High

**Delivered.** `POST /oauth/token` implements RFC 6749 client credentials over a
form body with permissive authentication (HTTP Basic, `client_secret_post`, or
`client_id` alone), a generic claim profile, optional `aud`, and `alg`/`ttl`
selection. `POST /introspect` implements RFC 7662 introspection against this
issuer's live keyring, echoing claims for active tokens and returning only
`active: false` otherwise. Discovery now advertises `/oauth/token` and
`/introspect`, adds `grant_types_supported`,
`token_endpoint_auth_methods_supported`, `claims_supported`, and optional
`scopes_supported`, and is served at both
`/.well-known/openid-configuration` and
`/.well-known/oauth-authorization-server` (RFC 8414). `DISCOVERY_EXTRA_JSON`
merges additional metadata without overriding the derived core endpoints, and
the legacy `/v2/oauth/token` endpoint now honors `alg` and `ttl` while retaining
its bespoke claims. The README and `docs/openapi.yaml` document the new
contracts.

**Remaining.** A real `/authorize` endpoint with authorization-code + PKCE and
automatic consent is still deferred to #12; this issuer intentionally has no
users, sessions, or consent UI. Client secrets remain ignored by design so the
tool stays useful for negative authentication tests.

**Historical problem.** Discovery previously advertised `/v2/oauth/token`, a
bespoke endpoint that required `X-Client-Id` and a `Scope` query parameter.
Generic OAuth clients POST form-encoded `grant_type=client_credentials` to
`token_endpoint` and failed. The shipped `/oauth/token` endpoint resolves that
gap while the legacy route remains available for its v2 claim profile.


## 4. More algorithms and negative-token controls

- **Status:** Shipped
- **Effort:** Medium
- **Value:** High

Delivered in this change: expanded asymmetric algorithms, configurable RSA size,
opt-in negative controls, explicit HS256 support for one-shot and embedded token
minting, and matching HTTP, CLI, embedding, and OpenAPI behavior.

The proposal below records the original rationale.

**Problem.** RS256, ES256, and EdDSA cover common cases but not PS256/PS384/PS512,
RS384/RS512, ES384/ES512, or HS256. There is also no supported way to generate
unsigned, malformed, or wrong-`kid` tokens for rejection tests.

**Proposal.**

- Add PS256/PS384/PS512, RS384/RS512, and ES384/ES512 alongside the existing
  algorithms. Make RSA size and EC curve configurable for tests that reject weak
  keys.
- Add an explicit `alg: "none"` mode and a deliberately invalid token mode
  (`corrupt: signature|payload|header`, truncated segments, duplicate claims)
  behind an opt-in flag or request field.
- Allow `kid` override / forced signing-key selection, `typ` (`JWT`, `at+jwt`),
  `cty`, and optional `x5c`/`x5u`/`jku` headers for middleware that inspects
  them.
- Decide HMAC handling. HS256 is useful, but a published shared secret is a
  different trust model. Options: accept `HMAC_SECRET` from env for
  `print-token` and embedded mode only; or expose an opt-in secret endpoint only
  when bound to loopback with `--expose-secrets`.

**Open questions.** Is an explicitly broken-token endpoint too easy to misuse?
Would a separate `jwtoken-tester invalid-token` command be safer than an HTTP
route? Which algorithms do users actually need most?

## 5. Claim and IdP profiles, `id_token`, and `/userinfo`

- **Status:** Candidate
- **Effort:** Medium
- **Value:** High

**Problem.** Every non-trivial gateway expects a particular claim shape. Users
currently hand-build maps for Entra ID (`scp`, `roles`, `oid`, `tid`, `azp`,
`ver`, `idtyp`), Auth0 (`permissions`, `scope`, `azp`), Keycloak
(`realm_access.roles`, `resource_access`), Okta (`scp`, `groups`), and Cognito
(`cognito:groups`, `token_use`, `username`). The existing `/v2/oauth/token`
endpoint is one hard-coded profile.

**Proposal.**

- Add `profile` to `POST /token` and the CLI: `entra-id`, `auth0`, `keycloak`,
  `okta`, `cognito`, and `generic-oauth2`. Ship presets as embedded data
  (JSON/YAML) so they are auditable and easy to extend.
- Add `DEFAULT_CLAIMS` / `CLAIMS_FILE` for claims that should appear on every
  token, plus `jti` by default with an opt-out, and optional `sid`, `nonce`, and
  `azp`.
- Add `id_token` issuance and `GET /userinfo` when `openid` is requested. Keep
  the docs explicit that there are no real users or sessions.
- Allow per-request `ttl`/`expires_in` and a choice between `aud` as a string or
  an array.

**Open questions.** Which profiles matter most? Should profile output be
versioned to avoid accidental overlap? How much OIDC (`id_token`/`userinfo`)
belongs in a JWT-focused test issuer?

## 6. JWKS caching headers

- **Status:** Candidate
- **Effort:** Small
- **Value:** Medium

The JWKS is currently served without cache metadata, so every consumer polls the
full set and rotation tests cannot exercise cache expiry or conditional
requests.

**Proposal.**

- Add a stable `ETag` derived from the sorted key IDs and `Last-Modified` from
  the newest key timestamp; honor `If-None-Match` with `304 Not Modified`.
- Serve `Cache-Control: public, max-age=...` for the JWKS, with a configurable
  max age, and `Cache-Control: public, max-age=31536000, immutable` for
  `/.well-known/jwks.json/{kid}` (keys are content-addressed by thumbprint).
- Add `Cache-Control: no-store` and `Pragma: no-cache` to the remaining token
  responses (RFC 6749 §5.1). `/oauth/token` and `/introspect` already send both;
  `/token` and `/v2/oauth/token` do not yet.
- Provide a no-cache mode for rotation tests, so consumers re-fetch immediately
  instead of serving a stale set.

## 7. Operability: logs, metrics, readiness, and timeouts

- **Status:** Candidate
- **Effort:** Small–Medium
- **Value:** Medium

- **Logs:** add `LOG_FORMAT=json|text` and `LOG_LEVEL`. The audit events already
  carry request IDs and client IPs; JSON output makes them usable in CI log
  aggregation.
- **Metrics:** add `/metrics` with `token_minted_total{alg}`, `token_mint_failed_total{reason}`,
  `rate_limit_exceeded_total`, `active_keys{alg}`, key age, and request
  duration. Prefer a small hand-rolled exposition or make
  `prometheus/client_golang` an explicit dependency decision.
- **Readiness:** add `/readyz` that verifies every enabled algorithm has an
  active signer and the keyring can serve the JWKS. Keep `/healthz` as
  liveness.
- **Timeouts:** expose `READ_TIMEOUT`, `WRITE_TIMEOUT`, `IDLE_TIMEOUT`, and
  `SHUTDOWN_TIMEOUT`; today only `ReadHeaderTimeout` is set and shutdown is
  hard-coded to five seconds.
- **Proxy handling:** do not trust `X-Forwarded-For` by default, or gate it behind
  `TRUSTED_PROXIES`. Today any client can choose its rate-limit bucket and grow
  the visitor map by spoofing the header.
- **Rate-limit responses:** include `Retry-After` and `X-Request-ID` on `429`;
  the outer rate-limit middleware currently bypasses the request-ID middleware.
- **CORS:** optional allowlist for browser-based tests that fetch the JWKS or
  discovery document cross-origin.
- **TLS:** optional native self-signed TLS (`TLS_CERT`/`TLS_KEY` or generated)
  for clients that insist on HTTPS. Keep reverse-proxy termination as the
  documented default.
- **Admin API:** add loopback/token-protected `POST /admin/rotate`,
  `POST /admin/prune`, and `GET /admin/keys` so integration tests can force key
  lifecycle events over HTTP. The embedded API already exposes rotation, so
  this mainly helps black-box suites.
- **Config dump:** add a redacted `GET /admin/config` to confirm the resolved
  settings inside a container.

## 8. Developer experience and distribution

- **Status:** Candidate
- **Effort:** Small–Medium
- **Value:** Medium–High

- **Serve the OpenAPI spec.** Embed `docs/openapi.yaml` with `//go:embed` and
  serve it at `GET /openapi.yaml`, optionally with a self-contained `/docs`
  page. Add a CI check that validates the spec and catches endpoint drift
  (contract tests against the handlers or a Go-based validator such as
  `kin-openapi`; keep the Node-free toolchain rule).
- **CI examples.** Publish copy-paste examples for GitHub Actions service
  containers, GitLab CI services, Kubernetes manifests/Helm, and
  Testcontainers. A Testcontainers module can live in its own module to avoid
  adding a dependency to the main binary.
- **CLI ergonomics.** Add `print-token --json` (full envelope) and
  `--claims-file`/stdin input; add `decode` and `verify` (see #2).
- **Benchmarks and integration checks.** Add `make bench` and a `make integration`
  target that boots the compose stack and verifies a token end to end. A small
  load-test script (vegeta/k6) would exercise rate limits and rotation under
  load.
- **Recipes.** Document Spring Security, go-jose/golang-jwt, Express, and
  FastAPI consumer setups. Keep examples documentation-only so the repository
  stays Node-toolchain-free.

## 9. Startup and configuration validation

- **Status:** Candidate
- **Effort:** Small
- **Value:** Medium

- Accept algorithm names case-insensitively and reject unknown entries with a
  clear error. Today `ALGORITHMS=FOO` produces the confusing message "at least
  one algorithm must be enabled".
- Derive a default `ISSUER` from `LISTEN` when the issuer is not set, and
  normalize trailing slashes consistently.
- Warn when `MAX_TTL > GRACE_PERIOD` (tokens can outlive their signing key),
  when `DEFAULT_TTL > MAX_TTL`, or when rotation is much faster than the grace
  period. Keep warnings rather than hard failures so existing deployments do
  not break.
- Warn when an env duration or number fails to parse instead of silently falling
  back to the default; preserve the documented fallback behavior.
- Define and document `RATE_LIMIT_RPS=0` (disable the limiter or keep the
  default) instead of silently treating non-positive values as "use 100".
- Log the fully resolved configuration at startup, excluding secrets and key
  material.

## 10. Supply chain and release hardening

- **Status:** Candidate
- **Effort:** Small–Medium
- **Value:** Medium

The repository already SHA-pins GitHub Actions and runs `govulncheck`. The next
layer of release trust would be:

- **SBOMs.** Add GoReleaser's `sboms:` section (Syft-based, SPDX or CycloneDX)
  and attach the result to the release. See the SBOM notes below.
- **Image signing and provenance.** Sign the image and checksums with Cosign
  keyless signing, and publish SLSA provenance. Document the verification
  commands.
- **Continuous scanning.** Add OpenSSF Scorecard, CodeQL or `gosec`, and
  `dependency-review-action` on pull requests.
- **Race-enabled CI.** Run at least one `go test -race ./...` job. The server
  uses shared maps, background goroutines, and an `httptest` lifecycle, so the
  race detector is directly relevant.
- **Container smoke test.** CI currently does not build the image; add a job that
  builds it and hits `/healthz`, `/version`, and `/token`.
- **Reproducibility.** Pin the Docker base images by digest and verify
  `go mod verify` in CI.

## 11. Importable or reproducible fixture keys

- **Status:** Deferred / conditional
- **Effort:** Medium
- **Value:** Medium

Ephemeral keys are the core promise, but some test suites need the same key
across processes or restarts (shared token fixtures, multi-process integration
tests, or a consumer that caches the JWKS for longer than one test run).

**Proposal.**

- Add `jwtoken-tester keygen --out keys.jwks --alg RS256` and a
  `serve --keys-file` / `print-token --keys-file` option that imports a private
  JWKS or PEM. Never log key material; warn if the file permissions are loose.
- Alternatively, add an explicit `--seed` mode that derives keys
  deterministically for a test run. This is easier to share but weaker than a
  real fixture file.
- Keep the default path ephemeral and keep the "no persisted secrets" warning in
  startup logs when key import is enabled.

**Open questions.** Does opt-in import undermine the project's promise, or is it
acceptable if it is never the default and is clearly labeled? Should key
generation live in a separate command rather than `serve`?

## 12. Advanced token formats and flows

- **Status:** Deferred / exploratory
- **Effort:** Medium–Large
- **Value:** Low–Medium

- **x5c / X.509 chains.** Generate a self-signed certificate and publish `x5c`
  in the JWKS and token headers for middleware that only accepts certificate
  chains.
- **JWE.** Encrypt tokens (or issue encrypted ID tokens) for consumers that test
  encrypted-token handling. This adds a key-management axis and a larger test
  matrix.
- **DPoP.** Generate DPoP proofs and `cnf.jkt` claims, and optionally verify
  proofs, for APIs that are moving to sender-constrained tokens.
- **Authorization-code + PKCE.** A stateless `/authorize` that immediately
  redirects with a code and an auto-consent screen would unlock frontend OIDC
  tests. This expands the scope beyond "no users/consent" and should be a
  deliberate decision.
- **Multiple issuers.** Serve more than one issuer from a single process. Not
  needed for the current scope; keep it out unless a concrete use case appears.

---

## ⏸️ Fuzz Testing

- **Status:** ⏸️ Deferred
**Priority:** Low  
**Reason:** Low ROI for an ephemeral test tool; the attack surface is small and
well covered by unit tests.

**When to revisit:**

- If the tool gains more parsers or input formats (claim profiles, key import,
  JWE).
- If a vulnerability class is discovered in similar JWT libraries.
- As a learning exercise for the team.

**Implementation (native Go fuzzing):**

Prefer Go's built-in fuzzing over the legacy `go-fuzz` tooling:

```go
func FuzzParseTimeValue(f *testing.F) {
    f.Add("90m")
    f.Add("in 1h")
    f.Add("1800000000")
    f.Fuzz(func(t *testing.T, value string) {
        _, _ = ParseTimeValue(value, time.Now())
    })
}
```

Targets:

- `internal/tokenfactory`: `ParseTimeValue` (duration, RFC 3339, epoch parsing).
- `internal/server`: JSON body decoding, claim validation, header handling.
- `internal/keyring`: JWK import/export (though `jwx` handles most parsing).

Run with `go test ./internal/tokenfactory -fuzz=FuzzParseTimeValue -fuzztime=30s`.

---

## 📦 SBOM Generation

- **Status:** ⏸️ Deferred
**Priority:** Low  
**Reason:** Supply-chain transparency is valuable but not critical for a
test-only tool with three direct dependencies.

**When to revisit:**

- If compliance requirements mandate SBOMs.
- If the dependency graph grows significantly.
- When image signing/provenance is added (see #10).

**Implementation (when needed):**

GoReleaser v2 already supports SBOM generation through Syft, so the release
pipeline can emit one without a separate action:

```yaml
# .goreleaser.yaml
sboms:
  - artifacts: archive
    documents:
      - "{{ .ProjectName }}_{{ .Version }}_{{ .Os }}_{{ .Arch }}.sbom.spdx.json"
```

Alternatively, use `syft` + `cosign` for signed attestations:

```bash
syft packages dir:. -o spdx-json=sbom.spdx.json
cosign attest --predicate sbom.spdx.json --type spdxjson ghcr.io/larryf1/jwtoken-tester:v1.2.3
```

---

## 📝 OpenAPI Spec Versioning

- **Status:** ✅ Version automated; content hand-maintained
**Mechanism:** Semrel's `@semrel/updater-replace` updates the `info.version`
field in `docs/openapi.yaml` on release, using the same version as `VERSION`,
the binary, and the Docker image. The old `make docs-openapi` target is
deprecated and is now a no-op.

**Limitation:** The spec is not served by the binary, is not validated in CI, and
can drift from the handlers. Historically the README omitted endpoints that the
spec already documented (for example `/version`). Candidate work in #8 covers
serving it, validating it, and adding contract checks.

**Version scheme:**

- Release tag `vX.Y.Z` → version `X.Y.Z`
- Dev build → `X.Y.Z-<n>-<short-sha>` (e.g., `1.1.0-1-81a0fb8`)
- No tags → `0.0.0-<n>-<short-sha>`

---

## 📋 Remaining Backlog

Smaller ideas that are not detailed above:

| Item | Effort | Value | Notes |
|------|--------|-------|-------|
| Load-test script (vegeta/k6) | Low | Medium | Exercise rate limits and rotation under load |
| Devcontainer / Codespaces config | Low | Low | Faster onboarding |
| Framework-specific recipes | Low | Medium | Spring, Express, FastAPI, go-jose; docs-only to keep the Node-free rule |
| Optional pprof/expvar endpoint | Low | Low | Loopback-only debug aid for performance investigations |
| Multiple active keys per algorithm | Medium | Medium | Overlapping rollover without treating the old key as retired |
| Weak-key / small-RSA test mode | Low | Medium | Negative tests for consumers that enforce key strength |
| `HEAD` support on metadata endpoints | Low | Low | Cheap health/cache probes |
| Configurable `aud`/`scope` claim shapes | Low | Medium | Complements the profile work in #5 |

---

## Decision Log

| Date | Decision | Rationale |
|------|----------|-----------|
| 2026-09-12 | Deferred fuzz testing | 3 direct deps, well covered by unit tests, test-tool threat model |
| 2026-09-12 | Deferred SBOM | Minimal deps, test-only tool, can add when compliance requires |
| 2026-09-12 | Automated OpenAPI versioning | `make docs-openapi` used the same git-describe scheme as binary/Docker (superseded 2026-11-01) |
| 2026-11-01 | OpenAPI versioning moved to Semrel | Release automation owns `VERSION` and `docs/openapi.yaml`; the Make target is deprecated |
| 2026-11-01 | Prioritized library ergonomics and debugging first | The embeddable API leaks internal types and `/token` has no verification counterpart; fix those before adding more IdP features |
| 2026-11-01 | Private-key import/export remains opt-in and off by default | Preserves the ephemeral-by-default promise while allowing explicit fixture workflows |
| 2026-11-02 | Shipped `/verify` and the `decode`/`verify` CLI | Verification is in the product; introspection moved to the OAuth/discovery item so its endpoint can be standards-compliant |
| 2026-11-02 | Shipped OAuth client-credentials, RFC 7662 introspection, and shared RFC 8414 discovery | Generic OAuth clients can now use the advertised endpoint; authorization-code/PKCE remains deferred because it needs users/consent |
