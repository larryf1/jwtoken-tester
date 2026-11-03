# Proposal

## Why

The issuer can mint tokens but cannot tell anyone why a consumer rejected one. When a token fails, the user has to decode it elsewhere and compare `kid`, `alg`, `iss`, `aud`, and timestamps against the JWKS by hand. The tool has an authoritative answer available in memory — the live keyring — and never uses it, so "the token is bad" is indistinguishable from "the consumer is misconfigured."

This is the highest-value gap after the v2.4.0 public API work: it turns jwtoken-tester from a token source into a debugging aid without expanding the issuer's scope.

## What Changes

- Add `POST /verify`: a self-check JSON endpoint that verifies a token against the issuer's live keyring and returns a machine-readable verdict — `valid`, a closed failure `reason`, the parsed `header`, authenticated `claims` or clearly labeled `unverified_claims`, and an advisory `kid_status` of `active`, `retired`, or `unknown`.
- Make `/verify` self-check only: `iss` always validates against the configured issuer, the accepted `alg` set defaults to the enabled algorithms, and optional `aud`/`leeway` simulate consumer expectations. The endpoint accepts **no caller-supplied key material and no key location** — not an inline JWKS, not a JWKS URL, not an issuer URL. It never makes an outbound network request.
- Add `jwtoken-tester decode <token>`: decode header and claims with no keys, no network, and no trust — works on any structurally valid JWT, including expired and foreign tokens.
- Add `jwtoken-tester verify`: verify a token against any issuer's keys by fetching a JWKS (`--jwks <url|file>`) or discovery document (`--issuer <url>`), with optional `--aud`, `--alg`, `--leeway`, stdin input, `--json` output, and distinct exit codes for invalid (`1`) versus operational failure (`2`).
- Add a key-status lookup to the keyring so verdicts can report whether a `kid` is active, retired but still published, or unknown/pruned.
- Apply non-cacheable responses and audit logging to verification: record the outcome, reason, `kid`, and `alg`, never the token or its claims.
- List `/verify` in the service index document, and update the OpenAPI spec, README, and FUTURE.md to reflect shipped behavior.
- Fix existing spec drift: the `cli` capability does not document the shipped `healthcheck` command.

**Non-goals.** No RFC 7662 `/introspect` (deferred to the standards-compliant OAuth/discovery work), no caller-supplied keys over HTTP, no `pkg/tester.Verify`, no time-travel (`now`) override, no PEM key input, and no fuzz target. The CLI is the only surface that accepts foreign key material.

## Capabilities

### New Capabilities

- `token-verification`: the verification contract and failure taxonomy — what a verdict contains, the closed reason set and its deterministic precedence, the claims-versus-unverified-claims trust split, key-status reporting, and the self-check-only invariant for the HTTP endpoint.

### Modified Capabilities

- `cli`: command dispatch gains `decode` and `verify`; the spec also gains the already-shipped `healthcheck` command and defines exit-code and input behavior for the new commands.
- `http-api/service-metadata`: the service index `endpoints` list advertises `POST /verify`.

## Impact

- New package `internal/verify` (policy-free classifier), new `/verify` handler in `internal/server`, key-status surface in `internal/keyring`, command wiring in `cmd/jwtoken-tester`.
- `golang-jwt/jwt/v5` moves from test-only use into the verification path; it is already a direct module dependency, so no new module is added. `jwx` remains the signer and JWKS encoder.
- `docs/openapi.yaml`, `README.md`, `FUTURE.md`, and the capability specs listed above.
- No breaking API changes. Existing endpoints, configuration, and `pkg/tester` behavior are unchanged.
- Deferred work that this change unblocks or touches: introspection and `introspection_endpoint` for the OAuth/discovery item; negative-token minting, which uses `/verify` as its oracle; fuzz testing, which FUTURE.md flags for revisit once the tool gains a parser.
