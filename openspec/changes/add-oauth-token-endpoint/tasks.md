# Tasks

## 1. Configuration surface

- [ ] 1.1 Add `AUDIENCE`, `SCOPES`, and `DISCOVERY_EXTRA_JSON` to `serveConfig`, environment reads, flags, and startup validation; verify table-driven tests in `cmd/jwtoken-tester/main_test.go` cover defaults, flag precedence, and invalid extra JSON.
- [ ] 1.2 Add `WithAudience`, `WithScopes`, and `WithDiscoveryExtra` server options and matching `pkg/tester` options; verify `go test ./internal/server ./pkg/tester` passes and a test round-trips each option, including an invalid extra-JSON startup error.
- [ ] 1.3 Document the three settings in the README configuration table and verify the table matches the env and flag names implemented in `main.go`.

## 2. Shared discovery and metadata endpoints

- [ ] 2.1 Implement one discovery document builder containing `issuer`, `jwks_uri`, `token_endpoint` of `/oauth/token`, `introspection_endpoint`, `grant_types_supported`, `token_endpoint_auth_methods_supported`, `scopes_supported` only when `SCOPES` is set, `response_types_supported`, and the generic `claims_supported`; verify tests assert the OIDC path has no `authorization_endpoint`, `code_challenge_methods_supported`, or `userinfo_endpoint`.
- [ ] 2.2 Add `GET /.well-known/oauth-authorization-server` and serve the same document as the OIDC path; verify a test compares both responses field by field.
- [ ] 2.3 Merge `DISCOVERY_EXTRA_JSON` additively while keeping `issuer`, `jwks_uri`, `token_endpoint`, and `introspection_endpoint` derived; verify tests cover an extra key, attempted core overrides, and invalid JSON failing startup.
- [ ] 2.4 Add `POST /oauth/token`, `POST /introspect`, and `GET /.well-known/oauth-authorization-server` to the service index; verify `GET /` returns all three in its `endpoints` array.
- [ ] 2.5 Update the README endpoint diagram, discovery section, and `docs/openapi.yaml` discovery paths/schemas; verify no discovery example still advertises `/v2/oauth/token` as `token_endpoint`.

## 3. OAuth token endpoint

- [ ] 3.1 Add `POST /oauth/token` with form parsing, the 1 MiB body limit, `grant_type` validation, permissive Basic/post/client-id authentication, and missing-client-id rejection; verify handler tests cover a valid request, missing grant type, unsupported grant type, non-form body, and missing client id.
- [ ] 3.2 Build the generic claim profile with `sub` and `client_id` from the client id, normalized `scope`, `jti`, and optional `aud`; verify tests cover scope normalization, omitted scope, audience set and unset, unlisted scope still accepted when `SCOPES` is set, and absence of all v2 claims.
- [ ] 3.3 Add `alg` and `ttl` selection with enabled-algorithm validation, RS256-then-first-enabled fallback, the `MAX_TTL` cap, and invalid or negative TTL rejection; verify tests cover every branch.
- [ ] 3.4 Add OAuth success and error envelopes, `scope` echo, `Cache-Control: no-store`, `Pragma: no-cache`, and the 405/500/503 mappings; verify handler tests assert each response shape and header.
- [ ] 3.5 Add audit events for successful and failed mints with algorithm, scope, and `expires_in`, excluding secrets and token values; verify a captured-log test asserts the fields.
- [ ] 3.6 Document `/oauth/token` in the README and `docs/openapi.yaml`; verify a test sends the documented form request and receives a token.

## 4. Introspection endpoint

- [ ] 4.1 Add `POST /introspect` with form parsing, the 1 MiB body limit, required `token`, ignored `token_type_hint`, permissive authentication, and no-store headers; verify handler tests cover a valid request, missing token, ignored hint, non-POST, and oversized body.
- [ ] 4.2 Reuse `verify.Verify` with this issuer's keyring and issuer, returning all claims for active tokens and authoritative `active`/`token_type`; verify tests cover active, expired, wrong issuer, unknown kid, bad signature, malformed, and retired-key-within-grace cases.
- [ ] 4.3 Ensure inactive responses contain only `active: false`; verify a test with a custom claim on an invalid token receives no claim fields.
- [ ] 4.4 Add an introspection audit event with the active verdict and internal reason, excluding the token value; verify a captured-log test asserts both the response and the log.
- [ ] 4.5 Document `/introspect` in the README and `docs/openapi.yaml`; verify a test sends the documented form request.

## 5. Legacy `/v2/oauth/token`

- [ ] 5.1 Add `alg` and `ttl` query parsing with enabled-algorithm validation, RS256-then-first-enabled fallback, the `MAX_TTL` cap, and invalid or negative rejection; verify handler tests cover every branch.
- [ ] 5.2 Preserve the bespoke claim profile and log the actual signing algorithm; verify tests assert `capabilities`, `idtyp`, `allowedResources`, and `version` remain present and the audit log reports the selected algorithm.
- [ ] 5.3 Update the README and `docs/openapi.yaml` for the query extensions and the discovery migration; verify no documentation still claims the endpoint is RS256-only.

## 6. Release documentation

- [ ] 6.1 Update `FUTURE.md` item #3 to reflect the shipped OAuth endpoint, discovery, and introspection work and the remaining deferred authorization-code/PKCE scope; verify the item no longer reads as an unimplemented candidate.
- [ ] 6.2 Add a `CHANGELOG.md` entry for the new endpoints, the discovery `token_endpoint` change, and the legacy endpoint extensions; verify the entry is under the current unreleased section.

## 7. Integration verification

- [ ] 7.1 Add an end-to-end test that reads discovery, posts `client_credentials` to the advertised `token_endpoint`, verifies the token, and introspects it; verify `go test ./...` passes.
- [ ] 7.2 Run `make lint`, `make coverage-check`, and `go test ./...`; verify all three succeed.

## Workflow follow-up

- Archive the change after the project's review requirements are satisfied.
