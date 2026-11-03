# Tasks

## 1. Keyring key-status surface

- [x] 1.1 Add `KeyStatus` (`active`/`retired`) and `Lookup(kid) (crypto.PublicKey, KeyStatus, error)` to `internal/keyring` and add the method to the `Ring` interface; verify with unit tests for an active kid, a retired kid inside grace, and an unknown kid returning `ErrKeyNotFound`
- [x] 1.2 Confirm `Lookup` reads the same snapshot and lock as `JWKS`/`Snapshot`; verify with `go test ./internal/keyring` and a rotation test under `-race`

## 2. Verification classifier

- [x] 2.1 Create `internal/verify` with the `Input`, `KeySource`, and `Verdict` types plus the closed reason constants; verify `go build ./...` succeeds with the new package
- [x] 2.2 Implement the unverified diagnostic pass and the explicit algorithm and key checks; verify table tests report `malformed`, `alg`, and `kid`
- [x] 2.3 Implement the verified pass with valid-method, issuer, audience, leeway, and issued-at options, and map library sentinels to reasons; verify tests cover `signature`, `expired`, `not_yet_valid`, `issuer`, and `audience`
- [x] 2.4 Implement claims labeling and numeric-date echoing; verify tests assert `claims` only after signature verification, `unverified_claims` otherwise, and neither for malformed input
- [x] 2.5 Implement `kid_status` from `KeySource.Lookup`; verify active, retired, and unknown cases, including a valid verdict for a retired key
- [x] 2.6 Verify deterministic precedence with the injected `Now`: expired plus unknown kid yields `kid`, expired plus bad signature yields `signature`, and audience plus expired yields `expired`
- [x] 2.7 Add the `jwx` parity matrix over RS256, ES256, and EdDSA; verify both libraries accept freshly minted tokens and reject tampered, expired, and wrong-issuer tokens
- [x] 2.8 Add hand-built `alg: none` and `HS256` header tokens over real payloads; verify the verdict reason is `alg`

## 3. POST /verify endpoint

- [x] 3.1 Register `POST /verify`, decode with `DisallowUnknownFields`, enforce the 1 MiB limit, accept `aud` as a string or array, and validate `alg` and `leeway`; verify handler tests for `200`, `400`, and `405`
- [x] 3.2 Verify a request carrying `jwks`, `jwks_url`, or `issuer` is rejected with `400` and that the handler constructs no outbound client
- [x] 3.3 Map unclassifiable failures to `500`, set `Cache-Control: no-store`, and emit the `token_verified` audit event; verify tests assert the header, status, and that the token and claim values never appear in logs
- [x] 3.4 Add `POST /verify` to the index endpoint list and document the endpoint and verdict schemas in `docs/openapi.yaml`; verify `GET /` advertises the route and the OpenAPI document still parses as YAML
- [x] 3.5 Add the `/verify` API section to `README.md`, including the self-check invariant and claims labeling; verify the documented request against a running `serve` returns the described response

## 4. decode command

- [x] 4.1 Add `decode` to dispatch and usage text; verify `help` lists it and an unknown command still exits non-zero
- [x] 4.2 Implement argument and stdin decoding with JSON output; verify tests for valid, expired, foreign, malformed, and piped input
- [x] 4.3 Document `decode` in the README CLI section; verify the documented commands produce the described output

## 5. verify command

- [x] 5.1 Implement JWKS loading from a URL or file with timeout, size, and redirect caps, converting JWKs to public keys; verify tests with a temp file and an `httptest` server, including the size cap and an unreachable URL
- [x] 5.2 Implement `--issuer` discovery, using `jwks_uri` for keys and the discovery `issuer` for the expected claim; verify tests for success, a missing `jwks_uri`, and an issuer mismatch
- [x] 5.3 Wire `--aud`, repeatable `--alg`, `--leeway`, `--json`, stdin, and usage errors; verify exit codes `0`, `1`, and `2` and that `--json` matches the HTTP verdict shape
- [x] 5.4 Add the `kid`/`unknown` hint mentioning `print-token` and server restarts; verify a test asserts the hint appears for that case
- [x] 5.5 Document `verify` in the README, including flags-before-token ordering and the `print-token` keyring caveat; verify the examples run as written against `serve`

## 6. Integration verification

- [x] 6.1 Run `go test ./...` and `go vet ./...`; verify both pass
- [x] 6.2 Run `go test -race ./internal/verify ./internal/server ./internal/keyring`; verify no races are reported
- [x] 6.3 End-to-end check: start `serve`, mint one token per enabled algorithm, verify each with `POST /verify`, `decode`, and `verify --issuer`; verify all agree and exit codes match the documented contract
- [x] 6.4 Update the `FUTURE.md` priority snapshot and decision log for this item; verify the entry matches the README and the release-generated changelog conventions

## Workflow follow-up

- Archive the change after review and merge.
- Confirm no `CHANGELOG.md` edit is needed, since the release tooling generates it from commits.
