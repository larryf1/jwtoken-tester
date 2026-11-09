# Tasks

## 1. Keyring algorithm foundation

- [x] 1.1 Add `RS384`, `RS512`, `PS256`, `PS384`, `PS512`, `ES384`, and `ES512` to `internal/keyring`; extend `allAlgorithms` and `jwaAlgorithms`; generate RSA keys for `RS*`/`PS*`, P-384/P-521 keys for `ES384`/`ES512`, and keep Ed25519 for `EdDSA`. Verify `go test ./internal/keyring` includes table-driven coverage of every algorithm's key type and JWA mapping.
- [x] 1.2 Add a `keyring.WithRSABits` option with a default of 2048 and a minimum of 1024; reject non-integers and undersized values. Verify tests cover the default, a custom size, below-minimum, and invalid input.
- [x] 1.3 Add `SignerByKID(kid, alg)` that selects active or retired keys, requires a matching algorithm, and returns key-not-found for unknown IDs. Verify tests cover active, retired, algorithm-mismatch, unknown, and post-prune cases.
- [x] 1.4 Keep `JWKS`, `Snapshot`, and `EnabledAlgorithms` asymmetric-only, deterministic, and ordered by key ID with the expanded algorithm set. Verify tests assert stable ordering and no `none`/HMAC entries.
- [x] 1.5 Update the README algorithm lists and defaults for the new asymmetric set and note that the new algorithms are opt-in. Verify the README list matches the supported keyring constants.

## 2. Token factory

- [x] 2.1 Extend `tokenfactory.Request` with `KID`, `Typ`, `CTY`, `Corrupt`, `DuplicateClaim`, and a non-JSON `AllowNegative` flag; validate the expanded algorithm set and the `none`/HS256 rules. Verify `go test ./internal/tokenfactory` covers each new field and algorithm.
- [x] 2.2 Implement `typ`/`cty`/`kid` protected-header handling, default `typ` of `JWT`, and rejection of reserved `alg`/`kid`/`typ`/`cty` values supplied through `headers`. Verify tests assert header contents and invalid-request errors.
- [x] 2.3 Add optional HMAC-secret support for HS256, enforce a minimum secret length of 32 bytes, and keep HS256 out of keyring and JWKS paths. Verify tests sign and verify HS256 with the same secret and reject missing or short secrets.
- [x] 2.4 Implement `alg: none` and the corrupt modes `signature`, `payload`, `header`, `truncate`, and `duplicate_claims` using the raw-JWS approach in `design.md`. Verify tests assert each defect and use the verifier to confirm corrupt signatures fail.
- [x] 2.5 Add `ErrNegativeDisabled` and gate recognized negative controls on `AllowNegative`; keep invalid corrupt modes as `ErrInvalidRequest`. Verify tests cover disabled, enabled, unknown-`kid`, and invalid-mode paths.

## 3. Server HTTP behavior

- [x] 3.1 Add a `WithAllowNegativeTokens` server option and set the resolved value on `/token` requests after JSON decoding, never from the request body. Verify httptest tests prove a request body cannot enable negative mode.
- [x] 3.2 Map `ErrNegativeDisabled` to `403`, keep the existing `400`/`503` mappings, and audit allowed and rejected negative mints with the control name. Verify tests assert status codes and audit attributes.
- [x] 3.3 Accept the new algorithms and `kid`/`typ`/`cty` fields on `/token`; reject `none`, HS256, and corrupt controls on `/oauth/token` and `/v2/oauth/token`. Verify tests for each endpoint.
- [x] 3.4 Verify discovery, JWKS, and health list the new enabled asymmetric algorithms and never list `none` or HS256; add or update tests for each document.
- [x] 3.5 Update the README API table and `docs/openapi.yaml` plus the swagger annotations for the new request fields, algorithm values, and `403`; run `make docs-openapi` and `make lint-openapi`, and verify `go test ./internal/server` passes.
- [x] 3.6 Verify `POST /verify` accepts tokens signed with each new asymmetric algorithm and still classifies `none`, HS256, and corrupt tokens with the expected reasons. Add tests that span the keyring and verifier.

## 4. Configuration and CLI

- [x] 4.1 Add `RSA_BITS`/`--rsa-bits`, `ALLOW_NEGATIVE_TOKENS`/`--allow-negative-tokens`, and `HMAC_SECRET`/`--hmac-secret-file` to the `serve` and `print-token` configuration; validate boolean and integer values; make `serve` reject HS256 in `ALGORITHMS` with a clear error. Verify table-driven tests in `cmd/jwtoken-tester` cover defaults, flag precedence, and invalid values.
- [x] 4.2 Extend `print-token` with `--kid`, `--typ`, `--cty`, `--corrupt`, `--duplicate-claim`, `--alg none`, and `--rsa-bits`; wire the HMAC secret and the CLI negative opt-in. Verify CLI tests cover each flag and the error exits for conflicting reserved headers and missing HS256 secrets.
- [x] 4.3 Update the README configuration table, CLI usage/examples, `FUTURE.md` item #4, and `CHANGELOG.md`. Verify the env and flag names match `main.go`, the examples run as written, and FUTURE #4 no longer lists the work as open.
- [x] 4.4 Verify `jwtoken-tester verify` accepts tokens signed with each new asymmetric algorithm and reports `none`, HS256, and corrupt tokens with the expected verdict. Add CLI tests that span the keyring and verifier.

## 5. Embedding API

- [x] 5.1 Add `RS384`, `RS512`, `PS256`, `PS384`, `PS512`, `ES384`, `ES512`, `HS256`, and `None` constants plus `WithRSAKeyBits`, `WithHMACSecret`, and `WithNegativeTokens`; keep `WithAlgorithms` asymmetric-only. Verify `go test ./pkg/tester` covers option behavior and startup validation.
- [x] 5.2 Extend `MintRequest` and the `Mint` mapping for `KID`, `Typ`, `CTY`, `Corrupt`, and `DuplicateClaim`; enforce negative-token gating and the HS256 secret requirement. Verify tests for new algorithms, header fields, negative on/off, and HS256.
- [x] 5.3 Verify `Keys` and `JWKSJSON` exclude HMAC and `none`, and that no accessor exposes the HMAC secret. Add tests for both properties.
- [x] 5.4 Update the README embedding options and examples. Verify the documented identifiers exist in `pkg/tester` and that `go doc ./pkg/tester` matches the documented surface.

## 6. Integration verification

- [x] 6.1 Run `make test`, `make vet`, and `make lint`; fix any failures.
- [x] 6.2 Run `make build` and smoke test the binary: enable a new algorithm, fetch JWKS/discovery/health, mint normal and negative tokens, confirm `403` when negative mode is disabled, and confirm `serve` rejects HS256. Record the commands and results.
- [x] 6.3 Run `make docs-openapi` and `make lint-openapi` after all changes; verify the generated OpenAPI has no drift.
- [x] 6.4 Run `go mod tidy` and verify the diff adds no new direct or indirect dependencies.

## Workflow follow-up

- Run `openspec validate "add-algorithms-and-negative-tokens" --type change --strict` before implementation review.
- Archive the change after the project's review requirements are satisfied and all tracked tasks are complete.
- Verify the archived specs and change status after archiving.
