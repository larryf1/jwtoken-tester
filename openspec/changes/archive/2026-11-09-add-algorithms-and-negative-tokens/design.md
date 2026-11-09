# Design

## Context

See `proposal.md` - Why for motivation. The current implementation has a narrow algorithm registry in `internal/keyring` (`RS256`, `ES256`, `EdDSA`), a single `tokenfactory.Request` shape (`claims`, `alg`, `headers`), and one signing path through `jwt.Sign`. JWKS, discovery, and health derive their algorithm lists from the keyring, so adding algorithms there propagates automatically. The CLI `print-token` builds a throwaway keyring, and `pkg/tester` wraps the same factory, so both surfaces share the new behavior if the factory and keyring are extended.

Two constraints shape the approach:

- The HTTP server must not expose HMAC material or a secret endpoint, and must not silently accept broken tokens.
- The default algorithm set and existing token behavior must remain unchanged.

## Goals / Non-Goals

**Goals:**

- Add RS384, RS512, PS256, PS384, PS512, ES384, and ES512 as opt-in asymmetric algorithms.
- Make RSA modulus size configurable while keeping EC curves fixed by JWA.
- Add HS256 only to `print-token` and `pkg/tester` with an explicit shared secret.
- Add opt-in negative-token controls (`none`, corrupt modes, key selection/override) across HTTP, CLI, and embedding.
- Keep JWKS, discovery, health, and key listings asymmetric-only.
- Keep the default set `RS256,ES256,EdDSA` and make all new behavior additive.

**Non-Goals:**

- No HTTP secret endpoint and no HMAC entry in any published key or metadata document.
- No `EC_CURVE` setting; ES256/ES384/ES512 always use P-256/P-384/P-521.
- No key import/export, persistence, or reproducible fixture keys.
- No change to the verification reason taxonomy or verification semantics.
- No new Go dependencies.
- No dedicated `invalid-token` command or HTTP endpoint; negative controls extend existing surfaces.

## Decisions

### Extend the keyring registry rather than adding a parallel signer

Add the new asymmetric constants to `internal/keyring`, extend `allAlgorithms` and `jwaAlgorithms`, and generate RSA keys for every `RS*`/`PS*` algorithm, P-256/P-384/P-521 keys for `ES*`, and Ed25519 for `EdDSA`. `allAlgorithms` stays ordered so discovery, health, and tests are deterministic.

HS256 is deliberately not a keyring algorithm. It has no generated key, no rotation, and no JWK. Adding it to the keyring would force every JWKS/health/discovery path to filter it and would imply a shared secret belongs in the key lifecycle. Instead, the factory accepts an optional HMAC secret and signs HS256 directly with jwx.

Alternative considered: a separate signer interface for HMAC. Rejected because the factory already owns signing and the extra abstraction adds no behavior.

### Add keyring options for RSA size

Keep `keyring.New(grace, algs, opts...)` source-compatible and add `keyring.WithRSABits(bits)`. The keyring validates the default (2048) and minimum (1024) and returns a configuration error for non-integers or undersized values. Call sites that do not pass the option keep the current behavior.

Alternative considered: a full `keyring.Config` struct. Rejected as a larger, unnecessary signature change for an internal package.

### Add raw-JWS construction for `none` and duplicate claims

Normal tokens continue through `jwt.Sign`. Two negative modes cannot be produced by `jwt.Sign`:

- `alg: none` needs an unsigned three-segment token with an empty signature.
- `duplicate_claims` needs a payload JSON object with a repeated key, which a Go map cannot represent.

For those modes, the factory builds the compact JWS from base64url-encoded header and payload bytes, signs the signing input for duplicate claims (or leaves the signature empty for `none`), and returns the result. `duplicate_claims` duplicates `duplicate_claim` (default `sub`) by inserting a second JSON member into the payload before signing, so the signature is valid and tests can observe how a parser handles duplicate names.

The other corrupt modes sign a normal token and then mutate the compact serialization deterministically:

- `signature`: alter bytes in the signature segment.
- `payload`: alter bytes in the payload segment after signing.
- `header`: alter bytes in the header segment after signing.
- `truncate`: remove trailing characters or a segment so the value is not a complete three-segment JWS.

Alternative considered: post-processing only for every mode. Rejected because `none` and duplicate claims need control over the unsigned/duplicate structure.

### Put negative-token gating in the factory request

Extend `tokenfactory.Request` with `KID`, `Typ`, `CTY`, `Corrupt`, `DuplicateClaim`, and a non-JSON `AllowNegative` flag. The factory validates the control, checks `AllowNegative`, and returns a new `ErrNegativeDisabled` sentinel when a recognized negative control is requested without permission. Invalid corrupt mode names return `ErrInvalidRequest` before the gate check, so malformed requests are `400` even when negative mode is off.

Callers set `AllowNegative` explicitly:

- `serve`: set from `ALLOW_NEGATIVE_TOKENS` after JSON decoding, never from the request body.
- `print-token`: always true because the CLI flags are the explicit opt-in.
- `pkg/tester`: set from `WithNegativeTokens`, applied by `Server.Mint`.

This keeps one enforcement point and prevents an HTTP client from enabling the feature by adding a JSON field.

Alternative considered: a factory-level boolean. Rejected because CLI and embedding share the factory type but need different defaults, and per-request state is easier to reason about.

### Select signing keys by `kid`, with unknown-kid as a negative control

Add `keyring.SignerByKID(kid, alg)` that searches active and retired keys and requires the key's algorithm to match. The factory uses it when `kid` is supplied. A matching key signs the token and its `kid` is written to the protected header. If no key matches:

- With `AllowNegative`, the active key for `alg` signs and the header carries the requested unknown `kid`, producing a wrong-kid token.
- Without `AllowNegative`, return `ErrNegativeDisabled` so the server can answer `403`.

An algorithm mismatch returns `ErrInvalidRequest` (`400`). Selecting a retired key does not change its lifecycle state; once pruned, it can no longer sign.

### Treat `typ` and `cty` as reserved header fields

Add `Typ` and `CTY` to the request and set them in the protected header. `typ` defaults to `JWT`; `cty` is omitted when empty. The reserved names `alg`, `kid`, `typ`, and `cty` are rejected inside `headers` so a caller cannot create an ambiguous or spoofed header. `x5c`, `x5u`, `jku`, and other extension parameters remain available through `headers`.

Alternative considered: let `headers` override dedicated fields. Rejected because silent precedence is harder to debug and makes it easy to produce a token whose header disagrees with the signing key.

### Map disabled negative controls to 403

The server maps `ErrNegativeDisabled` to `403 Forbidden` and keeps `400` for invalid JSON, invalid time values, unsupported algorithms, invalid corrupt modes, and lifetime-cap violations. `503` remains for a missing active key. The audit event records the requested control and the rejection. This distinguishes "you asked for a feature that is turned off" from "your request is malformed".

### Keep HS256 surface-specific and secret-explicit

`tokenfactory` accepts an optional `[]byte` HMAC secret. `print-token` resolves it from `HMAC_SECRET` or `--hmac-secret-file` (file wins) and rejects secrets shorter than 32 bytes. `pkg/tester` exposes `WithHMACSecret`. `serve` never reads the secret and rejects `HS256` in `ALGORITHMS` at startup with a clear error. No JWKS, discovery, health, key listing, or accessor returns the secret.

Alternative considered: allow HS256 on `serve` and publish the secret through an endpoint. Rejected because a published shared secret is a different trust model and expands the HTTP attack surface.

### Extend the embedding API additively

Add constants for the new asymmetric algorithms plus `HS256` and `None` as request selectors. `WithAlgorithms` continues to accept only asymmetric algorithms and rejects `HS256`/`None`; `MintRequest.Algorithm` may use `HS256` when a secret is configured and `None` when negative tokens are enabled. Add `WithRSAKeyBits`, `WithHMACSecret`, and `WithNegativeTokens`. `MintRequest` gains `KID`, `Typ`, `CTY`, `Corrupt`, and `DuplicateClaim`.

### Keep documentation and OpenAPI in lockstep

Update the README configuration table, API field table, CLI examples, and embedding options; update `docs/openapi.yaml` and the swagger annotations for the new request fields, algorithm values, and `403`; update `FUTURE.md` item #4 and `CHANGELOG.md`. The JWKS/discovery/health documents remain generated from the keyring, so no static algorithm list is duplicated.

## Assumptions

The clarifying-question tool could not be shown to the user, so this change records these assumptions:

- HS256 is opt-in for `print-token` and `pkg/tester` only; `serve` has no HS256 and no secret endpoint.
- Negative tokens extend the existing `/token` and `print-token` surfaces behind an explicit opt-in rather than adding a new command or endpoint.
- The default algorithm set stays `RS256,ES256,EdDSA`; new algorithms are opt-in through `ALGORITHMS`.
- `RSA_BITS` defaults to 2048 and rejects values below 1024.
- HMAC secrets must be at least 32 bytes.
- An unknown `kid` is a negative control and returns `403` when negative mode is disabled.
- Reserved JOSE parameters in `headers` are rejected rather than silently overridden.
- `duplicate_claims` duplicates `sub` unless `duplicate_claim` names another claim.

## Risks / Trade-offs

- **HMAC secret exposure** → Use a file flag for shells, never log or publish the secret, require at least 32 bytes, and keep HS256 off `serve`.
- **Negative mode accidentally enabled** → Default `false`, require an explicit env/flag/option, return `403` when disabled, and audit every negative request.
- **Corrupt output accidentally verifies** → Assert each corrupt mode with the existing verifier in tests and use deterministic mutations; duplicate claims are intentionally signed and are expected to test parser behavior rather than signature rejection.
- **Large algorithm sets slow startup** → Keep defaults unchanged and document that each enabled algorithm generates a key at startup.
- **RSA-1024 is weak** → Allow it only for consumer-compatibility tests, document the risk, and keep the default at 2048.
- **Retired-key signing can fail after pruning** → Document that forced key selection works only while the retired key remains in memory and add tests for the pruned case.
- **`403` is a new status for `/token`** → Document it in OpenAPI and the README so clients handle it explicitly.
- **Duplicate JSON members are parser-dependent** → Document that `duplicate_claims` is for parser-behavior tests and may be accepted by permissive parsers.

## Migration Plan

The change is additive. Existing deployments keep the same defaults and existing tokens remain valid. New algorithms require an explicit `ALGORITHMS` change, negative mode requires an explicit opt-in, and HS256 is unavailable on `serve`. Deploy normally; rollback is a code revert with no data migration because keys are in memory. Operators who previously set `ALGORITHMS=HS256` on `serve` will now receive a clear startup error instead of the generic "at least one algorithm" error.

## Open Questions

- Whether to add HS384/HS512 for the CLI/embedding surfaces later.
- Whether a dedicated `invalid-token` command or endpoint is preferable to extending `/token` after user feedback.
- Whether RSA sizes below 2048 should emit a runtime warning in addition to the documentation warning.
