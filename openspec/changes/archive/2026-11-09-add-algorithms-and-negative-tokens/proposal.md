# Proposal

## Why

The issuer supports only RS256, ES256, and EdDSA, so consumers that require PS256/PS384/PS512, RS384/RS512, ES384/ES512, or HS256 cannot be exercised against realistic tokens. It also has no supported way to mint deliberately unsigned, malformed, wrong-`kid`, or duplicate-claim tokens, which forces tests to hand-craft broken JWTs. FUTURE #4 identifies both gaps as high value.

## What Changes

- Add the asymmetric algorithms RS384, RS512, PS256, PS384, PS512, ES384, and ES512 across the keyring, token factory, discovery, JWKS, health, `/token`, `/oauth/token`, `/v2/oauth/token`, `/verify`, CLI, and embedded API. Defaults stay `RS256,ES256,EdDSA`; the new algorithms are opt-in through `ALGORITHMS`.
- Add configurable RSA modulus size (`RSA_BITS`, default `2048`, minimum `1024`) for tests that reject weak keys. EC curves remain algorithm-determined per JWA (ES256 uses P-256, ES384 uses P-384, ES512 uses P-521); no `EC_CURVE` setting is introduced.
- Add opt-in HS256 for `print-token` and `pkg/tester` only, using an explicit shared secret (`HMAC_SECRET` or `--hmac-secret-file` for the CLI, `WithHMACSecret` for embedding). The HTTP `serve` command does not enable HS256, never publishes an HMAC key in JWKS, and exposes no secret endpoint.
- Add opt-in negative-token controls:
  - `alg: "none"` unsigned tokens.
  - `corrupt` modes: `signature`, `payload`, `header`, `truncate`, and `duplicate_claims`.
  - `kid` override and forced signing-key selection, including retired keys; an unknown `kid` produces a wrong-`kid` token only in negative mode.
  - First-class `typ` and `cty` fields; `x5c`, `x5u`, and `jku` remain available through `headers`.
  - Server gate `ALLOW_NEGATIVE_TOKENS` / `--allow-negative-tokens`, default `false`. CLI flags and explicit embedded requests are the opt-in on those surfaces.
- Extend `print-token` with `--kid`, `--typ`, `--cty`, `--corrupt`, `--alg none`, and HS256 support.
- Extend `pkg/tester` with new algorithm constants, `WithRSAKeyBits`, `WithHMACSecret`, `WithNegativeTokens`, and `MintRequest` fields.
- Update the README, OpenAPI spec, FUTURE #4, and CHANGELOG.

## Capabilities

### New Capabilities

- `negative-token-controls`: deliberately broken, unsigned, wrong-`kid`, and duplicate-claim token generation, including gating, safety, and audit behavior across HTTP, CLI, and embedding.

### Modified Capabilities

- `key-management`: new asymmetric algorithms, configurable RSA size, key selection by `kid` including retired keys, and HMAC key handling that never enters the JWKS.
- `token-minting`: expanded algorithm set, `kid`/`typ`/`cty` request fields, `alg: none`, corrupt modes, and negative-mode gating.
- `configuration`: expanded `ALGORITHMS` set, `RSA_BITS`, `ALLOW_NEGATIVE_TOKENS`, and `print-token` HMAC secret settings.
- `cli`: `print-token` algorithm/header/`kid`/negative flags and HS256 secret input.
- `embedding`: new algorithm constants, key-size/HMAC/negative options, and `MintRequest` fields.
- `http-api/jwks`: publish the new asymmetric `alg` values and never publish HS256 material.
- `http-api/discovery`: advertise new enabled algorithms and never advertise HS256.
- `http-api/health`: report new enabled algorithms and active key IDs, with no HMAC entry.

## Impact

- `internal/keyring`: algorithm registry, key generation, RSA size, and signer lookup by `kid`.
- `internal/tokenfactory`: algorithm validation, HMAC signing, `typ`/`cty`/`kid` handling, negative modes, and raw JWS construction.
- `internal/server`: `/token` request fields, negative-mode gate, audit events, and error mapping; discovery and health stay dynamic.
- `cmd/jwtoken-tester`: new settings and `print-token` flags; `serve` rejects HS256 with a clear error.
- `pkg/tester`: public constants, options, and `MintRequest` fields; HS256 and negative modes; JWKS remains asymmetric-only.
- `README.md`, `docs/openapi.yaml`, `FUTURE.md`, `CHANGELOG.md`, and tests.
- No new Go dependencies; jwx already provides the JWA algorithms.
- Compatibility: the default algorithm set and existing tokens are unchanged. New request fields are additive. HS256 is unavailable on `serve`. Negative mode is off by default. `ALGORITHMS=HS256` on `serve` fails with a clear error instead of the generic "at least one algorithm" message.
