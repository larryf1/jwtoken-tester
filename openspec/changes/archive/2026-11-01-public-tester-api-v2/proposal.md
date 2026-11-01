# Proposal

## Why

`pkg/tester` is the only exported library package, but it is not safe to depend on: it exposes `TokenFactory()` and `KeyRing()`, so every exported signature pulls in `internal/tokenfactory`, `internal/keyring`, and `jwx/v4` types, and `KeyRing().Signer()` hands out private key material. Its lifecycle also leaks: `Close` does not stop key rotation, the internal `cleanupVisitors` goroutine outlives the server, and `NewServer` mutates the issuer and factory after the server is already serving. The module path is `github.com/larryf1/jwtoken-tester` while the repository is already on `v2.x` tags, so `go get ...@v2.3.0` fails and `@latest` silently resolves to `v1.3.0`.

This change is the one opportunity to fix all three at once: a small, leak-free public API, and a module path (`/v2`) that makes the next release fetchable.

## What Changes

- **BREAKING**: module path becomes `github.com/larryf1/jwtoken-tester/v2`; every internal import is rewritten and the README install/embed paths follow.
- **BREAKING**: `pkg/tester` drops `TokenFactory()` and `KeyRing()`, and `NewServer` returns only `*Server`. The exported surface becomes neutral: `tester.Algorithm` constants, `MintRequest`, `Token`, `KeyInfo`, public error sentinels, and accessors that return only standard-library types (`crypto.PublicKey`, `[]byte`, `time.Duration`). `jwx` and the `internal/...` packages are no longer reachable from a consumer.
- Add `Start(opts ...Option) (*Server, error)` for non-`testing.T` callers; `NewServer(t, ...)` becomes a thin wrapper that calls `Start` and registers `t.Cleanup`.
- Add `Keys()`, `ActiveKeyID`, `PublicKey`, `PublicKeyPEM`, `JWKSJSON`, `Rotate`, `PruneAt`, `Handler`, `URL`, `Issuer`, `Client`, `Close`, and `WithLogger`.
- Make `Close` resource-only and idempotent: stop the listener, cancel rotation, stop visitor cleanup, and wait for both goroutines. `Mint` and the key accessors keep working afterwards; no `ErrClosed` state.
- Remove the post-start mutation race by binding the listener first (`httptest.NewUnstartedServer`), deriving the issuer, then building the handler before `Start`.
- Make JWKS and `Keys()` deterministic by sorting keys by `kid`; include retired keys so grace-window tokens stay verifiable.
- Internally, give `keyring.Key` a cached public key, add `Snapshot`/`PublicKeyByKID`/`ErrKeyNotFound`, return a done channel from `StartRotation`, and let `internal/server` accept a logger and be closed.
- Add a release-pipeline guard: a `/vN` module SHALL only release within major `N`, and the release SHALL fail fast if the computed version's major does not match the module path.

## Capabilities

### New Capabilities

None. The change reshapes an existing capability rather than introducing a new one.

### Modified Capabilities

- `embedding`: the start-up contract, options, and accessors change. `NewServer` no longer returns a URL, `WithAlgorithms` takes `tester.Algorithm`, and the requirement that the handle expose the token factory and key ring is replaced by the neutral mint/key/JWKS surface plus a resource-only `Close`.
- `release-pipeline`: adds the `/vN` major-version guard. Breaking changes can no longer produce a major bump that the module path cannot tag; migrating to `/v(N+1)` becomes a deliberate change, and a mismatched computed major fails the release.

## Impact

- `go.mod` and 16 import lines across `cmd/jwtoken-tester/main.go`, `internal/server/server.go`, `internal/server/server_test.go`, `internal/tokenfactory/factory.go`, `internal/tokenfactory/factory_test.go`, and `pkg/tester/*.go`.
- `pkg/tester/tester.go`, `tester_test.go`, `usecase_test.go`: full rewrite around `Start`/`Close`; scenario 09 moves from `KeyRing().PruneAt` to `Rotate` + `PruneAt`.
- `internal/keyring`: `Public` field on `Key`, sorted JWKS, `Snapshot`, `PublicKeyByKID`, `ErrKeyNotFound`, done channel from `StartRotation`.
- `internal/server`: variadic `WithLogger`, `Close` that stops and waits for `cleanupVisitors`; the CLI's signal context now actually stops that goroutine.
- `README.md` (install and embedding sections), `FUTURE.md` (item #1 and priority snapshot), `Makefile` (`COVER_PKGS` gains `/v2` and `pkg/tester`).
- `.semrel.yaml` / release workflow: guard logic for `/vN` module paths. `v2.0.0`–`v2.3.0` remain unfetchable for the new path; the first valid `/v2` tag is `v2.4.0`, cut from a `feat:` commit with no breaking marker.
- Unaffected: `.goreleaser.yaml`, `docker/`, CI workflows, `docs/openapi.yaml`, `docker/demo-service` (separate module).
- Out of scope: token verification/introspection, claim profiles, new algorithms, key import/export, JWKS caching headers, embedded rate-limit default changes, and key zeroization on `Close`.
