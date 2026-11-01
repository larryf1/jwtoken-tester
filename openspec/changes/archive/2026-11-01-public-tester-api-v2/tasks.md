# Tasks

## 1. Module path migration

- [x] 1.1 Change `go.mod` to `module github.com/larryf1/jwtoken-tester/v2` and rewrite the 16 internal import lines across `cmd/`, `internal/`, and `pkg/`; verify with `go build ./...` and `go vet ./...`
- [x] 1.2 Update the README install command and embedding import to the `/v2` path; verify no unsuffixed module import remains with `go list -f '{{.ImportPath}}' ./...`
- [x] 1.3 Update `COVER_PKGS` in the Makefile to the `/v2` prefix; verify `make coverage` still runs and reports the existing packages
- [x] 1.4 Confirm generated/adjacent artifacts need no change (`.goreleaser.yaml`, `docker/Dockerfile`, `docker/demo-service`, CI workflows, `docs/openapi.yaml`); verify with `go build ./cmd/jwtoken-tester` and a docker build dry check

## 2. Internal keyring support

- [x] 2.1 Add `Public crypto.PublicKey` to `keyring.Key`, populate it from the generated signer, and verify with a test that every enabled algorithm exposes a usable public key
- [x] 2.2 Sort active and retired keys by `kid` in `jwksUnlocked`; verify a test calling `JWKS()` repeatedly returns identical key order
- [x] 2.3 Add `Snapshot()` (sorted copy including retired keys and `RetiredAt`) and `PublicKeyByKID()` plus `ErrKeyNotFound`; verify tests for active, retired, pruned, and unknown kids
- [x] 2.4 Change `StartRotation` to return a done channel closed when the goroutine exits, and return an already-closed channel for a non-positive interval; verify tests for cancellation and disabled rotation

## 3. Internal server lifecycle and logging

- [x] 3.1 Add variadic `WithLogger(*slog.Logger)` to `internal/server.New`, use it for audit events, and fall back to `slog.Default()`; verify existing call sites compile unchanged and a logger test captures events
- [x] 3.2 Add `Server.Close()` that cancels and waits for `cleanupVisitors`; verify a test asserts the goroutine exits and repeated close is safe
- [x] 3.3 Wire the CLI's signal context and `Close` into `runServe`; verify the graceful-shutdown CLI test still passes and the cleanup goroutine stops on SIGINT/SIGTERM

## 4. Public `pkg/tester` API

- [x] 4.1 Define `Algorithm` constants, `MintRequest`, `Token`, `KeyInfo`, options, and public error sentinels; verify option validation tests for empty algorithms and empty issuer
- [x] 4.2 Implement `Start`/`NewServer` with listener-first startup (`httptest.NewUnstartedServer`) and issuer derivation; verify tests for default issuer, explicit issuer, and failed startup leaving no listener or goroutine
- [x] 4.3 Implement `Mint` and map `tokenfactory` errors to the public sentinels; verify tests for default RS256, ES256/EdDSA, TTL-too-long, and unsupported algorithm
- [x] 4.4 Implement `Keys`, `ActiveKeyID`, `PublicKey`, `PublicKeyPEM`, and `JWKSJSON`; verify tests for `kid` ordering, retired keys, PKIX PEM round-trip, and `ErrKeyNotFound`
- [x] 4.5 Implement `Rotate` and `PruneAt`; verify the grace-window test (replacing scenario 09's `KeyRing().PruneAt`) shows retired keys until pruned
- [x] 4.6 Implement resource-only `Close` with `sync.Once`, stopping the listener and waiting for rotation and cleanup; verify idempotent/concurrent close and `Mint` after close
- [x] 4.7 Implement `Handler`, `URL`, `Issuer`, and `Client`; verify the handler serves discovery, JWKS, and token endpoints for the effective issuer
- [x] 4.8 Thread `WithLogger` into the internal server and default to a discard logger; verify no output by default and routed output when configured
- [x] 4.9 Rewrite `tester_test.go` and `usecase_test.go` against the new surface; verify `go test ./pkg/tester` passes
- [x] 4.10 Add `pkg/tester` to the Makefile coverage packages and update the README embedding section plus FUTURE item #1; verify `make coverage` meets the gate and the README snippet matches the exported API

## 5. Integration and leak proof

- [x] 5.1 Add `public_api_test.go` in `package tester_test` importing only `pkg/tester` and `golang-jwt/jwt/v5`; verify it compiles and verifies a minted token against `JWKSJSON`
- [x] 5.2 Add a concurrent-startup `-race` test asserting minted tokens and discovery advertise the final bound issuer; verify `go test -race ./pkg/tester`
- [x] 5.3 Add a start/close cycle test asserting rotation and cleanup goroutines exit and no goroutine accumulates; verify `go test -race -run TestNoLeak ./pkg/tester`
- [x] 5.4 Add `ExampleNewServer` so pkg.go.dev renders a snippet; verify `go test -run Example ./pkg/tester` passes

## 6. Release major guard

- [x] 6.1 Add a major-derivation and guard step that reads the module path (`/vN` → `N`, unsuffixed → `1`) and rejects a computed version with a different major; verify unit tests for `/v2` match, `/v2` vs `v3.0.0` mismatch, and unsuffixed paths
- [x] 6.2 Wire the guard into the release workflow before any pre-tag or release plugin runs; verify a dry-run dispatch fails on a simulated mismatch and passes on the normal range
- [x] 6.3 Document the `/vN` release and migration procedure in the release docs; verify the steps name the guard, the required `/v(N+1)` change, and the `feat:` commit rule
- [x] 6.4 Run a dry-run release and confirm the candidate is `v2.4.0` with the guard passing; verify no file, commit, tag, or remote write occurs

## Workflow follow-up

- Archive the change after review and a successful release.
- After the real release, verify `go list -m -versions github.com/larryf1/jwtoken-tester/v2` shows `v2.4.0` and `go install github.com/larryf1/jwtoken-tester/v2/cmd/jwtoken-tester@latest` resolves.
