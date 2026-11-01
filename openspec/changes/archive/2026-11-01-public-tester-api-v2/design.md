# Design

## Context

See `proposal.md` for motivation. The constraints that shape the approach:

- `pkg/tester` is the only exported library package and currently re-exports internal types (`*tokenfactory.Factory`, `keyring.Ring`) plus a private-key-bearing `KeyRing()`. Everything exported by it is effectively a compatibility promise.
- `internal/server.New` builds handlers from a `keyring.Ring` and `*tokenfactory.Factory` and starts a `cleanupVisitors` goroutine with no stop path. `pkg/tester` currently works around this by mutating `srv.Factory` and `srv.Issuer` after `httptest.NewServer` has already begun serving.
- `internal/keyring` stores both private and public JWKs per key, builds JWKS by iterating maps, and has `PruneAt(time.Time)` but no public-facing snapshot.
- The repository is already tagged `v2.0.0`–`v2.3.0`, but `go.mod` says `github.com/larryf1/jwtoken-tester`. The Go module proxy only resolves `v1.x` for that path, so `/v2` is a prerequisite for shipping any new version.
- `.semrel.yaml` maps breaking changes to a major bump, which would compute `v3.0.0` for a `/v2` module — an untaggable version.

## Goals / Non-Goals

**Goals:**

- One exported surface in `pkg/tester` that uses only standard-library types and `pkg/tester` types, and never exposes private keys.
- A lifecycle with a single owner: listener, rotation, and visitor cleanup all stop and are waited on by `Close`.
- Startup that binds the listener before deriving the issuer, so no field is mutated after serving begins.
- Deterministic key and JWKS output.
- A module path that makes the next release fetchable, plus a release guard that keeps a `/vN` path and its tags in agreement.

**Non-Goals:**

- Token verification or introspection helpers; claim profiles; new algorithms; key import/export; JWKS cache headers; rate-limit default changes; memory zeroization on close.
- Changing binary behavior, the HTTP API, or the CLI beyond wiring the new internal `Close`/logger.
- Rewriting the historical `v2.0.0`–`v2.3.0` tags; they stay invalid for the new path.

## Decisions

### 1. Neutral key surface (option A)

`Keys() []KeyInfo`, `ActiveKeyID`, `PublicKey(kid) crypto.PublicKey`, `PublicKeyPEM(kid)`, and `JWKSJSON() ([]byte, error)` are the public key API. `jwx` remains an internal dependency.

- **Why:** the package's contract stays stable across a future `jwx` major upgrade, and a `jwx` consumer converts with one `jwk.Parse` call.
- **Alternatives:** jwx-native (`jwk.Set`, `jwk.Key`) ties the API to `jwx/v4`; both adds two ways to do the same thing and enlarges the surface for no behavioral gain.
- **Consequence:** `PublicKeyPEM` emits PKIX (`PUBLIC KEY`), matching `x509.ParsePKIXPublicKey` and most TLS/config plumbing. `JWKSJSON` is compact; the HTTP endpoint keeps its indented encoding. Same keys, same order, different whitespace — documented so consumers do not compare bytes across the two.

### 2. Resource-only, idempotent `Close` (option A)

`Close` stops the listener, cancels rotation, stops visitor cleanup, and waits for both goroutines. It is `sync.Once`-guarded and safe to call concurrently. `Mint` and the key accessors keep working afterwards because they only touch in-memory state.

- **Why:** the OS resources are the listener and goroutines; the keyring is ordinary memory. Adding `ErrClosed` would force an error path on operations tests rarely do on purpose and would not make the helper safer.
- **Alternatives:** strict close (inert handle, `ErrClosed`) adds state and sentinels; destructive close (zeroize keys) makes `Close` irreversible and goes beyond "leak-free".
- **Consequence:** "leak-free" is testable by asserting goroutines/listener are gone, not by asserting the handle refuses work.

### 3. `Start` owns lifecycle; `NewServer` is a `testing` wrapper

`Start(opts ...Option) (*Server, error)` returns a live handle the caller must close. `NewServer(t TestingT, opts ...Option) *Server` calls `Start`, panics on error (test-helper convention), and registers `t.Cleanup(s.Close)`. `NewServer` returns only `*Server`; `s.URL()` replaces the second return value.

- **Why:** `TestMain`, benchmarks, and non-`testing` callers are legitimate; `NewServer` cannot be the only entry point once `Close` exists.
- **Alternatives:** keep the `(srv, url)` pair — redundant with `URL()` and mislabeled today (it returns the base URL, not the configured issuer).

### 4. Listener-first startup

```
keyring.New                     can fail; no listener yet
      |
httptest.NewUnstartedServer     listener bound; URL known
      |
issuer = WithIssuer value or bound URL
      |
factory + internal server built with the final issuer and a cancellable context
      |
ts.Config.Handler = srv.Handler()
      |
ts.Start()                      nothing is mutated after this
      |
Server{ts, cancel, closeOnce}
```

- **Why:** removes the post-start `Factory`/`Issuer` writes and the race between startup and the first request.
- **Alternatives:** start then patch fields (current behavior, racy); reserve a port separately then start `httptest` (extra failure mode and no benefit).

### 5. `WithIssuer("")` means auto-issuer

The zero value of the issuer option selects the bound URL. This replaces the `"http://127.0.0.1:8080"` magic sentinel.

- **Why:** the sentinel leaks a CLI default into library semantics and breaks when the listener binds elsewhere.
- **Consequence:** `Issuer()` always returns the effective issuer; discovery and minted tokens always agree with it.

### 6. Deterministic ordering by `kid`

`keyring.jwksUnlocked` sorts active and retired keys by `kid` before adding them to the JWKS set. `Keys()` sorts the same way.

- **Why:** map iteration currently makes JWKS order random per call. A public `JWKSJSON()` turns that into a contract bug, and FUTURE #6's ETag would inherit it.
- **Alternatives:** sort in `pkg/tester` only — leaves the HTTP endpoint and future consumers inconsistent; keep insertion order — impossible with map-backed storage.

### 7. Cache the public key on the internal key

Add `Public crypto.PublicKey` to `keyring.Key`, populated from `priv.(crypto.Signer).Public()` at generation time. `Keys()` and `PublicKey(kid)` then have no error path except `ErrKeyNotFound`; `PublicKeyPEM` can still fail on marshal.

- **Why:** converting `jwk.Key` back through `jwk.Export` can fail, which would force `Keys() ([]KeyInfo, error)` on every caller for no useful reason.
- **Alternatives:** export from JWK on demand — error-prone and slower.

### 8. `StartRotation` returns a done channel

`StartRotation(ctx, interval, logger) <-chan struct{}` returns a channel closed when the goroutine exits. A non-positive interval returns an already-closed channel.

- **Why:** `Close` must wait for the goroutine, not just signal it. A done channel is simpler than threading a `*sync.WaitGroup` through the keyring API, and it composes with `server.Close`.
- **Alternatives:** `WaitGroup` parameter — leaks concurrency primitives into the interface; sleep-and-hope — untestable.

### 9. `internal/server` gains `Close` and a logger option

`New(ring, factory, issuer, version, rps, burst, opts ...Option)` keeps existing call sites compiling; `WithLogger(*slog.Logger)` is the only option. `Server.Close()` cancels the visitor-cleanup goroutine and waits for it. Audit events use the server logger, falling back to `slog.Default()`.

- **Why:** variadic options avoid touching every `server_test.go` call site, and the CLI's signal context can finally stop `cleanupVisitors`.
- **Consequence:** `pkg/tester` passes a discard logger by default; the binary keeps `slog.Default()` behavior.

### 10. Rate limits stay at 100/200

`internal/server.New` keeps treating `0, 0` as "use 100/200". `WithRateLimit` is the escape hatch; embedded defaults stay 100/200.

- **Why:** changing `0` to mean "disabled" would alter binary configuration semantics and entangle this change with FUTURE #9.
- **Alternatives:** disable rate limiting in the helper — a test helper that 429s is surprising, but the semantics change is larger than this change should carry.

### 11. Public error sentinels map internal ones

`ErrUnsupportedAlgorithm`, `ErrTTLTooLong`, `ErrInvalidRequest`, and `ErrKeyNotFound` are declared in `pkg/tester`. `Mint` maps `tokenfactory` errors with `errors.Is`; key lookups map `keyring.ErrKeyNotFound`.

- **Why:** callers can branch without importing internal packages, and the mapping is one small function that tests can pin.
- **Consequence:** `Mint` wraps rather than replaces, so the underlying message survives in logs.

### 12. `/v2` module path plus a release major guard

`go.mod` becomes `github.com/larryf1/jwtoken-tester/v2`; internal imports and docs follow. The release workflow gains a preflight check that derives the expected major from the module path (`/vN` → `N`, no suffix → `1`) and fails if the computed next version's major differs, before any pre-tag plugin writes a file.

- **Why:** Semrel's conventional-commit rules alone cannot express "a `/vN` module cannot tag `v(N+1)`". The guard makes the invariant explicit and testable.
- **Alternatives:** remove the breaking-change rule — hides the conflict instead of enforcing it; rely on tag protection to reject a bad tag — too late, after the release commit and changelog are written.
- **Consequence:** this change must land as `feat:` (minor), producing `v2.4.0`, with no `!` or `BREAKING CHANGE:` marker. `v2.4.0` is the first tag fetchable for `/v2`.

### 13. Public `PruneAt` preserves deterministic grace-window tests

Removing `KeyRing()` removes `usecase_test.go` scenario 09's direct access to `PruneAt`. The public `PruneAt(time.Time)` keeps that story expressible without sleeping.

- **Why:** pruning is observable behavior (retired keys disappear from `Keys`/JWKS), so it belongs in the public contract, not just in internals.

## Risks / Trade-offs

- **[Release guard placement]** A guard implemented only in `.semrel.yaml` cannot inspect the computed version before the release phase. → Implement it as an explicit preflight step/script run before Semrel's release phase, with a unit test for the major-derivation function.
- **[Guard false negatives]** Parsing the module path from `go.mod` can drift from the actual import path. → Derive from `go list -m` or the single `module` line and assert both agree in the guard test.
- **[Goroutine-leak tests are flaky]** Counting goroutines globally is noisy. → Assert the done channels returned by rotation/cleanup are closed, and use goroutine counts only with retry tolerance.
- **[Breaking v1 consumers]** Existing importers of the unsuffixed path stay on `v1.3.0`. → That is the intended major-version dance; the rename breaks nobody automatically, and the README documents the new import path.
- **[`Close` after `httptest` cleanup]** Double close could panic if `httptest.Server.Close` is called twice. → `sync.Once` guards the whole release path; `t.Cleanup` and explicit `Close` are both safe.
- **[`Keys()` includes retired keys]** Consumers may assume one key per algorithm. → Document that retired keys appear until pruned, and expose `Retired`/`RetiredAt` in `KeyInfo`.
- **[Tag ruleset blocks fixes]** Once `v2.4.0` is published, the tag cannot be rewritten. → Verify with `openspec validate`, the full test suite, and a dry-run release before dispatching the real release.

## Migration Plan

1. Land module path + imports + docs and the internal/API rewrite in one change, as a single `feat:` commit with no breaking marker.
2. Update `pkg/tester` tests to the new surface; add `public_api_test.go` in `package tester_test` that imports only `pkg/tester` and `golang-jwt/jwt/v5`.
3. Run `go test -race ./...`, the coverage gate with `pkg/tester` added to `COVER_PKGS`, and `golangci-lint`.
4. Run the release workflow in dry-run mode; confirm the candidate is `v2.4.0` and the major guard passes.
5. Dispatch the real release; confirm `go list -m -versions github.com/larryf1/jwtoken-tester/v2` shows `v2.4.0` and `go install .../v2/cmd/jwtoken-tester@latest` resolves.
6. Rollback before release: revert the change. After release: publish a follow-up patch; do not rewrite the tag (ruleset forbids it).

## Open Questions

None blocking. The embedded rate-limit default and `RATE_LIMIT_RPS=0` semantics remain deferred to FUTURE #9, and verification helpers to FUTURE #2, without affecting this design.
