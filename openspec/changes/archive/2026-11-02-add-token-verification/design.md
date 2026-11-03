# Design

## Context

See `proposal.md` for motivation and `specs/token-verification/spec.md` plus `specs/cli/spec.md` for the behavior contract.

Current constraints that shape the approach:

- `internal/keyring` already stores both the private key and a `crypto.PublicKey` on every `Key`, and it already knows `CreatedAt`/`RetiredAt`. The `Ring` interface used by `internal/server` and `internal/tokenfactory` exposes signing and JWKS but no key-status or public-key lookup, so verification cannot answer "is this kid active or retired?" without an interface addition.
- `internal/tokenfactory` owns minting policy (issuer, TTLs, caps). Verification has different inputs and no TTL policy, so it does not belong there.
- `golang-jwt/jwt/v5` is already a direct module dependency, used only by tests to cross-check what `jwx` signs. It has one sentinel error per failure class and `ParseUnverified` for diagnostics. `jwx/v4` remains the signer and the JWK/JWKS codec.
- Tokens minted by `print-token` come from a fresh in-process keyring, so they can never verify against a running `serve` instance. This is correct behavior and needs to be explained, not worked around.

## Goals / Non-Goals

**Goals:**

- One verification implementation with one failure taxonomy, shared by the HTTP endpoint and both CLI commands.
- A deterministic reason for every failure, enforced by control flow rather than library error ordering.
- A verdict envelope that makes the trust level of every claim set explicit.
- Server-side verification that cannot be pointed at an external key source, by construction rather than by a rejection branch.
- CLI verification that works against any issuer, with fs/network behavior owned by the client process.

**Non-Goals:**

- RFC 7662 introspection, `introspection_endpoint`, and OAuth client authentication (deferred to the OAuth/discovery change).
- Time travel (`now`/`--at`), secondary-failure reporting, PEM key input, `pkg/tester.Verify`, and fuzzing.
- Replacing the signing path or changing minted-token behavior.
- Caching, ETags, or discovery changes.

## Decisions

### D1. A policy-free classifier in `internal/verify`, with policy supplied by each caller

The classifier takes everything it needs as input and knows nothing about HTTP or flags:

```
type Input struct {
    Token          string
    Keys           KeySource     // lookup by kid -> public key + status
    ExpectedIssuer string        // "" disables the issuer check (CLI without --issuer)
    AllowedAlgs    []string      // empty means every algorithm present in Keys
    Audience       []string      // empty disables the audience check
    Leeway         time.Duration
    Now            time.Time     // injected for deterministic tests
}

type KeySource interface {
    Lookup(kid string) (crypto.PublicKey, keyring.KeyStatus, error)
    Algorithms() []string        // algorithms usable from this source
}
```

| Surface | Keys | ExpectedIssuer | AllowedAlgs | Audience |
|---|---|---|---|---|
| `POST /verify` | live ring | server issuer, always | enabled algorithms, optionally narrowed | request, optional |
| `verify --jwks` | parsed JWKS | empty unless `--issuer` | `--alg`, or key-set algorithms | `--aud`, optional |
| `verify --issuer` | JWKS from discovery | discovery `issuer` | as above | as above |

Consequences:

- The HTTP handler has no field it could use to name another key source. The invariant in the spec falls out of the type, not a guard clause.
- The CLI reuses the exact reason taxonomy, so a `--json` verdict and an HTTP verdict are the same document.
- `decode` does not use the classifier at all; it only needs structural decoding.

Alternative considered: separate HTTP and CLI verification code. Rejected because the failure mapping would drift between them, and the reason enum is the part most likely to be extended.

Alternative considered: putting verification in `internal/tokenfactory`. Rejected: the factory holds signing configuration (issuer, default/max TTL) and has no business doing key lookup or claim validation policy.

### D2. The HTTP endpoint accepts only a token and consumer expectations

Request body, decoded with unknown fields rejected:

```jsonc
{
  "token":  "eyJ...",          // required
  "aud":    "my-service",       // optional; string or array of strings
  "alg":    ["RS256"],          // optional; non-empty subset of enabled
  "leeway": "30s"               // optional; Go duration, default 0
}
```

- `json.Decoder.DisallowUnknownFields` is deliberate. A client that sends `jwks`, `jwks_url`, `issuer`, or a typo gets `400` instead of a silently ignored field and a misleading verdict.
- The server never constructs an HTTP client for verification. The absence of a fetch path is the SSRF control.
- Body limit reuses the existing 1 MiB `maxRequestBody`; the handler mirrors `/token`'s error shape.

### D3. Verdict via `golang-jwt/v5`; `jwx` stays the signer and JWK codec

`golang-jwt` gives a second implementation for signature and claim checks, plus sentinels that map cleanly onto the reason enum. For HTTP it also avoids JWK conversion entirely: the keyring already holds `crypto.PublicKey`.

For the CLI, `jwx` parses the JWKS and exports each JWK to a raw public key, which is then handed to `golang-jwt` through a `Keyfunc`. `jwx` still signs and still emits the server's JWKS.

Alternative considered: `jwx` only (`jwt.Parse` / `jwt.ParseInsecure`). One library and fewer moving parts, but the verifier then mirrors the signer, so a signing quirk that only `jwx` understands would pass verification. The project already treats an independent library as the interop check; this promotes it from tests into the product. Cost: two libraries on one path, mitigated by a parity test matrix (D9).

Alternative considered: `jwx` for parsing plus `golang-jwt` only for signature bytes. Rejected as the worst of both: two libraries and manual claims handling.

### D4. Two-pass parsing: unverified for diagnostics, verified for truth

```
  token
    |
    +--> ParseUnverified(token, MapClaims)
    |      | error -> malformed (structure/base64/JSON/claim shape)
    |      +-> header + raw claims, used for alg/kid checks and for echoing
    |
    +--> explicit header checks
    |      | alg missing / not allowed -> alg
    |      | kid missing / not in KeySource -> kid
    |
    +--> verified parse (valid methods, issuer, audience, leeway, iat)
    |      | signature family -> signature
    |      | expired -> expired
    |      | not-yet-valid / used-before-issued -> not_yet_valid
    |      | issuer -> issuer
    |      | audience -> audience
    |      | unclassifiable -> 500 (no verdict)
    |
    v
  valid
```

Why two passes rather than one:

- The endpoint always needs the header and claims for the response, even when verification fails.
- Precedence is ours. `golang-jwt` returns the first error it encounters; relying on that would couple the public reason enum to a dependency's internal ordering.
- Signature-before-time is enforced explicitly, so a tampered payload can never be diagnosed as `expired`.

Structural parsing failures at the first pass are `malformed`; signature failures at the second are `signature`. That is how the two are distinguished without string matching.

`Now` is injected rather than read from the clock inside the classifier, so expiry, leeway, and `nbf` tests run without sleeping.

### D5. Reason mapping is a closed table, and unmappable errors are server errors

| Observation | Reason |
|---|---|
| Not three segments, bad base64, bad JSON, wrong claims shape | `malformed` |
| `alg` missing, disabled, or outside the requested allowlist | `alg` |
| `kid` missing, unknown, or pruned | `kid` |
| `ErrTokenSignatureInvalid`, `ErrInvalidKey`, `ErrInvalidKeyType`, key mismatch | `signature` |
| `ErrTokenExpired` | `expired` |
| `ErrTokenNotValidYet`, `ErrTokenUsedBeforeIssued` | `not_yet_valid` |
| `ErrTokenInvalidIssuer` | `issuer` |
| `ErrTokenInvalidAudience` | `audience` |
| Anything else | HTTP `500` / CLI exit `2` |

The enum stays closed. A dependency upgrade that introduces a new error class surfaces as a server/operational failure rather than a made-up verdict.

### D6. Claims are labeled by whether the signature verified

- Signature verified: `claims`.
- Parsed but not verified: `unverified_claims`.
- Not parseable: neither.

Both fields are `omitempty`, so exactly one appears whenever claims are available. The classifier returns the label alongside the data, and the HTTP JSON and CLI `--json` output use the same field names.

The raw `exp`, `iat`, and `nbf` values are echoed as the numeric dates that appeared in the token. This is another reason to parse with `golang-jwt`'s `MapClaims`: `jwx`'s `jwt.Token` converts them to `time.Time`, which would serialize differently from the token payload.

### D7. Key status comes from the keyring, through a new lookup method

Add to `keyring.Ring`:

```
Lookup(kid string) (crypto.PublicKey, KeyStatus, error)   // ErrKeyNotFound when absent
```

`KeyStatus` is `active` or `retired`; `unknown` is the not-found case and is never returned by the keyring. `Lookup` takes the read lock once and searches the same snapshot that `JWKS()` uses, so a concurrent rotation cannot produce a torn answer.

The HTTP and CLI verdicts derive `kid_status` from this: found + active, found + retired, or not found. This is a small surface change to an internal interface; `pkg/tester` keeps its neutral `KeyInfo` mapping.

Alternative considered: two calls (`PublicKeyByKID` then a new `StatusByKID`). Rejected because it takes two locks and can observe a rotation between them.

### D8. HTTP handler details

- Route: `POST /verify`, registered on the existing mux. Non-POST falls through to the mux's `405`.
- Response: `200` for any completed verdict, `400` for request errors (missing/blank token, unknown fields, bad `leeway`, empty/unknown `alg`, oversize body), `500` for unclassifiable verification failures, `405` for the wrong method.
- `Cache-Control: no-store` on verdicts.
- Audit event `token_verified` with `valid`, `reason` (when invalid), `kid`, `kid_status`, `alg`, `request_id`, `client_ip`, `method`, `path`. Reuses the existing `logTokenEvent` plumbing. The token and claims never enter the event.
- `aud` accepts a string or an array of strings; matching is any-of.
- `leeway` is a Go duration string, consistent with the project's configuration conventions.

### D9. CLI details

```
jwtoken-tester decode <token>                    # stdin if omitted
jwtoken-tester verify --jwks <url|file> <token>
jwtoken-tester verify --issuer <url> <token>
jwtoken-tester verify --jwks ... --aud my-svc --alg RS256 --leeway 30s --json
```

- `decode` prints an indented JSON object with `header` and `claims`. It never contacts a key source and never validates time claims. Exit `0` when structurally decodable, `1` otherwise.
- `verify` requires exactly one of `--jwks` or `--issuer`. Both or neither is a usage error (exit `2`).
- `--jwks` treats a value with an `http`/`https` scheme as a URL and everything else as a file path. Fetch limits: 5-second timeout, 1 MiB response cap, at most 5 redirects. Parse with `jwx`, export public keys, verify with `golang-jwt`.
- `--issuer` fetches `<issuer>/.well-known/openid-configuration`, reads `jwks_uri`, then loads that JWKS. The expected issuer is the discovery document's `issuer` field, falling back to the flag value; this avoids trailing-slash mismatches between the flag and the minted claim.
- `--jwks` alone does **not** enable the issuer check, because a JWKS carries no issuer identity. `--issuer` enables it.
- Output is human-readable by default and the verdict envelope with `--json`. Exit `0` valid, `1` invalid, `2` operational failure (fetch, file, parse of key source, usage).
- Flags use the standard `flag` package like the other commands, so flags precede the positional token; the README documents `<command> [flags] [token]` and recommends stdin for pipelines.
- `print-token` uses a throwaway keyring. When the verdict is `kid`/`unknown`, the CLI adds a hint that the token may come from `print-token` or a restarted server rather than treating it as a bug.

### D10. Testing strategy

- Classifier table tests: one case per reason, each precedence pair that matters (expired + unknown kid, expired + bad signature, audience + expired), and each claims-label state.
- Parity matrix: for RS256, ES256, and EdDSA, a freshly minted token is accepted by both the `golang-jwt` verdict path and `jwx`'s `jwt.Parse`; tampered, expired, and wrong-issuer tokens are rejected by both.
- Rotation: mint, rotate, verify -> valid + `retired`; advance the grace period and prune -> `kid` + `unknown`.
- Algorithm confusion without waiting for the negative-token work: hand-build tokens with `alg: none` / `HS256` headers over a real payload and assert `alg`, not `signature`.
- Handler tests: strict unknown fields, `aud` string vs array, `leeway` boundary, 1 MiB limit, `405`, `no-store`, 500 on an injected classifier error, and audit attributes that never contain the token.
- CLI tests: decode (valid, expired, foreign, malformed, stdin), verify (JWKS file, JWKS over `httptest`, discovery, aud/alg/leeway, exit 0/1/2, `--json`).
- All time-dependent cases use the injected `Now`; no sleeps.

## Risks / Trade-offs

- **Two libraries disagree** -> The verdict is `golang-jwt`; the parity matrix catches divergence, and a divergence is treated as a bug in whichever library is wrong, not papered over.
- **Unverified claims are mistaken for facts** -> Separate field names, `no-store`, no logging, and a README warning. The envelope never uses `claims` before signature verification.
- **Strict unknown fields break a future caller** -> The API is new and versioned with the binary; rejecting typos is worth more than forward compatibility here.
- **Adversarial input reaches the parser** -> `golang-jwt` is the same parser already used in tests; the HTTP body is bounded. Fuzzing is explicitly deferred but this change is the trigger recorded in FUTURE.md.
- **Token in argv is visible in a process list** -> Low risk for ephemeral test tokens; stdin is documented as the pipeline form.
- **Rotation races between lookup and response** -> `Lookup` and the JWKS snapshot share the read lock; a status may change immediately after the verdict, which is acceptable for a diagnostic.
- **`print-token` tokens fail verification against `serve`** -> Correct, and the `kid` hint plus README guidance turns a confusing failure into an explanation.
- **Extra dependency surface in the binary** -> `golang-jwt` is already a direct module dependency, so no new module; only the linked code grows.

## Migration Plan

Additive only: a new route, two new commands, and a new internal package. No configuration, environment variable, or existing endpoint changes; no data migration. Rolling back means dropping the route and commands, which affects nothing else. `pkg/tester` and existing consumers are untouched.

## Open Questions

- Exact human-readable wording for the `verify` verdict line (cosmetic; `--json` is the stable surface and the tests assert it).
- Whether `verify --jwks` should later accept a single JWK document as well as a JWKS. Deferrable; `jwx` already parses both, so the change would not affect the classifier or the specs.
