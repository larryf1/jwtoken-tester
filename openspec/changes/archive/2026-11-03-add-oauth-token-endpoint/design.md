# Design

## Context

The existing issuer has three token surfaces with different contracts: `POST /token` is a raw JSON JWT builder, `POST /v2/oauth/token` is a bespoke OAuth-shaped endpoint, and `POST /verify` self-checks tokens against the live keyring. Discovery currently points at the bespoke endpoint and omits OAuth authorization-server metadata. See `proposal.md` for the motivation.

The server builds its route table in `internal/server.Handler`, mints through `internal/tokenfactory.Factory`, verifies through `internal/verify.Verify`, and reads configuration in `cmd/jwtoken-tester/main.go`. `pkg/tester` embeds the same server over `httptest`.

## Goals / Non-Goals

**Goals:**

- One RFC 6749 `client_credentials` endpoint that generic OAuth clients can use through discovery.
- One RFC 7662 introspection endpoint that reuses the existing verification engine.
- One shared discovery document served at both well-known paths, with additive-only overrides.
- Algorithm and TTL selection that makes `ALGORITHMS=ES256` work end to end.
- No new dependencies; all parsing and responses use the standard library.

**Non-Goals:**

- Authorization-code, PKCE, `id_token`, `/userinfo`, refresh tokens, users, or consent.
- Client registration or client-secret validation.
- Claim/IdP profiles; `/v2/oauth/token` remains the only bespoke profile.
- JWKS caching headers, CORS, metrics, native TLS, or other operability work.
- Normalizing issuer trailing slashes or broader startup validation.

## Decisions

### Keep `/token`, `/oauth/token`, and `/v2/oauth/token` as distinct surfaces

`/token` stays the raw builder. `/oauth/token` becomes the generic standards-shaped surface. `/v2/oauth/token` stays the legacy bespoke profile. This avoids overloading one endpoint with three claim-shape modes and leaves claim profiles for a later change.

Alternative considered: make `/oauth/token` emit both `scope` and the v2 claims. Rejected because the two representations can drift and the v2 profile belongs to the legacy endpoint.

### Use functional options for the new server settings

`server.New` already accepts `Option` values for cross-cutting settings such as the logger. Add `WithAudience`, `WithScopes`, and `WithDiscoveryExtra` rather than extending the positional signature. `pkg/tester` gets matching options so embedded users have parity; unset options preserve current behavior.

Alternative considered: a `server.Config` struct. Rejected because it would restructure an established constructor for three optional values.

### Build one discovery document, apply extras first, then derived fields

A single `discoveryDocument` helper returns the shared metadata. When extras are configured, start with the extra map and overwrite it with derived core fields (`issuer`, `jwks_uri`, `token_endpoint`, `introspection_endpoint`). Both discovery routes call the same helper. This guarantees the two paths cannot drift and keeps core endpoints truthful.

Alternative considered: two separate document builders. Rejected because RFC 8414 and OIDC metadata overlap almost entirely here.

### Default the OAuth algorithm to the first enabled algorithm

`/oauth/token` and `/v2/oauth/token` select `RS256` when it is enabled, otherwise the first entry from `ring.EnabledAlgorithms()`. `/token` keeps its existing “omitted alg means RS256” contract. This makes `ALGORITHMS=ES256` usable through discovery without changing the raw token builder.

Alternative considered: require an explicit `alg` whenever RS256 is disabled. Rejected because generic OAuth clients cannot send the non-standard `alg` extension.

### Reuse `verify.Verify` for introspection

Introspection calls `verify.Verify` with this issuer’s keyring and issuer, then projects the verdict: `active: true` plus a clone of `Claims` for a valid token, or `active: false` for anything invalid. The internal reason is logged, never returned. This keeps `/verify` and `/introspect` aligned and avoids a second validation implementation.

Alternative considered: parse JWT claims without verification and expose them. Rejected because it would vouch for unverified tokens.

### Keep OAuth errors separate from the legacy error shape

The new endpoints use `{"error": "<code>", "error_description": "<message>"}`. `/v2/oauth/token` keeps its existing `{"error": "<message>"}` shape so current callers are not broken. A shared `writeOAuthError` helper handles the new envelope.

### Treat `alg` and `ttl` as test extensions in the endpoint’s natural parameter location

`/oauth/token` reads them from the form body; `/v2/oauth/token` reads them from the query string. `ttl` accepts Go duration syntax, is capped by `MAX_TTL`, and rejects invalid or negative values. `ttl` is translated into an `exp` claim for `tokenfactory.Mint`, so the existing time-value parser and lifetime cap stay in one place.

### Include no-store headers now

Token and introspection responses set `Cache-Control: no-store` and `Pragma: no-cache`. RFC 6749 and RFC 7662 require it, and it is a response-header change rather than a caching feature. FUTURE #6 still owns JWKS cache metadata.

## Risks / Trade-offs

- [Discovery now advertises a different token endpoint and claim profile] → Keep `/v2/oauth/token` available, document the migration, and mark the change breaking. Generic clients that could not use the old endpoint are the primary audience.
- [The OIDC discovery path is not a full OpenID Provider document] → Document it as a compatibility hybrid; the RFC 8414 path is the standards-compliant one. Do not advertise an authorization endpoint the server does not serve.
- [Introspection echoes arbitrary claims] → The caller already holds the JWT; inactive responses contain no claims, and no-store prevents caching.
- [Additive extras can still override non-core metadata] → Protect the four derived core fields and document that other fields are caller-controlled.
- [No `invalid_client` path] → This is deliberate for a test issuer; a future opt-in validation mode can add it without changing the new endpoint’s request shape.
- [New settings expand the configuration surface] → Keep all three optional, default to current behavior, and expose the same options through `pkg/tester`.

## Migration Plan

1. Add the new handlers and settings, keep `/v2/oauth/token` and `/token` working, and ship the discovery switch together.
2. Update README, OpenAPI, and the service index so the new routes are discoverable.
3. Callers that followed discovery and depended on the v2 claim shape must either use `/v2/oauth/token` directly or adopt the generic `scope` claim.
4. Rollback is configuration-free: remove the new routes and restore the previous `token_endpoint` value. No persisted state or data migration exists.
