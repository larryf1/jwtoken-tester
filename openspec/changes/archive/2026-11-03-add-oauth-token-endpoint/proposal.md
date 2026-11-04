# Proposal

## Why

Discovery advertises `/v2/oauth/token`, but that endpoint requires an `X-Client-Id` header and a `Scope` query parameter. A standards-compliant OAuth client that POSTs `grant_type=client_credentials` as a form body cannot use the advertised issuer at all. The same endpoint also hard-codes RS256, so `ALGORITHMS=ES256` leaves the advertised token endpoint unable to mint. There is no RFC 8414 metadata document and no RFC 7662 introspection endpoint.

## What Changes

- Add `POST /oauth/token` implementing the RFC 6749 `client_credentials` grant with `application/x-www-form-urlencoded` input.
  - Accept `client_secret_basic`, `client_secret_post`, and `client_id`-only requests; require `client_id`; ignore the client secret.
  - Mint the generic OAuth profile: `iss`, `sub`, `client_id`, `scope`, `iat`, `nbf`, `exp`, `jti`, and `aud` only when configured.
  - Accept non-standard `alg` and `ttl` test extensions.
  - Return standard OAuth error objects and `Cache-Control: no-store` / `Pragma: no-cache`.
- Add `POST /introspect` implementing RFC 7662 over this issuer's own keyring and issuer.
  - Echo all claims for active tokens, plus authoritative `active` and `token_type`.
  - Return only `active: false` for invalid, expired, unknown-key, or wrong-issuer tokens.
- Add `GET /.well-known/oauth-authorization-server` with RFC 8414 metadata.
  - Point `token_endpoint` at `/oauth/token` and advertise `introspection_endpoint`.
  - Advertise `grant_types_supported: ["client_credentials"]` and the accepted token endpoint auth methods.
  - Omit `authorization_endpoint`, `code_challenge_methods_supported`, and `userinfo_endpoint`, because no authorization-code or OIDC login flow is served.
  - Serve the same metadata at `/.well-known/openid-configuration`, documented as a compatibility hybrid rather than a full OpenID Provider.
- Add `DISCOVERY_EXTRA_JSON` as an additive-only metadata escape hatch; derived core fields always win.
- Add `AUDIENCE` (default: omit `aud`) and `SCOPES` (default: omit `scopes_supported`; advertisement only).
- Make `/v2/oauth/token` honor `alg` and `ttl` query parameters.
  - When `alg` is omitted, use RS256 if enabled, otherwise the first enabled algorithm.
  - Keep `/v2/oauth/token`'s bespoke `capabilities`/`idtyp`/`allowedResources` claim profile unchanged.
- **BREAKING**: Discovery now advertises `token_endpoint` as `/oauth/token` instead of `/v2/oauth/token`. Clients that follow discovery switch from the bespoke v2 claim profile to the generic OAuth profile. `/v2/oauth/token` remains available for compatibility.

## Capabilities

### New Capabilities

- `http-api/oauth`: RFC 6749 `client_credentials` token endpoint and RFC 7662 introspection endpoint, including request parsing, client-auth policy, generic claim profile, error mapping, response headers, and introspection semantics.

### Modified Capabilities

- `http-api/discovery`: adds RFC 8414 metadata, moves the advertised token endpoint, adds introspection and auth-method metadata, and defines additive-only extra metadata.
- `http-api/security`: adds the RFC 8414 document to the GET-only endpoint set and the method-matching contract.
- `http-api/service-metadata`: advertises the new OAuth token, introspection, and RFC 8414 routes in the service index.
- `token-minting`: changes the legacy `/v2/oauth/token` behavior to honor algorithm and TTL selection while preserving its bespoke claim profile.
- `configuration`: adds `AUDIENCE`, `SCOPES`, and `DISCOVERY_EXTRA_JSON` settings with environment/flag precedence and documented defaults.

## Impact

- `internal/server/server.go`: new routes and handlers, discovery changes, legacy endpoint changes, audit events.
- `cmd/jwtoken-tester/main.go`: new environment variables and flags.
- `pkg/tester`: embedded server inherits the new routes; public options may be added for the new settings.
- `README.md`, `docs/openapi.yaml`: document the new endpoints, metadata, and configuration.
- `FUTURE.md` and `CHANGELOG.md`: mark the work shipped after implementation.
- Tests: `internal/server/server_test.go`, `pkg/tester` coverage, and new endpoint/discovery tests.
- No new Go dependencies.
