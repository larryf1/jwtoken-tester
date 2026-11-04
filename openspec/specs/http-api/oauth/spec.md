# http-api/oauth Specification

## Purpose

Defines the RFC 6749 client-credentials token endpoint and RFC 7662 introspection endpoint used by machine-to-machine test clients, including permissive client authentication, the generic token claim profile, algorithm and TTL selection, error mapping, and response caching rules.

## Requirements

### Requirement: Client-credentials token request
`POST /oauth/token` SHALL accept `application/x-www-form-urlencoded` bodies containing `grant_type=client_credentials`. It SHALL accept `scope`, `client_id`, `client_secret`, `alg`, and `ttl` form parameters. A missing or unsupported `grant_type` SHALL be rejected with a standard OAuth error. A body that is not form-encoded SHALL be rejected with `invalid_request`.

#### Scenario: Valid client-credentials request
- **WHEN** a client posts `grant_type=client_credentials&client_id=test-client&scope=read write`
- **THEN** the response is `200` with an access token

#### Scenario: Missing grant type
- **WHEN** a client posts a form body without `grant_type`
- **THEN** the response is `400` with `error` of `invalid_request`

#### Scenario: Unsupported grant type
- **WHEN** a client posts `grant_type=password`
- **THEN** the response is `400` with `error` of `unsupported_grant_type`

#### Scenario: Non-form body rejected
- **WHEN** a client posts a JSON body to `/oauth/token`
- **THEN** the response is `400` with `error` of `invalid_request`

### Requirement: Permissive client authentication
The token endpoint SHALL require a client identifier but SHALL NOT validate the client secret. It SHALL accept HTTP Basic, `client_secret_post`, and `client_id`-only requests. A missing `client_id` SHALL return `400 invalid_request`. An incorrect secret SHALL still receive a token.

#### Scenario: Basic authentication accepted
- **WHEN** a client sends `Authorization: Basic` with a client identifier and secret
- **THEN** the token is minted

#### Scenario: Form authentication accepted
- **WHEN** a client sends `client_id` and `client_secret` in the form body
- **THEN** the token is minted

#### Scenario: Client identifier only accepted
- **WHEN** a client sends only `client_id` in the form body
- **THEN** the token is minted

#### Scenario: Missing client identifier rejected
- **WHEN** a client sends `grant_type=client_credentials` with no client identifier
- **THEN** the response is `400` with `error` of `invalid_request`

#### Scenario: Incorrect secret ignored
- **WHEN** a client sends a `client_secret` that does not match any configured value
- **THEN** the token is minted because no secret is validated

### Requirement: Generic OAuth token claim profile
Tokens minted by `/oauth/token` SHALL contain `iss`, `sub` and `client_id` set to the client identifier, `iat`, `nbf`, `exp`, `jti`, and a space-normalized `scope` claim when scope is requested. They SHALL contain `aud` only when `AUDIENCE` is configured. They SHALL NOT contain `capabilities`, `idtyp`, `allowedResources`, or `version`.

#### Scenario: Scope mapped to standard claim
- **WHEN** a client requests `scope=read write`
- **THEN** the token contains `scope` with value `read write` and no `capabilities` claim

#### Scenario: Scope whitespace normalized
- **WHEN** a client requests a scope containing repeated or leading whitespace
- **THEN** the token contains a single-space-delimited `scope` value

#### Scenario: Scope omitted
- **WHEN** a client sends no `scope`
- **THEN** the token contains no `scope` claim

#### Scenario: Audience configured
- **WHEN** `AUDIENCE` is set and a token is minted
- **THEN** the token contains the configured `aud` value

#### Scenario: Audience omitted
- **WHEN** `AUDIENCE` is unset and a token is minted
- **THEN** the token contains no `aud` claim

#### Scenario: Legacy claims absent
- **WHEN** a token is minted by `/oauth/token`
- **THEN** it does not contain `capabilities`, `idtyp`, `allowedResources`, or `version`

### Requirement: Algorithm and TTL selection on the OAuth token endpoint
The token endpoint SHALL accept `alg` and `ttl` form parameters. `alg` SHALL be an enabled algorithm; when omitted, the endpoint SHALL use RS256 when enabled, otherwise the first enabled algorithm. `ttl` SHALL be a non-negative Go duration that defaults to `DEFAULT_TTL` and SHALL NOT exceed `MAX_TTL` when that cap is nonzero. Invalid values SHALL return `invalid_request`.

#### Scenario: Algorithm honored
- **WHEN** a client requests `alg=ES256` and ES256 is enabled
- **THEN** the token header uses ES256

#### Scenario: Algorithm falls back to an enabled algorithm
- **WHEN** `alg` is omitted and RS256 is disabled
- **THEN** the token is signed with the first enabled algorithm

#### Scenario: TTL honored
- **WHEN** a client requests `ttl=5m`
- **THEN** the token expires five minutes after issuing and `expires_in` is `300`

#### Scenario: TTL cap enforced
- **WHEN** a client requests a `ttl` beyond `MAX_TTL`
- **THEN** the response is `400` with `error` of `invalid_request`

#### Scenario: Invalid TTL rejected
- **WHEN** a client requests a `ttl` that is not a non-negative Go duration
- **THEN** the response is `400` with `error` of `invalid_request`

#### Scenario: Disabled algorithm rejected
- **WHEN** a client requests an algorithm that is unknown or not enabled
- **THEN** the response is `400` with `error` of `invalid_request`

### Requirement: OAuth token response and error contract
Responses SHALL be JSON. Success SHALL include `access_token`, `token_type` of `Bearer`, `expires_in`, and `scope` when scope was requested. Token responses SHALL include `Cache-Control: no-store` and `Pragma: no-cache`. Errors SHALL use `{"error": "<code>", "error_description": "<message>"}` with standard OAuth codes. A missing signing key SHALL return `503 temporarily_unavailable`; an internal failure SHALL return `500 server_error`. Non-POST methods SHALL return `405`.

#### Scenario: Success envelope
- **WHEN** a token is minted successfully
- **THEN** the response contains `access_token`, `token_type`, and `expires_in`

#### Scenario: Requested scope echoed
- **WHEN** a token is minted with a requested scope
- **THEN** the response includes the same `scope` value

#### Scenario: Token response is not cached
- **WHEN** a token is minted successfully
- **THEN** the response includes `Cache-Control: no-store` and `Pragma: no-cache`

#### Scenario: Standard error envelope
- **WHEN** a token request is rejected
- **THEN** the response contains `error` and `error_description` fields

#### Scenario: Missing signing key
- **WHEN** no active signing key is available
- **THEN** the response is `503` with `error` of `temporarily_unavailable`

#### Scenario: Non-POST method rejected
- **WHEN** a client sends `GET /oauth/token`
- **THEN** the response is `405`

### Requirement: OAuth token request body is size-bounded
The token endpoint SHALL reject request bodies larger than 1 MiB with `400 invalid_request` and no token.

#### Scenario: Oversized token request rejected
- **WHEN** a client submits a form body larger than 1 MiB
- **THEN** the response is `400` with `error` of `invalid_request`

### Requirement: Introspection request
`POST /introspect` SHALL accept `application/x-www-form-urlencoded` bodies containing `token` and an optional `token_type_hint`. The hint SHALL be accepted and ignored. A missing `token` SHALL return `400 invalid_request`. The endpoint SHALL use the same permissive client authentication as the token endpoint and SHALL include `Cache-Control: no-store`. Non-POST methods SHALL return `405`, and bodies larger than 1 MiB SHALL be rejected with `400 invalid_request`.

#### Scenario: Valid introspection request
- **WHEN** a client posts a valid token as a form field
- **THEN** the response is `200` and contains an `active` field

#### Scenario: Missing token rejected
- **WHEN** a client posts an empty form body
- **THEN** the response is `400` with `error` of `invalid_request`

#### Scenario: Token type hint ignored
- **WHEN** a client posts `token_type_hint=refresh_token` with a valid access token
- **THEN** the token is still introspected

#### Scenario: Introspection response is not cached
- **WHEN** an introspection request completes
- **THEN** the response includes `Cache-Control: no-store`

#### Scenario: Non-POST introspection rejected
- **WHEN** a client sends `GET /introspect`
- **THEN** the response is `405`

#### Scenario: Oversized introspection request rejected
- **WHEN** a client submits a form body larger than 1 MiB
- **THEN** the response is `400` with `error` of `invalid_request`

### Requirement: Introspection verdict
The introspection endpoint SHALL verify the supplied token against this issuer's keyring and configured issuer. It SHALL return `active: true` only when the signature verifies, the key identifier is known, the issuer matches, and the time claims are valid. It SHALL return `200` with `active: false` for invalid signatures, unknown keys, wrong issuers, expired or not-yet-valid tokens, and malformed tokens.

#### Scenario: Active token reported
- **WHEN** a valid, unexpired token from this issuer is introspected
- **THEN** the response contains `active: true`

#### Scenario: Expired token reported inactive
- **WHEN** an expired token from this issuer is introspected
- **THEN** the response contains `active: false`

#### Scenario: Wrong issuer reported inactive
- **WHEN** a token signed by this keyring but carrying a different `iss` is introspected
- **THEN** the response contains `active: false`

#### Scenario: Unknown key reported inactive
- **WHEN** a token with an unknown `kid` is introspected
- **THEN** the response contains `active: false`

#### Scenario: Bad signature reported inactive
- **WHEN** a token with a corrupted signature is introspected
- **THEN** the response contains `active: false`

#### Scenario: Malformed token reported inactive
- **WHEN** a value that is not a compact JWS is introspected
- **THEN** the response contains `active: false`

#### Scenario: Retired key within grace reported active
- **WHEN** an unexpired token signed by a retired key still inside its grace window is introspected
- **THEN** the response contains `active: true`

### Requirement: Introspection response contents
For an active token, the introspection response SHALL echo every claim from the token and SHALL set `active` and `token_type` authoritatively. For an inactive token, the response SHALL contain only `active: false` and SHALL NOT include token claims.

#### Scenario: Custom claims echoed
- **WHEN** an active token contains a custom claim
- **THEN** the introspection response includes that claim

#### Scenario: Active and token type are authoritative
- **WHEN** an active token contains claims named `active` or `token_type`
- **THEN** the response uses `active: true` and `token_type` of `Bearer`

#### Scenario: Inactive response hides claims
- **WHEN** an invalid or expired token is introspected
- **THEN** the response contains `active: false` and no token claims

### Requirement: OAuth endpoint auditing
The token and introspection endpoints SHALL log an audit event containing the request ID, client IP, and path. Token events SHALL include the signing algorithm, scope, and lifetime. Introspection events SHALL include the active verdict and, server-side only, the failure reason. Client secrets and token values SHALL NOT be logged.

#### Scenario: Successful mint audited
- **WHEN** a token is minted through `/oauth/token`
- **THEN** an audit event records the algorithm, scope, and `expires_in`

#### Scenario: Failed mint audited
- **WHEN** a token request fails
- **THEN** an audit event records the error

#### Scenario: Introspection audited
- **WHEN** a token is introspected
- **THEN** an audit event records the active verdict and the internal reason

#### Scenario: Secrets and tokens not logged
- **WHEN** token or introspection requests are audited
- **THEN** the client secret and token value do not appear in the log entry
