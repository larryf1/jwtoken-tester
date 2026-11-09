# http-api/discovery Specification

## Purpose

Serves an OpenID Connect-style discovery document so JWT-aware test clients can auto-configure their issuer, JWKS, and token endpoints without hardcoding URLs.

## Requirements

### Requirement: OIDC discovery document
`GET /.well-known/openid-configuration` SHALL return JSON advertising `issuer`, `jwks_uri`, `token_endpoint`, `introspection_endpoint`, `grant_types_supported`, `token_endpoint_auth_methods_supported`, `subject_types_supported`, `id_token_signing_alg_values_supported`, `response_types_supported`, and `claims_supported`. `token_endpoint`, `jwks_uri`, and `introspection_endpoint` SHALL be derived from the configured issuer. The document SHALL NOT advertise an `authorization_endpoint`, `code_challenge_methods_supported`, or `userinfo_endpoint`. The `id_token_signing_alg_values_supported` list SHALL contain every enabled asymmetric algorithm and SHALL NOT contain `none` or `HS256`.

#### Scenario: Discovery lists enabled algorithms
- **WHEN** a client requests the discovery document and only RS256 is enabled
- **THEN** the response advertises issuer, derived endpoints, and `id_token_signing_alg_values_supported` of `["RS256"]`

#### Scenario: Discovery lists new asymmetric algorithms
- **WHEN** RS384, PS256, PS512, ES384, and ES512 are enabled
- **THEN** `id_token_signing_alg_values_supported` contains all five algorithms

#### Scenario: Discovery includes standard metadata
- **WHEN** a client requests the discovery document
- **THEN** the response includes `jwks_uri`, `token_endpoint` of `<issuer>/oauth/token`, `introspection_endpoint`, `grant_types_supported` of `["client_credentials"]`, and the supported claims `iss`, `sub`, `aud`, `exp`, `nbf`, `iat`, `jti`, `scope`, `client_id`

#### Scenario: Discovery advertises accepted client authentication
- **WHEN** a client requests the discovery document
- **THEN** `token_endpoint_auth_methods_supported` contains `client_secret_basic`, `client_secret_post`, and `none`

#### Scenario: Discovery omits unsupported flows
- **WHEN** a client requests the discovery document
- **THEN** the response has no `authorization_endpoint`, no `code_challenge_methods_supported`, and no `userinfo_endpoint`

#### Scenario: Discovery advertises configured scopes
- **WHEN** `SCOPES` is set
- **THEN** `scopes_supported` contains the configured scopes

#### Scenario: Discovery omits scopes when unconfigured
- **WHEN** `SCOPES` is unset
- **THEN** the response has no `scopes_supported` field

#### Scenario: Response types remain for metadata compatibility
- **WHEN** a client requests the discovery document
- **THEN** `response_types_supported` contains `token` even though no authorization endpoint is advertised

#### Scenario: none and HS256 are not advertised
- **WHEN** negative-token controls or an HMAC secret are configured
- **THEN** `id_token_signing_alg_values_supported` contains neither `none` nor `HS256`

### Requirement: RFC 8414 authorization server metadata
`GET /.well-known/oauth-authorization-server` SHALL return the same JSON metadata document as the OIDC discovery endpoint, including `issuer`, `jwks_uri`, `token_endpoint`, `introspection_endpoint`, `grant_types_supported`, `response_types_supported`, and `token_endpoint_auth_methods_supported`.

#### Scenario: RFC 8414 path returns metadata
- **WHEN** a client requests `/.well-known/oauth-authorization-server`
- **THEN** the response is `200` JSON containing the authorization server metadata

#### Scenario: Both discovery paths agree
- **WHEN** a client requests both discovery paths on the same server
- **THEN** both responses contain the same metadata values

### Requirement: Additive discovery metadata
When `DISCOVERY_EXTRA_JSON` is set to a JSON object, its members SHALL be merged into the discovery document. The derived core fields `issuer`, `jwks_uri`, `token_endpoint`, and `introspection_endpoint` SHALL remain derived and SHALL NOT be replaced. Invalid JSON or a non-object value SHALL fail startup.

#### Scenario: Extra metadata appears
- **WHEN** `DISCOVERY_EXTRA_JSON` contains an additional field
- **THEN** that field appears in both discovery documents

#### Scenario: Core metadata is protected
- **WHEN** `DISCOVERY_EXTRA_JSON` attempts to replace `issuer`, `jwks_uri`, `token_endpoint`, or `introspection_endpoint`
- **THEN** the derived value is served instead

#### Scenario: Invalid extra metadata fails startup
- **WHEN** `DISCOVERY_EXTRA_JSON` is not a JSON object
- **THEN** the server fails to start with a configuration error

### Requirement: Unsigned and HMAC algorithms are never advertised
The discovery documents SHALL NOT advertise `none` or `HS256` in `id_token_signing_alg_values_supported` or any other algorithm list, regardless of CLI or embedding HMAC configuration.

#### Scenario: none is omitted
- **WHEN** negative-token controls are enabled
- **THEN** neither discovery document advertises `none`

#### Scenario: HS256 is omitted
- **WHEN** an embedded issuer is configured with an HMAC secret
- **THEN** neither discovery document advertises `HS256`

