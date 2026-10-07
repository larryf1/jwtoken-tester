# http-api/discovery Specification

## Purpose

Serves an OpenID Connect-style discovery document so JWT-aware test clients can auto-configure their issuer, JWKS, and token endpoints without hardcoding URLs.

## Requirements

### Requirement: OIDC discovery document
`GET /.well-known/openid-configuration` SHALL return JSON advertising `issuer`, `jwks_uri`, `token_endpoint`, `subject_types_supported`, `id_token_signing_alg_values_supported`, `response_types_supported`, and `claims_supported`. The advertised `jwks_uri` and `token_endpoint` SHALL be derived from the configured issuer.

#### Scenario: Discovery lists enabled algorithms
- **WHEN** a client requests the discovery document and only RS256 is enabled
- **THEN** the response advertises issuer, derived endpoints, and `id_token_signing_alg_values_supported` of `["RS256"]`

#### Scenario: Discovery includes standard metadata
- **WHEN** a client requests the discovery document
- **THEN** the response includes `jwks_uri`, `token_endpoint`, and the supported claims `iss`, `sub`, `aud`, `exp`, `nbf`, `iat`, `jti`
