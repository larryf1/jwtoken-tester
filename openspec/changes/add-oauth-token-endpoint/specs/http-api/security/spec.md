# Spec Delta

## MODIFIED Requirements

### Requirement: Read-only endpoints reject non-GET methods
Every GET-only endpoint — `/`, `/healthz`, `/version`, `/.well-known/openid-configuration`, `/.well-known/oauth-authorization-server`, and the JWKS routes — SHALL reject non-GET methods with `405`.

#### Scenario: POST to a GET-only endpoint
- **WHEN** a client sends a non-GET method to a GET-only endpoint
- **THEN** the response is `405`

#### Scenario: POST to the RFC 8414 metadata endpoint
- **WHEN** a client sends `POST /.well-known/oauth-authorization-server`
- **THEN** the response is `405`
