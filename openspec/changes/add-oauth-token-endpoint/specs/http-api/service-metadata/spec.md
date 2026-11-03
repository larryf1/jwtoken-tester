# Spec Delta

## MODIFIED Requirements

### Requirement: Service index document
`GET /` SHALL return JSON identifying the service, the running version, an ephemeral-issuer warning, and the list of available endpoints. The endpoint list SHALL include the OAuth token, introspection, RFC 8414 metadata, verification, health, version, JWKS, discovery, and raw token routes.

#### Scenario: Index returns service metadata
- **WHEN** a client requests `GET /`
- **THEN** the response is `200` JSON containing `service`, `version`, `warning`, and an `endpoints` array listing the API routes

#### Scenario: Index advertises verification
- **WHEN** a client requests `GET /`
- **THEN** the `endpoints` array includes `POST /verify`

#### Scenario: Index advertises OAuth protocol endpoints
- **WHEN** a client requests `GET /`
- **THEN** the `endpoints` array includes `POST /oauth/token`, `POST /introspect`, and `GET /.well-known/oauth-authorization-server`
