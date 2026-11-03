# Spec Delta

## MODIFIED Requirements

### Requirement: Service index document
`GET /` SHALL return JSON identifying the service, the running version, an ephemeral-issuer warning, and the list of available endpoints. The endpoint list SHALL include the token verification route alongside the existing health, version, JWKS, discovery, and token routes.

#### Scenario: Index returns service metadata
- **WHEN** a client requests `GET /`
- **THEN** the response is `200` JSON containing `service`, `version`, `warning`, and an `endpoints` array listing the API routes

#### Scenario: Index advertises verification
- **WHEN** a client requests `GET /`
- **THEN** the `endpoints` array includes `POST /verify`
