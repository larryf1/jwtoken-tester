# Spec Delta

## MODIFIED Requirements

### Requirement: Mint a signed JWT
The `POST /token` endpoint SHALL accept a JSON body and return a signed JWS compact serialization token with its metadata. An empty body SHALL mint an anonymous token with default settings.

#### Scenario: Empty body mints an anonymous token
- **WHEN** an empty body is POSTed
- **THEN** the response is a valid token with `access_token`, `token_type: "Bearer"`, and a positive `expires_in`

#### Scenario: Custom claims are embedded
- **WHEN** a JSON body includes arbitrary `claims`
- **THEN** the minted token carries those claims
- AND the response `expires_in` equals the token lifetime in seconds

#### Scenario: Versioned OAuth token carries granted capabilities
- **WHEN** a versioned OAuth token request authenticates a client and requests capabilities through the `Scope` parameter
- **THEN** the minted token is versioned and carries the granted capabilities and allowed resources
