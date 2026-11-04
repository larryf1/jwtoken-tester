# Spec Delta

## ADDED Requirements

### Requirement: Legacy OAuth token endpoint selection
`POST /v2/oauth/token` SHALL accept `alg` and `ttl` query parameters. `alg` SHALL be enabled; when omitted, the endpoint SHALL use RS256 when enabled, otherwise the first enabled algorithm. `ttl` SHALL be a non-negative Go duration defaulting to `DEFAULT_TTL` and SHALL NOT exceed a nonzero `MAX_TTL`. Invalid values SHALL return `400`. The bespoke `capabilities`, `idtyp`, `allowedResources`, and `version` claims SHALL remain unchanged.

#### Scenario: Algorithm honored
- **WHEN** a client requests `/v2/oauth/token?Scope=read&alg=ES256` and ES256 is enabled
- **THEN** the token header uses ES256

#### Scenario: Algorithm falls back to an enabled algorithm
- **WHEN** `alg` is omitted and RS256 is disabled
- **THEN** the token is signed with the first enabled algorithm

#### Scenario: TTL honored
- **WHEN** a client requests `/v2/oauth/token?Scope=read&ttl=5m`
- **THEN** the token expires five minutes after issuing and `expires_in` is `300`

#### Scenario: TTL cap enforced
- **WHEN** a requested `ttl` exceeds `MAX_TTL`
- **THEN** the response is `400`

#### Scenario: Invalid selection rejected
- **WHEN** a client requests an unknown algorithm or an invalid or negative `ttl`
- **THEN** the response is `400`

#### Scenario: Bespoke claim profile preserved
- **WHEN** a token is minted by `/v2/oauth/token`
- **THEN** it still carries `capabilities`, `idtyp`, `allowedResources`, and `version`
