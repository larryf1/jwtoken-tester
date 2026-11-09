# Spec Delta

## MODIFIED Requirements

### Requirement: Mint a signed JWT
The `POST /token` endpoint SHALL accept a JSON body and return a token with its metadata. By default the token SHALL be a signed JWS compact serialization. An empty body SHALL mint an anonymous token with default settings. When negative-token controls are enabled, a request MAY instead return an unsigned `alg: none` token or a deliberately corrupted token.

#### Scenario: Empty body mints an anonymous token
- **WHEN** an empty body is POSTed
- **THEN** the response is a valid token with `access_token`, `token_type: "Bearer"`, and a positive `expires_in`

#### Scenario: Custom claims are embedded
- **WHEN** a JSON body includes arbitrary `claims`
- **THEN** the minted token carries those claims
- **AND** the response `expires_in` equals the token lifetime in seconds

#### Scenario: Versioned OAuth token carries granted capabilities
- **WHEN** a versioned OAuth token request authenticates a client and requests capabilities through the `Scope` parameter
- **THEN** the minted token is versioned and carries the granted capabilities and allowed resources

#### Scenario: Negative mode returns the requested defect
- **WHEN** negative tokens are enabled and the request asks for `alg: "none"` or a `corrupt` mode
- **THEN** the response contains the requested unsigned or corrupted token

### Requirement: Algorithm selection is validated
An omitted `alg` SHALL default to RS256. A recognized-but-disabled or unknown algorithm SHALL fail the request. The endpoint SHALL accept every enabled asymmetric algorithm and, when negative tokens are enabled, `none`. HS256 SHALL be accepted only on surfaces that support it and only when an explicit shared secret is configured.

#### Scenario: Explicit algorithm honored
- **WHEN** `alg` is `ES256` and ES256 is enabled
- **THEN** the token header uses the ES256 signing algorithm

#### Scenario: New asymmetric algorithm honored
- **WHEN** `alg` is `PS256`, `RS384`, or `ES512` and that algorithm is enabled
- **THEN** the token header uses the requested algorithm

#### Scenario: Unsupported algorithm rejected
- **WHEN** `alg` is not a supported or enabled algorithm
- **THEN** the request fails with a client error

#### Scenario: none rejected when negative tokens are disabled
- **WHEN** `alg` is `none` and negative tokens are disabled
- **THEN** the request fails with a client error

### Requirement: Custom protected JOSE headers are embedded
The `headers` object SHALL be embedded as protected JOSE header parameters in the token header. The `typ`, `cty`, and `kid` request fields SHALL control those protected headers directly. The reserved parameters `alg`, `kid`, `typ`, and `cty` SHALL be rejected when supplied through `headers`. `typ` SHALL default to `JWT`.

#### Scenario: Custom header present in token
- **WHEN** a JSON body includes `headers` with a custom parameter
- **THEN** the minted token's header contains that parameter alongside `alg` and `kid`

#### Scenario: typ and cty fields are embedded
- **WHEN** a JSON body includes `typ` and `cty`
- **THEN** the protected header carries those values

#### Scenario: Reserved header parameters are rejected
- **WHEN** `headers` supplies `alg`, `kid`, `typ`, or `cty`
- **THEN** the request fails with a client error

### Requirement: Token errors map to HTTP status codes
The endpoint SHALL return `{"error": "<message>"}` with `400` for invalid JSON, invalid time values, unsupported algorithms, invalid negative controls, and lifetime-cap violations, and `403` when a negative-token control is requested while negative tokens are disabled. It SHALL return `503` when no active signing key is available. A non-POST method SHALL be rejected with `405` and a plain-text body.

#### Scenario: Invalid JSON rejected
- **WHEN** the body is not valid JSON
- **THEN** the response is `400` with an error message

#### Scenario: Wrong method rejected
- **WHEN** a non-POST request is sent to `/token`
- **THEN** the response is `405`

#### Scenario: Disabled negative control is forbidden
- **WHEN** a request asks for `alg: "none"`, a `corrupt` mode, or an unknown `kid` while negative tokens are disabled
- **THEN** the response is `403` with an error message and no token

#### Scenario: Invalid negative control rejected
- **WHEN** a request supplies an unrecognized `corrupt` mode
- **THEN** the response is `400` with an error message

### Requirement: Token minting is audited
The system SHALL log a `token_minted` event for successful mints and a `token_mint_failed` event for failures, including the request ID, client IP, path, algorithm, and relevant request attributes. Negative mints SHALL be distinguishable by recording the negative control and that it was explicitly allowed.

#### Scenario: Successful mint logged
- **WHEN** a token is minted successfully
- **THEN** an audit log entry records the event, algorithm, key id, and `expires_in`

#### Scenario: Failed mint logged
- **WHEN** a token request fails
- **THEN** an audit log entry records the event and the error

#### Scenario: Negative mint logged distinctly
- **WHEN** a negative token is minted successfully
- **THEN** an audit log entry records the event, the negative control, and that it was allowed

### Requirement: Legacy OAuth token endpoint selection
`POST /v2/oauth/token` SHALL accept `alg` and `ttl` query parameters. `alg` SHALL be an enabled asymmetric algorithm; `none`, HS256, and corrupt controls SHALL NOT be accepted. When omitted, the endpoint SHALL use RS256 when enabled, otherwise the first enabled algorithm. `ttl` SHALL be a non-negative Go duration defaulting to `DEFAULT_TTL` and SHALL NOT exceed a nonzero `MAX_TTL`. Invalid values SHALL return `400`. The bespoke `capabilities`, `idtyp`, `allowedResources`, and `version` claims SHALL remain unchanged.

#### Scenario: Algorithm honored
- **WHEN** a client requests `/v2/oauth/token?Scope=read&alg=ES256` and ES256 is enabled
- **THEN** the token header uses ES256

#### Scenario: New asymmetric algorithm honored
- **WHEN** a client requests `/v2/oauth/token?Scope=read&alg=PS384` and PS384 is enabled
- **THEN** the token header uses PS384

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
- **WHEN** a client requests an unknown algorithm, `none`, HS256, or an invalid or negative `ttl`
- **THEN** the response is `400`

#### Scenario: Bespoke claim profile preserved
- **WHEN** a token is minted by `/v2/oauth/token`
- **THEN** it still carries `capabilities`, `idtyp`, `allowedResources`, and `version`

## ADDED Requirements

### Requirement: Token request accepts key and header fields
The `POST /token` request body SHALL accept optional `kid`, `typ`, `cty`, `corrupt`, and `duplicate_claim` string fields in addition to `claims`, `alg`, and `headers`. The `kid`, `typ`, and `cty` fields SHALL control the protected header. The `corrupt` and `duplicate_claim` fields SHALL request a negative control subject to the negative-token gate.

#### Scenario: Key and header fields are accepted
- **WHEN** a JSON body supplies `kid`, `typ`, and `cty`
- **THEN** the minted token's protected header carries those values

#### Scenario: Corrupt field requests a defect
- **WHEN** a JSON body supplies `corrupt` of `signature`
- **THEN** the response contains a token whose signature does not verify
