# token-minting Specification

## Purpose

Defines the observable behavior of the `POST /token` endpoint — request shape, claim handling, time-value parsing, TTL defaults and caps, algorithms, custom JOSE headers, response format, and error mapping.

## Requirements

### Requirement: Mint a signed JWT
The `POST /token` endpoint SHALL accept a JSON body and return a signed JWS compact serialization token with its metadata. An empty body SHALL mint an anonymous token with default settings.

#### Scenario: Empty body mints an anonymous token
- **WHEN** an empty body is POSTed
- **THEN** the response is a valid token with `access_token`, `token_type: "Bearer"`, and a positive `expires_in`

#### Scenario: Custom claims are embedded
- **WHEN** a JSON body includes arbitrary `claims`
- **THEN** the minted token carries those claims
- **AND** the response `expires_in` equals the token lifetime in seconds

### Requirement: Standard claims are injected unless provided
The system SHALL inject `iss`, `iat`, and `nbf` when absent. Explicit values in `claims` SHALL win over injected defaults, including an override of `iss`.

#### Scenario: Standard claims injected by default
- **WHEN** a token is minted without `iss`, `iat`, or `nbf` in `claims`
- **THEN** the token has the configured issuer as `iss` and current time as `iat` and `nbf`

#### Scenario: Explicit issuer overrides injection
- **WHEN** `claims.iss` is set to a different value
- **THEN** the minted token uses that value as `iss`

### Requirement: exp, iat, and nbf accept multiple time formats
`exp`, `iat`, and `nbf` claims SHALL accept epoch seconds (number or numeric string), Go duration strings (`90m`, `in 1h`, negative for the past), and RFC 3339 timestamps. An unparsable time value SHALL fail the request.

#### Scenario: Epoch seconds accepted
- **WHEN** `exp` is given as the epoch second `1800000000`
- **THEN** the token expires at that instant

#### Scenario: Duration string accepted
- **WHEN** `exp` is given as `"in 1h"`
- **THEN** the token expires one hour from the current time

#### Scenario: RFC 3339 timestamp accepted
- **WHEN** `iat` is given as an RFC 3339 timestamp
- **THEN** the token carries exactly that issued-at time

#### Scenario: Invalid time value rejected
- **WHEN** `exp` is given as a value that is neither epoch, duration, nor RFC 3339
- **THEN** the request fails with a client error

### Requirement: Default and maximum token lifetimes
An omitted `exp` SHALL expire the token at current time plus `DEFAULT_TTL`. A requested lifetime beyond `MAX_TTL` (when the cap is nonzero) SHALL be refused. Tokens that are already expired SHALL be minted successfully.

#### Scenario: Default expiration applied
- **WHEN** `exp` is omitted
- **THEN** the token expires `DEFAULT_TTL` after issuing

#### Scenario: Lifetime cap enforced
- **WHEN** the computed lifetime exceeds `MAX_TTL`
- **THEN** the request is refused with a client error

#### Scenario: Already-expired token minted
- **WHEN** `exp` is set in the past
- **THEN** the token is minted with `expires_in` reflecting the negative lifetime

### Requirement: Algorithm selection is validated
An omitted `alg` SHALL default to RS256. A recognized-but-disabled or unknown algorithm SHALL fail the request.

#### Scenario: Explicit algorithm honored
- **WHEN** `alg` is `ES256` and ES256 is enabled
- **THEN** the token header uses the ES256 signing algorithm

#### Scenario: Unsupported algorithm rejected
- **WHEN** `alg` is not a supported or enabled algorithm
- **THEN** the request fails with a client error

### Requirement: Custom protected JOSE headers are embedded
The `headers` object SHALL be embedded as protected JOSE header parameters in the token header.

#### Scenario: Custom header present in token
- **WHEN** a JSON body includes `headers` with a custom parameter
- **THEN** the minted token's header contains that parameter alongside `alg` and `kid`

### Requirement: Token errors map to HTTP status codes
The endpoint SHALL return `{"error": "<message>"}` with `400` for invalid JSON, invalid time values, unsupported algorithms, and lifetime-cap violations, and `503` when no active signing key is available. A non-POST method SHALL be rejected with `405` and a plain-text body.

#### Scenario: Invalid JSON rejected
- **WHEN** the body is not valid JSON
- **THEN** the response is `400` with an error message

#### Scenario: Wrong method rejected
- **WHEN** a non-POST request is sent to `/token`
- **THEN** the response is `405`

### Requirement: Token request body is size-bounded
The system SHALL reject `POST /token` request bodies larger than 1 MiB with a client error.

#### Scenario: Oversized body rejected
- **WHEN** a client submits a request body larger than 1 MiB
- **THEN** the request fails with a `400` error and no token is returned

### Requirement: Token minting is audited
The system SHALL log a `token_minted` event for successful mints and a `token_mint_failed` event for failures, including the request ID, client IP, path, algorithm, and relevant request attributes.

#### Scenario: Successful mint logged
- **WHEN** a token is minted successfully
- **THEN** an audit log entry records the event, algorithm, key id, and `expires_in`

#### Scenario: Failed mint logged
- **WHEN** a token request fails
- **THEN** an audit log entry records the event and the error
