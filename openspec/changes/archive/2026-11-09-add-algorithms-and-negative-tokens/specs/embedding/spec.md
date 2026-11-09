# Spec Delta

## MODIFIED Requirements

### Requirement: Test server options
The embedding SHALL support options for issuer, default TTL, max TTL, rotation interval, grace period, enabled algorithms, rate limits, logging, RSA modulus size, HMAC secret, and negative-token controls. Enabled algorithms SHALL be expressed as embedding-defined algorithm values covering RS256, RS384, RS512, PS256, PS384, PS512, ES256, ES384, ES512, and EdDSA. Rotation SHALL start only when a positive rotation interval is configured. An empty issuer value SHALL select the bound server URL, and enabling no algorithms SHALL fail startup. Negative-token controls SHALL default to disabled.

#### Scenario: Options shape server behavior
- **WHEN** a test enables only RS256 and sets a custom default TTL
- **THEN** only RS256 keys exist and omitted `exp` uses the custom TTL
- **AND** no rotation goroutine runs unless a positive rotation interval was set

#### Scenario: New algorithm options are accepted
- **WHEN** a test enables PS256, RS512, and ES384
- **THEN** only those three keys exist and discovery advertises those algorithms

#### Scenario: RSA size option is honored
- **WHEN** a test configures a 3072-bit RSA size
- **THEN** generated RSA keys use a 3072-bit modulus

#### Scenario: Empty issuer selects the bound URL
- **WHEN** a test passes an empty issuer value
- **THEN** the issuer is the bound server URL rather than a fixed placeholder

#### Scenario: No enabled algorithms is rejected
- **WHEN** a test enables an empty algorithm set
- **THEN** startup fails with a configuration error

#### Scenario: Logging is opt-in
- **WHEN** a test does not configure a logger
- **THEN** the embedded issuer emits no log output, and configuring a logger routes its events to that logger

#### Scenario: Negative tokens are disabled by default
- **WHEN** a test does not enable negative-token controls
- **THEN** requests for `none`, corrupt modes, or an unknown `kid` fail

### Requirement: Token minting through the public API
`Mint` SHALL accept a request carrying claims, an optional algorithm, optional headers, and optional `kid`, `typ`, `cty`, `corrupt`, and `duplicate_claim` fields, and SHALL return the encoded token, its type, and its lifetime as a duration. A zero algorithm SHALL select RS256. An unsupported algorithm, a TTL above the configured maximum, and a malformed request SHALL each return the corresponding public error sentinel. `none` and corrupt modes SHALL be available only when negative-token controls are enabled. HS256 SHALL be available only when an HMAC secret was configured.

#### Scenario: Default algorithm is RS256
- **WHEN** a test mints a token without specifying an algorithm
- **THEN** the token header reports RS256 and it verifies with the active RS256 public key

#### Scenario: Requested algorithm honored
- **WHEN** a test mints with ES256 or EdDSA
- **THEN** the token uses that algorithm and verifies with the matching active public key

#### Scenario: New algorithm honored
- **WHEN** a test mints with PS384 or ES512
- **THEN** the token uses that algorithm and verifies with the matching active public key

#### Scenario: TTL above the maximum is rejected
- **WHEN** a test requests an `exp` further out than the configured maximum TTL
- **THEN** `Mint` returns the TTL error sentinel and no token

#### Scenario: Unsupported algorithm is rejected
- **WHEN** a test requests an algorithm that is not enabled
- **THEN** `Mint` returns the unsupported-algorithm sentinel

#### Scenario: Negative mode is gated
- **WHEN** a test requests `none` or a corrupt mode without enabling negative-token controls
- **THEN** `Mint` returns the unsupported-algorithm or invalid-request sentinel

#### Scenario: Negative mode is available when enabled
- **WHEN** a test enables negative-token controls and requests `none` or a corrupt mode
- **THEN** `Mint` returns the requested unsigned or corrupted token

#### Scenario: Header fields are honored
- **WHEN** a test supplies `kid`, `typ`, or `cty` in the request
- **THEN** the minted token's protected header carries those values

### Requirement: Deterministic key and JWKS views
`Keys` and the JWKS document SHALL include active and retired asymmetric keys and SHALL be ordered by key ID, so repeated calls return the same order. `JWKSJSON` SHALL emit compact JSON. HMAC secrets and unsigned algorithms SHALL NOT appear in either view. The HTTP JWKS endpoint MAY differ in whitespace but SHALL expose the same keys in the same order.

#### Scenario: Ordering is stable across calls
- **WHEN** a test calls `Keys` or `JWKSJSON` twice with no rotation in between
- **THEN** both calls return the same key order, sorted by key ID

#### Scenario: Retired keys remain visible
- **WHEN** keys are rotated and the grace period has not elapsed
- **THEN** `Keys` and JWKS still include the retired keys and their public keys remain retrievable

#### Scenario: Pruning at a chosen time is deterministic
- **WHEN** a test rotates keys and prunes at a time past the grace period
- **THEN** the retired keys disappear from `Keys` and JWKS, and looking one up by key ID returns the key-not-found sentinel

#### Scenario: HTTP and programmatic JWKS agree
- **WHEN** a test compares the JWKS endpoint response with `JWKSJSON`
- **THEN** both contain the same key IDs in the same order

#### Scenario: HMAC and none never appear
- **WHEN** a test configures an HMAC secret or enables negative-token controls
- **THEN** `Keys` and `JWKSJSON` contain only asymmetric public keys

## ADDED Requirements

### Requirement: Embedded HMAC signing requires an explicit secret
An embedded server SHALL accept a caller-supplied HMAC secret for HS256. Without a secret, HS256 requests SHALL fail with the unsupported-algorithm sentinel. The secret SHALL NOT be exposed through any accessor, key listing, or JWKS.

#### Scenario: HS256 works with a secret
- **WHEN** a test configures an HMAC secret of at least 32 bytes and mints with HS256
- **THEN** the token is signed with HS256

#### Scenario: HS256 without a secret is rejected
- **WHEN** a test mints with HS256 and no HMAC secret is configured
- **THEN** `Mint` returns the unsupported-algorithm sentinel

#### Scenario: Secret is not exposed
- **WHEN** a test inspects the server handle's exported accessors and JWKS
- **THEN** the HMAC secret is not returned
