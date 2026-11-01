# Spec Delta

## MODIFIED Requirements

### Requirement: Start an in-process issuer for tests
`Start` SHALL start an in-process issuer over an `httptest` server and return a handle plus an error; the caller is responsible for closing it. `NewServer` SHALL start the same issuer, register automatic cleanup on the testing value, and return only the handle. When no explicit issuer is configured, the bound server URL SHALL be used as the issuer.

#### Scenario: Default issuer derived from server URL
- **WHEN** a test calls `NewServer(t)` without `WithIssuer`
- **THEN** the server is started, its `URL()` equals its `Issuer()`, and the discovery document advertises that URL
- **AND** cleanup is registered so the server closes when the test finishes

#### Scenario: Explicit issuer honored
- **WHEN** a test configures `WithIssuer("https://idp.example.com")`
- **THEN** minted tokens carry that issuer and the discovery document advertises it

#### Scenario: Start outside a test function
- **WHEN** a caller invokes `Start` without a testing value
- **THEN** a running handle is returned and the caller can release it with `Close`

#### Scenario: Failed startup returns no handle
- **WHEN** startup fails because of an invalid option
- **THEN** `Start` returns an error and no listener or background goroutine remains running

### Requirement: Test server options
The embedding SHALL support options for issuer, default TTL, max TTL, rotation interval, grace period, enabled algorithms, rate limits, and logging. Enabled algorithms SHALL be expressed as embedding-defined algorithm values. Rotation SHALL start only when a positive rotation interval is configured. An empty issuer value SHALL select the bound server URL, and enabling no algorithms SHALL fail startup.

#### Scenario: Options shape server behavior
- **WHEN** a test enables only RS256 and sets a custom default TTL
- **THEN** only RS256 keys exist and omitted `exp` uses the custom TTL
- **AND** no rotation goroutine runs unless a positive rotation interval was set

#### Scenario: Empty issuer selects the bound URL
- **WHEN** a test passes an empty issuer value
- **THEN** the issuer is the bound server URL rather than a fixed placeholder

#### Scenario: No enabled algorithms is rejected
- **WHEN** a test enables an empty algorithm set
- **THEN** startup fails with a configuration error

#### Scenario: Logging is opt-in
- **WHEN** a test does not configure a logger
- **THEN** the embedded issuer emits no log output, and configuring a logger routes its events to that logger

### Requirement: In-process server accessors
The returned server handle SHALL expose its base URL, issuer, HTTP client, HTTP handler, token minting, and read-only key material: the key list, the active key ID for an algorithm, a public key by key ID, that key's PEM encoding, and the JWKS document. It SHALL NOT expose private keys or internal implementation types.

#### Scenario: Accessors expose the running services
- **WHEN** a test holds a server handle
- **THEN** it can mint tokens, enumerate keys, read public keys and PEM, fetch JWKS JSON, use the bound HTTP client and handler, and close the server explicitly

#### Scenario: Private key material is unreachable
- **WHEN** a consumer inspects the exported surface of the embedding package
- **THEN** no exported function or type returns a private key or an internal package type

#### Scenario: Handler is always available
- **WHEN** a test obtains the handler without configuring an explicit issuer
- **THEN** the handler serves discovery, JWKS, and token endpoints for the bound URL issuer

## ADDED Requirements

### Requirement: Token minting through the public API
`Mint` SHALL accept a request carrying claims, an optional algorithm, and optional headers, and SHALL return the encoded token, its type, and its lifetime as a duration. A zero algorithm SHALL select RS256. An unsupported algorithm, a TTL above the configured maximum, and a malformed request SHALL each return the corresponding public error sentinel.

#### Scenario: Default algorithm is RS256
- **WHEN** a test mints a token without specifying an algorithm
- **THEN** the token header reports RS256 and it verifies with the active RS256 public key

#### Scenario: Requested algorithm honored
- **WHEN** a test mints with ES256 or EdDSA
- **THEN** the token uses that algorithm and verifies with the matching active public key

#### Scenario: TTL above the maximum is rejected
- **WHEN** a test requests an `exp` further out than the configured maximum TTL
- **THEN** `Mint` returns the TTL error sentinel and no token

#### Scenario: Unsupported algorithm is rejected
- **WHEN** a test requests an algorithm that is not enabled
- **THEN** `Mint` returns the unsupported-algorithm sentinel

### Requirement: Deterministic key and JWKS views
`Keys` and the JWKS document SHALL include active and retired keys and SHALL be ordered by key ID, so repeated calls return the same order. `JWKSJSON` SHALL emit compact JSON. The HTTP JWKS endpoint MAY differ in whitespace but SHALL expose the same keys in the same order.

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

### Requirement: Closing releases resources without invalidating the issuer
`Close` SHALL stop the listener, cancel key rotation, stop internal cleanup, and wait for those goroutines to finish. It SHALL be idempotent and safe to call concurrently. Minting and key accessors SHALL continue to work after `Close` because they use in-memory state only.

#### Scenario: Close releases listener and goroutines
- **WHEN** a test closes a server that was started with rotation enabled
- **THEN** the listener is closed, rotation and cleanup goroutines have exited, and no goroutine remains from that server

#### Scenario: Close is idempotent and concurrent-safe
- **WHEN** `Close` is called multiple times, including concurrently
- **THEN** every call returns without panicking or blocking

#### Scenario: Minting still works after Close
- **WHEN** a test mints a token and reads keys after `Close`
- **THEN** the token is produced and the key accessors return the same in-memory key set
