# Spec Delta

## Purpose

Exposes jwtoken-tester as an embeddable Go test helper that starts an in-process issuer over `httptest` so Go test suites can mint and verify tokens without spawning a binary.

## ADDED Requirements

### Requirement: Start an in-process issuer for tests
`NewServer` SHALL start an in-process issuer, register automatic cleanup on the testing value, and return a server handle plus its base URL. When no explicit issuer is configured, the returned URL SHALL be used as the issuer.

#### Scenario: Default issuer derived from server URL
- **WHEN** a test calls `NewServer(t)` without `WithIssuer`
- **THEN** the server is started and its `URL()` equals the configured issuer value
- **AND** cleanup is registered so the server closes when the test finishes

#### Scenario: Explicit issuer honored
- **WHEN** a test configures `WithIssuer("https://idp.example.com")`
- **THEN** minted tokens carry that issuer and the discovery document advertises it

### Requirement: Test server options
The embedding SHALL support options for issuer, default TTL, max TTL, rotation interval, grace period, enabled algorithms, and rate limits. Rotation SHALL start only when a positive rotation interval is configured.

#### Scenario: Options shape server behavior
- **WHEN** a test enables only RS256 and sets a custom default TTL
- **THEN** only RS256 keys exist and omitted `exp` uses the custom TTL
- **AND** no rotation goroutine runs unless a positive rotation interval was set

### Requirement: In-process server accessors
The returned server handle SHALL expose its base URL, an HTTP client, the token factory, the key ring, and the issuer, and SHALL support explicit closing.

#### Scenario: Accessors expose the running services
- **WHEN** a test holds a server handle
- **THEN** it can mint tokens through the factory, read the key ring, use the bound HTTP client, and close the server explicitly