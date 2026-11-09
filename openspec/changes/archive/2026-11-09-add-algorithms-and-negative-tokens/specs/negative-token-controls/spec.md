# Spec Delta

## Purpose

Lets callers mint deliberately unsigned, malformed, wrong-key, and duplicate-claim JWTs behind explicit opt-in controls so negative-path tests do not need hand-crafted tokens.

## ADDED Requirements

### Requirement: Negative token controls are opt-in
The HTTP `/token` endpoint SHALL reject requests that ask for `alg: "none"`, a `corrupt` mode, or an unknown `kid` unless negative tokens are enabled for the server. CLI and embedded callers SHALL opt in per invocation or per server. A rejected request SHALL return a client error and SHALL NOT mint a token.

#### Scenario: Disabled server rejects a negative request
- **WHEN** negative tokens are disabled and `POST /token` requests `alg: "none"`, a `corrupt` mode, or an unknown `kid`
- **THEN** the response is a client error and no token is returned

#### Scenario: Enabled server permits a negative request
- **WHEN** negative tokens are enabled and a request asks for a supported negative control
- **THEN** the request succeeds and returns the requested deliberately invalid token

#### Scenario: CLI opts in per invocation
- **WHEN** `print-token` is run with a negative flag
- **THEN** the token is produced without requiring a server-wide setting

### Requirement: Unsigned tokens use alg none
When negative tokens are enabled, `alg: "none"` SHALL produce an unsigned compact JWS whose header has `alg` of `none` and whose signature segment is empty. `none` SHALL NOT be treated as an enabled signing algorithm and SHALL NOT appear in JWKS, discovery, health, or key listings.

#### Scenario: Unsigned token structure
- **WHEN** a request asks for `alg: "none"`
- **THEN** the returned token has three segments, an `alg` of `none`, and an empty signature segment

#### Scenario: none is never advertised
- **WHEN** the issuer publishes JWKS, discovery, or health metadata
- **THEN** `none` does not appear as a signing algorithm or key

### Requirement: Corrupt modes produce deterministic defects
When negative tokens are enabled, `corrupt` SHALL accept `signature`, `payload`, `header`, `truncate`, and `duplicate_claims`. Each mode SHALL produce a structurally recognizable JWT with the named defect. `duplicate_claims` SHALL duplicate the claim named by `duplicate_claim`, defaulting to `sub`.

#### Scenario: Corrupted signature
- **WHEN** `corrupt` is `signature`
- **THEN** the token keeps a valid three-segment shape but its signature does not verify

#### Scenario: Corrupted payload
- **WHEN** `corrupt` is `payload`
- **THEN** the payload is altered after signing so the signature does not match the claims

#### Scenario: Corrupted header
- **WHEN** `corrupt` is `header`
- **THEN** the header is altered after signing so the signature does not match the header

#### Scenario: Truncated token
- **WHEN** `corrupt` is `truncate`
- **THEN** the token is cut short so it is not a complete three-segment compact JWS

#### Scenario: Duplicate claim
- **WHEN** `corrupt` is `duplicate_claims`
- **THEN** the payload JSON contains a repeated claim name while remaining parseable

### Requirement: Key ID selection and overrides
A `kid` request field SHALL set the protected header `kid`. When the value identifies an active or retired key whose algorithm matches the requested algorithm, that key SHALL sign the token. When it does not identify a matching key, the request SHALL fail unless negative tokens are enabled, in which case the active key SHALL sign the token while it carries the unknown `kid`.

#### Scenario: Retired key signs the token
- **WHEN** `kid` identifies a retired key of the requested algorithm
- **THEN** the token is signed by that retired key and its header carries that `kid`

#### Scenario: Unknown kid produces a wrong-kid token
- **WHEN** negative tokens are enabled and `kid` does not identify a live key
- **THEN** the token is signed by the active key and its header carries the unknown `kid`

#### Scenario: Unknown kid rejected when negative tokens are disabled
- **WHEN** negative tokens are disabled and `kid` does not identify a live key
- **THEN** the request fails with a client error

#### Scenario: Algorithm mismatch rejected
- **WHEN** `kid` identifies a key whose algorithm differs from the requested `alg`
- **THEN** the request fails with a client error

### Requirement: typ and cty are first-class headers
The `typ` and `cty` request fields SHALL set the protected JOSE headers `typ` and `cty`. When `typ` is omitted, the token SHALL carry `typ` of `JWT`. When `cty` is omitted, no `cty` header SHALL be present. Other header parameters, including `x5c`, `x5u`, and `jku`, SHALL remain available through `headers`.

#### Scenario: Custom typ and cty are embedded
- **WHEN** a request supplies `typ` of `at+jwt` and `cty` of `application/json`
- **THEN** the protected header carries both values

#### Scenario: Default typ is JWT
- **WHEN** a request omits `typ`
- **THEN** the protected header carries `typ` of `JWT`

#### Scenario: Extension headers remain available
- **WHEN** a request supplies `x5c`, `x5u`, or `jku` through `headers`
- **THEN** those parameters appear in the protected header

### Requirement: Negative minting is audited
The server SHALL audit every negative-token request, recording the requested control and whether it was accepted or rejected, and SHALL distinguish accepted negative mints from ordinary successful mints.

#### Scenario: Accepted negative mint is logged
- **WHEN** a negative-token request succeeds
- **THEN** the audit event records the negative control and that it was allowed

#### Scenario: Rejected negative mint is logged
- **WHEN** a negative-token request is rejected because negative tokens are disabled
- **THEN** the audit event records the requested control and the rejection
