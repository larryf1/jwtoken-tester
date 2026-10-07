# Spec Delta

## Purpose

Manages the lifecycle of in-memory signing keys — generation per algorithm, RFC 7638 thumbprint-derived key IDs, rotation, the grace window for retired keys, pruning, and JWKS access.

## ADDED Requirements

### Requirement: Keypairs are generated in memory at startup
The system SHALL generate one active signing keypair per enabled algorithm from a secure random source at startup. RSA-2048 keys SHALL be used for RS256, P-256 curve keys for ES256, and Ed25519 keys for EdDSA. Private keys SHALL exist only in memory and SHALL never be persisted to disk, environment, logs, or HTTP responses.

#### Scenario: One active key per enabled algorithm
- **WHEN** the server starts with RS256, ES256, and EdDSA enabled
- **THEN** exactly one active signing key exists for each of the three algorithms

#### Scenario: JWKS exposes public keys only
- **WHEN** a client fetches the JWKS
- **THEN** every returned key is a public JWK and no private key material is present

### Requirement: Key IDs are RFC 7638 thumbprints
The `kid` of every key SHALL be the unpadded URL-safe base64 SHA-256 thumbprint of its public JWK, and every published JWK SHALL carry `kid`, `use=sig`, and the signing algorithm.

#### Scenario: JWKS entries carry matching kid, use, and alg
- **WHEN** a client reads a JWKS entry
- **THEN** the entry has a thumbprint-derived `kid`, `use=sig`, and an `alg` of RS256, ES256, or EdDSA

### Requirement: Signing keys rotate on a fixed interval
When rotation is enabled, the system SHALL replace the active key of every enabled algorithm on each rotation tick. The previous active key SHALL become a retired key timestamped at the rotation time. Rotation SHALL be disabled when the configured interval is zero.

#### Scenario: Active key is replaced on rotation
- **WHEN** a rotation occurs
- **THEN** each enabled algorithm has a new active key with a different `kid`, and the former key is retained as retired

#### Scenario: Retired keys accumulate during heavy rotation
- **WHEN** multiple rotations occur within a single grace period
- **THEN** the JWKS MAY contain multiple retired keys per algorithm alongside the active key

### Requirement: Retired keys stay published during the grace period
A retired key SHALL remain available in the JWKS and by `kid` lookup until its grace window elapses. Once past the grace window, the key SHALL be pruned from the live set; RSA and Ed25519 private key material SHALL be zeroized in memory, while ECDSA private keys are released with the process.

#### Scenario: Retired key reachable inside the grace window
- **WHEN** a consumer fetches a retired key's `kid` before the grace period elapses
- **THEN** the JWK is returned successfully

#### Scenario: Retired key pruned after the grace window
- **WHEN** a grace period has fully elapsed for a retired key and a subsequent rotation occurs
- **THEN** the key no longer appears in the JWKS and is no longer queryable by `kid`

### Requirement: Algorithm enablement governs key operations
The system SHALL only generate, sign, and advertise keys for enabled algorithms. Operations requesting a disabled or unknown algorithm SHALL fail.

#### Scenario: Disabled algorithm rejected when signing
- **WHEN** a token request specifies an algorithm that is not enabled
- **THEN** the request fails rather than producing a token