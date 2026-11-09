# Spec Delta

## MODIFIED Requirements

### Requirement: Keypairs are generated in memory at startup
The system SHALL generate one active signing keypair per enabled asymmetric algorithm from a secure random source at startup. RSA algorithms SHALL use an RSA key of the configured modulus size, ES256 SHALL use P-256, ES384 SHALL use P-384, ES512 SHALL use P-521, and EdDSA SHALL use Ed25519. Private keys SHALL exist only in memory and SHALL never be persisted to disk, environment, logs, or HTTP responses. HMAC keys SHALL NOT be generated automatically and SHALL be used only when a caller supplies an explicit shared secret.

#### Scenario: One active key per enabled algorithm
- **WHEN** the server starts with RS256, RS384, PS256, ES256, ES384, ES512, and EdDSA enabled
- **THEN** exactly one active signing key exists for each of the seven algorithms

#### Scenario: JWKS exposes public keys only
- **WHEN** a client fetches the JWKS
- **THEN** every returned key is a public JWK and no private key material is present

#### Scenario: No HMAC key is generated automatically
- **WHEN** the server starts without a caller-supplied HMAC secret
- **THEN** no HMAC signing key exists in the key set

### Requirement: Key IDs are RFC 7638 thumbprints
The `kid` of every key SHALL be the unpadded URL-safe base64 SHA-256 thumbprint of its public JWK, and every published JWK SHALL carry `kid`, `use=sig`, and the signing algorithm. The published `alg` SHALL be one of the enabled asymmetric algorithms.

#### Scenario: JWKS entries carry matching kid, use, and alg
- **WHEN** a client reads a JWKS entry
- **THEN** the entry has a thumbprint-derived `kid`, `use=sig`, and an `alg` from the enabled asymmetric algorithm set

#### Scenario: HMAC material has no published JWK
- **WHEN** an HMAC secret is configured for a surface that supports HS256
- **THEN** no JWK is derived from that secret

### Requirement: Algorithm enablement governs key operations
The system SHALL only generate, sign, and advertise keys for enabled asymmetric algorithms. Operations requesting a disabled or unknown algorithm SHALL fail. `none` and HS256 SHALL NOT be treated as enabled keyring algorithms; `none` is an unsigned negative mode, and HS256 uses a caller-supplied shared secret outside the keyring.

#### Scenario: Disabled algorithm rejected when signing
- **WHEN** a token request specifies an algorithm that is not enabled
- **THEN** the request fails rather than producing a token

#### Scenario: none and HS256 are not keyring algorithms
- **WHEN** an operation asks the keyring for a `none` or HS256 signing key
- **THEN** the operation fails as an unsupported algorithm

## ADDED Requirements

### Requirement: RSA modulus size is configurable
RSA key generation SHALL use a configurable modulus size with a default of 2048 bits and a minimum of 1024 bits. A size below the minimum or a value that is not an integer SHALL fail startup.

#### Scenario: Default RSA size is 2048 bits
- **WHEN** no RSA size is configured
- **THEN** generated RSA keys use a 2048-bit modulus

#### Scenario: Custom RSA size is honored
- **WHEN** the RSA size is configured as 3072
- **THEN** generated RSA keys use a 3072-bit modulus

#### Scenario: Undersized RSA key is rejected
- **WHEN** the RSA size is configured below 1024
- **THEN** startup fails with a configuration error

### Requirement: EC curves are determined by algorithm
ES256 SHALL use P-256, ES384 SHALL use P-384, and ES512 SHALL use P-521. No separate curve setting SHALL override the curve required by the selected algorithm.

#### Scenario: ES384 uses P-384
- **WHEN** an ES384 key is generated
- **THEN** the key uses the P-384 curve

#### Scenario: No EC curve override exists
- **WHEN** a caller configures algorithms and RSA size
- **THEN** no setting changes the curve used by an EC algorithm

### Requirement: Signing keys are selectable by key ID
A signing request SHALL be able to select the active or retired key identified by `kid`, provided the key's algorithm matches the requested algorithm. Selecting a key SHALL NOT remove it from its current lifecycle state. An unknown `kid` SHALL fail unless negative-token controls are enabled.

#### Scenario: Retired key selected for signing
- **WHEN** a request selects a retired key's `kid` while the key is still inside its grace window
- **THEN** that key signs the token and remains retired

#### Scenario: Key algorithm must match
- **WHEN** a request selects a key whose algorithm differs from the requested algorithm
- **THEN** the request fails

#### Scenario: Unknown key rejected without negative mode
- **WHEN** a request selects a `kid` that is not in the live key set and negative-token controls are disabled
- **THEN** the request fails with a key-not-found error

### Requirement: HMAC keys are never part of the public key set
HMAC shared secrets SHALL NOT be generated, rotated, published, or returned by JWKS, discovery, health, or key-listing views. A caller-supplied HMAC secret SHALL be used only to sign HS256 tokens on surfaces that support HS256.

#### Scenario: JWKS has no HMAC entry
- **WHEN** an embedded issuer is configured with an HMAC secret
- **THEN** the HTTP and programmatic JWKS contain only asymmetric public keys

#### Scenario: Key listings exclude HMAC material
- **WHEN** a caller enumerates keys
- **THEN** no HMAC key or shared secret is returned
