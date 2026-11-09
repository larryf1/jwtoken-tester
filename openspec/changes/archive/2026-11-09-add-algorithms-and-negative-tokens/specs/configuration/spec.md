# Spec Delta

## MODIFIED Requirements

### Requirement: Enabled algorithms are selected by a comma-separated list
The `ALGORITHMS` setting SHALL enable a subset of `RS256`, `RS384`, `RS512`, `PS256`, `PS384`, `PS512`, `ES256`, `ES384`, `ES512`, and `EdDSA`. At least one algorithm SHALL be enabled, otherwise the server SHALL fail to start. `none` and `HS256` SHALL NOT be accepted by `serve`, and requesting either SHALL fail startup with a clear error.

#### Scenario: Subset enabled
- **WHEN** `--algorithms RS256` is passed
- **THEN** only RS256 keys are generated and only RS256 is advertised

#### Scenario: New asymmetric algorithms enabled
- **WHEN** `--algorithms RS256,PS256,ES384` is passed
- **THEN** only RS256, PS256, and ES384 keys are generated and advertised

#### Scenario: No algorithms enabled
- **WHEN** the resolved `ALGORITHMS` list is empty
- **THEN** the server fails to start with an error

#### Scenario: HS256 rejected by serve
- **WHEN** `ALGORITHMS` includes `HS256` for the `serve` command
- **THEN** startup fails with an error explaining that HS256 is not supported by `serve`

#### Scenario: none rejected by serve
- **WHEN** `ALGORITHMS` includes `none`
- **THEN** startup fails with a configuration error

## ADDED Requirements

### Requirement: RSA modulus size setting
`RSA_BITS` SHALL set the modulus size for RSA algorithms with a default of `2048` and a minimum of `1024`, with an equivalent `--rsa-bits` flag that takes precedence over the environment variable. A non-integer value or a value below the minimum SHALL fail startup.

#### Scenario: Default RSA size
- **WHEN** `RSA_BITS` is unset
- **THEN** RSA keys use a 2048-bit modulus

#### Scenario: Custom RSA size from environment
- **WHEN** `RSA_BITS=3072` is set
- **THEN** RSA keys use a 3072-bit modulus

#### Scenario: RSA size flag wins
- **WHEN** `RSA_BITS=3072` is set and `--rsa-bits 4096` is passed
- **THEN** RSA keys use a 4096-bit modulus

#### Scenario: Invalid RSA size fails startup
- **WHEN** `RSA_BITS` is not an integer or is below 1024
- **THEN** the server fails to start with a configuration error

### Requirement: Negative token setting
`ALLOW_NEGATIVE_TOKENS` SHALL enable negative-token controls on the HTTP server, with an equivalent `--allow-negative-tokens` flag that takes precedence over the environment variable. The default SHALL be `false`. When false, the server SHALL reject negative-token requests.

#### Scenario: Negative tokens are disabled by default
- **WHEN** `ALLOW_NEGATIVE_TOKENS` is unset and no flag is passed
- **THEN** negative-token requests are rejected

#### Scenario: Negative tokens enabled from environment
- **WHEN** `ALLOW_NEGATIVE_TOKENS=true` is set
- **THEN** negative-token requests are accepted

#### Scenario: Negative token flag wins
- **WHEN** `ALLOW_NEGATIVE_TOKENS=false` is set and `--allow-negative-tokens` is passed
- **THEN** negative-token requests are accepted

### Requirement: HMAC secret setting for one-shot tokens
`HMAC_SECRET` SHALL supply the shared secret used by `print-token` for HS256, with an equivalent `--hmac-secret-file` flag that takes precedence by reading the secret from a file. The secret SHALL be at least 32 bytes. The `serve` command SHALL NOT consult this setting and SHALL NOT enable HS256.

#### Scenario: Secret supplied from environment
- **WHEN** `HMAC_SECRET` contains at least 32 bytes and `print-token --alg HS256` is run
- **THEN** the token is signed with HS256

#### Scenario: Secret file flag wins
- **WHEN** `HMAC_SECRET` is set and `--hmac-secret-file` is passed
- **THEN** the file contents supply the signing secret

#### Scenario: Short secret rejected
- **WHEN** the resolved HMAC secret is shorter than 32 bytes
- **THEN** the command fails with a configuration error

#### Scenario: serve ignores the HMAC setting
- **WHEN** `HMAC_SECRET` is set and the `serve` command starts
- **THEN** HS256 is not enabled and no HMAC key is published
