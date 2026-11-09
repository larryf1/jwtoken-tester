# configuration Specification

## Purpose

Configures the jwtoken-tester server and one-shot token mode from environment variables and CLI flags, including defaults, precedence, and duration semantics.

## Requirements

### Requirement: Server settings are configurable via environment or flags
The server SHALL read every setting from an environment variable or an equivalent CLI flag. When both are set for the same setting, the flag SHALL take precedence.

#### Scenario: Defaults are used when neither source is set
- **WHEN** the server starts with no relevant environment variables and no flags
- **THEN** it binds to `127.0.0.1:8080`, uses issuer `http://127.0.0.1:8080`, default TTL `1h`, max TTL `24h`, rotation interval `30m`, grace period `25h`, algorithms `RS256,ES256,EdDSA`, and rate limit `100` rps with burst `200`

#### Scenario: Flag wins over environment
- **WHEN** `LISTEN=0.0.0.0:9090` is set and `--listen 127.0.0.1:8081` is passed
- **THEN** the server binds to `127.0.0.1:8081`

#### Scenario: Environment is used when no flag is passed
- **WHEN** `LISTEN=0.0.0.0:9090` is set and no `--listen` flag is given
- **THEN** the server binds to `0.0.0.0:9090`

### Requirement: Duration settings use Go duration syntax
Duration-valued settings (`LISTEN` excluded) SHALL parse Go duration syntax such as `30s`, `45m`, or `12h`. An unparsable duration value SHALL fall back to that setting's default.

#### Scenario: Valid duration accepted
- **WHEN** `DEFAULT_TTL=90m` is set
- **THEN** tokens minted without an explicit `exp` expire 90 minutes after issuing

#### Scenario: Invalid duration falls back to default
- **WHEN** `DEFAULT_TTL=not-a-duration` is set
- **THEN** the server runs with the `1h` default for omitted `exp`

### Requirement: Zero values disable caps and rotation
`MAX_TTL=0` SHALL disable the maximum-lifetime cap, and `ROTATION_INTERVAL=0` SHALL disable automatic key rotation.

#### Scenario: Max TTL disabled
- **WHEN** `MAX_TTL=0` is set
- **THEN** tokens with any explicit `exp` are minted without a lifetime cap

#### Scenario: Rotation disabled
- **WHEN** `ROTATION_INTERVAL=0` is set
- **THEN** the active signing keys never rotate while the server runs

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

### Requirement: Audience setting
`AUDIENCE` SHALL set the `aud` claim on tokens minted by `/oauth/token`, with an equivalent `--audience` flag that takes precedence over the environment variable. When `AUDIENCE` is unset, `/oauth/token` SHALL omit the `aud` claim.

#### Scenario: Audience applied from environment
- **WHEN** `AUDIENCE=my-api` is set and a token is minted by `/oauth/token`
- **THEN** the token contains `aud` of `my-api`

#### Scenario: Audience flag wins
- **WHEN** `AUDIENCE=from-env` is set and `--audience from-flag` is passed
- **THEN** the token contains `aud` of `from-flag`

#### Scenario: Audience omitted when unset
- **WHEN** `AUDIENCE` is unset
- **THEN** tokens minted by `/oauth/token` contain no `aud` claim

### Requirement: Supported scopes setting
`SCOPES` SHALL be a comma-separated list of scope names advertised as `scopes_supported` in discovery, with an equivalent `--scopes` flag that takes precedence over the environment variable. When `SCOPES` is unset, discovery SHALL omit `scopes_supported`. The setting SHALL NOT restrict the scopes a client may request from `/oauth/token`.

#### Scenario: Scopes advertised from environment
- **WHEN** `SCOPES=read,write` is set
- **THEN** discovery advertises `scopes_supported` of `["read", "write"]`

#### Scenario: Scopes flag wins
- **WHEN** `SCOPES=from-env` is set and `--scopes from-flag` is passed
- **THEN** discovery advertises `from-flag`

#### Scenario: Scopes omitted when unset
- **WHEN** `SCOPES` is unset
- **THEN** discovery contains no `scopes_supported` field

#### Scenario: Unlisted scope still accepted
- **WHEN** `SCOPES=read` is set and a client requests `scope=admin`
- **THEN** the token is minted with `scope` of `admin`

### Requirement: Extra discovery metadata setting
`DISCOVERY_EXTRA_JSON` SHALL be a JSON object merged additively into both discovery documents, with an equivalent `--discovery-extra-json` flag that takes precedence over the environment variable. Derived core fields SHALL win over extra fields. Invalid JSON or a non-object value SHALL fail startup.

#### Scenario: Extra metadata applied from environment
- **WHEN** `DISCOVERY_EXTRA_JSON` contains `{"service_documentation": "https://example.test/docs"}`
- **THEN** both discovery documents include that field

#### Scenario: Extra metadata flag wins
- **WHEN** `DISCOVERY_EXTRA_JSON` and `--discovery-extra-json` both set a field
- **THEN** the flag value is served

#### Scenario: Derived core fields win
- **WHEN** `DISCOVERY_EXTRA_JSON` attempts to replace `issuer`, `jwks_uri`, `token_endpoint`, or `introspection_endpoint`
- **THEN** the derived value is served

#### Scenario: Invalid extra metadata fails startup
- **WHEN** `DISCOVERY_EXTRA_JSON` is not a JSON object
- **THEN** the server fails to start with a configuration error

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



