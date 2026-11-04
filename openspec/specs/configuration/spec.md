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
The `ALGORITHMS` setting SHALL enable a subset of `RS256`, `ES256`, `EdDSA`. At least one algorithm SHALL be enabled, otherwise the server SHALL fail to start.

#### Scenario: Subset enabled
- **WHEN** `--algorithms RS256` is passed
- **THEN** only RS256 keys are generated and only RS256 is advertised

#### Scenario: No algorithms enabled
- **WHEN** the resolved `ALGORITHMS` list is empty
- **THEN** the server fails to start with an error

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
