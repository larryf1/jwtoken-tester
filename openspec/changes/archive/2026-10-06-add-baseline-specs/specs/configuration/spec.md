# Spec Delta

## Purpose

Configures the jwtoken-tester server and one-shot token mode from environment variables and CLI flags, including defaults, precedence, and duration semantics.

## ADDED Requirements

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