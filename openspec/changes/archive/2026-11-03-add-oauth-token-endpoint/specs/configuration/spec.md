# Spec Delta

## ADDED Requirements

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
