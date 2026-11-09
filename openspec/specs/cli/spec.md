# cli Specification





## Purpose

Defines the `jwtoken-tester` command-line entrypoint — its subcommands, usage output, one-shot token printing, graceful shutdown, and version resolution.

## Requirements

### Requirement: Top-level command dispatch
The binary SHALL accept `serve`, `print-token`, `decode`, `verify`, `healthcheck`, and `help` as commands. Running with no command SHALL print usage to stdout and exit non-zero; an unknown command SHALL report the command on stderr, print usage to stdout, and exit non-zero.

#### Scenario: No command prints usage and exits non-zero
- **WHEN** the binary is run with no arguments
- **THEN** usage text is printed and the process exits non-zero

#### Scenario: Unknown command rejected
- **WHEN** the binary is run with an unrecognized command
- **THEN** the command is reported on stderr, usage is printed, and the process exits non-zero

### Requirement: serve runs the HTTP server with graceful shutdown
The `serve` command SHALL start the issuer on the configured address, log a test-issuer warning, and on SIGINT or SIGTERM SHALL shut down the HTTP server gracefully and exit.

#### Scenario: Graceful shutdown on termination signal
- **WHEN** the process receives SIGINT or SIGTERM while serving
- **THEN** in-flight shutdown completes and the process exits, logging that ephemeral signing keys were discarded

#### Scenario: Non-loopback bind warns
- **WHEN** `--listen` binds to a non-loopback address
- **THEN** the server logs a warning that the test issuer is exposed on the network

### Requirement: Version resolution
The reported version SHALL be the value baked into the binary at build time, falling back to the `VERSION` file, then to Go build metadata, and SHALL never report a `dev` placeholder.

#### Scenario: Baked version is reported
- **WHEN** the binary is built with `-X main.Version=<version>`
- **THEN** the version endpoints report `<version>`

#### Scenario: Version falls back to build metadata
- **WHEN** the binary is built without a baked version and no `VERSION` file exists
- **THEN** the version endpoints report a version derived from Go build metadata or the module version, never `dev`

### Requirement: print-token mints one token to stdout
The `print-token` command SHALL mint a single token from its flags and print only the `access_token` to stdout. Invalid flags, unparsable JSON, or minting errors SHALL print an error and exit non-zero.

#### Scenario: Single token printed to stdout
- **WHEN** `print-token --claims '{"sub":"user-123","aud":["my-service"]}' --alg RS256` is run
- **THEN** one JWT is written to stdout and the process exits zero

#### Scenario: Unparsable claims exit non-zero
- **WHEN** `--claims` is not valid JSON
- **THEN** an error is logged and the process exits non-zero

### Requirement: healthcheck probes the local server
The `healthcheck` command SHALL probe the `/healthz` endpoint using the binary itself. It SHALL derive the target URL from `LISTEN` unless `--url` is supplied, SHALL apply a configurable `--timeout`, and SHALL exit non-zero when the request fails or the response status is not `200`.

#### Scenario: URL derived from LISTEN
- **WHEN** `healthcheck` runs with `LISTEN=0.0.0.0:9090` and no `--url`
- **THEN** it probes `http://127.0.0.1:9090/healthz`

#### Scenario: Explicit URL used
- **WHEN** `--url http://127.0.0.1:8080/healthz` is supplied
- **THEN** that URL is probed instead of the derived one

#### Scenario: Unhealthy response exits non-zero
- **WHEN** the probe returns a status other than `200` or the connection fails
- **THEN** the command reports the failure on stderr and exits non-zero

### Requirement: decode prints a token without verification
The `decode` command SHALL accept a token as a positional argument or read it from stdin, SHALL decode the JOSE header and payload without keys or network access, and SHALL print them as JSON. It SHALL succeed for any structurally decodable JWT and SHALL NOT validate the signature, time claims, issuer, or audience. A structurally invalid value SHALL produce an error and a non-zero exit.

#### Scenario: Expired token decoded
- **WHEN** `decode` receives a correctly formed but expired token
- **THEN** it prints the header and claims and exits zero

#### Scenario: Foreign token decoded
- **WHEN** `decode` receives a token signed by an unknown issuer
- **THEN** it prints the header and claims without contacting any key source

#### Scenario: Malformed value rejected
- **WHEN** the input is not a three-segment compact JWS
- **THEN** the command reports an error and exits non-zero

#### Scenario: Token read from stdin
- **WHEN** no positional token is supplied and a token is piped to stdin
- **THEN** the piped token is decoded

### Requirement: verify checks a token against an external key source
The `verify` command SHALL verify a token against keys obtained from `--jwks <url|file>` or discovered from `--issuer <url>`. It SHALL accept optional `--aud`, repeatable `--alg`, and `--leeway` constraints, SHALL read the token from a positional argument or stdin, and SHALL perform key retrieval in the client process rather than through the local server.

#### Scenario: Token verified against a JWKS URL
- **WHEN** `verify --jwks http://127.0.0.1:8080/.well-known/jwks.json <token>` is run for a token from that issuer
- **THEN** the token is reported valid

#### Scenario: Issuer discovery supplies keys and issuer check
- **WHEN** `verify --issuer http://127.0.0.1:8080 <token>` is run
- **THEN** the discovery document's `jwks_uri` supplies the keys
- **AND** the token's `iss` is checked against the supplied issuer URL

#### Scenario: Missing key source is a usage error
- **WHEN** `verify` is run without `--jwks` or `--issuer`
- **THEN** the command reports a usage error and exits non-zero

#### Scenario: Invalid token reported
- **WHEN** the token is well formed but fails signature, time, issuer, audience, or algorithm checks
- **THEN** the command reports the failure reason and exits non-zero

### Requirement: verify exposes machine-readable verdicts and exit codes
`verify` SHALL print a human-readable verdict by default and SHALL print the verification verdict envelope as JSON when `--json` is supplied. It SHALL exit `0` for a valid token, `1` for an invalid token, and `2` for operational failures such as an unreadable key source, a failed fetch, or a usage error.

#### Scenario: Valid token exits zero
- **WHEN** verification succeeds
- **THEN** the command exits `0`

#### Scenario: Invalid token exits one
- **WHEN** verification completes with `valid: false`
- **THEN** the command exits `1`

#### Scenario: Operational failure exits two
- **WHEN** the key source cannot be read or fetched
- **THEN** the command reports the operational error and exits `2`

#### Scenario: JSON output
- **WHEN** `--json` is supplied
- **THEN** the output is the same verdict envelope the HTTP endpoint returns

### Requirement: print-token accepts algorithm and header controls
`print-token` SHALL accept `--alg` for every enabled asymmetric algorithm, `--algorithms`, `--headers`, `--kid`, `--typ`, `--cty`, and `--rsa-bits`. `--kid` SHALL set the protected header and SHALL select a generated key when it matches. `--typ` SHALL default to `JWT`. Conflicting reserved values in `--headers` SHALL be rejected.

#### Scenario: New asymmetric algorithm printed
- **WHEN** `print-token --alg PS256` is run
- **THEN** the printed token header uses PS256

#### Scenario: Custom typ and cty printed
- **WHEN** `print-token --typ at+jwt --cty application/json` is run
- **THEN** the printed token header carries both values

#### Scenario: Unknown kid produces a wrong-kid token
- **WHEN** `print-token --kid does-not-exist` is run
- **THEN** the printed token is signed by the active key and carries the supplied `kid`

#### Scenario: Conflicting reserved header rejected
- **WHEN** `--headers` supplies `kid`, `typ`, or `cty` that conflicts with its dedicated flag
- **THEN** the command reports an error and exits non-zero

### Requirement: print-token supports negative and HMAC modes
`print-token` SHALL accept `--alg none`, `--corrupt <mode>`, `--duplicate-claim <name>`, and `--hmac-secret-file <path>`. Negative modes SHALL be enabled by the explicit flag without a server-wide gate. HS256 SHALL require a shared secret of at least 32 bytes.

#### Scenario: Unsigned token printed
- **WHEN** `print-token --alg none` is run
- **THEN** the printed token has an `alg` of `none` and an empty signature segment

#### Scenario: Corrupt token printed
- **WHEN** `print-token --corrupt signature` is run
- **THEN** the printed token has a signature that does not verify

#### Scenario: Duplicate claim printed
- **WHEN** `print-token --corrupt duplicate_claims --duplicate-claim sub` is run
- **THEN** the printed payload contains a repeated `sub` claim

#### Scenario: HS256 printed with a secret
- **WHEN** `print-token --alg HS256 --hmac-secret-file secret.txt` is run with a secret of at least 32 bytes
- **THEN** the printed token is signed with HS256

#### Scenario: HS256 without a secret fails
- **WHEN** `print-token --alg HS256` is run without a configured secret
- **THEN** the command reports an error and exits non-zero


