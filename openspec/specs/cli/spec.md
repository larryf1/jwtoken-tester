# cli Specification

## Purpose

Defines the `jwtoken-tester` command-line entrypoint — its subcommands, usage output, one-shot token printing, graceful shutdown, and version resolution.

## Requirements

### Requirement: Top-level command dispatch
The binary SHALL accept `serve`, `print-token`, and `help` as commands. Running with no command SHALL print usage to stdout and exit non-zero; an unknown command SHALL report the command on stderr, print usage to stdout, and exit non-zero.

#### Scenario: No command prints usage and exits non-zero
- **WHEN** the binary is run with no arguments
- **THEN** usage text is printed and the process exits non-zero

#### Scenario: Unknown command rejected
- **WHEN** the binary is run with an unrecognized command
- **THEN** usage text is printed and the process exits non-zero

### Requirement: serve runs the HTTP server with graceful shutdown
The `serve` command SHALL start the issuer on the configured address, log a test-issuer warning, and on SIGINT or SIGTERM SHALL shut down the HTTP server gracefully and exit.

#### Scenario: Graceful shutdown on termination signal
- **WHEN** the process receives SIGINT or SIGTERM while serving
- **THEN** in-flight shutdown completes and the process exits, logging that ephemeral signing keys were discarded

#### Scenario: Non-loopback bind warns
- **WHEN** `--listen` binds to a non-loopback address
- **THEN** the server logs a warning that the test issuer is exposed on the network

### Requirement: Version resolution
The reported version SHALL be the value baked into the binary at build time, falling back to the `VERSION` file, and finally to `dev` when neither is available.

#### Scenario: Version falls back to dev
- **WHEN** the binary is built without a baked version and no `VERSION` file exists
- **THEN** the version endpoints report `dev`

### Requirement: print-token mints one token to stdout
The `print-token` command SHALL mint a single token from its flags and print only the `access_token` to stdout. Invalid flags, unparsable JSON, or minting errors SHALL print an error and exit non-zero.

#### Scenario: Single token printed to stdout
- **WHEN** `print-token --claims '{"sub":"user-123","aud":["my-service"]}' --alg RS256` is run
- **THEN** one JWT is written to stdout and the process exits zero

#### Scenario: Unparsable claims exit non-zero
- **WHEN** `--claims` is not valid JSON
- **THEN** an error is logged and the process exits non-zero
