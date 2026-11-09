# Spec Delta

## MODIFIED Requirements

### Requirement: print-token mints one token to stdout
The `print-token` command SHALL mint a single token from its flags and print only the `access_token` to stdout. Invalid flags, unparsable JSON, or minting errors SHALL print an error and exit non-zero.

#### Scenario: Single token printed to stdout
- **WHEN** `print-token --claims '{"sub":"user-123","aud":["my-service"]}' --alg RS256` is run
- **THEN** one JWT is written to stdout and the process exits zero

#### Scenario: Unparsable claims exit non-zero
- **WHEN** `--claims` is not valid JSON
- **THEN** an error is logged and the process exits non-zero

## ADDED Requirements

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
