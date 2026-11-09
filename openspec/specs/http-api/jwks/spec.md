# http-api/jwks Specification

## Purpose

Serves the live JSON Web Key Set and individual public keys by key ID so JWT consumers can fetch and match the verification keys for minted tokens.

## Requirements

### Requirement: Publish the JSON Web Key Set
`GET /.well-known/jwks.json` SHALL return a `200` JSON JWKS document whose `keys` array contains the active key and every retired key still inside its grace window for each enabled asymmetric algorithm. HMAC keys, `none`, and any caller-supplied shared secret SHALL NOT appear.

#### Scenario: JWKS contains active and retiring keys
- **WHEN** a client requests `GET /.well-known/jwks.json`
- **THEN** the response is a JWKS whose `keys` include the current active keys and any retired keys still in the grace period
- **AND** each entry is a public JWK with `kid`, `use`, and `alg`

#### Scenario: New asymmetric algorithms appear
- **WHEN** RS384, PS256, PS512, ES384, or ES512 is enabled
- **THEN** each enabled algorithm has a public JWK entry with the matching `alg`

#### Scenario: HMAC and none are absent
- **WHEN** a client requests the JWKS
- **THEN** no entry has an `alg` of `HS256` or `none` and no shared secret is present

### Requirement: Fetch a single JWK by key ID
`GET /.well-known/jwks.json/{kid}` SHALL return a `200` JSON document containing just the matching public key's JWK, including retired keys still within the grace window.

#### Scenario: Known kid returns its JWK
- **WHEN** a client requests a `kid` that exists in the live key set
- **THEN** the response is `200` JSON describing that single JWK

#### Scenario: Missing kid rejected
- **WHEN** a client requests `/.well-known/jwks.json/` with no `kid` in the path
- **THEN** the response is `400` with an error message

#### Scenario: Unknown kid returns 404
- **WHEN** a client requests a `kid` that is not in the live key set
- **THEN** the response is `404` with an error message

### Requirement: HMAC and unsigned algorithms are never published
The JWKS and single-key endpoints SHALL NOT return an HMAC key, a shared secret, or an entry with `alg` of `none` or `HS256`, even when HS256 or negative-token controls are configured on a surface that supports them.

#### Scenario: Embedded HMAC secret is not published
- **WHEN** an embedded issuer is configured with an HMAC secret
- **THEN** the HTTP JWKS contains only asymmetric public keys

#### Scenario: none is not published
- **WHEN** negative-token controls are enabled
- **THEN** no JWKS entry advertises `none`

