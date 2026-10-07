# http-api/jwks Specification

## Purpose

Serves the live JSON Web Key Set and individual public keys by key ID so JWT consumers can fetch and match the verification keys for minted tokens.

## Requirements

### Requirement: Publish the JSON Web Key Set
`GET /.well-known/jwks.json` SHALL return a `200` JSON JWKS document whose `keys` array contains the active key and every retired key still inside its grace window for each enabled algorithm.

#### Scenario: JWKS contains active and retiring keys
- **WHEN** a client requests `GET /.well-known/jwks.json`
- **THEN** the response is a JWKS whose `keys` include the current active keys and any retired keys still in the grace period
- **AND** each entry is a public JWK with `kid`, `use`, and `alg`

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
