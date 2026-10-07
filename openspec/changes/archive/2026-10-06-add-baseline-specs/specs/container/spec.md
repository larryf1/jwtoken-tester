# Spec Delta

## Purpose

Packages jwtoken-tester as a container image and provides a docker-compose demo with a token-protected sample service for exercising the issuer end to end.

## ADDED Requirements

### Requirement: Distroless non-root image
The container image SHALL contain a statically linked `jwtoken-tester` binary, run it with the `serve` command, expose port 8080, and execute as a non-root user.

#### Scenario: Image runs the issuer as non-root
- **WHEN** a container is started from the image
- **THEN** the process runs `/jwtoken-tester serve` as a non-root user and listens on the configured address

### Requirement: OCI metadata labels
The image SHALL carry `org.opencontainers.image` labels for title, description, version, revision, source, license, and created time.

#### Scenario: Labels present on the image
- **WHEN** the image is inspected
- **THEN** the OCI metadata labels record the version, revision, source URL, license, and creation time

### Requirement: Docker-compose demo stack
The compose file SHALL start the issuer and a demo protected service. The demo service SHALL fetch the JWKS and validate Bearer tokens against the issuer, enforcing the signing algorithms, issuer, and audience. An unrouted invalid request SHALL be rejected.

#### Scenario: Valid token grants access
- **WHEN** a client presents a token minted by the issuer with the demo service's expected audience
- **THEN** the demo service returns the protected resource content

#### Scenario: Missing or invalid token rejected
- **WHEN** a client calls the protected endpoint without a valid Bearer token
- **THEN** the demo service responds with an authorization error