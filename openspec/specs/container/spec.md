# container Specification

## Purpose

Packages jwtoken-tester as a container image and provides a docker-compose demo with a token-protected sample service for exercising the issuer end to end.

## Requirements

### Requirement: Distroless non-root image
The container image SHALL contain a statically linked `jwtoken-tester` binary, run it with the `serve` command, expose port 8080, and execute as a non-root user.

#### Scenario: Image runs the issuer as non-root
- **WHEN** a container is started from the image
- **THEN** the process runs `/jwtoken-tester serve` as a non-root user and listens on the configured address

### Requirement: Container defaults and version metadata
The image SHALL default `LISTEN` to `0.0.0.0:8080` so a published port is reachable without extra configuration. It SHALL be tagged as `ghcr.io/larryf1/jwtoken-tester:<computed-version>` (plus `latest` for local builds), and the image tag, OCI version label, and the version reported by the running binary SHALL all come from the same computed version.

#### Scenario: Published port works without extra environment
- **WHEN** the image is started with `docker run -p 8080:8080` and no `LISTEN` variable
- **THEN** the server listens on `0.0.0.0:8080` and the published port reaches it

#### Scenario: Image version matches /version
- **WHEN** an image built by `make docker-build` is started
- **THEN** its tag, `org.opencontainers.image.version` label, and `/version` response all report the same computed version

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
