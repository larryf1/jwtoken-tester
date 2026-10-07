# Spec Delta

## Purpose

Serves the service index and version metadata endpoints so clients and operators can identify the running instance and its capabilities.

## ADDED Requirements

### Requirement: Service index document
`GET /` SHALL return JSON identifying the service, the running version, an ephemeral-issuer warning, and the list of available endpoints.

#### Scenario: Index returns service metadata
- **WHEN** a client requests `GET /`
- **THEN** the response is `200` JSON containing `service`, `version`, `warning`, and an `endpoints` array listing the API routes

### Requirement: Version endpoint
`GET /version` SHALL return the running server version as JSON.

#### Scenario: Version returned
- **WHEN** a client requests `GET /version`
- **THEN** the response is `200` JSON containing the exact `version` string