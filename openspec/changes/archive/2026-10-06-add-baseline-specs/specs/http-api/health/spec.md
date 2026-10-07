# Spec Delta

## Purpose

Provides the liveness endpoint used by operators, orchestration, and container healthchecks to confirm the issuer is up and report its active signing keys per algorithm.

## ADDED Requirements

### Requirement: Liveness health check
`GET /healthz` SHALL return `200` JSON with `status: "ok"`, the server version, a test-issuer warning, the enabled algorithms, and the active key IDs per algorithm.

#### Scenario: Healthy server reports status and active keys
- **WHEN** a client requests `GET /healthz`
- **THEN** the response is `200` JSON with `status: "ok"` and an `active_kids` object mapping each enabled algorithm to its active key ID