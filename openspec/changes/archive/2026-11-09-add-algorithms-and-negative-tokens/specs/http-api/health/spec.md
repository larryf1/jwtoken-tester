# Spec Delta

## MODIFIED Requirements

### Requirement: Liveness health check
`GET /healthz` SHALL return `200` JSON with `status: "ok"`, the server version, a test-issuer warning, the enabled asymmetric algorithms, and the active key IDs per algorithm. HMAC and `none` SHALL NOT appear in the algorithm list or active key map.

#### Scenario: Healthy server reports status and active keys
- **WHEN** a client requests `GET /healthz`
- **THEN** the response is `200` JSON with `status: "ok"` and an `active_kids` object mapping each enabled algorithm to its active key ID

#### Scenario: New asymmetric algorithms are reported
- **WHEN** RS384, PS256, ES512, and EdDSA are enabled
- **THEN** the enabled algorithm list and `active_kids` contain exactly those four algorithms

#### Scenario: HMAC and none are omitted
- **WHEN** an HMAC secret or negative-token controls are configured
- **THEN** neither `HS256` nor `none` appears in the enabled algorithm list or `active_kids`
