# http-api/security Specification

## Purpose

Applies cross-cutting HTTP behavior — security headers, per-client rate limiting, request-ID correlation, method matching, and plaintext-only transport — to every endpoint the issuer serves.

## Requirements

### Requirement: Security headers on all responses
Every HTTP response SHALL include `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, and a restrictive `Content-Security-Policy`.

#### Scenario: Middleware applies headers to every endpoint
- **WHEN** a client requests any endpoint served by the issuer
- **THEN** the response carries all four security headers

### Requirement: Per-client rate limiting
Each client IP SHALL be limited to a configurable rate (default 100 requests/sec) with a burst allowance (default 200). The client identity SHALL honor the first entry of `X-Forwarded-For` when present. Exceeding the limit SHALL return `429` with a JSON error.

#### Scenario: Rate limit exceeded
- **WHEN** a client sends requests faster than the configured rate and burst allow
- **THEN** the server responds `429` with `{"error": "rate limit exceeded"}`

#### Scenario: Forwarded header identifies the client
- **WHEN** a request carries `X-Forwarded-For` with multiple addresses
- **THEN** the first address is used as the rate-limit client identity

### Requirement: Request-ID correlation
Every response served by the routing layer SHALL include an `X-Request-ID` header: a request-supplied value SHALL be echoed, otherwise the server SHALL generate one and use it for audit logging. Rate-limit rejections (`429`) are produced by an outer middleware and do not include the header.

#### Scenario: Supplied request ID echoed
- **WHEN** a client sends a request with an `X-Request-ID` header
- **THEN** the response echoes the same value

#### Scenario: Generated request ID
- **WHEN** a client sends a request without an `X-Request-ID`
- **THEN** the response includes a generated `X-Request-ID`

### Requirement: Read-only endpoints reject non-GET methods
Every GET-only endpoint — `/`, `/healthz`, `/version`, the discovery document, and the JWKS routes — SHALL reject non-GET methods with `405`.

#### Scenario: POST to a GET-only endpoint
- **WHEN** a client sends a non-GET method to a GET-only endpoint
- **THEN** the response is `405`

### Requirement: Issuer serves plaintext HTTP without TLS
The issuer SHALL serve plaintext HTTP and SHALL NOT terminate TLS. Clients that require HTTPS SHALL place a TLS-terminating proxy in front of the issuer.

#### Scenario: HTTPS not supported directly
- **WHEN** a client attempts an HTTPS connection directly to the issuer
- **THEN** no TLS handshake is completed because the issuer only serves plaintext HTTP
