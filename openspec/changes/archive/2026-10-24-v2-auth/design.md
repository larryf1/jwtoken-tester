# Design

## Context

The issuer currently mints tokens only through `POST /token` with a JSON body (`claims`, `alg`, `headers`) and returns `{access_token, token_type, expires_in}`. Clients previously relied on static API keys, which expired and were not renewed by re-signing in, so issuance had to move to short-lived, capability-scoped tokens.

## Goals / Non-Goals

**Goals:**

- Support the versioned (v2) OAuth token request syntax: client credentials via `X-Client-Id` / `X-Client-Secret`, capability scope via `Scope`, and a versioned token response with capabilities and allowed resources.

**Non-Goals:**

- Real client secret storage or full IdP integration (the issuer runs with ephemeral in-memory keys).
- Transport security (TLS termination stays at the reverse proxy).

## Decisions

- **D1: Versioned endpoint `POST /v2/oauth/token`** for OAuth-issued tokens, keeping `POST /token` unchanged for anonymous/custom-claims mints. *Why:* isolates the versioned OAuth contract; alternative considered was a single endpoint with a version discriminator, rejected because it couples anonymous minting with client-credential flows.
- **D2: Client authentication via `X-Client-Id` / `X-Client-Secret` headers**, capability scope via the `Scope` query parameter (comma-separated capability identifiers). *Why:* matches the requested client integration. *Alternative considered:* client credentials in the request body - deferred to a later change.
- **D3: Minted v2 tokens** embed `version: "2.0"`, granted `capabilities`, `allowedResources`, and client identity claims (`sub`, `aud`, `client_id`, `idtyp`) alongside the standard claims, signed through the existing keyring algorithm support and protected-header mechanism.

## Risks / Trade-offs

- [Risk] Unrecognized capability identifiers could be granted. → Mitigation: fail closed by validating requested capabilities against the configured capability registry at mint time.
- [Risk] `allowedResources` shape (e.g. per-partner allow lists) is still being finalized. → Mitigation: source from per-client policy configuration; revisit if policy surface changes.

## Migration Plan

- Add the versioned endpoint and v2 minting path behind the existing rate limiting, security headers, and audit logging.
- Keep the legacy `POST /token` path and response envelope intact during rollout.
- Migrate clients from expired API keys to v2 capability-scoped tokens; no data migration is required (ephemeral issuer).

## Open Questions

- Whether `allowedResources` should be expressed as a flat allow list or a nested mapping (e.g. per-partner entries) in the token claims.
