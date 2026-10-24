# Tasks

## 1. Versioned token endpoint

- [x] 1.1 Add the versioned OAuth token route (`POST /v2/oauth/token`) to the server handler while keeping the legacy `POST /token` route intact; verify with routing tests that both endpoints are registered and behave independently.

## 2. Versioned token minting

- [x] 2.1 Implement client credential and capability scope handling for the versioned token flow; verify with handler tests that authenticated requests carrying a scope mint a token and unauthenticated or malformed requests are rejected.

- [x] 2.2 Extend the token factory to mint versioned v2 tokens carrying `version`, granted `capabilities`, and `allowedResources` alongside the standard claims; verify with token factory unit tests asserting the minted claim set.

## 3. Response contract and documentation

- [x] 3.1 Return the versioned token response envelope (`access_token`, `token_type`, `expires_in`) for v2 mints; verify with handler tests.

- [x] 3.2 Update the OpenAPI document and the discovery document `claims_supported` for the v2 token format; verify the OpenAPI YAML parses and the documented contract stays in sync.

## Workflow follow-up

- Archive the change after the project's review requirements are satisfied.
- Verify the archived result.
