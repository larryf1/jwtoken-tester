# Proposal

## Why

The integration's static API key has expired, and signing in again did not renew it - a replacement key had to be created in the console. The durable remediation is to stop relying on static API keys and instead issue short-lived, capability-scoped JWTs through the OAuth 2.0 token endpoint, so clients can request exactly the capabilities they need.

## What Changes

- Add support for the JWT **v2** OAuth token request syntax:

  ```
  curl --request POST \
    --url 'https://jwt.net/v2/oauth/token? Scope=capability1,capability2' \
    --header 'X-Client-Id: client-id' \
    --header 'X-Client-Secret: REDACTED' \
    --header 'accept: application/json'
  ```

- Accept client credentials on token requests via the `X-Client-Id` / `X-Client-Secret` headers and a capability scope via the `Scope` query parameter (comma-separated capability identifiers).
- Return versioned **v2** token responses whose claims include `sub`, `aud`, `nbf`, `capabilities`, `idtyp`, `iss`, `allowedResources`, `exp`, `iat`, `version: "2.0"`, `jti`, and `client_id`, alongside the existing access token metadata.

## Capabilities

### New Capabilities

None - the v2 token format is an evolution of the existing token minting behavior rather than a brand-new capability.

### Modified Capabilities

- `token-minting`: the token minted through the OAuth flow now uses the versioned v2 format, including granted capabilities, allowed resources, and client identity claims.

## Impact

- Affected code: `internal/tokenfactory`, `internal/server`, `docs/openapi.yaml`, and related tests in `internal/server` and `internal/tokenfactory`.
- APIs: the token endpoint gains v2 OAuth request/response handling (client credentials + scope, versioned claims).
- Dependencies: none new expected; the JWT library in use already supports custom claims and protected JOSE headers.
