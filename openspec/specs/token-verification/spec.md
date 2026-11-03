# token-verification Specification

## Purpose

Defines how jwtoken-tester verifies and diagnoses tokens: the self-check `/verify` contract, the closed failure taxonomy with deterministic precedence, and the labeling that separates authenticated claims from unverified ones.

## Requirements

### Requirement: Verification uses only the issuer's live keyring
`POST /verify` SHALL verify the submitted token using only the keys held by the running issuer. It SHALL NOT accept caller-supplied key material or key locations, including an inline JWKS, a JWKS URL, or an issuer or discovery URL, and it SHALL NOT make outbound network requests. A request that supplies such a field SHALL be rejected with `400`.

#### Scenario: External key source rejected
- **WHEN** a client posts a verification request containing a `jwks` object or a `jwks_url`
- **THEN** the response is `400` and no verification is attempted

#### Scenario: Foreign token fails without a fetch
- **WHEN** a client posts a token signed by a key that is not in the live keyring
- **THEN** the verdict is not valid because of the missing key
- **AND** the server performs no outbound request

### Requirement: A valid token returns a verdict with authenticated claims
`POST /verify` SHALL accept a JSON body with a required `token` string and optional `aud`, `alg`, and `leeway` fields, and SHALL return `200` with a JSON verdict. A verified token SHALL produce `valid: true` together with `header`, `claims`, and `kid_status`.

#### Scenario: Valid token accepted
- **WHEN** a client posts a token recently minted by this issuer with an enabled algorithm
- **THEN** the response is `200` with `valid: true`, the token `header`, the token `claims`, and `kid_status`

#### Scenario: Empty token rejected
- **WHEN** the request body omits `token` or supplies an empty string
- **THEN** the response is `400` with an error message

### Requirement: Failure reasons form a closed, ordered set
A failed verification SHALL return `valid: false` with exactly one `reason` drawn from `malformed`, `alg`, `kid`, `signature`, `expired`, `not_yet_valid`, `issuer`, or `audience`, plus a non-empty `error` message. Checks SHALL run structural, algorithm, key, signature, time, issuer, then audience, and a later failure SHALL NOT replace an earlier one.

#### Scenario: Structural failure reported as malformed
- **WHEN** the submitted value is not a three-segment compact JWS or its segments do not decode
- **THEN** the verdict reason is `malformed`

#### Scenario: Disabled algorithm reported as alg
- **WHEN** the token header names an algorithm the issuer does not enable
- **THEN** the verdict reason is `alg`

#### Scenario: Unknown key reported as kid
- **WHEN** the token header names a `kid` that is not in the live keyring
- **THEN** the verdict reason is `kid`

#### Scenario: Bad signature reported as signature
- **WHEN** the token signature does not verify with the key selected by `kid`
- **THEN** the verdict reason is `signature`

#### Scenario: Expired token reported as expired
- **WHEN** a correctly signed token's `exp` is in the past beyond the accepted leeway
- **THEN** the verdict reason is `expired`

#### Scenario: Future token reported as not_yet_valid
- **WHEN** a correctly signed token's `nbf` or `iat` is in the future beyond the accepted leeway
- **THEN** the verdict reason is `not_yet_valid`

#### Scenario: Issuer mismatch reported as issuer
- **WHEN** a correctly signed token's `iss` does not equal the configured issuer
- **THEN** the verdict reason is `issuer`

#### Scenario: Audience mismatch reported as audience
- **WHEN** a request supplies an `aud` and a correctly signed token carries no matching audience
- **THEN** the verdict reason is `audience`

#### Scenario: Earlier failure takes precedence
- **WHEN** a token is both expired and signed with an unknown key
- **THEN** the verdict reason is `kid`

### Requirement: Claims are labeled by verification state
The verdict SHALL expose token claims under `claims` only after signature verification succeeds, and SHALL expose claims parsed before that point only under `unverified_claims`. A verdict SHALL NOT expose unverified claims under `claims`.

#### Scenario: Signature failure exposes unverified claims only
- **WHEN** the token payload is decodable but the signature does not verify
- **THEN** the verdict contains `unverified_claims` and no `claims`

#### Scenario: Time or claim-check failure exposes authenticated claims
- **WHEN** the signature verifies but the token fails the time, issuer, or audience check
- **THEN** the verdict contains `claims` and no `unverified_claims`

#### Scenario: Malformed token exposes no claims
- **WHEN** the token cannot be structurally decoded
- **THEN** the verdict contains neither `claims` nor `unverified_claims`

### Requirement: The issuer claim is always validated
`/verify` SHALL validate `iss` against the issuer's configured value and SHALL NOT accept an issuer override. A token minted with a deliberately different `iss` SHALL fail with `reason: issuer`.

#### Scenario: Matching issuer accepted
- **WHEN** a token's `iss` equals the configured issuer
- **THEN** the issuer check passes

#### Scenario: Overridden issuer rejected
- **WHEN** a token's `iss` was explicitly set to a different value at mint time
- **THEN** the verdict reason is `issuer`

### Requirement: Algorithm acceptance defaults to enabled algorithms
The accepted algorithm set SHALL be the algorithms the issuer has enabled. An optional `alg` request list SHALL narrow that set. A request whose `alg` list is empty or names an algorithm the issuer does not enable SHALL be rejected with `400`.

#### Scenario: Default accepts every enabled algorithm
- **WHEN** a request omits `alg` and the token uses any enabled algorithm
- **THEN** the algorithm check passes

#### Scenario: Narrowing rejects an otherwise valid algorithm
- **WHEN** the request restricts `alg` to a subset that excludes the token's algorithm
- **THEN** the verdict reason is `alg`

#### Scenario: Unsupported algorithm in the request rejected
- **WHEN** the request names an algorithm the issuer does not support
- **THEN** the response is `400`

### Requirement: Audience and leeway are optional consumer expectations
`/verify` SHALL check `aud` only when the request supplies one, accepting a match against any member of a string or array audience. An optional `leeway` SHALL widen the accepted time window for `exp`, `nbf`, and `iat`; its absence SHALL mean no leeway.

#### Scenario: Audience is not checked when omitted
- **WHEN** the request omits `aud`
- **THEN** no audience mismatch is reported

#### Scenario: Audience array matches any member
- **WHEN** the request supplies an audience that appears anywhere in an array-valued token audience
- **THEN** the audience check passes

#### Scenario: Leeway admits a recently expired token
- **WHEN** a token expired within the supplied `leeway`
- **THEN** the verdict is valid

### Requirement: Key status accompanies every readable kid
Whenever the token header carries a `kid`, the verdict SHALL include `kid_status` set to `active`, `retired`, or `unknown`. `retired` SHALL mean the key is still published within its grace window; `unknown` SHALL mean no key with that `kid` is available.

#### Scenario: Active key reported
- **WHEN** a token is signed with the current active key
- **THEN** `kid_status` is `active`

#### Scenario: Retired key still verifies
- **WHEN** a token signed before a rotation still verifies with a key inside its grace window
- **THEN** the verdict is valid and `kid_status` is `retired`

#### Scenario: Pruned key reported as unknown
- **WHEN** the token's key has been pruned from the keyring
- **THEN** the verdict reason is `kid` and `kid_status` is `unknown`

### Requirement: Request errors use client-error statuses
A missing or empty `token`, an unparsable JSON body, an invalid `leeway`, or an invalid `alg` list SHALL return `400`. A non-POST method SHALL return `405`. A body larger than 1 MiB SHALL return `400` without a verdict.

#### Scenario: Wrong method rejected
- **WHEN** a client sends a non-POST request to `/verify`
- **THEN** the response is `405`

#### Scenario: Oversized body rejected
- **WHEN** the request body exceeds 1 MiB
- **THEN** the response is `400` and no verdict is returned

### Requirement: Unclassifiable failures are server errors
If verification fails for a reason outside the closed reason set, the server SHALL return `500` rather than inventing a reason or reporting a verdict.

#### Scenario: Unexpected verification error
- **WHEN** verification fails with an error that cannot be mapped to a closed reason
- **THEN** the response is `500` with an error message

### Requirement: Verification responses are not cacheable
`POST /verify` responses SHALL carry `Cache-Control: no-store`.

#### Scenario: Verdict is not cached
- **WHEN** a client posts a verification request
- **THEN** the response includes `Cache-Control: no-store`

### Requirement: Verification is audited without token contents
The server SHALL log a verification event containing the outcome, the failure reason when invalid, `kid`, `kid_status`, and algorithm. The log event SHALL NOT contain the token or its claims.

#### Scenario: Invalid verdict logged
- **WHEN** a verification returns `valid: false`
- **THEN** the audit event records the reason and key status
- **AND** the token value and claim values do not appear in the event
