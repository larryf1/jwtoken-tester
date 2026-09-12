# Security Policy

## Supported versions

| Version | Supported          |
|---------|--------------------|
| latest  | :white_check_mark: |
| < latest | :x:               |

Only the most recent release receives security fixes.

## Reporting a vulnerability

jwtoken-tester is a **test-time identity provider**, so most security impact is
limited to test environments. Still, we take reports seriously.

Please report suspected vulnerabilities privately — **do not open a public
issue or PR**:

- Email: `larryf1@gmail.com`
- Subject prefix: `[jwtoken-tester] Security report`

What to include:

- Affected version / commit and the platform it was run on
- A minimal reproduction (curl snippet or test-helper usage)
- Impact: what an attacker could gain and under what conditions
- Suggested fix, if you have one

### Response expectations

- An acknowledgement within 3 business days.
- A triage decision (accepted / declined / needs info) within 7 business days.
- We coordinate disclosure with you once a fix lands.

## Not security vulnerabilities

This is a deliberately insecure-by-default tool: **no TLS**, permissive signing,
warnings when bound beyond loopback. Behaviour that is "insecure *on purpose*"
and documented in the README is usually not a vulnerability. If you are unsure,
report it anyway.

### TLS / HTTPS

jwtoken-tester does not implement TLS. It speaks plain HTTP only.
For test environments requiring HTTPS, place a reverse proxy (nginx, Caddy, Traefik,
envoy, etc.) in front to terminate TLS. This is by design — the tool focuses on
JWT/JWKS correctness, not transport security.

## Security guardrails we keep in the codebase

- Private keys are generated in memory and zeroized; they must never be
  persisted, logged, or returned over HTTP.
- The server refuses to serve as a production IdP: it warns loudly when bound
  beyond `127.0.0.1`.
- Contributions that weaken these properties are rejected (see
  [`CONTRIBUTING.md`](CONTRIBUTING.md)).