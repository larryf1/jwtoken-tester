# Design

## Context

The project has OpenSpec initialized with an empty `openspec/specs/`. This change captures the shipped behavior of jwtoken-tester (see proposal.md - Why) as the first spec inventory. There is no application code change; the deliverable is spec content that will become the main specs after archive.

## Goals / Non-Goals

**Goals:**
- Produce a complete, validated baseline of capabilities and requirements that describe the system as it exists today.
- Organize capabilities so future changes can target a stable, cohesive boundary rather than re-documenting the whole system.

**Non-Goals:**
- No code, configuration, or dependency changes to the application.
- No capture of the CI, publish, and release workflows, which are slated for re-implementation.
- No capture of developer-only `make` targets or test/coverage tooling.
- The issuer deliberately does not implement TLS; HTTPS test environments terminate TLS at a reverse proxy in front of the service. This is captured as a spec requirement so consumers rely on it.

## Decisions

### Capability decomposition mirrors behavior, not packages
Capabilities are grouped by observable system behavior (`token-minting`, `key-management`, `http-api/*`, ...) rather than by the internal packages (`internal/keyring`, `internal/tokenfactory`, `internal/server`). An implementation detail (e.g., the Go package that produces a key) can change without perturbing the behavior contract a consumer relies on. The `http-api/` grouping nests the endpoint and middleware capabilities so the REST surface stays navigable as endpoints evolve.

### Requirement granularity is one behavior per requirement
Each requirement states a single externally observable behavior; alternatives and edge cases live in scenarios. This keeps requirement descriptions under the 500-character guidance and makes each requirement independently testable. Time-value parsing, TTL behavior, and error mapping are separate requirements even though they all surface on `POST /token`.

### CI/publish/release and dev tooling are excluded
The change deliberately leaves these out because they are being re-implemented (CI/publish/release) or are irrelevant to external behavior (dev `make` convenience targets). Capturing them now would immediately go stale.

### Completion is defined by archive
The change's tasks are the drafting, validation, and archive steps. Archiving merges the delta specs into `openspec/specs/` under the existing archive procedure; no custom script is needed.

## Risks / Trade-offs

- [Specs may drift from reality if the project changes before archive] → This change is authored directly from the current source and README; archive promptly after review.
- [Capability boundaries are a judgment call and may be re-cut later] → Boundaries are recorded in the proposal; re-cutting is a normal follow-up OpenSpec change, not a blocker.
- [Baseline capture is large in one change] → Split across 11 focused capability files so review and future diffs stay scoped; each file is independently validatable.