# Tasks

## 1. Verify configuration and CLI specs against the source

- [x] 1.1 Read `cmd/jwtoken-tester/main.go` and confirm `configuration/spec.md` matches every env var, flag, default, and precedence rule, then verify with `openspec validate --changes`
- [x] 1.2 Confirm `cli/spec.md` matches the `serve`, `print-token`, and `help` behavior, usage/exit semantics, and version fallback by reviewing `main.go`

## 2. Verify key management spec against the source

- [x] 2.1 Read `internal/keyring/keyring.go` and confirm `key-management/spec.md` matches generation, thumbprint kids, rotation, grace/pruning, zeroization, and algorithm enablement, then verify with `openspec validate --changes`

## 3. Verify token minting spec against the source and tests

- [x] 3.1 Read `internal/tokenfactory/factory.go`, the `/token` handler in `internal/server/server.go`, and `internal/tokenfactory/factory_test.go` and confirm `token-minting/spec.md` matches request/response shape, time parsing, TTL behavior, algorithm validation, JOSE headers, error mapping, and audit events, then verify with `openspec validate --changes`

## 4. Verify HTTP API specs against the source and tests

- [x] 4.1 Read `internal/server/server.go`, `docs/openapi.yaml`, and `internal/server/server_test.go` and confirm the `http-api/*` specs (service-metadata, health, discovery, jwks, security) match the handlers, response schemas, security headers, rate limiting, and request IDs, then verify with `openspec validate --changes`

## 5. Verify embedding and container specs

- [x] 5.1 Read `pkg/tester/tester.go` and `pkg/tester/tester_test.go` and confirm `embedding/spec.md` matches the `NewServer` API, options, accessors, and cleanup behavior, then verify with `openspec validate --changes`
- [x] 5.2 Read `docker/Dockerfile`, `docker/docker-compose.yml`, and `docker/demo-service/main.go` and confirm `container/spec.md` matches the image contract, OCI labels, and demo stack behavior, then verify with `openspec validate --changes`

## 6. Validate the complete change

- [x] 6.1 Run `openspec validate --change add-baseline-specs` and confirm the proposal, all 11 delta specs, design, and tasks pass without findings
- [x] 6.2 Confirm every capability in the proposal has a matching `specs/<capability-path>/spec.md` file that exists on disk

## Workflow follow-up

- Archive the change with `openspec archive add-baseline-specs --yes` once review is satisfied; this merges the delta specs into `openspec/specs/`.
- Verify the archived result with `openspec list --specs` and `openspec validate --specs`.