# Docker Setup

This directory contains Docker configuration for running jwtoken-tester and a demo protected service.

## Quick Start

```bash
# From project root
make docker-compose-up

# Or directly with docker compose
docker compose -f docker/docker-compose.yml up --build -d
```

This starts two services:
- **jwtoken-tester** (port 8080): Ephemeral JWT/JWKS issuer
- **demo-protected-service** (port 8081): Demo service that validates JWTs from jwtoken-tester

## Testing the Integration

1. Start the stack:
   ```bash
   make docker-compose-up
   ```

2. Get a token from jwtoken-tester:
   ```bash
   curl -s http://localhost:8080/token -d '{
     "claims": {
       "sub": "user-123",
       "aud": ["demo-service"],
       "roles": ["admin"]
     }
   }'
   ```

3. Use the token to access the protected endpoint:
   ```bash
   TOKEN=<access_token_from_step_2>
   curl -H "Authorization: Bearer $TOKEN" http://localhost:8081/protected
   ```

4. Check health endpoints:
   ```bash
   curl http://localhost:8080/healthz
   curl http://localhost:8081/healthz
   ```

## Environment Variables

### jwtoken-tester
| Variable | Default | Description |
|----------|---------|-------------|
| LISTEN | 0.0.0.0:8080 | Bind address |
| ISSUER | http://jwtoken-tester:8080 | External issuer URL |
| DEFAULT_TTL | 1h | Default token lifetime |
| MAX_TTL | 24h | Maximum token lifetime |
| ROTATION_INTERVAL | 30m | Key rotation interval (0 to disable) |
| GRACE_PERIOD | 25h | Grace period for retired keys |
| ALGORITHMS | RS256,ES256,EdDSA | Enabled algorithms |

### demo-protected-service
| Variable | Default | Description |
|----------|---------|-------------|
| PORT | 8081 | Listen port |
| ISSUER_URL | http://jwtoken-tester:8080 | Issuer URL for token validation |
| JWKS_URL | http://jwtoken-tester:8080/.well-known/jwks.json | JWKS endpoint |
| ALLOWED_AUD | demo-service | Required audience claim |
| JWKS_REFRESH | 5m | JWKS cache refresh interval |

## Stopping

```bash
make docker-compose-down
# or
docker compose -f docker/docker-compose.yml down
```

## Building Images Individually

```bash
# Build jwtoken-tester image
make docker-build
# or
docker build -f docker/Dockerfile -t jwtoken-tester:latest .

# Build demo service image
docker build -f docker/demo-service/Dockerfile -t demo-service:latest docker/demo-service
```