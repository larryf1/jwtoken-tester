# Build stage
FROM golang:1.27-alpine AS builder

ARG VERSION

WORKDIR /src

# A version is required: never bake a placeholder into the image. The Makefile
# and the publish/release workflows compute it with scripts/version.sh.
RUN test -n "$VERSION" || { \
		echo "VERSION build arg is required (use 'make docker-build' or pass --build-arg VERSION=<version>)" >&2; \
		exit 1; \
	}

# Copy go.mod and go.sum for dependency caching
COPY go.mod go.sum ./
# go.mod replaces this module with a local directory, so its go.mod must be
# present before dependency resolution runs.
COPY third_party/conventionalcommit-parser/go.mod ./third_party/conventionalcommit-parser/go.mod
RUN go mod download

# Copy source code
COPY . .

# Build the binary statically with the injected version
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.Version=${VERSION}" -o /jwtoken-tester ./cmd/jwtoken-tester

# Runtime stage - distroless static
FROM gcr.io/distroless/static:nonroot

ARG VERSION
ARG REVISION=unknown
ARG CREATED=unknown

LABEL org.opencontainers.image.title="jwtoken-tester"
LABEL org.opencontainers.image.description="Ephemeral JWT/JWKS test issuer"
LABEL org.opencontainers.image.version="${VERSION}"
LABEL org.opencontainers.image.revision="${REVISION}"
LABEL org.opencontainers.image.source="https://github.com/larryf1/jwtoken-tester"
LABEL org.opencontainers.image.licenses="MIT"
LABEL org.opencontainers.image.created="${CREATED}"

WORKDIR /

COPY --from=builder /jwtoken-tester /jwtoken-tester

# Listen on all interfaces so a published port works without extra flags. The
# binary default stays loopback-only for local, non-container runs.
ENV LISTEN=0.0.0.0:8080

# Expose the default port
EXPOSE 8080

# Run as non-root user (distroless static:nonroot uses user 65532:65532)
ENTRYPOINT ["/jwtoken-tester", "serve"]