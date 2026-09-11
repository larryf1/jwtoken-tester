# Build stage
FROM golang:1.27-alpine AS builder

ARG VERSION=dev

WORKDIR /src

# Copy go.mod and go.sum for dependency caching
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build the binary statically with the injected version
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.Version=${VERSION}" -o /jwtoken-tester ./cmd/jwtoken-tester

# Runtime stage - distroless static
FROM gcr.io/distroless/static:nonroot

ARG VERSION=dev
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

# Expose the default port
EXPOSE 8080

# Run as non-root user (distroless static:nonroot uses user 65532:65532)
ENTRYPOINT ["/jwtoken-tester", "serve"]