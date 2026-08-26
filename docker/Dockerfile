# Build stage
FROM golang:1.27-alpine AS builder

WORKDIR /src

# Copy go.mod and go.sum for dependency caching
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build the binary statically
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o /jwtoken-tester ./cmd/jwtoken-tester

# Runtime stage - distroless static
FROM gcr.io/distroless/static:nonroot

WORKDIR /

COPY --from=builder /jwtoken-tester /jwtoken-tester

# Expose the default port
EXPOSE 8080

# Run as non-root user (distroless static:nonroot uses user 65532:65532)
ENTRYPOINT ["/jwtoken-tester", "serve"]