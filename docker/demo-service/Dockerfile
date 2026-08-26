# Build stage
FROM golang:1.27-alpine AS builder

WORKDIR /src

# Copy go.mod and go.sum for dependency caching
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build the binary statically
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o /demo-service .

# Runtime stage - distroless static
FROM gcr.io/distroless/static:nonroot

WORKDIR /

COPY --from=builder /demo-service /demo-service

EXPOSE 8081

ENTRYPOINT ["/demo-service"]