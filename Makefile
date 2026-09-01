BINARY := jwtoken-tester
MAIN_PKG := ./cmd/jwtoken-tester
BIN_DIR := bin
VERSION := $(shell cat VERSION 2>/dev/null || echo "dev")

ifeq ($(OS),Windows_NT)
EXE_SUFFIX := .exe
else
EXE_SUFFIX :=
endif

.PHONY: all build run test coverage coverage-html lint lint-install vet fmt fmt-check tidy clean help docker-build docker-push docker-compose-up docker-compose-down docker-logs

all: lint test build ## Lint, test, then build

build: ## Compile the server binary into bin/
	go build -trimpath -ldflags "-s -w -X main.Version=$(VERSION)" -o $(BIN_DIR)/$(BINARY)$(EXE_SUFFIX) $(MAIN_PKG)

run: build ## Build then run the server
	$(BIN_DIR)/$(BINARY)$(EXE_SUFFIX)

# Docker targets
DOCKER_IMAGE := jwtoken-tester
DOCKER_TAG ?= latest
DOCKER_REGISTRY ?=

docker-build: ## Build distroless Docker image
	docker build -f docker/Dockerfile -t $(DOCKER_IMAGE):$(DOCKER_TAG) .

docker-push: docker-build ## Push Docker image to registry (set DOCKER_REGISTRY)
	docker tag $(DOCKER_IMAGE):$(DOCKER_TAG) $(DOCKER_REGISTRY)/$(DOCKER_IMAGE):$(DOCKER_TAG)
	docker push $(DOCKER_REGISTRY)/$(DOCKER_IMAGE):$(DOCKER_TAG)

docker-compose-up: ## Start docker-compose stack (jwtoken-tester + demo service)
	docker compose -f docker/docker-compose.yml up --build -d
	@echo "jwtoken-tester: http://localhost:8080"
	@echo "demo-service:   http://localhost:8081"

docker-compose-down: ## Stop docker-compose stack
	docker compose -f docker/docker-compose.yml down

docker-logs: ## Follow docker-compose logs
	docker compose -f docker/docker-compose.yml logs -f

test: ## Run all unit tests
	go test ./...

COVERAGE_THRESHOLD ?= 90
COVER_PKGS := jwtoken-tester/internal/keyring jwtoken-tester/internal/server jwtoken-tester/internal/tokenfactory
COVER_PROFILE := coverage.out

coverage: ## Run tests and print total coverage percentage
	go test -covermode=atomic -coverprofile=$(COVER_PROFILE) $(COVER_PKGS)
	@go run cmd/coverage/main.go $(COVER_PROFILE)

coverage-check: ## Run tests and fail if total coverage is below threshold (default 90%)
	go test -covermode=atomic -coverprofile=$(COVER_PROFILE) $(COVER_PKGS)
	@go run cmd/coverage/main.go $(COVER_PROFILE) --threshold=$(COVERAGE_THRESHOLD)

coverage-html: ## Generate coverage.html from the latest coverage run
	go tool cover -html=coverage.out -o coverage.html
	@echo "coverage report written to coverage.html"

lint: fmt-check ## golangci-lint + gofmt formatting check
	golangci-lint run ./...

lint-install: ## Install golangci-lint
	go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@latest

vet: ## Static analysis with go vet
	go vet ./...

fmt: ## Rewrite all Go sources with gofmt
	gofmt -w .

fmt-check: ## Fail if any Go source is not gofmt-formatted
	@files=$$(gofmt -l .); \
	if [ -n "$$files" ]; then \
		echo "not gofmt-formatted:"; echo "$$files"; \
		echo "run 'make fmt' to fix"; \
		exit 1; \
	fi

tidy: ## Prune and sync module dependencies
	go mod tidy

clean: ## Remove build artifacts and test caches
	go clean -testcache
	$(RM) -r $(BIN_DIR)
	$(RM) coverage* cover*

help: ## List available targets
	@grep -E '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  %-13s %s\n", $$1, $$2}'
