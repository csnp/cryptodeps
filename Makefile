.PHONY: build test lint clean install run help generate-db update-db db-stats release release-snapshot release-check

# Binary name
BINARY=cryptodeps

# Build variables
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo "none")
DATE    ?= $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")
LDFLAGS := -ldflags "-X main.version=$(VERSION) -X main.commit=$(COMMIT) -X main.date=$(DATE)"

# Default target
all: build

## build: Build the binary
build:
	go build $(LDFLAGS) -o $(BINARY) ./cmd/cryptodeps

## install: Install the binary to $GOPATH/bin
install:
	go install $(LDFLAGS) ./cmd/cryptodeps

## test: Run tests
test:
	go test -v -race -coverprofile=coverage.out ./...

## test-short: Run tests without race detector
test-short:
	go test -v -coverprofile=coverage.out ./...

## coverage: Show test coverage
coverage: test
	go tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report: coverage.html"

## lint: Run linter
lint:
	golangci-lint run ./...

## fmt: Format code
fmt:
	go fmt ./...
	gofumpt -l -w .

## clean: Remove build artifacts
clean:
	rm -f $(BINARY)
	rm -f coverage.out coverage.html
	rm -rf dist/

## run: Build and run with sample input
run: build
	./$(BINARY) version

## deps: Download dependencies
deps:
	go mod download
	go mod tidy

## generate-db: Generate data/crypto-database.json for GitHub releases
generate-db:
	@echo "Generating crypto-database.json..."
	@go run cmd/gendb/main.go 2>/dev/null > data/crypto-database.json
	@echo "Done. Database saved to data/crypto-database.json"
	@echo "Packages: $$(jq '.packages | length' data/crypto-database.json)"

## update-db: Update local database cache from GitHub releases
update-db:
	./$(BINARY) update || go run ./cmd/cryptodeps update

## db-stats: Show database statistics
db-stats:
	./$(BINARY) status || go run ./cmd/cryptodeps status

## release-check: Validate goreleaser configuration
release-check:
	goreleaser check

## release-snapshot: Build a snapshot release (no publish)
release-snapshot:
	goreleaser release --snapshot --clean

## release: Build and publish a release (requires GITHUB_TOKEN)
release:
	goreleaser release --clean

## docker-build: Build Docker image locally
docker-build: build
	docker build -t cryptodeps:local -f Dockerfile.goreleaser .

## help: Show this help
help:
	@echo "CryptoDeps - Dependency Crypto Analyzer"
	@echo ""
	@echo "Usage: make [target]"
	@echo ""
	@echo "Targets:"
	@grep -E '^## ' Makefile | sed 's/## /  /'
