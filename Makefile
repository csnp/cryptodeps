.PHONY: build test lint clean install run help

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

## help: Show this help
help:
	@echo "CryptoDeps - Dependency Crypto Analyzer"
	@echo ""
	@echo "Usage: make [target]"
	@echo ""
	@echo "Targets:"
	@grep -E '^## ' Makefile | sed 's/## /  /'
