# Contributing to CryptoDeps

Thank you for your interest in contributing to CryptoDeps! This document provides guidelines for contributing to the project.

## Getting Started

### Prerequisites

- Go 1.21 or later
- Git

### Setup

```bash
git clone https://github.com/csnp/qramm-cryptodeps.git
cd qramm-cryptodeps
go mod download
go build -o cryptodeps ./cmd/cryptodeps
go test ./...
```

## Development Workflow

### Running Tests

```bash
# Run all tests
go test -race ./...

# Run tests without race detector (faster)
go test ./...

# View coverage report
go test -coverprofile=coverage.out ./...
go tool cover -html=coverage.out
```

### Code Style

```bash
# Format code
go fmt ./...
gofumpt -w .

# Run linter
golangci-lint run
```

## Contributing Code

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/my-feature`
3. Make your changes
4. Run tests: `go test -race ./...`
5. Run linter: `golangci-lint run`
6. Commit with a descriptive message
7. Push and open a Pull Request

### Commit Messages

Use conventional commits:

```
feat: add support for Cargo.toml
fix: correct SHA-384 classification
docs: update installation instructions
test: add tests for npm parser
refactor: improve reachability analysis performance
```

## Contributing Package Data

Help expand the crypto knowledge database by contributing analysis for packages not yet in the database.

### Finding Unknown Packages

```bash
# Scan a project and identify unknown packages
cryptodeps analyze /path/to/project --deep

# Look for packages marked as "unknown" or "low confidence"
```

### Submitting Package Data

1. Analyze the package source code to identify crypto usage
2. Create a JSON entry following the schema below
3. Submit a Pull Request with the new package data

### Package Entry Format

Add entries to `data/crypto-database.json`:

```json
{
  "name": "package-name",
  "ecosystem": "go",
  "crypto": [
    {
      "algorithm": "RSA",
      "type": "asymmetric",
      "quantumRisk": "vulnerable",
      "usage": "Key exchange",
      "file": "crypto.go",
      "evidence": "Uses crypto/rsa package",
      "confidence": "high"
    }
  ]
}
```

**Ecosystem values**: `go`, `npm`, `pypi`, `maven`

**quantumRisk values**: `vulnerable`, `partial`, `safe`

**confidence values**: `verified`, `high`, `medium`, `low`

## Adding Detection Patterns

### Import Patterns

Add new import patterns in `pkg/crypto/patterns.go`:

```go
{Pattern: "new/crypto/package", Ecosystem: types.EcosystemGo, Description: "Description", Algorithms: []string{"RSA", "AES"}},
```

### Algorithm Classifications

Add new algorithms in `pkg/crypto/quantum.go`:

```go
"new-algorithm": {Name: "New-Algorithm", Type: "encryption", QuantumRisk: types.RiskSafe, Severity: types.SeverityInfo, Description: "Description", Remediation: "Guidance"},
```

See [PATTERNS.md](PATTERNS.md) for the complete list of current patterns.

## Reporting Issues

### Bug Reports

Include:
- CryptoDeps version (`cryptodeps version`)
- Operating system and architecture
- Steps to reproduce
- Expected vs actual behavior
- Relevant manifest file (sanitized of sensitive data)

### Feature Requests

Describe:
- The problem you're trying to solve
- Your proposed solution
- Alternatives you've considered

### Security Vulnerabilities

For security issues, please email security@csnp.org instead of opening a public issue.

## Pull Request Guidelines

### Before Submitting

- [ ] Tests pass: `go test -race ./...`
- [ ] Linter passes: `golangci-lint run`
- [ ] Code is formatted: `go fmt ./...`
- [ ] Documentation updated if needed
- [ ] Commit messages follow conventional commits

### PR Description

Include:
- Summary of changes
- Motivation and context
- Testing performed
- Screenshots (if UI changes)

### Review Process

1. All PRs require at least one review
2. CI must pass before merge
3. Squash commits on merge for clean history

## Code of Conduct

Be respectful and constructive. We're all here to improve quantum security.

## License

By contributing, you agree that your contributions will be licensed under the Apache License 2.0.

## Questions?

- Open an issue for questions
- Visit [QRAMM.org](https://qramm.org) for quantum readiness resources
- Contact [CSNP](https://csnp.org) for organizational inquiries
