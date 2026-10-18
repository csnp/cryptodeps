# Development

How to build and test CryptoDeps locally. The full contribution guidelines are in [CONTRIBUTING.md](../CONTRIBUTING.md).

## Contributing

We welcome contributions from the community! See [CONTRIBUTING.md](../CONTRIBUTING.md) for guidelines.

## Development Setup

```bash
# Clone the repository
git clone https://github.com/csnp/qramm-cryptodeps.git
cd qramm-cryptodeps

# Install dependencies
go mod download

# Run tests
go test -race ./...

# Build
go build -o cryptodeps ./cmd/cryptodeps

# Run linter
make lint
```

## Adding Package Data

Help expand the crypto knowledge database by contributing analysis for new packages. See [CONTRIBUTING.md](../CONTRIBUTING.md) for the package entry format.
