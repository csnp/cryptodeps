# How it works

How the CryptoDeps code is organized, from the command-line entry point to the crypto database. Start with the [README](../README.md) if you are new to CryptoDeps.

## Architecture

```
qramm-cryptodeps/
├── cmd/cryptodeps/          # CLI entry point
├── internal/
│   ├── analyzer/            # Core analysis engine
│   │   ├── ast/             # Language-specific AST parsing
│   │   ├── ondemand/        # Source code fetching & analysis
│   │   ├── reachability/    # Call graph analysis (Go)
│   │   └── source/          # Package source resolution
│   ├── database/            # Crypto knowledge database
│   ├── manifest/            # Dependency manifest parsers
│   └── registry/            # Package registry fetchers
├── pkg/
│   ├── crypto/              # Algorithm patterns & remediation
│   ├── output/              # Formatters (table, JSON, CBOM, SARIF)
│   └── types/               # Shared type definitions
├── data/                    # Crypto database (downloaded by `cryptodeps update`)
└── examples/                # Sample projects for testing
```
