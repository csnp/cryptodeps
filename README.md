# CryptoDeps

[![CI](https://github.com/csnp/qramm-cryptodeps/actions/workflows/ci.yml/badge.svg)](https://github.com/csnp/qramm-cryptodeps/actions/workflows/ci.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/csnp/qramm-cryptodeps)](https://goreportcard.com/report/github.com/csnp/qramm-cryptodeps)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)

**Dependency Crypto Analyzer** — Identify quantum-vulnerable cryptographic algorithms in your software dependencies.

Part of the [QRAMM Toolkit](https://qramm.org) by [CSNP](https://csnp.org).

---

## The Problem

Your code might be quantum-safe, but what about your **847 dependencies**?

Most cryptographic vulnerabilities hide in the dependency tree — libraries you didn't write and rarely audit. When quantum computers arrive, RSA and ECDSA in your dependencies will be just as broken as in your own code.

**CryptoDeps answers:** *"Which of my dependencies use quantum-vulnerable crypto, and how does that crypto reach my code?"*

---

## Quick Start

### Installation

**Option 1: Build from Source** (Recommended)

Requires **Go 1.21+** ([install Go](https://go.dev/dl/))

```bash
git clone https://github.com/csnp/qramm-cryptodeps.git
cd qramm-cryptodeps
go build -o cryptodeps ./cmd/cryptodeps
sudo mv cryptodeps /usr/local/bin/
```

**Option 2: Download Binary**

Download from [Releases](https://github.com/csnp/qramm-cryptodeps/releases).

### Basic Usage

```bash
# Analyze current directory (auto-detects manifest)
cryptodeps analyze .

# Analyze specific manifest
cryptodeps analyze ./go.mod
cryptodeps analyze ./package.json
cryptodeps analyze ./requirements.txt
cryptodeps analyze ./pom.xml

# Output formats
cryptodeps analyze . --format table     # Human-readable (default)
cryptodeps analyze . --format json      # Machine-readable
cryptodeps analyze . --format cbom      # CycloneDX CBOM
cryptodeps analyze . --format sarif     # GitHub Security
cryptodeps analyze . --format markdown  # Reports
```

---

## Example Output

```
$ cryptodeps analyze ./go.mod

Scanning go.mod... found 47 dependencies

DEPENDENCY                              CRYPTO               RISK
────────────────────────────────────────────────────────────────────────────────
golang.org/x/crypto v0.17.0             Ed25519, X25519      VULNERABLE
                                        ChaCha20             SAFE
github.com/golang-jwt/jwt/v5 v5.2.0     RS256, ES256         VULNERABLE
                                        HS256                PARTIAL
github.com/go-sql-driver/mysql v1.7.1   SHA256               PARTIAL

────────────────────────────────────────────────────────────────────────────────
SUMMARY: 47 deps | 12 use crypto | 4 vulnerable | 3 partial

⚠ 2 packages not in database (use --deep to analyze)
```

---

## Features

### Supported Ecosystems

| Ecosystem | Manifest Files | Status |
|-----------|---------------|--------|
| **Go** | `go.mod` | Supported |
| **npm** | `package.json` | Supported |
| **Python** | `requirements.txt`, `pyproject.toml` | Supported |
| **Maven** | `pom.xml` | Supported |

### Output Formats

| Format | Flag | Use Case |
|--------|------|----------|
| **Table** | `--format table` | Human-readable CLI output |
| **JSON** | `--format json` | Automation and scripting |
| **CBOM** | `--format cbom` | CycloneDX compliance (OMB M-23-02) |
| **SARIF** | `--format sarif` | GitHub Security integration |
| **Markdown** | `--format markdown` | Reports and documentation |

### Quantum Risk Classification

| Risk | Meaning | Algorithms | Recommended Action |
|------|---------|------------|-------------------|
| **VULNERABLE** | Broken by quantum computers | RSA, ECDSA, Ed25519, DH | Migrate to PQC |
| **PARTIAL** | Security reduced by quantum | AES-128, SHA-256 | Increase key sizes |
| **SAFE** | Quantum-resistant | AES-256, ML-KEM, ML-DSA | No action needed |

---

## How It Works

CryptoDeps uses a **hybrid analysis approach**:

```
┌─────────────────────────────────────────────────────────────────┐
│                     Your Project                                │
│                     go.mod / package.json                       │
└──────────────────────────┬──────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────────┐
│                   CryptoDeps Analyzer                           │
│                                                                 │
│    ┌────────────────────┐     ┌────────────────────┐           │
│    │  Database Lookup   │     │  On-Demand Analysis │           │
│    │  (milliseconds)    │     │  (--deep flag)      │           │
│    │                    │     │                     │           │
│    │  Known packages    │     │  Unknown packages   │           │
│    │  with crypto data  │     │  analyzed via AST   │           │
│    └────────────────────┘     └─────────────────────┘           │
└──────────────────────────┬──────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────────┐
│               Quantum Risk Report                               │
│     SARIF / CBOM / JSON / Table / Markdown                      │
└─────────────────────────────────────────────────────────────────┘
```

1. **Fast Path (Database)**: Known packages are looked up in a curated database of crypto usage patterns. Returns results in milliseconds.

2. **Slow Path (On-Demand)**: Unknown packages can be analyzed via AST parsing with the `--deep` flag. Results are cached and can be contributed back.

---

## CI/CD Integration

### GitHub Actions

```yaml
name: Crypto Dependency Scan
on: [push, pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install CryptoDeps
        run: |
          curl -sSL https://github.com/csnp/qramm-cryptodeps/releases/latest/download/cryptodeps_linux_x86_64.tar.gz | tar xz
          sudo mv cryptodeps /usr/local/bin/

      - name: Scan Dependencies
        run: cryptodeps analyze . --format sarif > cryptodeps.sarif

      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: cryptodeps.sarif
```

### GitLab CI

```yaml
crypto-scan:
  stage: security
  script:
    - cryptodeps analyze . --format json > crypto-report.json
  artifacts:
    reports:
      security: crypto-report.json
```

---

## CLI Reference

```
cryptodeps analyze [path] [flags]

Flags:
  -f, --format string       Output format: table, json, cbom, sarif, markdown (default "table")
      --offline             Only use local database, no downloads
      --deep                Force on-demand analysis for unknown packages
      --risk string         Filter by risk level: vulnerable, partial, all
      --min-severity string Minimum severity to report

Database Commands:
  cryptodeps db stats       Show database statistics
  cryptodeps db update      Update the database (coming soon)
```

---

## Database

CryptoDeps uses a community-curated database of package-to-crypto mappings:

```bash
# View database stats
cryptodeps db stats

# Output:
CryptoDeps Database Statistics
==============================
Total packages: 8

By ecosystem:
  go: 2
  npm: 3
  pypi: 2
  maven: 1

Database type: embedded (built-in seed data)
```

The embedded database contains seed data for common crypto-using packages. A full community database is planned for future releases.

---

## Related Tools

CryptoDeps is part of the **QRAMM Toolkit** for quantum readiness:

| Tool | Purpose | Status |
|------|---------|--------|
| [**CryptoScan**](https://github.com/csnp/qramm-cryptoscan) | Scan source code for crypto usage | Available |
| [**TLS-Analyzer**](https://github.com/csnp/qramm-tls-analyzer) | Analyze TLS configurations | Available |
| **CryptoDeps** | Analyze dependency crypto usage | Available |
| [**QRAMM Toolkit**](https://github.com/csnp/qramm-toolkit) | Assessment framework | Available |

---

## Contributing

We welcome contributions! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

### Contributing Package Data

Help expand the database by contributing crypto analysis for packages:

```bash
# Analyze an unknown package
cryptodeps analyze . --deep --export-unknown

# Submit the generated YAML to the database repo
# (Coming soon)
```

---

## About CSNP

CryptoDeps is developed by **CSNP** (Cyber Security Non-Profit), a 501(c)(3) organization advancing cybersecurity through education, research, and open-source tools.

**Mission:** Empower organizations worldwide to achieve quantum readiness through accessible, high-quality security tools.

- Website: [csnp.org](https://csnp.org)
- QRAMM: [qramm.org](https://qramm.org)

---

## License

Apache License 2.0 — See [LICENSE](LICENSE) for details.

---

## References

- [NIST FIPS 203 - ML-KEM](https://csrc.nist.gov/pubs/fips/203/final)
- [NIST FIPS 204 - ML-DSA](https://csrc.nist.gov/pubs/fips/204/final)
- [CycloneDX CBOM Specification](https://cyclonedx.org/capabilities/cbom/)
- [OMB M-23-02 - Federal Crypto Inventory](https://www.whitehouse.gov/wp-content/uploads/2022/11/M-23-02-M-Memo-on-Migrating-to-Post-Quantum-Cryptography.pdf)
