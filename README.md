# QRAMM CryptoDeps

[![CI](https://github.com/csnp/qramm-cryptodeps/actions/workflows/ci.yml/badge.svg)](https://github.com/csnp/qramm-cryptodeps/actions/workflows/ci.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/csnp/qramm-cryptodeps)](https://goreportcard.com/report/github.com/csnp/qramm-cryptodeps)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)

## Overview

QRAMM CryptoDeps is an open-source command-line tool that identifies quantum-vulnerable cryptographic algorithms hiding in your software dependencies. Your code might be quantum-safe, but what about the **hundreds of dependencies** in your project? Most cryptographic vulnerabilities lurk in the dependency tree — libraries you didn't write and rarely audit.

Part of the [QRAMM (Quantum Readiness Assurance Maturity Model)](https://qramm.org) toolkit, developed by the [Cyber Security Non-Profit (CSNP)](https://csnp.org).

## Why Dependency Crypto Analysis Matters

- **Hidden Attack Surface**: The average project has 300-1000+ transitive dependencies, each potentially using vulnerable cryptography
- **Harvest Now, Decrypt Later (HNDL)**: Adversaries are collecting encrypted data today to decrypt once quantum computers become available
- **CNSA 2.0 Compliance**: NSA's timeline requires hybrid PQC by 2027 — dependencies with RSA/ECDSA will block compliance
- **Supply Chain Risk**: Third-party libraries with vulnerable crypto create exposure beyond your direct control
- **OMB M-23-02**: Federal agencies must inventory all cryptographic assets, including those in dependencies

## Quick Start

```bash
# Clone and build (requires Go 1.21+)
git clone https://github.com/csnp/qramm-cryptodeps.git
cd qramm-cryptodeps
go build -o cryptodeps ./cmd/cryptodeps

# Analyze your project
./cryptodeps analyze .

# Expected output: Dependency crypto inventory with quantum risk classification
# - VULNERABLE: RSA, ECDSA, Ed25519 (broken by quantum)
# - PARTIAL: AES-128, SHA-256 (reduced security)
# - SAFE: AES-256, ChaCha20 (quantum-resistant)
```

Don't have Go? Download pre-built binaries from [Releases](https://github.com/csnp/qramm-cryptodeps/releases).

## Features

### Dependency Analysis

| Feature | Description |
|---------|-------------|
| Multi-Ecosystem Support | Go (go.mod), npm (package.json), Python (requirements.txt, pyproject.toml), Maven (pom.xml) |
| Transitive Scanning | Analyzes entire dependency tree, not just direct dependencies |
| Database Lookup | Millisecond lookups for 72+ known crypto-using packages |
| On-Demand Analysis | AST-based source code analysis for unknown packages (`--deep`) |

### Quantum Risk Assessment

| Feature | Description |
|---------|-------------|
| Algorithm Classification | Categorizes all detected crypto as VULNERABLE, PARTIAL, or SAFE |
| Risk Scoring | Quantifies quantum exposure across your dependency tree |
| Remediation Guidance | Actionable recommendations for each vulnerable dependency |
| CNSA 2.0 Alignment | Maps findings to NSA's post-quantum migration timeline |

### Compliance & Reporting

| Feature | Description |
|---------|-------------|
| CycloneDX CBOM | Generate Cryptographic Bill of Materials (OMB M-23-02 compliant) |
| SARIF Output | Native GitHub Security tab integration |
| CI/CD Exit Codes | Fail builds on quantum-vulnerable dependencies |
| Multiple Formats | Table, JSON, Markdown, SARIF, CBOM output options |

## Usage

### Output Formats

```bash
./cryptodeps analyze .                          # Human-readable table (default)
./cryptodeps analyze . --format json            # JSON for automation
./cryptodeps analyze . --format cbom            # CycloneDX CBOM
./cryptodeps analyze . --format sarif           # SARIF for GitHub Security
./cryptodeps analyze . --format markdown        # Markdown reports
```

### Analysis Modes

```bash
./cryptodeps analyze ./go.mod                   # Specific manifest file
./cryptodeps analyze . --deep                   # On-demand analysis for unknown packages
./cryptodeps analyze . --offline                # Use only local database
./cryptodeps analyze . --risk vulnerable        # Filter by risk level
```

### CI/CD Integration

```bash
./cryptodeps analyze . --fail-on vulnerable     # Exit 1 on quantum-broken crypto
./cryptodeps analyze . --fail-on partial        # Exit 3 on reduced-security crypto
./cryptodeps analyze . --fail-on any            # Exit non-zero on any crypto
./cryptodeps analyze . --fail-on none           # Never fail (report only)
```

## Example Output

Sample terminal output:

```
═══════════════════════════════════════════════════════════════════════════════
  QRAMM CryptoDeps - Dependency Crypto Analyzer
═══════════════════════════════════════════════════════════════════════════════

  Project: my-application
  Manifest: go.mod
  Scanned: 2025-01-15 10:30:00 UTC

───────────────────────────────────────────────────────────────────────────────
  SCAN RESULTS
───────────────────────────────────────────────────────────────────────────────

  Total Dependencies:    47
  Using Crypto:          12
  Quantum Vulnerable:     4
  Partial Risk:           3

  DEPENDENCY                              ALGORITHM        RISK         SEVERITY
  ──────────────────────────────────────────────────────────────────────────────
  golang.org/x/crypto v0.17.0             Ed25519          VULNERABLE   HIGH
                                          X25519           VULNERABLE   HIGH
                                          ChaCha20         SAFE         -
  github.com/golang-jwt/jwt/v5 v5.2.0     RS256            VULNERABLE   HIGH
                                          ES256            VULNERABLE   HIGH
                                          HS256            PARTIAL      MEDIUM
  github.com/go-sql-driver/mysql v1.7.1   SHA-256          PARTIAL      LOW

───────────────────────────────────────────────────────────────────────────────
  REMEDIATION
───────────────────────────────────────────────────────────────────────────────

  VULNERABLE (4 findings)
    Ed25519, X25519, RS256, ES256
    → Migrate to ML-KEM for key exchange, ML-DSA for signatures
    → Timeline: Complete by 2027 for CNSA 2.0 compliance

  PARTIAL (3 findings)
    SHA-256, HS256
    → Upgrade to SHA-384 or SHA-512 for long-term security
    → Consider SHA-3 for new implementations

───────────────────────────────────────────────────────────────────────────────
  2 packages not in database. Use --deep to analyze source code.
───────────────────────────────────────────────────────────────────────────────
```

Other formats: `--format json` for automation, `--format cbom` for CycloneDX CBOM, `--format sarif` for GitHub Security.

## Quantum Risk Classification

### Risk Levels

| Risk | Score Impact | Description | Examples |
|------|--------------|-------------|----------|
| **VULNERABLE** | Critical | Completely broken by quantum computers | RSA, ECDSA, Ed25519, DH, DSA |
| **PARTIAL** | Medium | Security reduced by Grover's algorithm | AES-128, SHA-256, HMAC-SHA256 |
| **SAFE** | None | Quantum-resistant with current key sizes | AES-256, SHA-384, SHA-512, ChaCha20 |

### Algorithm Classification

| Status | Description | Examples |
|--------|-------------|----------|
| **Approved** | CNSA 2.0 approved | ML-KEM, ML-DSA, SLH-DSA, AES-256, SHA-384+ |
| **Transitional** | Allowed until 2027-2030 | RSA-3072+, ECDSA-P384 (hybrid only) |
| **Deprecated** | Phase out immediately | RSA-2048, ECDSA-P256 |
| **Prohibited** | Never use | DES, 3DES, RC4, MD5, SHA-1 |

## CI/CD Integration

### GitHub Actions

```yaml
name: Crypto Security Scan
on: [push, pull_request]

permissions:
  security-events: write

jobs:
  cryptodeps:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Scan for Quantum-Vulnerable Crypto
        uses: csnp/qramm-cryptodeps@v1
        with:
          path: '.'
          fail-on: 'vulnerable'
          format: 'table'
          sarif-file: 'cryptodeps.sarif'
```

### GitLab CI

```yaml
cryptodeps:
  stage: security
  image: golang:1.22-alpine
  before_script:
    - go install github.com/csnp/qramm-cryptodeps/cmd/cryptodeps@latest
  script:
    - cryptodeps analyze . --fail-on vulnerable
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
```

### Exit Codes

| Code | Meaning | When |
|------|---------|------|
| **0** | Success | No quantum-vulnerable findings |
| **1** | Vulnerable | Quantum-vulnerable crypto detected |
| **2** | Error | Analysis failed |
| **3** | Partial | Partial-risk crypto detected (with `--fail-on partial`) |

## CLI Reference

```
USAGE:
  cryptodeps [command] [flags]

COMMANDS:
  analyze     Analyze dependencies for cryptographic usage
  update      Download latest crypto knowledge database
  status      Show database statistics and cache info
  version     Print version information

ANALYZE FLAGS:
  -f, --format string       Output format: table, json, cbom, sarif, markdown (default "table")
      --fail-on string      Exit non-zero when risk found: vulnerable, partial, any, none
      --offline             Only use local database, no auto-updates
      --deep                Force on-demand analysis for unknown packages
      --risk string         Filter by risk level: vulnerable, partial, all
      --min-severity string Minimum severity to report
  -o, --output string       Output file (default: stdout)
  -h, --help                Help for cryptodeps
```

## Architecture

```
qramm-cryptodeps/
├── cmd/
│   └── cryptodeps/
│       └── main.go              # CLI entry point, flag parsing
├── internal/
│   ├── analyzer/
│   │   ├── analyzer.go          # Core analysis orchestration
│   │   ├── ast/                  # AST-based source code analysis
│   │   │   ├── go.go            # Go crypto detection
│   │   │   ├── javascript.go    # JavaScript/npm crypto detection
│   │   │   ├── python.go        # Python crypto detection
│   │   │   └── java.go          # Java/Maven crypto detection
│   │   ├── ondemand/            # On-demand package analysis
│   │   └── source/              # Source code fetching
│   ├── database/
│   │   ├── database.go          # Crypto knowledge database
│   │   └── updater.go           # Database auto-updates
│   └── manifest/
│       ├── gomod.go             # go.mod parser
│       ├── npm.go               # package.json parser
│       ├── python.go            # requirements.txt, pyproject.toml parser
│       └── maven.go             # pom.xml parser
├── pkg/
│   ├── crypto/
│   │   ├── patterns.go          # Crypto detection patterns
│   │   ├── quantum.go           # Quantum risk classification
│   │   └── remediation.go       # Remediation recommendations
│   ├── output/
│   │   ├── table.go             # Terminal output
│   │   ├── json.go              # JSON output
│   │   ├── cbom.go              # CycloneDX CBOM
│   │   ├── sarif.go             # SARIF output
│   │   └── markdown.go          # Markdown output
│   └── types/
│       └── types.go             # Shared types and structures
└── data/
    └── packages/                # Curated crypto database (72+ packages)
```

## About QRAMM

QRAMM (Quantum Readiness Assurance Maturity Model) is an evidence-based framework designed to help enterprises systematically prepare for the quantum computing threat to current cryptographic systems. QRAMM provides structured evaluation across quantum readiness dimensions.

Visit [qramm.org](https://qramm.org) to learn more about:
- Quantum readiness assessment
- Migration planning resources
- Implementation guidance
- Industry benchmarks

### QRAMM Toolkit

This analyzer is part of the QRAMM open-source toolkit:

| Tool | Description |
|------|-------------|
| [TLS Analyzer](https://github.com/csnp/qramm-tls-analyzer) | TLS/SSL configuration analysis with quantum readiness |
| [CryptoScan](https://github.com/csnp/qramm-cryptoscan) | Cryptographic discovery scanner for source code |
| **CryptoDeps** | Dependency cryptographic analysis (this tool) |

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup and guidelines.

### Contributing Package Data

Help expand the database by contributing crypto analysis for packages:

```bash
# Analyze an unknown package and export findings
cryptodeps analyze . --deep --export-unknown

# Submit the generated YAML to the database
# See CONTRIBUTING.md for details
```

## References

- [NSA CNSA 2.0 Guidance](https://media.defense.gov/2022/Sep/07/2003071834/-1/-1/0/CSA_CNSA_2.0_ALGORITHMS_.PDF) - Commercial National Security Algorithm Suite 2.0
- [NIST Post-Quantum Cryptography](https://csrc.nist.gov/projects/post-quantum-cryptography) - PQC Standardization
- [FIPS 203: ML-KEM](https://csrc.nist.gov/pubs/fips/203/final) - Module-Lattice Key Encapsulation
- [FIPS 204: ML-DSA](https://csrc.nist.gov/pubs/fips/204/final) - Module-Lattice Digital Signatures
- [CycloneDX CBOM](https://cyclonedx.org/capabilities/cbom/) - Cryptographic Bill of Materials
- [OMB M-23-02](https://www.whitehouse.gov/wp-content/uploads/2022/11/M-23-02-M-Memo-on-Migrating-to-Post-Quantum-Cryptography.pdf) - Federal Crypto Inventory Requirements

## License

This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- NSA's CNSA 2.0 guidance for post-quantum cryptography standards
- NIST for PQC algorithm standardization (ML-KEM, ML-DSA, SLH-DSA)
- CycloneDX for the CBOM specification
- The Go team for excellent tooling support
- Our contributors and the open-source community

---

Built with purpose by [CSNP](https://csnp.org)

[QRAMM](https://qramm.org) | [CSNP](https://csnp.org) | [Report Bug](https://github.com/csnp/qramm-cryptodeps/issues) | [Request Feature](https://github.com/csnp/qramm-cryptodeps/issues)
