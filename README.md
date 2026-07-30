# CryptoDeps

**Quantum-Safe Dependency Analysis for Your Software Supply Chain**

Find the cryptography your dependencies bring in, see which of it quantum computers will break, and tell apart what your code actually calls from what is merely available to it.

[![CI](https://github.com/csnp/qramm-cryptodeps/actions/workflows/ci.yml/badge.svg)](https://github.com/csnp/qramm-cryptodeps/actions/workflows/ci.yml)
[![Go Report Card](https://img.shields.io/badge/go%20report-A-brightgreen)](https://goreportcard.com/report/github.com/csnp/qramm-cryptodeps)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Go Version](https://img.shields.io/github/go-mod/go-version/csnp/qramm-cryptodeps)](go.mod)

[Why CryptoDeps](#why-cryptodeps) | [Quick Start](#quick-start) | [Features](#features) | [Full Documentation](#cli-reference) | [Patterns](PATTERNS.md) | [Contributing](#contributing)

---

## The Quantum Computing Challenge

Quantum computers will break RSA, ECDSA, and Diffie-Hellman within the next decade. This isn't speculation: the NSA, NIST, and major technology companies are already migrating to post-quantum cryptography (PQC).

The challenge? **You can't migrate what you can't find.**

Your code might be quantum-safe, but what about your **dependencies**? The average software project has 300-1000+ transitive dependencies. Each one potentially uses cryptographic algorithms that quantum computers will break. Traditional security scanners miss this: they focus on CVEs, not cryptographic readiness.

CryptoDeps reads the dependencies your manifests declare, identifies the cryptography each one provides, and uses **reachability analysis** to show which of it your code actually calls rather than merely has available. Transitive dependencies are not enumerated yet: lock files are not read, so a package pulled in only by another package is outside what a scan reports.

---

## Why CryptoDeps

CryptoDeps is purpose-built for quantum readiness assessment:

| Capability | CryptoDeps | grep/ripgrep | Commercial Tools |
|------------|------------|--------------|------------------|
| Declared dependency analysis | Yes | No | Some |
| Reachability analysis | Yes (Go) | No | Rarely |
| Quantum risk classification | Yes | No | Some |
| Context-aware confidence | Yes | No | Varies |
| CBOM output | Yes | No | Rarely |
| SARIF for GitHub Security | Yes | No | Yes |
| GitHub URL scanning | Yes | No | Some |
| Migration guidance | Yes | No | Varies |
| Multi-ecosystem support | Yes | Manual | Varies |
| Open source | Yes | Yes | No |
| Price | Free | Free | $$ |

<details>
<summary><strong>What These Capabilities Mean</strong></summary>

- **Declared dependency analysis**: Scans the dependencies your manifests declare. Lock files are not read, so transitive dependencies are not enumerated today
- **Reachability analysis**: Traces call graphs to find crypto your code actually invokes
- **Quantum risk classification**: Categorizes by threat level (VULNERABLE, PARTIAL, SAFE)
- **Context-aware confidence**: Distinguishes confirmed usage from mere availability
- **CBOM output**: Cryptographic Bill of Materials for OMB M-23-02 compliance
- **SARIF output**: Integrates with GitHub Security tab
- **GitHub URL scanning**: Analyze any public/private GitHub repository directly
- **Migration guidance**: Actionable recommendations with NIST standards references
- **Multi-ecosystem support**: Go, npm, Python, Maven from a single tool

</details>

---

## Quick Start

### Installation

**Option 1: Build from Source**

Requires Go 1.21+ ([install Go](https://golang.org/doc/install))

Copy and paste this entire block:

```bash
git clone https://github.com/csnp/qramm-cryptodeps.git
cd qramm-cryptodeps
make build
sudo mv cryptodeps /usr/local/bin/
cd .. 
cryptodeps version
```

**Option 2: Go Install**

For Go developers:

```bash
go install github.com/csnp/qramm-cryptodeps/cmd/cryptodeps@latest
```

**Option 3: Download Binary**

Download pre-built binaries from [GitHub Releases](https://github.com/csnp/qramm-cryptodeps/releases).

### Basic Usage

```bash
# Analyze a local directory
cryptodeps analyze .

# Analyze a GitHub repository directly
cryptodeps analyze hashicorp/vault
cryptodeps analyze https://github.com/golang-jwt/jwt

# Output to JSON for automation
cryptodeps analyze . --format json > findings.json

# Generate SARIF for GitHub Security integration
cryptodeps analyze . --format sarif > results.sarif

# Generate CBOM for compliance
cryptodeps analyze . --format cbom > crypto-bom.json
```

### Try It Out

This repository includes a sample vulnerable project for testing:

```bash
# Clone and build
git clone https://github.com/csnp/qramm-cryptodeps.git
cd qramm-cryptodeps
make build

# Scan the sample project
./cryptodeps analyze ./examples/vulnerable-demo

# Expected: Findings showing Ed25519, RSA, ECDSA usage
# - CONFIRMED crypto your code calls
# - AVAILABLE crypto in dependencies
# - Remediation guidance for each
```

---

## Features

### Reachability Analysis

CryptoDeps goes beyond simple dependency scanning by analyzing your code's call graph:

| Level | Meaning | Action |
|-------|---------|--------|
| **CONFIRMED** | Your code directly calls this crypto | Immediate remediation required |
| **REACHABLE** | In call graph from your code | Monitor and plan migration |
| **AVAILABLE** | In dependency but not called | Lower priority (future planning) |

### Multi-Ecosystem Support

| Ecosystem | Manifest Files |
|-----------|----------------|
| Go | `go.mod`, `go.sum` |
| npm | `package.json`, `package-lock.json` |
| Python | `requirements.txt` and the `requirements-*.txt` family, `requirements/*.txt`, `pyproject.toml` (PEP 621 and Poetry), `Pipfile` |
| Maven | `pom.xml` |

### Workspace & Monorepo Support

CryptoDeps automatically discovers all manifest files in workspaces and monorepos:

- **npm/yarn/pnpm**: Detects `workspaces` in package.json and pnpm-workspace.yaml
- **Go**: Detects `go.work` files and all `go.mod` in subdirectories
- **Recursive discovery**: Walks directory tree to find all manifests
- **Smart filtering**: Skips node_modules, vendor, .git, build directories

```bash
# Scan entire monorepo - finds all projects automatically
cryptodeps analyze /path/to/monorepo

# Disable workspace discovery (scan single manifest only)
cryptodeps analyze /path/to/monorepo --no-workspaces
```

### Quantum Risk Classification

Every finding is classified by quantum computing threat level:

| Marker | Risk Level | Quantum Threat | Examples |
|--------|------------|----------------|----------|
| `[!]` | VULNERABLE | Shor's algorithm | RSA, ECDSA, Ed25519, ECDH, DH, DSA |
| `[~]` | PARTIAL | Grover's algorithm | AES-128, SHA-256, HMAC-SHA256 |
| `[OK]` | SAFE | Resistant | AES-256, SHA-384+, ChaCha20, Argon2 |
| `[?]` | UNKNOWN | Not classified | Algorithms absent from the database |

### Smart Remediation

Context-aware recommendations that consider:
- Token lifetimes (short-lived JWTs vs long-lived certificates)
- Industry standards (wait for PQ-JWT vs migrate now)
- Migration effort (simple change vs architectural overhaul)
- NIST standards references (FIPS 203, 204, 205)

### Multiple Output Formats

```bash
# Human-readable table (default)
cryptodeps analyze .

# JSON for automation
cryptodeps analyze . --format json

# CycloneDX CBOM for compliance
cryptodeps analyze . --format cbom

# SARIF for GitHub Security
cryptodeps analyze . --format sarif

# Markdown for reports
cryptodeps analyze . --format markdown
```

---

## CLI Reference

```
cryptodeps <command> [flags]

Commands:
  analyze     Analyze project dependencies for cryptographic usage
  update      Download latest crypto knowledge database
  status      Show database statistics and cache info
  version     Print version information

Analyze Flags:
  -f, --format string       Output format: table, json, cbom, sarif, markdown (default "table")
      --fail-on string      Fail threshold: vulnerable, partial, any, none (default "vulnerable")
      --reachability        Analyze call graph for actual crypto usage (default true, Go only)
      --deep                Force AST analysis for packages not in database
      --offline             Use only local database, skip auto-updates
      --no-workspaces       Disable workspace discovery (scan single manifest only)
      --risk string         Report only this risk level: vulnerable, partial, safe, unknown, all
      --min-severity string Report only findings at or above: info, low, medium, high, critical
  -h, --help                Show help
```

`--risk` and `--min-severity` filter the report. The summary and the exit code
are computed from what the filters leave, so every number in the output
describes the same set of findings. When a filter removes everything, the tool
says so rather than reporting a clean scan.

### Exit codes

| Code | Meaning |
|------|---------|
| 0 | No quantum-vulnerable findings |
| 1 | Quantum-vulnerable findings detected |
| 2 | Analysis error, including any manifest that was found but could not be read |
| 3 | Partial-risk findings detected (with `--fail-on partial`) |

A manifest that cannot be parsed is always reported by name, with the reason,
and always exits 2. A scan that silently omitted a dependency file would let a
build pass on a report that never read it.

### Common Workflows

```bash
# Focus on confirmed vulnerabilities only (what you actually use)
cryptodeps analyze . --reachability

# CI/CD: Fail if quantum-vulnerable crypto is detected
cryptodeps analyze . --fail-on vulnerable

# Quick scan without call graph analysis
cryptodeps analyze . --reachability=false

# Analyze a specific manifest file
cryptodeps analyze ./go.mod

# Offline mode (use cached database)
cryptodeps analyze . --offline

# Update the crypto knowledge database
cryptodeps update

# Check database status
cryptodeps status
```

---

## Sample Output

```

Scanning /home/dev/myproject...

[*] Scanning ./go.mod... found 2 dependencies

[!] CONFIRMED - Actually used by your code (requires action):
──────────────────────────────────────────────────────────────────────────────────────────
  [!]  Ed25519        VULNERABLE    1-2yr         low
     └─ golang.org/x/crypto@v0.31.0
        > Called from: crypto.GenerateEd25519KeyPair
        > Called from: crypto.SignMessage
  [~]  HS256          PARTIAL       -             low
     └─ github.com/golang-jwt/jwt/v5@v5.3.0
        > Called from: auth.JWTService.GenerateAccessToken
  [OK] bcrypt         SAFE          -             -
     └─ golang.org/x/crypto@v0.31.0
        > Called from: auth.HashPassword

[.] AVAILABLE - In dependencies but not called (lower priority):
──────────────────────────────────────────────────────────────────────────────────────────
  github.com/golang-jwt/jwt/v5@v5.3.0
     └─ [!] ES256, [!] ES384, [!] ES512, [!] RS256, [!] RS384, [!] RS512, [~] HS384, [OK] HS512
  golang.org/x/crypto@v0.31.0
     └─ [!] X25519, [OK] Argon2, [OK] ChaCha20-Poly1305

══════════════════════════════════════════════════════════════════════════════════════════
SUMMARY: 2 deps | 2 with crypto | 8 vulnerable | 2 partial
REACHABILITY: 3 confirmed | 0 reachable | 11 available-only

REMEDIATION GUIDANCE:
══════════════════════════════════════════════════════════════════════════════════════════

[!] Ed25519 [PRIORITY]
──────────────────────────────────────────────────
  Action:       Plan migration to ML-DSA; prioritize if signing long-lived data or certificates
  Replace with: ML-DSA-65 (FIPS 204)
  NIST:         FIPS 204
  Timeline:     Short-term (1-2 years)
  Effort:       Low (simple change)
  Libraries:    github.com/cloudflare/circl/sign/mldsa
```

---

## CI/CD Integration

### GitHub Actions with SARIF

```yaml
# .github/workflows/crypto-scan.yml
name: Quantum Security Scan

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  cryptodeps:
    runs-on: ubuntu-latest
    permissions:
      security-events: write
      contents: read
    steps:
      - uses: actions/checkout@v4

      - name: Setup Go
        uses: actions/setup-go@v5
        with:
          go-version: '1.22'

      - name: Install CryptoDeps
        run: go install github.com/csnp/qramm-cryptodeps/cmd/cryptodeps@latest

      - name: Run Scan
        run: cryptodeps analyze . --format sarif > results.sarif

      - name: Upload SARIF to GitHub Security
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif

      - name: Fail on Vulnerable Crypto
        run: cryptodeps analyze . --fail-on vulnerable
```

### GitLab CI

```yaml
cryptodeps:
  stage: security
  image: golang:1.22
  script:
    - go install github.com/csnp/qramm-cryptodeps/cmd/cryptodeps@latest
    - cryptodeps analyze . --format json > crypto-findings.json
    - cryptodeps analyze . --fail-on vulnerable
  artifacts:
    paths:
      - crypto-findings.json
```

### Exit Codes

| Code | Meaning | Trigger |
|------|---------|---------|
| `0` | Success | No findings matching `--fail-on` threshold |
| `1` | Vulnerable | Quantum-vulnerable crypto detected |
| `2` | Error | Analysis failed, including any manifest that was found but could not be read |
| `3` | Partial | Partial-risk crypto detected (with `--fail-on partial`) |

---

## Output Formats Explained

### SARIF (Static Analysis Results Interchange Format)

SARIF output integrates with GitHub Code Scanning, VS Code SARIF Viewer, and other security tools:

```json
{
  "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
  "version": "2.1.0",
  "runs": [{
    "tool": {
      "driver": {
        "name": "CryptoDeps",
        "informationUri": "https://github.com/csnp/qramm-cryptodeps"
      }
    },
    "results": [...]
  }]
}
```

### CBOM (Cryptographic Bill of Materials)

Just as an SBOM inventories software dependencies, a CBOM inventories all cryptographic algorithms in your systems. Required by emerging regulations (OMB M-23-02, NIST guidelines).

```json
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.5",
  "serialNumber": "urn:uuid:...",
  "components": [
    {
      "type": "cryptographic-asset",
      "name": "RSA-2048",
      "cryptoProperties": {
        "assetType": "algorithm",
        "algorithmProperties": {
          "primitive": "pke",
          "parameterSetIdentifier": "2048"
        }
      }
    }
  ]
}
```

---

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

---

## Roadmap

### v1.2 (Released)

- [x] Multi-ecosystem dependency scanning (Go, npm, Python, Maven)
- [x] Reachability analysis for Go projects
- [x] Multiple output formats (table, JSON, CBOM, SARIF, Markdown)
- [x] Quantum risk classification with CNSA 2.0 timeline
- [x] Smart remediation guidance with NIST references
- [x] GitHub repository URL scanning
- [x] Crypto database of curated and inferred package entries, refreshed weekly
      (run `cryptodeps status` for the counts your install currently holds)
- [x] Workspace & monorepo support (npm, pnpm, Go workspaces)
- [x] Multi-project aggregated results

### v1.3 (Next release)

Correctness of what the tool reports, rather than new surfaces.

- [x] Every machine-readable output reports the tool version that produced it
- [x] Manifests that cannot be read are named, with the reason, and exit 2
- [x] Manifests for unsupported ecosystems are reported without failing the scan
- [x] A scan that examined nothing no longer reports a clean result
- [x] `--risk` and `--min-severity` filter, and say how much they withheld
- [x] SARIF results point at the manifest they came from, relative to the root
- [x] Stable ordering across runs of the same scan, in all five formats
      (the scan timestamp and the CBOM serial number necessarily differ)

### v1.4 (Planned)

- [ ] Improved reachability for npm/Python projects
- [ ] Transitive dependency crypto inheritance
- [ ] Configuration file support (.cryptodeps.yaml)
- [ ] Watch mode for continuous monitoring

### v2.0 (Future)

- [ ] Direct integration with SBOMs (merge SBOM + CBOM)
- [ ] Cloud KMS detection (AWS, Azure, GCP)
- [ ] Certificate chain analysis
- [ ] IDE plugins (VS Code, JetBrains)

---

## Contributing

We welcome contributions from the community! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

### Development Setup

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
golangci-lint run
```

### Adding Package Data

Help expand the crypto knowledge database by contributing analysis for new packages. See [CONTRIBUTING.md](CONTRIBUTING.md) for the package entry format.

---

## About CSNP

CryptoDeps is developed by the [Cyber Security Non-Profit (CSNP)](https://csnp.org), a 501(c)(3) organization dedicated to making cybersecurity knowledge accessible to everyone through education, community, and practical resources.

### Our Mission

We believe that:

- **Accessibility**: Cybersecurity knowledge should be available to everyone
- **Community**: Supportive communities help people learn and grow together
- **Education**: Practical resources empower people to implement better security
- **Integrity**: The highest ethical standards in all operations

### QRAMM Toolkit

CryptoDeps is part of the Quantum Readiness Assurance Maturity Model (QRAMM) toolkit:

| Tool | Description |
|------|-------------|
| **CryptoDeps** | Dependency cryptographic analysis (this project) |
| [CryptoScan](https://github.com/csnp/qramm-cryptoscan) | Source code cryptographic discovery |
| [TLS Analyzer](https://github.com/csnp/qramm-tls-analyzer) | TLS/SSL configuration analysis |

Learn more at [qramm.org](https://qramm.org) and [csnp.org](https://csnp.org).

---

## References

### NIST Post-Quantum Cryptography Standards

- [FIPS 203 - ML-KEM](https://csrc.nist.gov/pubs/fips/203/final): Module-Lattice-Based Key-Encapsulation Mechanism (replaces RSA/ECDH)
- [FIPS 204 - ML-DSA](https://csrc.nist.gov/pubs/fips/204/final): Module-Lattice-Based Digital Signature Algorithm (replaces RSA/ECDSA)
- [FIPS 205 - SLH-DSA](https://csrc.nist.gov/pubs/fips/205/final): Stateless Hash-Based Digital Signature Algorithm
- [NIST SP 800-131A Rev 2](https://csrc.nist.gov/publications/detail/sp/800-131a/rev-2/final): Transitioning cryptographic algorithms and key lengths

### Additional Resources

- [NSA CNSA 2.0](https://media.defense.gov/2022/Sep/07/2003071834/-1/-1/0/CSA_CNSA_2.0_ALGORITHMS_.PDF): Commercial National Security Algorithm Suite
- [OMB M-23-02](https://www.whitehouse.gov/wp-content/uploads/2022/11/M-23-02-M-Memo-on-Migrating-to-Post-Quantum-Cryptography.pdf): Federal PQC Migration Requirements
- [CISA Post-Quantum Cryptography Initiative](https://www.cisa.gov/quantum)
- [CycloneDX CBOM](https://cyclonedx.org/capabilities/cbom/): Cryptographic Bill of Materials

---

## License

Apache License 2.0. See [LICENSE](LICENSE) for details.

Copyright 2025 Cyber Security Non-Profit (CSNP)

---

Built with purpose by [CSNP](https://csnp.org). Advancing cybersecurity for everyone.

[QRAMM](https://qramm.org) | [CSNP](https://csnp.org) | [Issues](https://github.com/csnp/qramm-cryptodeps/issues) | [Twitter](https://twitter.com/caborgsec)
