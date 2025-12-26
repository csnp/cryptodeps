# QRAMM CryptoDeps

[![CI](https://github.com/csnp/qramm-cryptodeps/actions/workflows/ci.yml/badge.svg)](https://github.com/csnp/qramm-cryptodeps/actions/workflows/ci.yml)
[![Go Report Card](https://img.shields.io/badge/go%20report-A-brightgreen)](https://goreportcard.com/report/github.com/csnp/qramm-cryptodeps)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)

**Quantum-safe dependency scanner that finds cryptographic vulnerabilities in your software supply chain.**

CryptoDeps analyzes your project dependencies to identify quantum-vulnerable cryptographic algorithms, showing you exactly which crypto is actually used by your code versus what's merely available in libraries. Stop guessing — know precisely where your quantum risk lies.

Part of the [QRAMM (Quantum Readiness Assurance Maturity Model)](https://qramm.org) toolkit by [CSNP](https://csnp.org).

---

## Table of Contents

- [Why CryptoDeps?](#why-cryptodeps)
- [Key Features](#key-features)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Reachability Analysis](#reachability-analysis)
- [Understanding the Output](#understanding-the-output)
- [Output Formats](#output-formats)
- [CI/CD Integration](#cicd-integration)
- [Command Reference](#command-reference)
- [Quantum Risk Classification](#quantum-risk-classification)
- [Remediation Guidance](#remediation-guidance)
- [FAQ](#faq)
- [Architecture](#architecture)
- [Contributing](#contributing)
- [References](#references)
- [License](#license)

---

## Why CryptoDeps?

Your code might be quantum-safe, but what about your **dependencies**?

The average software project has 300-1000+ transitive dependencies. Each one potentially uses cryptographic algorithms that quantum computers will break. Traditional security scanners miss this — they focus on known CVEs, not cryptographic readiness.

### The Problem

| Challenge | Impact |
|-----------|--------|
| **Hidden Crypto** | RSA, ECDSA, Ed25519 buried deep in dependency trees |
| **Harvest Now, Decrypt Later** | Adversaries collecting encrypted data today for future quantum decryption |
| **CNSA 2.0 Timeline** | NSA requires hybrid PQC by 2027 — non-compliant dependencies block migration |
| **Supply Chain Blind Spots** | Third-party crypto creates risk beyond your direct control |
| **False Positives** | Most tools flag all crypto, not just what you actually use |

### The Solution

CryptoDeps solves this with **reachability analysis** — it doesn't just find crypto in your dependencies, it tells you:

- **CONFIRMED**: Crypto your code actually calls (requires action)
- **REACHABLE**: Crypto in your call graph (monitor closely)
- **AVAILABLE**: Crypto that exists but isn't used (lower priority)

This means you focus remediation effort on what matters, not chase phantom vulnerabilities.

---

## Key Features

### Reachability Analysis (Go)
Builds a call graph from your code to identify which cryptographic functions are actually invoked — not just present in dependencies.

### Multi-Ecosystem Support
| Ecosystem | Manifest Files |
|-----------|----------------|
| Go | `go.mod`, `go.sum` |
| npm | `package.json`, `package-lock.json` |
| Python | `requirements.txt`, `pyproject.toml`, `Pipfile` |
| Maven | `pom.xml` |

### Smart Remediation
Context-aware recommendations that consider:
- Token lifetimes (short-lived JWTs vs long-lived certificates)
- Industry standards (wait for PQ-JWT vs migrate now)
- Migration effort (simple change vs architectural overhaul)

### Compliance-Ready Output
- **CycloneDX CBOM** for OMB M-23-02 compliance
- **SARIF** for GitHub Security integration
- **JSON** for automation pipelines
- **Markdown** for documentation

---

## Installation

### Pre-built Binaries (Recommended)

Download from [GitHub Releases](https://github.com/csnp/qramm-cryptodeps/releases):

```bash
# macOS (Apple Silicon)
curl -LO https://github.com/csnp/qramm-cryptodeps/releases/latest/download/cryptodeps-darwin-arm64
chmod +x cryptodeps-darwin-arm64
sudo mv cryptodeps-darwin-arm64 /usr/local/bin/cryptodeps

# macOS (Intel)
curl -LO https://github.com/csnp/qramm-cryptodeps/releases/latest/download/cryptodeps-darwin-amd64
chmod +x cryptodeps-darwin-amd64
sudo mv cryptodeps-darwin-amd64 /usr/local/bin/cryptodeps

# Linux (x86_64)
curl -LO https://github.com/csnp/qramm-cryptodeps/releases/latest/download/cryptodeps-linux-amd64
chmod +x cryptodeps-linux-amd64
sudo mv cryptodeps-linux-amd64 /usr/local/bin/cryptodeps

# Windows (PowerShell)
Invoke-WebRequest -Uri "https://github.com/csnp/qramm-cryptodeps/releases/latest/download/cryptodeps-windows-amd64.exe" -OutFile "cryptodeps.exe"
```

### Build from Source

Requires Go 1.21+:

```bash
git clone https://github.com/csnp/qramm-cryptodeps.git
cd qramm-cryptodeps
go build -o cryptodeps ./cmd/cryptodeps
```

### Go Install

```bash
go install github.com/csnp/qramm-cryptodeps/cmd/cryptodeps@latest
```

---

## Quick Start

```bash
# Analyze current directory
cryptodeps analyze .

# Analyze a specific project
cryptodeps analyze /path/to/project

# Analyze a GitHub repository directly
cryptodeps analyze hashicorp/vault
cryptodeps analyze https://github.com/golang-jwt/jwt

# Generate CBOM for compliance
cryptodeps analyze . --format cbom > crypto-bom.json

# CI/CD: Fail on quantum-vulnerable crypto
cryptodeps analyze . --fail-on vulnerable
```

---

## Reachability Analysis

CryptoDeps goes beyond simple dependency scanning by analyzing your code's call graph to determine which cryptographic algorithms are actually used.

### How It Works

1. **Parses your source code** — Builds an AST of your Go files
2. **Identifies entry points** — `main()`, `init()`, exported functions
3. **Traces call paths** — Follows function calls to crypto imports
4. **Classifies reachability** — Marks each crypto usage as CONFIRMED, REACHABLE, or AVAILABLE

### Reachability Levels

| Level | Meaning | Action |
|-------|---------|--------|
| **CONFIRMED** | Your code directly calls this crypto | Immediate remediation required |
| **REACHABLE** | In call graph from your code | Monitor and plan migration |
| **AVAILABLE** | In dependency but not called | Lower priority (future planning) |

### Example

```
CONFIRMED - Actually used by your code (requires action):
──────────────────────────────────────────────────────────────────────────────────────────
  [!] Ed25519        VULNERABLE    [short-term]  Effort: Low (simple change)
     └─ golang.org/x/crypto@v0.31.0
        > Called from: crypto.GenerateEd25519KeyPair
        > Called from: crypto.SignMessage
        > Called from: crypto.VerifySignature

  [~] HS256          PARTIAL       [medium-term]  Effort: Low (simple change)
     └─ github.com/golang-jwt/jwt/v5@v5.3.0
        > Called from: auth.JWTService.GenerateAccessToken
        > Called from: auth.JWTService.GenerateRefreshToken

AVAILABLE - In dependencies but not called (lower priority):
──────────────────────────────────────────────────────────────────────────────────────────
  golang.org/x/crypto@v0.31.0
     └─ [!] X25519, [OK] ChaCha20-Poly1305, [OK] Argon2
  github.com/golang-jwt/jwt/v5@v5.3.0
     └─ [!] RS256, [!] ES256, [~] HS384, [OK] HS512
```

### Disabling Reachability

Reachability analysis is enabled by default for Go projects. To disable:

```bash
cryptodeps analyze . --reachability=false
```

---

## Understanding the Output

### Risk Indicators

| Symbol | Risk Level | Meaning |
|--------|------------|---------|
| `[!]` | VULNERABLE | Broken by quantum computers (Shor's algorithm) |
| `[~]` | PARTIAL | Weakened by quantum computers (Grover's algorithm) |
| `[OK]` | SAFE | Quantum-resistant with current parameters |

### Sample Output

```
Scanning go.mod... found 36 dependencies

CONFIRMED - Actually used by your code (requires action):
──────────────────────────────────────────────────────────────────────────────────────────
  [!] Ed25519        VULNERABLE    [short-term]  Effort: Low (simple change)
     └─ golang.org/x/crypto@v0.31.0
        > Called from: application.AgentService.CreateAgent
        > Called from: crypto.ED25519Service.Sign
  [~] HS256          PARTIAL       [medium-term]  Effort: Low (simple change)
     └─ github.com/golang-jwt/jwt/v5@v5.3.0
        > Called from: auth.JWTService.GenerateAccessToken
  [OK] bcrypt         SAFE          [none]  Effort: None
     └─ golang.org/x/crypto@v0.31.0
        > Called from: auth.HashPassword

══════════════════════════════════════════════════════════════════════════════════════════
SUMMARY: 36 deps | 2 with crypto | 8 vulnerable | 2 partial
REACHABILITY: 3 confirmed | 0 reachable | 11 available-only

REMEDIATION - Action Required:
══════════════════════════════════════════════════════════════════════════════════════════

[!] Ed25519
──────────────────────────────────────────────────
  Action:      Plan migration to ML-DSA; prioritize if signing long-lived data
  Replace:     ML-DSA-65 (FIPS 204)
  NIST:        FIPS 204
  Timeline:    Short-term (1-2 years)
  Effort:      Low (simple change)
  Libraries:   github.com/cloudflare/circl/sign/mldsa
  Note:        Priority depends on what you're signing: long-lived certificates
               need migration soon, short-lived auth tokens are lower priority.

[~] HS256
──────────────────────────────────────────────────
  Action:      Adequate for most use cases; upgrade to HS512 for defense-in-depth
  Replace:     HS512 (optional)
  Timeline:    Medium-term (2-5 years)
  Effort:      Low (simple change)
  Note:        HMAC-SHA256 provides ~128-bit post-quantum security. Sufficient
               for most applications.

PLANNING - Available in Dependencies (not currently used):
──────────────────────────────────────────────────────────────────────────────────────────
These algorithms exist in your dependencies but aren't called by your code.
Review if you plan to use these features in the future.

[!] RS256
──────────────────────────────────────────────────
  Action:      Wait for PQ-JWT standards; use HS256/HS512 if symmetric acceptable
  Replace:     HS256/HS512 (now) or PQ-JWT algorithms (when standardized)
  Timeline:    Short-term (1-2 years)
  Note:        For short-lived tokens, the quantum threat is not immediate.
               IETF is developing PQ-JWT standards.
```

---

## Output Formats

### Table (Default)

Human-readable terminal output with colors and formatting:

```bash
cryptodeps analyze .
```

### JSON

Machine-readable output for automation:

```bash
cryptodeps analyze . --format json
cryptodeps analyze . --format json | jq '.dependencies[] | select(.analysis.crypto != null)'
```

### CycloneDX CBOM

Cryptographic Bill of Materials for compliance (OMB M-23-02, CNSA 2.0):

```bash
cryptodeps analyze . --format cbom > crypto-bom.json
```

### SARIF

GitHub Security tab integration:

```bash
cryptodeps analyze . --format sarif > results.sarif
# Upload to GitHub Security
gh api repos/{owner}/{repo}/code-scanning/sarifs -f sarif=@results.sarif
```

### Markdown

Documentation and reports:

```bash
cryptodeps analyze . --format markdown > crypto-report.md
```

---

## CI/CD Integration

### GitHub Actions

```yaml
name: Quantum Security Scan

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

permissions:
  security-events: write
  contents: read

jobs:
  cryptodeps:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Setup Go
        uses: actions/setup-go@v5
        with:
          go-version: '1.22'

      - name: Install CryptoDeps
        run: go install github.com/csnp/qramm-cryptodeps/cmd/cryptodeps@latest

      - name: Run Crypto Analysis
        run: cryptodeps analyze . --format sarif > cryptodeps.sarif
        continue-on-error: true

      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: cryptodeps.sarif

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
    - cryptodeps analyze . --fail-on vulnerable
  allow_failure: false
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
    - if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH
```

### Jenkins

```groovy
pipeline {
    agent any
    stages {
        stage('Crypto Scan') {
            steps {
                sh 'go install github.com/csnp/qramm-cryptodeps/cmd/cryptodeps@latest'
                sh 'cryptodeps analyze . --format json > crypto-report.json'
                sh 'cryptodeps analyze . --fail-on vulnerable'
            }
            post {
                always {
                    archiveArtifacts artifacts: 'crypto-report.json'
                }
            }
        }
    }
}
```

### Exit Codes

| Code | Meaning | Trigger |
|------|---------|---------|
| `0` | Success | No findings matching `--fail-on` threshold |
| `1` | Vulnerable | Quantum-vulnerable crypto detected |
| `2` | Error | Analysis failed (invalid manifest, network error) |
| `3` | Partial | Partial-risk crypto detected (with `--fail-on partial`) |

---

## Command Reference

```
USAGE:
  cryptodeps <command> [flags]

COMMANDS:
  analyze     Analyze project dependencies for cryptographic usage
  update      Download latest crypto knowledge database
  status      Show database statistics and cache info
  version     Print version information

ANALYZE FLAGS:
  -f, --format string       Output format: table, json, cbom, sarif, markdown (default "table")
      --fail-on string      Fail threshold: vulnerable, partial, any, none (default "vulnerable")
      --reachability        Analyze call graph for actual crypto usage (default true, Go only)
      --deep                Force AST analysis for packages not in database
      --offline             Use only local database, skip auto-updates
      --risk string         Filter by risk: vulnerable, partial, all
      --min-severity string Minimum severity to report

UPDATE FLAGS:
      --url string          Custom database URL
  -v, --verbose             Verbose output

EXAMPLES:
  cryptodeps analyze .                              # Analyze current directory
  cryptodeps analyze ./go.mod                       # Specific manifest
  cryptodeps analyze hashicorp/vault                # GitHub repository
  cryptodeps analyze . --format cbom                # Generate CBOM
  cryptodeps analyze . --fail-on vulnerable         # CI/CD gate
  cryptodeps analyze . --reachability=false         # Skip call graph analysis
  cryptodeps update                                 # Update crypto database
```

---

## Quantum Risk Classification

### Risk Levels

| Risk | Quantum Threat | Description | Examples |
|------|----------------|-------------|----------|
| **VULNERABLE** | Shor's Algorithm | Completely broken by quantum computers | RSA, ECDSA, Ed25519, ECDH, DH, DSA |
| **PARTIAL** | Grover's Algorithm | Security reduced (halved key strength) | AES-128, SHA-256, HMAC-SHA256 |
| **SAFE** | Resistant | Maintains security against known quantum attacks | AES-256, SHA-384+, ChaCha20, Argon2 |

### CNSA 2.0 Compliance

| Timeline | Requirement |
|----------|-------------|
| **2025** | Begin hybrid implementations |
| **2027** | Complete hybrid transition for key establishment |
| **2030** | Complete migration to pure PQC |
| **2033** | Sunset classical algorithms |

### NIST Post-Quantum Standards

| Standard | Algorithm | Use Case |
|----------|-----------|----------|
| FIPS 203 | ML-KEM (Kyber) | Key encapsulation |
| FIPS 204 | ML-DSA (Dilithium) | Digital signatures |
| FIPS 205 | SLH-DSA (SPHINCS+) | Stateless hash-based signatures |

---

## Remediation Guidance

CryptoDeps provides intelligent, context-aware remediation recommendations:

### For JWT Algorithms

| Current | Recommendation |
|---------|----------------|
| RS256/RS384/RS512 | Wait for PQ-JWT standards; use HS256/HS512 if symmetric is acceptable |
| ES256/ES384/ES512 | Same as above — ECDSA is quantum-vulnerable |
| HS256 | Adequate for most use cases; optionally upgrade to HS512 |
| HS512 | Already quantum-safe, no action needed |

### For Signatures

| Current | Recommendation | NIST Standard |
|---------|----------------|---------------|
| RSA | Migrate to ML-DSA | FIPS 204 |
| ECDSA | Migrate to ML-DSA | FIPS 204 |
| Ed25519 | Plan migration to ML-DSA; prioritize long-lived signatures | FIPS 204 |

### For Key Exchange

| Current | Recommendation | NIST Standard |
|---------|----------------|---------------|
| RSA-KEM | Migrate to ML-KEM | FIPS 203 |
| ECDH | Migrate to ML-KEM or hybrid X25519+ML-KEM | FIPS 203 |
| X25519 | Use hybrid X25519+ML-KEM during transition | FIPS 203 |

### Recommended Libraries

| Ecosystem | Library |
|-----------|---------|
| Go | `github.com/cloudflare/circl` |
| JavaScript/npm | `@noble/post-quantum` |
| Python | `pqcrypto`, `liboqs-python` |
| Java | `org.bouncycastle:bcprov-jdk18on` |

---

## FAQ

### Why focus on dependencies instead of my own code?

Most cryptographic vulnerabilities hide in dependencies — libraries you didn't write and rarely audit. Your code might use `bcrypt` for passwords (quantum-safe), but a dependency three levels deep might use RSA for certificate validation (quantum-vulnerable).

### What makes CryptoDeps different from other scanners?

**Reachability analysis.** Most tools flag every crypto algorithm in your dependency tree, creating noise. CryptoDeps traces your code's call graph to show what's actually used versus what's merely present.

### Does it work with private repositories?

Yes. For local projects, just point it at your directory:
```bash
cryptodeps analyze /path/to/private/project
```

For private GitHub repos, set up authentication:
```bash
export GITHUB_TOKEN=your_token
cryptodeps analyze https://github.com/your-org/private-repo
```

### How often should I run this?

- **PR/MR checks**: Every pull request that changes dependencies
- **Scheduled**: Weekly or monthly full scans
- **Release gates**: Before major releases

### What about false positives?

CryptoDeps minimizes false positives through:
1. **Reachability analysis** — Only flags crypto your code actually uses
2. **Curated database** — 72+ packages with verified crypto signatures
3. **AST-based detection** — Analyzes actual code, not just package names

### Is reachability analysis perfect?

No static analysis is perfect. Reachability analysis may miss:
- Dynamic dispatch / reflection
- Plugin systems
- Runtime code generation

When in doubt, use `--reachability=false` for a complete inventory.

---

## Architecture

```
qramm-cryptodeps/
├── cmd/cryptodeps/           # CLI entry point
├── internal/
│   ├── analyzer/
│   │   ├── analyzer.go       # Core orchestration
│   │   ├── ast/              # Language-specific AST analysis
│   │   ├── ondemand/         # Source code fetching & analysis
│   │   ├── reachability/     # Call graph analysis (Go)
│   │   └── source/           # Package source resolution
│   ├── database/             # Crypto knowledge database
│   └── manifest/             # Dependency manifest parsers
├── pkg/
│   ├── crypto/               # Algorithm patterns & remediation
│   ├── output/               # Formatters (table, JSON, CBOM, SARIF)
│   └── types/                # Shared types
└── data/packages/            # Curated crypto database (72+ packages)
```

---

## Contributing

We welcome contributions! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

### Areas for Contribution

- **Package database**: Add crypto analysis for popular packages
- **Language support**: Improve AST analysis for npm, Python, Maven
- **Reachability**: Extend call graph analysis to other languages
- **Output formats**: Add new compliance formats

### Development Setup

```bash
git clone https://github.com/csnp/qramm-cryptodeps.git
cd qramm-cryptodeps
go mod download
go test ./...
go build -o cryptodeps ./cmd/cryptodeps
```

---

## References

### Standards & Guidance

- [NIST FIPS 203: ML-KEM](https://csrc.nist.gov/pubs/fips/203/final) — Module-Lattice Key Encapsulation
- [NIST FIPS 204: ML-DSA](https://csrc.nist.gov/pubs/fips/204/final) — Module-Lattice Digital Signatures
- [NIST FIPS 205: SLH-DSA](https://csrc.nist.gov/pubs/fips/205/final) — Stateless Hash-Based Signatures
- [NSA CNSA 2.0](https://media.defense.gov/2022/Sep/07/2003071834/-1/-1/0/CSA_CNSA_2.0_ALGORITHMS_.PDF) — Commercial National Security Algorithm Suite
- [OMB M-23-02](https://www.whitehouse.gov/wp-content/uploads/2022/11/M-23-02-M-Memo-on-Migrating-to-Post-Quantum-Cryptography.pdf) — Federal PQC Migration Requirements
- [CycloneDX CBOM](https://cyclonedx.org/capabilities/cbom/) — Cryptographic Bill of Materials

### QRAMM Toolkit

| Tool | Description |
|------|-------------|
| **CryptoDeps** | Dependency cryptographic analysis (this tool) |
| [TLS Analyzer](https://github.com/csnp/qramm-tls-analyzer) | TLS/SSL configuration analysis |
| [CryptoScan](https://github.com/csnp/qramm-cryptoscan) | Source code cryptographic discovery |

---

## License

Apache License 2.0 — See [LICENSE](LICENSE) for details.

---

## About

Built by the [Cyber Security Non-Profit (CSNP)](https://csnp.org) as part of the [QRAMM](https://qramm.org) quantum readiness framework.

**CSNP Mission**: Advancing cybersecurity through education, research, and open-source tools.

---

[Website](https://qramm.org) | [Documentation](https://docs.qramm.org) | [Report Bug](https://github.com/csnp/qramm-cryptodeps/issues) | [Request Feature](https://github.com/csnp/qramm-cryptodeps/issues)
