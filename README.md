# CryptoDeps

**Quantum-Safe Dependency Analysis for Your Software Supply Chain**

Find the cryptography your dependencies bring in, see which of it quantum computers will break, and tell apart what your code actually calls from what is merely available to it.

[![CI](https://github.com/csnp/qramm-cryptodeps/actions/workflows/ci.yml/badge.svg)](https://github.com/csnp/qramm-cryptodeps/actions/workflows/ci.yml)
[![Go Report Card](https://img.shields.io/badge/go%20report-A-brightgreen)](https://goreportcard.com/report/github.com/csnp/qramm-cryptodeps)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Go Version](https://img.shields.io/github/go-mod/go-version/csnp/qramm-cryptodeps)](go.mod)

[Why CryptoDeps](docs/USE-CASES.md#why-cryptodeps) | [Quick Start](#quick-start) | [What It Finds](#what-it-finds) | [Full Documentation](#documentation) | [Patterns](PATTERNS.md) | [Contributing](CONTRIBUTING.md)

---

## Quick start

Install with Go, then scan a project folder:

```bash
go install github.com/csnp/qramm-cryptodeps/cmd/cryptodeps@latest
cryptodeps analyze .
```

```text

Scanning /home/dev/myproject...
Database: downloaded 1.1.0 (2026-10-12), 860 packages

[*] Scanning ./go.mod... found 2 dependencies

[!] CONFIRMED - Actually used by your code (requires action):
       ALGORITHM      RISK          TIMELINE      EFFORT
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
SUMMARY: 2 deps | 2 with crypto | 8 vulnerable | 2 partial | 4 safe
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

## What it finds

CryptoDeps reads the dependencies your manifests declare, identifies the cryptography each one provides, and uses **reachability analysis** to show which of it your code actually calls rather than merely has available.

How much of the tree that covers depends on the ecosystem, so it is worth stating plainly. In Go, `go.mod` lists indirect requirements, and CryptoDeps reads and analyzes them, so a tidied `go.mod` gives you the full closure.

In npm, Python and Maven it reads only what the manifest itself declares: lock files are not parsed, so a package pulled in only by another package is outside what those scans report.

### Quantum risk classification

Every finding is classified by quantum computing threat level:

| Marker | Risk Level | Quantum Threat | Examples |
|--------|------------|----------------|----------|
| `[!]` | VULNERABLE | Shor's algorithm | RSA, ECDSA, Ed25519, ECDH, DH, DSA |
| `[~]` | PARTIAL | Grover's algorithm | AES-128, SHA-256, HMAC-SHA256 |
| `[OK]` | SAFE | Resistant | AES-256, SHA-384+, ChaCha20, Argon2 |
| `[?]` | UNKNOWN | Not classified | Algorithms absent from the database |

### Reachability analysis

CryptoDeps goes beyond simple dependency scanning by analyzing your code's call graph:

| Level | Meaning | Action |
|-------|---------|--------|
| **CONFIRMED** | Your code directly calls this crypto | Immediate remediation required |
| **REACHABLE** | In call graph from your code | Monitor and plan migration |
| **AVAILABLE** | In dependency but not called | Lower priority (future planning) |

### Multi-ecosystem support

| Ecosystem | Manifest Files |
|-----------|----------------|
| Go | `go.mod` |
| npm | `package.json` |
| Python | `requirements.txt` and the `requirements-*.txt` family, `requirements/*.txt`, `pyproject.toml` (PEP 621 and Poetry), `Pipfile` |
| Maven | `pom.xml` |

Lock files (`go.sum`, `package-lock.json` and the Python and Maven equivalents) are not read, so point CryptoDeps at the manifest beside one, for example `cryptodeps analyze ./go.mod` rather than `./go.sum`.

### Smart remediation

Context-aware recommendations that consider:
- Token lifetimes (short-lived JWTs vs long-lived certificates)
- Industry standards (wait for PQ-JWT vs migrate now)
- Migration effort (simple change vs architectural overhaul)
- NIST standards references (FIPS 203, 204, 205)

---

## Usage

### Scan a folder or a GitHub repository

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

### Try it on the sample project

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

### Workspaces and monorepos

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

### Run it in GitHub Actions

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
        run: cryptodeps analyze . --format sarif --fail-on none > results.sarif

      - name: Upload SARIF to GitHub Security
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif

      - name: Fail on Vulnerable Crypto
        run: cryptodeps analyze . --fail-on vulnerable
```

The last step exits 1 when it finds quantum-vulnerable cryptography, which fails the job. The other exit codes are in [docs/commands.md](docs/commands.md#exit-codes).

---

## Install

- **Go install**: the `go install` line in the [Quick start](#quick-start).
- **Download binary**: pre-built binaries are on [GitHub Releases](https://github.com/csnp/qramm-cryptodeps/releases).
- **Build from source**: the steps are in [docs/install.md](docs/install.md).

---

## Documentation

- [Commands](docs/commands.md): the `analyze`, `update`, `status` and `version` commands, the `analyze` flags, report filters, exit codes and common workflows.
- [Output formats](docs/output-formats.md): table, JSON, CBOM, SARIF and Markdown, with SARIF and CBOM examples.
- [CI/CD recipes](docs/ci.md): GitHub Actions and GitLab CI, and the exit codes a pipeline sees.
- [How it works](docs/how-it-works.md): how the code is organized, from the command-line entry point to the crypto database.
- [Background](docs/USE-CASES.md): the quantum computing challenge, how CryptoDeps compares with other tools, and standards references.
- [Detection patterns](PATTERNS.md): the cryptographic patterns CryptoDeps uses and how it classifies them.
- [Roadmap](docs/releases.md): what each release delivered and what is planned next.
- [Contributing](CONTRIBUTING.md): guidelines and the package entry format. [Development setup](docs/development.md) covers building and testing locally.
- [About CSNP](docs/about.md): the nonprofit behind CryptoDeps, its mission, and the QRAMM toolkit.

---

## License

Apache License 2.0. See [LICENSE](LICENSE) for details.

Copyright 2025 Cyber Security Non-Profit (CSNP)

---

Built with purpose by [CSNP](https://csnp.org). Advancing cybersecurity for everyone.

[QRAMM](https://qramm.org) | [CSNP](https://csnp.org) | [Issues](https://github.com/csnp/qramm-cryptodeps/issues) | [Twitter](https://twitter.com/caborgsec)
