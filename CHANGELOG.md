# Changelog

All notable changes to QRAMM CryptoDeps will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.2.1] - 2025-12-27

### Added
- **Expanded remediation database**: 30+ additional algorithm entries
  - Authenticated encryption: ChaCha20-Poly1305, AES-GCM, XSalsa20-Poly1305
  - MACs: HMAC, HMAC-SHA256/512, Poly1305
  - Post-quantum algorithms: ML-KEM, ML-DSA (marked as quantum-safe)
  - NIST curves: P-256, P-384, P-521, secp256k1
  - RSA variants: RSA-OAEP, RSA-PSS, PS256/384/512
  - ECDH variants: ECDH-ES
  - Hash functions: BLAKE2b, BLAKE2s, BLAKE3
  - Chinese national algorithms: SM2, SM3, SM4

### Fixed
- **@noble/ed25519 false positives**: Database entry incorrectly reported RSA, ECDSA, ECDH, AES; now correctly shows only Ed25519 and X25519
- **Maven property resolution**: Parser now resolves `${property}` placeholders from `<properties>` section (e.g., `${bouncycastle.version}` → `1.77`)
- **AES remediation**: Added generic "AES" entry for cases where key size isn't specified

## [1.2.0] - 2025-12-27

### Added
- **Workspace & monorepo support**: Automatically discovers all manifest files in project directories
  - npm/yarn workspaces via `package.json` workspaces field
  - pnpm workspaces via `pnpm-workspace.yaml`
  - Go workspaces via `go.work` files
  - Recursive directory walking with smart filtering (skips node_modules, vendor, .git, etc.)
- **Multi-project output**: Aggregated results across all discovered projects
- **`--no-workspaces` flag**: Disable workspace discovery for single-manifest scanning

### Changed
- **Output formatting**: Clean, professional terminal design with colored status indicators
  - 🔴 Vulnerable (quantum-broken by Shor's algorithm)
  - 🟡 Partial risk (weakened by Grover's algorithm)
  - 🟢 Safe (quantum-resistant)
- Improved remediation guidance layout with aligned fields
- Call trace formatting now uses `>` prefix for cleaner output

## [1.1.0] - 2025-12-26

### Added
- **GitHub URL scanning**: Analyze any public GitHub repository directly without cloning
  - Full URL support: `cryptodeps analyze https://github.com/owner/repo`
  - Shorthand support: `cryptodeps analyze owner/repo`
  - Branch/path support: `cryptodeps analyze https://github.com/owner/repo/tree/main/subdir`
- **Dynamic database updates**: Fetch crypto packages from npm, PyPI, Go, and Maven registries
- **Weekly auto-update workflow**: Database automatically refreshes every Monday
- **Algorithm inference**: Intelligent detection of crypto algorithms from package metadata
- **Confidence levels**: Packages marked as `verified`, `high`, `medium`, or `low` confidence
- **Demo project**: `examples/vulnerable-demo` showcasing quantum-safe and vulnerable crypto

### Changed
- Database expanded from 69 to 1,122 packages
- Improved snapshot versioning for non-semver tags

### Fixed
- GoReleaser build failures with database release tags (db-*)

## [1.0.0] - 2025-12-26

### Added
- Initial release of QRAMM CryptoDeps
- **Multi-ecosystem support**: Go (go.mod), npm (package.json), Python (requirements.txt, pyproject.toml), Maven (pom.xml)
- **Quantum risk classification**: VULNERABLE, PARTIAL, SAFE categories
- **Output formats**: Table, JSON, CycloneDX CBOM, SARIF, Markdown
- **CI/CD integration**: Exit codes for pipeline automation
- **On-demand analysis**: AST-based source code analysis with `--deep` flag
- **Database**: 69 curated crypto-using packages with verified algorithms
- **Remediation guidance**: Actionable recommendations for each finding

### Security
- Identifies quantum-vulnerable algorithms (RSA, ECDSA, Ed25519, DH, DSA)
- Maps findings to CNSA 2.0 compliance requirements
- Supports OMB M-23-02 cryptographic inventory requirements

[1.2.1]: https://github.com/csnp/qramm-cryptodeps/compare/v1.2.0...v1.2.1
[1.2.0]: https://github.com/csnp/qramm-cryptodeps/compare/v1.1.0...v1.2.0
[1.1.0]: https://github.com/csnp/qramm-cryptodeps/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/csnp/qramm-cryptodeps/releases/tag/v1.0.0
