# Changelog

All notable changes to QRAMM CryptoDeps will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

Release-blocking defects found by a fresh-user release test on the 1.3.0
candidate. 1.3.0 was never tagged.

### Fixed

- **Every machine-readable output reported the wrong tool version.** One binary
  gave four answers: `version` said 1.3.0 while SARIF and CBOM both claimed
  1.0.0 and JSON carried no version at all. SARIF and CBOM are provenance
  artifacts, so a stale literal there is a false record of what produced the
  document. A new `pkg/version` package is now the single source of truth, fed
  once from the values GoReleaser injects into `main`. SARIF also gained
  `semanticVersion`, and JSON gained a top-level `tool` object.

- **A manifest that could not be parsed was dropped silently and the scan still
  reported a clean summary.** A tree containing a good and a corrupt
  `package.json` scanned only the good one and never mentioned the other, so a
  manifest broken by a bad merge became invisible and CI went green. The cause
  was not the parse-error path: discovery rejected the file before any parser
  ran. Unreadable manifests are now listed by name with the reason in the table,
  JSON, markdown and SARIF output, and always exit 2. A tree whose only manifest
  is corrupt no longer claims that no manifest was found.

- **A scan where every dependency was unknown reported "No cryptographic usage
  detected".** Nothing had been examined. The three cases (no dependencies, all
  dependencies unknown, and dependencies analyzed with no findings) are now
  worded differently, and the `--deep` hints that the analyzer had always
  generated are finally printed.

- **`--risk` and `--min-severity` did nothing.** Both were stored and never
  read, so every value, including a misspelt one, produced byte-identical
  output. They now filter, and the summary and exit code are computed from what
  survives so that every number describes the same set of findings. Unknown
  values are rejected instead of ignored. When a filter removes every finding,
  the report says so rather than reporting a clean scan.

- **Every SARIF result pointed at a literal path `"multiple"`.** Multi-project
  runs flattened all projects into one synthetic result, discarding the real
  manifest paths, so every alert landed on a file that does not exist. Results
  now carry their own project's manifest, relative to the scan root and declared
  through `SRCROOT` in `originalUriBaseIds`.

- **Output order shuffled between runs of the same scan.** `package.json`
  dependency blocks were read by ranging over maps, and findings were sorted on
  risk alone with a non-stable sort. The finding set was stable but the order
  was not, which breaks golden-file CI and reproducible SBOMs. Discovery,
  parsing and rendering are now fully ordered; all five output formats are
  byte-identical across runs.

- **A repository containing an unsupported manifest type always exited 2.**
  Discovery recognised `Cargo.toml`, `Gemfile`, `composer.json` and the Gradle
  files, but no parser exists for any of them, so each became a reported skip,
  and a skip forces exit 2. A tree with a `go.mod` beside a `Cargo.toml`
  reported an analysis error instead of the exit 1 its real quantum-vulnerable
  findings had earned, so the CI signal the tool exists to emit was replaced by
  an error about a file cryptodeps never claimed to read. Such files are now
  reported as an unsupported ecosystem rather than an unread manifest, and only
  a manifest that should have been readable and was not marks the scan
  incomplete.

- **A filtered scan reported clean in every format except the table.** The
  verdict that distinguishes "nothing was found" from "nothing was examined"
  from "everything was withheld" reached the table only. Markdown still printed
  "No cryptographic usage detected in dependencies.", SARIF asserted
  `executionSuccessful` over an empty result set, and CBOM emitted no
  components and said nothing, so a consumer of any of them read a clean bill
  of health. All five formats now classify through one shared function, SARIF
  records coverage as `toolExecutionNotifications`, and CBOM records it as
  `metadata.properties`.

- **The aggregate summary of a workspace scan omitted the withheld count.**
  `AggregateResults` summed nine fields and not `filteredOut`, so
  `totalSummary.filteredOut` stayed absent while the per-project summaries
  reported dozens. The totals a reader actually looks at described a filtered
  scan as a complete one.

- **`--min-severity` discarded findings whose severity was not upper case.**
  Severity ranking is keyed by the upper-case constants and a Go map returns
  zero for an absent key, so an unrecognised severity ranked as `INFO` and any
  higher threshold dropped it, uncounted. Database records arrive from a remote
  feed with no normalisation, so a record carrying `critical` was discarded by
  the very filter a user reaches for to see critical findings. Ranking is now
  case-insensitive, and a severity that cannot be ranked is reported rather
  than withheld.

- **`analyze <manifest-file>` emitted SARIF pointing at nothing.** Passing a
  file rather than a directory made the `SRCROOT` base the manifest itself, so
  every result resolved to the literal `"."`. The base is now the containing
  directory.

- **The markdown remediation table shuffled between runs.** It was the one
  format still ranging over a map after the determinism work, so ten runs of
  the same scan produced ten different documents.

- **The GitHub Action published zero counts and could not upload SARIF.** It
  read `.summary` from JSON, but workspace discovery is the default and a
  multi-project document carries `.totalSummary`, so `vulnerable-count` was
  always 0. Its SARIF step also treated any non-zero exit as a step failure,
  which skipped the upload for exactly the incomplete scans most worth
  reporting.

### Changed

- Coloured emoji in the table output are replaced by the ASCII markers the
  section headers already use: `[!]` vulnerable, `[~]` partial, `[OK]` safe,
  `[?]` unknown. They need no legend, and unlike the emoji they survive a pipe
  into a file, a terminal without an emoji font, and a screen reader. This also
  brings the tool in line with the CSNP no-emoji standard.

- A runtime failure no longer prints the full flag list after the error. The
  message that explains the failure was being pushed off the top of the
  terminal. Usage is still shown for genuine flag mistakes, where it helps.

## [1.3.0] - 2026-07-27

Fixes both open community issues, plus a silent false negative found while
reproducing them.

### Fixed

- **`requirements-*.txt` files were skipped**
  ([#1](https://github.com/csnp/cryptodeps/issues/1)). Manifest discovery
  matched the exact filename `requirements.txt`, so the
  `requirements-dev.txt` and `requirements-prod.txt` split that most Python
  projects use was never scanned. The `requirements*.txt` family and the
  `requirements/*.txt` directory layout are now discovered and parsed.
- **CBOM did not identify which dependency an algorithm came from**
  ([#2](https://github.com/csnp/cryptodeps/issues/2)). Output emitted only the
  algorithm, carrying the dependency's version but never its name, so a
  component reading `{"name": "RSA", "version": "1.3.2"}` was unattributable.
  Each dependency is now emitted as its own `library` component with a
  `bom-ref`, and the CycloneDX `dependencies` graph links each algorithm to the
  library that provides it.
- **`pyproject.toml` and `Pipfile` produced fabricated dependencies.** Both were
  advertised as supported, but parsing fell through to the `requirements.txt`
  line parser behind a `TODO`. A `pyproject.toml` yielded entries named after
  TOML keys (`name`, `dependencies`, `requires-python`), and because the real
  packages were never identified, a project depending on `cryptography` reported
  "No cryptographic usage detected". Both formats now have real TOML parsers
  covering PEP 621, Poetry, and Pipfile layouts.
- **Every CBOM shared one serial number.** `generateUUID` returned a hardcoded
  all-zero UUID, which also failed the CycloneDX `urn:uuid` pattern. Serial
  numbers are now random version 4 UUIDs.
- **Unresolved build properties were emitted as versions.** A Maven dependency
  declared as `${java-jwt.version}` appeared in the CBOM with that literal as
  its version. Version ranges such as `>=2.0` were likewise emitted where
  CycloneDX expects a concrete version. Only pinned versions are now reported as
  versions; the declared constraint is preserved in the component description.
- **CBOM `primitive` values were outside the CycloneDX enum**, which failed
  schema validation for the whole document. Categories now map onto the
  permitted enum, resolving `encryption` by algorithm where possible.

### Added

- Regression tests for manifest discovery, the three Python formats, PEP 508
  requirement parsing, CBOM dependency attribution, version resolution, serial
  number uniqueness, and primitive enum conformance.

### Dependencies

- Added `github.com/BurntSushi/toml` for pyproject.toml and Pipfile parsing.

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
  - Vulnerable (quantum-broken by Shor's algorithm)
  - Partial risk (weakened by Grover's algorithm)
  - Safe (quantum-resistant)
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
