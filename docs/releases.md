# Roadmap

What each release delivered and what is planned next. Start with the [README](../README.md) if you are new to CryptoDeps.

## v1.2 (Released)

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

## v1.3 (Released)

Correctness of what the tool reports, rather than new surfaces.

- [x] Every machine-readable output reports the tool version that produced it
- [x] Manifests that cannot be read are named, with the reason, and exit 2
- [x] Manifests for unsupported ecosystems are reported without failing the scan
- [x] A scan that examined nothing no longer reports a clean result
- [x] `--risk` and `--min-severity` filter, and say how much they withheld
- [x] SARIF results point at the manifest they came from, relative to the root
- [x] Stable ordering across runs of the same scan, in all five formats
      (the scan timestamp and the CBOM serial number necessarily differ)

## v1.4 (Next release)

- [ ] Improved reachability for npm/Python projects
- [ ] Transitive dependency crypto inheritance
- [ ] Configuration file support (.cryptodeps.yaml)
- [ ] Watch mode for continuous monitoring

## v2.0 (Future)

- [ ] Direct integration with SBOMs (merge SBOM + CBOM)
- [ ] Cloud KMS detection (AWS, Azure, GCP)
- [ ] Certificate chain analysis
- [ ] IDE plugins (VS Code, JetBrains)
