# Commands

Every command and flag, the report filters, the exit codes and common workflows. Start with the [README](../README.md) if you are new to CryptoDeps.

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

## Exit codes

| Code | Meaning |
|------|---------|
| 0 | No quantum-vulnerable findings |
| 1 | Quantum-vulnerable findings detected |
| 2 | Analysis error, including any manifest that was found but could not be read |
| 3 | Partial-risk findings detected (with `--fail-on partial`) |

A manifest that cannot be parsed is always reported by name, with the reason,
and always exits 2. A scan that silently omitted a dependency file would let a
build pass on a report that never read it.

## Common Workflows

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
