# Commands

The `analyze`, `update`, `status` and `version` commands, the `analyze` flags, the report filters, the exit codes and common workflows. Start with the [README](../README.md) if you are new to CryptoDeps.

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

`--risk` and `--min-severity` filter the report. The report and its summary
are computed from what the filters leave, so every number in them describes
the same set of findings. The exit code still counts the findings the filters
withheld: a filter changes what the report shows, not the `--fail-on` result.
When a filter removes everything, the tool says so rather than reporting a
clean scan.

When findings set the exit code to 1 or 3, one line on
stderr after the report says which findings did. For a project with six
quantum-vulnerable findings, scanned with `--risk partial`, the summary reads
`0 vulnerable` and the line reads:

```
Exit code 1 (--fail-on vulnerable): the scan found 6 quantum-vulnerable findings. None of them is in the report: --risk or --min-severity hid them, and hidden findings still count toward the exit code. Run the same command without --risk and --min-severity to list them.
```

For a Go project, where reachability analysis runs, the line also splits the
findings in the report by reachability: called from your code, reached from
your code through other calls, or in dependencies where no call from your code
was found.

The line goes to stderr only, so JSON, SARIF and CBOM output on stdout is
unchanged.

## Exit codes

| Code | Meaning |
|------|---------|
| 0 | No finding reached the `--fail-on` threshold |
| 1 | Quantum-vulnerable findings detected, under any `--fail-on` threshold except `none` |
| 2 | Analysis error, including any manifest that was found but could not be read |
| 3 | Findings reached the `partial` or `any` threshold, and none of them is quantum-vulnerable |

What each `--fail-on` threshold exits with when the analysis succeeds. Findings
withheld by `--risk` or `--min-severity` count here too.

| `--fail-on` | Exits 1 when | Exits 3 when |
|-------------|--------------|--------------|
| `vulnerable` (default) | a quantum-vulnerable finding is detected | never |
| `partial` | a quantum-vulnerable finding is detected | a partial-risk finding is detected and no quantum-vulnerable one |
| `any` | a quantum-vulnerable finding is detected | cryptography is detected and none of it is quantum-vulnerable, including when all of it is quantum-safe |
| `none` | never | never |

Under `--fail-on none` a scan exits 0 whatever it finds, which is why the CI
recipes use it for the step that writes the report. Code 2 does not depend on
the threshold.

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
