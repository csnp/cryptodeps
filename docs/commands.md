# Commands

The `analyze`, `update`, `status` and `version` commands, the `analyze` flags, the report filters, how an argument is read as a local path or a GitHub repository, the exit codes and common workflows. Start with the [README](../README.md) if you are new to CryptoDeps.

## CLI Reference

```
cryptodeps <command> [flags]

Commands:
  analyze     Analyze project dependencies for cryptographic usage
  update      Download latest crypto knowledge database
  status      Show database statistics and cache info
  version     Print version information (also cryptodeps --version or -v)

Analyze Flags:
  -f, --format string       Output format: table, json, cbom, sarif, markdown (default "table")
      --fail-on string      Fail threshold: vulnerable, partial, any, none (default "vulnerable")
      --reachability        Analyze call graph for actual crypto usage (default true, Go only)
      --deep                Analyze the source of packages not in the database (downloads each
                            package: needs network access, and go or npm on PATH for Go modules
                            and npm packages; skipped under --offline)
      --offline             Make no network connections: local database and local paths only
      --no-workspaces       Disable workspace discovery (scan single manifest only)
      --risk string         Report only this risk level: vulnerable, partial, safe, unknown, all
      --min-severity string Report only findings at or above: info, low, medium, high, critical
  -h, --help                Show help
```

`--risk` and `--min-severity` filter the report. The report and its summary
count the findings the filters leave, and say how many they withheld.
The exit code still counts the findings the filters
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

For a Go project scanned from a local path, where reachability analysis runs,
the line also splits the findings in the report by reachability: called from
your code, reached from your code through other calls, or in dependencies where
no call from your code was found.

The line goes to stderr only, so JSON, SARIF and CBOM output on stdout is
unchanged.

## Local paths and GitHub repositories

`analyze` reads its argument as a local path whenever a file or directory of
that name exists. Only when none does is an argument shaped like `owner/repo`,
`github.com/owner/repo` or `https://github.com/owner/repo` fetched from GitHub,
and the first line on stderr says so:

```
No file or directory named servics/api was found, so fetching the GitHub repository servics/api instead...
```

A report of a fetched repository names the repository and branch in every
output format (see [Output formats](output-formats.md)).

Only the repository's manifest files are fetched, not its source code, so
reachability is not analyzed for a fetched repository: no finding carries a
CONFIRMED, REACHABLE or AVAILABLE label, and the JSON summaries have no
`reachabilityAnalyzed` field. For a Go project, a line on stderr after the
report says so:

```
Reachability was not analyzed: only the manifest files were fetched from GitHub, not the source code. To see which of this cryptography the code calls, clone the repository and scan the local copy.
```

With `--offline`, nothing is fetched. An argument that is not a local path is
reported before anything else runs, and the command exits 2:

```
Error: No file or directory named servics/api. --offline does not fetch repositories.
```

Without `--offline`, an argument that is not a local path and is not shaped
like a repository is reported the same way, also before anything else runs,
and the command exits 2, for example
`Error: No file or directory named ./servics/api.`

An empty argument, which `cryptodeps analyze "$SCAN_PATH"` passes when
`SCAN_PATH` is empty, is reported as `Error: The path argument is empty.`,
with or without `--offline`. An argument that starts or ends with a space, or
holds a tab or another character that does not print, is shown in double
quotes, for example `Error: No file or directory named " ".`

## Exit codes

| Code | Meaning |
|------|---------|
| 0 | No finding reached the `--fail-on` threshold |
| 1 | Quantum-vulnerable findings detected, under any `--fail-on` threshold except `none` |
| 2 | Analysis error, including any manifest that was found but could not be read, and an argument that is not a local path under `--offline` |
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

# Offline mode (cached database, no network connections)
cryptodeps analyze . --offline

# Update the crypto knowledge database
cryptodeps update

# Check database status
cryptodeps status
```
