# CI/CD Integration

Recipes for running CryptoDeps in a pipeline, and the exit codes a pipeline sees. The [README](../README.md#run-it-in-github-actions) keeps the GitHub Actions recipe.

## GitHub Actions with SARIF

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

## GitLab CI

```yaml
cryptodeps:
  stage: security
  image: golang:1.22
  script:
    - go install github.com/csnp/qramm-cryptodeps/cmd/cryptodeps@latest
    - cryptodeps analyze . --format json --fail-on none > crypto-findings.json
    - cryptodeps analyze . --fail-on vulnerable
  artifacts:
    when: always
    paths:
      - crypto-findings.json
```

The report line passes `--fail-on none` so that it exits 0 and the next line
runs. The last line is the one that fails the job, and `when: always` uploads
the report when it does. GitLab's default, `on_success`, uploads artifacts only
when the job succeeds.

## Exit Codes

| Code | Meaning | Trigger |
|------|---------|---------|
| `0` | Success | No findings matching `--fail-on` threshold |
| `1` | Vulnerable | Quantum-vulnerable crypto detected, with any `--fail-on` threshold except `none` |
| `2` | Error | Analysis failed, including any manifest that was found but could not be read |
| `3` | Partial | Partial-risk crypto detected with `--fail-on partial`, or crypto with no quantum-vulnerable finding with `--fail-on any` |

[Exit codes](commands.md#exit-codes) on the Commands page gives, for each
`--fail-on` threshold, when it exits 1 and when it exits 3.
