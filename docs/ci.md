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
        run: cryptodeps analyze . --format sarif > results.sarif

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
    - cryptodeps analyze . --format json > crypto-findings.json
    - cryptodeps analyze . --fail-on vulnerable
  artifacts:
    paths:
      - crypto-findings.json
```

## Exit Codes

| Code | Meaning | Trigger |
|------|---------|---------|
| `0` | Success | No findings matching `--fail-on` threshold |
| `1` | Vulnerable | Quantum-vulnerable crypto detected |
| `2` | Error | Analysis failed, including any manifest that was found but could not be read |
| `3` | Partial | Partial-risk crypto detected (with `--fail-on partial`) |
