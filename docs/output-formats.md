# Output formats

How to choose an output format, and what the SARIF and CBOM formats contain. Start with the [README](../README.md) if you are new to CryptoDeps.

## Multiple Output Formats

```bash
# Human-readable table (default)
cryptodeps analyze .

# JSON for automation
cryptodeps analyze . --format json

# CycloneDX CBOM for compliance
cryptodeps analyze . --format cbom

# SARIF for GitHub Security
cryptodeps analyze . --format sarif

# Markdown for reports
cryptodeps analyze . --format markdown
```

## Scans of a GitHub repository

A repository fetched from GitHub is scanned from a temporary directory, so each
format also names the repository and the branch that were read, and the
subdirectory when the argument named one:

| Format | Where |
|--------|-------|
| table | A `Repository:` line above the report |
| json | A `source` object with `repository`, `branch` and `path` |
| sarif | `runs[].versionControlProvenance`, with `repositoryUri` and `branch`, and the subdirectory in `properties.path` |
| cbom | `metadata.properties` named `cryptodeps:sourceRepository`, `cryptodeps:sourceBranch` and `cryptodeps:sourcePath` |
| markdown | `Repository` and `Branch` rows, and `Repository Path`, in the summary table |

A scan of a local path has none of these.

The source code of a fetched repository is not downloaded, so reachability is
not analyzed for it, and no format gives its findings a reachability label (see
[Commands](commands.md#local-paths-and-github-repositories)).

## Output Formats Explained

### SARIF (Static Analysis Results Interchange Format)

SARIF output integrates with GitHub Code Scanning, VS Code SARIF Viewer, and other security tools:

```json
{
  "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
  "version": "2.1.0",
  "runs": [{
    "tool": {
      "driver": {
        "name": "CryptoDeps",
        "informationUri": "https://github.com/csnp/qramm-cryptodeps"
      }
    },
    "results": [...]
  }]
}
```

### CBOM (Cryptographic Bill of Materials)

Just as an SBOM inventories software dependencies, a CBOM inventories all cryptographic algorithms in your systems. Required by emerging regulations (OMB M-23-02, NIST guidelines).

```json
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:...",
  "components": [
    {
      "type": "cryptographic-asset",
      "name": "RSA-2048",
      "cryptoProperties": {
        "assetType": "algorithm",
        "algorithmProperties": {
          "primitive": "pke",
          "parameterSetIdentifier": "2048"
        }
      }
    }
  ]
}
```
