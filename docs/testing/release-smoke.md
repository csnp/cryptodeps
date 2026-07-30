# Release smoke test: cryptodeps

Manual pre-release walkthrough. Run this before every tag push, against the
CI-equivalent binary, not against `go run` and not against a binary already on
`PATH`. Record the actual output, not a summary.

Build the artifact the way the release workflow does, so the version it reports
is the version being released:

```bash
VERSION=<version being released, no leading v>
CGO_ENABLED=0 go build -trimpath \
  -ldflags="-s -w -X main.version=${VERSION} -X main.commit=$(git rev-parse HEAD) -X main.date=$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  -o /tmp/cryptodeps-rc ./cmd/cryptodeps
/tmp/cryptodeps-rc version    # must print ${VERSION}, not "dev"
```

Build the previously released version the same way and keep both. Nearly every
finding on this tool has turned out to be pre-existing, and that changes the
release decision:

```bash
git archive v<previous> | tar -x -C /tmp/prev && cd /tmp/prev
CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -X main.version=<previous>" -o /tmp/cryptodeps-prev ./cmd/cryptodeps
```

## 1. Build and suite

- [ ] `go build ./...`, `go vet ./...`, `gofmt -l .` all clean.
- [ ] `go test ./...` green, and green under `-race`.
- [ ] `goreleaser check` validates.
- [ ] `goreleaser release --snapshot --clean --skip=publish,docker,sign` produces
      the same five archive names as the previous release, version token aside.

## 2. Core user paths

- [ ] **Scan a project with real crypto dependencies.** Findings name the
      package and version, the summary line agrees with the finding list, and
      the exit code is 1.
- [ ] **Scan a clean project.** The verdict distinguishes "no dependencies",
      "dependencies all absent from the database" and "analyzed, nothing found".
      None of them may say cryptographic usage was not detected when nothing was
      examined.
- [ ] **Scan a tree holding a corrupt manifest beside a good one.** The corrupt
      file is named with a reason, and the scan exits 2. This is the case the
      tool exists to get right: a scanner may skip input, it must never skip it
      silently.

## 3. Every output format

Run `--format` for each of table, json, cbom, sarif, markdown on the same tree.

- [ ] All five agree on the finding set and on the counts.
- [ ] The tool version is the version being released in JSON `tool`, CBOM
      `metadata.tools`, and SARIF `version` and `semanticVersion`.
- [ ] CBOM validates against the official CycloneDX 1.6 schema and SARIF against
      official SARIF 2.1.0, both fetched upstream, not against the tool's own
      tests.
- [ ] Five runs of each format are byte-identical once the JSON `scanDate` and
      the CBOM `serialNumber` are normalized.
- [ ] No emoji, no em-dashes, no ANSI escape bytes in any format.

## 4. Untrusted input

Both a filesystem path and a dependency name/version come from the repository
under scan, and the bundled Action publishes the markdown report.

- [ ] A directory named with embedded newlines and `## Scan result: CLEAN` puts
      no heading in the markdown report.
- [ ] A dependency whose version contains a newline and the same text puts no
      heading in the report either. The database lookup falls back from
      `name@version` to the name alone, so a real package with a hostile version
      still resolves and still reaches the findings table.
- [ ] Both are still named in the report, rendered inert, rather than dropped.

## 5. Error handling and exit codes

Check each against the table in `analyze --help`.

- [ ] Empty directory, missing directory, a file instead of a directory.
- [ ] An empty manifest, and a manifest the process cannot read (`chmod 000`).
- [ ] A tree whose only manifest is of an unsupported type. It must not be
      reported as a file that could not be read.
- [ ] `--risk` and `--min-severity` change the report, the summary and the exit
      code together, and reject an unknown value rather than ignoring it.
- [ ] A runtime error prints the message without the full flag list after it.

## 6. Verdict sanity, including the best achievable case

- [ ] Scan a project whose only crypto dependency is a post-quantum library.
      Read the verdict as its maintainer would. A project that has already
      migrated must not be told to adopt the scheme it is using. Sanity-check
      the best achievable posture, not just the worst.
- [ ] Every finding names what is wrong and gives a next action. A hint that
      tells the user to run a flag they just ran is a dead end.

## 7. Database

- [ ] `cryptodeps status` agrees with the database's own `stats` block and with
      a direct count of its records.
- [ ] With no `~/.cryptodeps` cache present, the built-in database is used and
      `status` says the cache is not downloaded.
- [ ] Compare the shipped `data/crypto-database.json` per-ecosystem counts
      against the previous release's published asset. A large drop in one
      ecosystem is a partial upstream fetch, not a real change.

## Result

- Date:
- Tester:
- Binary under test (version and commit):
- Previous binary compared against:
- Verdict: PASS / FAIL
- Findings, each marked pre-existing or new:
