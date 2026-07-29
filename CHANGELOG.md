# Changelog

All notable changes to QRAMM CryptoDeps will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.3.0] - 2026-07-29

Fixes both open community issues, and the release-blocking defects a fresh-user
release test then found while reproducing them. An earlier 1.3.0 candidate
carrying only the community fixes was prepared on 2026-07-27 but never tagged,
so everything below ships together in this release.

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

- **`--deep` results were then ignored by that same verdict, and the report sent
  the user back to `--deep`.** Found while release-testing this version, and a
  regression against 1.2.2 rather than a pre-existing defect: `analyze <tree>
  --deep`, where the database covers none of the dependencies and source
  analysis reads all of them, printed "Not analyzed. All 3 dependencies are
  absent from the crypto database, so no conclusion about cryptographic usage
  can be drawn from this scan. Run with `--deep`". Every clause of that was
  false for the run that produced it, the JSON for the same invocation reported
  `deepAnalyzed` on all three, and 1.2.2 printed a correct clean verdict. The
  fix above asked whether the database covered a package in order to answer
  whether anything had examined it, which were the same question until `--deep`
  became a second way to examine one. Coverage is now counted where examination
  happens, as `summary.notExamined`, and every format reads it. Reports also
  distinguish "not examined because you did not ask for source analysis", where
  the next step is `--deep`, from "not examined because the package could not be
  fetched", where it is not; `summary.deepAttempted` records which.

- **A cached package that had never been unpacked was counted as analyzed.**
  The npm and PyPI fetchers returned one directory after extracting an archive
  and a different one on a cache hit, and the cache-hit check asked only whether
  the version directory existed. A directory holding nothing but the downloaded
  tarball answers yes, so its contents were walked, no source file was found,
  and the package was recorded as read by source analysis with no findings and
  no warning. The two paths disagreed for real packages too: an npm tarball that
  does not unpack to `package/`, as `ejs` does not, failed on the first run and
  was silently analyzed from the wrong root on every run after it, so the same
  project reported 43 packages analyzed with a warning and then 44 without one.
  Both paths now resolve the extracted source through one helper, and a cache
  entry that holds none is refetched rather than accepted. The Maven fetcher
  accepted an `extracted/` directory that a failed unzip had left empty; that is
  covered by the same check.

- **A cache entry the fetcher could not identify was deleted rather than
  reported.** Where an entry held more than one candidate directory, the
  resolver could not say which was the package and returned an error saying so.
  All three cache-hit sites discarded that error and cleared the entry, so a
  cached tree that may well have held the findings was destroyed by a scan that
  had only failed to identify it, the refetch loop was unbounded, and the
  diagnostic written for the case was unreachable: the user was shown whatever
  the refetch failed with, typically `npm pack failed`. Such an entry is now
  kept and the reason reported.

- **A deep scan of a package with no readable source was counted as an
  examination.** `--deep` marked a dependency analyzed whenever the fetch and
  the walk both returned without an error, and a walk over a tree holding no
  file the analyzer understands returns nothing rather than an error. A Maven
  artifact whose sources JAR does not exist falls back to the main JAR, which
  carries compiled classes only, so no `.java` file was ever read and the report
  still said `No cryptographic usage detected in the 1 of 1 dependencies that
  were examined`. The walkers now report how many files they parsed, the count
  travels with the analysis as `analysis.filesAnalyzed`, and the claim of an
  examination is made from it. A package whose archive holds nothing readable is
  reported as not examined, with the reason on stderr and in the `error` field
  of the document, so a consumer can tell it from a package that was skipped.
  1.2.2 answers the same scan with a plain clean verdict, so this is not a
  regression; the wording introduced in this release asserted an examination
  that had not happened.

- **`pyproject.toml` and `Pipfile` kept the comparison operator in the version.**
  The same two packages gave `pycryptodome@3.20.0` through `requirements.txt`
  and `pycryptodome@==3.20.0` through the other two formats, and within one scan
  the CBOM purl normalised it while JSON and SARIF did not, so a consumer could
  not join the two documents by version. It also reached the fetcher, which
  builds a pip spec as `name==version`. New in 1.3.0, alongside the parsers that
  made those formats work at all.

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
  parsing and rendering are now fully ordered, so ordering is stable across runs
  in all five formats. The JSON scan timestamp and the CBOM serial number
  necessarily differ between runs; every other byte is identical.

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

- **A CBOM published the operator's filesystem layout.** Manifest paths were
  rendered relative to the scan root so that a shared bill of materials carries
  the repository layout and not a home directory or a CI runner's workspace
  path, but the comparison used the scan root exactly as it was typed while the
  manifest paths had already been absolutized. `cryptodeps analyze /abs/path`
  produced relative paths and `cryptodeps analyze .`, which is the default and
  what the Action runs, emitted absolute ones. SARIF had always normalized the
  root; both formats now share one implementation, so they cannot disagree again.

- **A scanned repository could write its own lines into the report.** Every
  filesystem path reached the table and markdown reports uninterpolated, and a
  path is attacker-controlled: a directory named with embedded newlines and the
  text `## Scan result: CLEAN` put exactly that heading in the markdown report,
  above the corrupt manifest the report exists to disclose. A directory named
  `a|b` shifted a column out of the "Not analyzed" table, because
  GitHub-flavoured markdown splits a cell on an unescaped pipe even inside a
  code span. Every path, skip reason and dependency string in the markdown report is now
  rendered inside a code span, where only a backtick and a pipe are active, rather than
  escaped character by character: the first attempt at this escaped control
  characters and left a bare `##` heading, so a directory named `**CLEAN**` or
  `[no findings](https://...)` still rendered as markup. In the plain-text
  report, and inside the code spans, anything carrying a control character, a
  Unicode line or paragraph separator, a bidi override, a zero-width character,
  a backtick or a pipe is rendered as a quoted string: single-line, reversible,
  and still naming the file. JSON, CBOM and SARIF were never affected by the
  line-injection vector, because `encoding/json` escapes what it emits.

- **A dependency string could write its own lines into the report too.** The
  path fix did not cover the other channel into the same document: a dependency
  name and version come from the manifest under scan, and both were interpolated
  bare into the markdown findings tables and the table report. It needs no
  filesystem access at all, which makes it easier to reach than the directory
  name that was fixed first: the database lookup falls back from "name@version"
  to the name alone, so a real package with a version of
  "1.3.1\n\n## Scan result: CLEAN" still resolved, reached the findings table,
  and put that heading in the report seven times. Now rendered through the same
  code spans every path uses. Present in 1.2.2 as well; the fix is not a
  regression repair.

- **The table and markdown reports named manifests differently from the CBOM and
  SARIF for the same scan.** Only the two machine-readable formats expressed a
  manifest relative to the scan root; the table used a string-prefix test that
  compared the root as typed against absolutized paths, and markdown did not
  relativize at all. Every surface of one run now names a manifest the same way,
  with one absolute anchor per document. `getRelativePath` also returned a path
  that does not exist when the root was a string prefix of a sibling directory,
  so `("/repo", "/repository/go.mod")` gave `./sitory/go.mod`.

- **`cryptodeps status` reported roughly twice the packages the database holds.**
  On a 901-record database it announced 1731, and every per-ecosystem number was
  wrong the same way. The index files each package under two keys,
  `name@version` and `name`, so a lookup succeeds with or without a version, and
  the count was of index entries rather than packages. `status` now reports the
  record count itself, matching the database's own stats block and a direct
  count of its records, and it lists the ecosystems in a fixed order instead of
  the order the map happened to iterate in.

### Security

- **A scanned manifest could point `--deep` at any directory the process could
  read.** The source cache path was built from the dependency name and version
  exactly as declared, so a `package.json` carrying
  `{"ejs": "../../../somewhere"}` resolved the cache entry outside the cache
  directory. That directory existed, the cache-hit check accepted it, and the
  analyzer walked it and published its absolute file paths and line numbers as
  that dependency's source. Scanning an untrusted repository in CI could
  therefore put the contents of an unrelated directory into the SARIF the run
  uploads. Present in 1.2.2 and in every earlier release with `--deep`.
  Manifest-supplied names and versions are now reduced to a single safe path
  segment before they are joined to the cache path, and a name or a version that
  names a local path is refused with a message saying so rather than passed to
  `npm pack` or `pip download`, which would resolve it. Registry and VCS
  references such as `github:owner/repo` are unaffected.

- **The same class reached the dependency name, not only the version.** Reducing
  the name to a safe path segment kept the cache entry in place, which made the
  name look handled, but the name is also given to the package manager as a
  spec, and `npm pack ../../../../victim` resolves a directory. A manifest
  declaring `{"../../../../victim": ""}` packed a tree outside the project,
  walked it and published its file names and line numbers. A path and a package
  spec are different guarantees; both are now checked, for every ecosystem, at
  the point the fetch is built.

- **A scanned `pom.xml` could write any file the scanning process could write.**
  This one is not a read. `fetchMavenArtifact` joined the `artifactId` from the
  manifest straight onto the download path handed to `curl -o`, and
  `filepath.Join` resolves `..` lexically, so the target escaped the cache. A
  `?` in the `artifactId` split the Maven URL so that its path portion still
  named a real artifact while the file portion traversed, which supplies the 200
  that `curl -f` needs in order to write at all. Reproduced against 1.2.2 and
  against the 1.3.0 candidate: a 26-byte file outside the cache was replaced
  with 234540 bytes of an unrelated archive by one `analyze --deep`. The
  attacker chooses the path; the content is any artifact on Maven Central.
  Coordinates are now validated as coordinates, which closes the URL and the
  path at once, and the file name the fetcher writes is derived from sanitized
  segments regardless.

  Present in 1.2.2 and in every earlier release with `--deep`, alongside the
  read above. All three require the operator to run `--deep` over a manifest
  they do not control, which is what a CI scan of an untrusted repository does.

- **The local-path guard did not cover the Windows spellings.** A colon was read
  as evidence that a reference was remote, so a drive letter passed: `C:\victim`,
  `\victim` and `\\host\share` reached the package manager as folder specs on a
  target this tool ships binaries for. They are now refused with the other local
  paths, together with the Yarn and pnpm `link:` and `portal:` spellings, which
  `npm pack` rejects today and which should not depend on another tool's parser
  staying strict. Maven coordinates and npm aliases, which legitimately carry a
  colon, are unaffected.

- **The source cache could delete more than the entry it meant to.** The only
  destructive operation in the fetcher took whatever path it was handed, and its
  argument is built from manifest-supplied text. Nothing stated its bounds:
  four separate mutations of it, up to and including removing the entire cache
  root, left the test suite passing. It now refuses anything that is not exactly
  one package entry inside the cache directory, and the failed-download paths
  route through the same guard. No input was found that reached the wider
  deletion, since the segments are sanitized before they are joined; this bounds
  the operation rather than closing a known route to it.

### Changed

- `output.PrintSkipped` takes the scan root as its second argument, so it can
  name a manifest the same way the rest of the report does. This is a breaking
  change to an exported function in an importable package.

- Coloured emoji in the table output are replaced by the ASCII markers the
  section headers already use: `[!]` vulnerable, `[~]` partial, `[OK]` safe,
  `[?]` unknown. They need no legend, and unlike the emoji they survive a pipe
  into a file, a terminal without an emoji font, and a screen reader. This also
  brings the tool in line with the CSNP no-emoji standard.

- A runtime failure no longer prints the full flag list after the error. The
  message that explains the failure was being pushed off the top of the
  terminal. Usage is still shown for genuine flag mistakes, where it helps.

### Added

- Regression tests for manifest discovery, the three Python formats, PEP 508
  requirement parsing, CBOM dependency attribution, version resolution, serial
  number uniqueness, and primitive enum conformance.

- `analysis.filesAnalyzed` on every deep-analyzed record, and `error` on any
  dependency source analysis could not examine, in JSON and YAML output. A
  document that claims a package was read now carries the count it was claimed
  from, and one that skips a package says why.

- `summary.notExamined` and `summary.deepAttempted` in JSON and YAML output, and
  a **Not Examined** row in the markdown summary table. How much of a tree a
  scan actually covered was previously only derivable, and only wrongly, from
  the count of packages missing from the database.

- Regression tests for the coverage verdict driven end to end through a real
  `--deep` scan against a pre-populated source cache, for cache entries that
  hold no extracted source, for an archive that carries no readable source at
  all, for the bounds of the cache reset, and for manifest-supplied paths in
  their Unix and Windows spellings. Each was confirmed to fail against the code
  it guards, and each was mutation-tested.

### Dependencies

- Added `github.com/BurntSushi/toml` for pyproject.toml and Pipfile parsing.

### Known limitations

Present in 1.2.2 as well unless noted. Each was reproduced by hand against both
the 1.2.2 and the 1.3.0 binary during the release test, and each is tracked.

- **A package that provides hybrid post-quantum cryptography is reported as
  quantum-vulnerable.** `@noble/post-quantum` carries X25519, ECDSA and Ed25519
  because they are one half of hybrid constructions such as X-Wing, whose other
  half is ML-KEM. The database marks all three `VULNERABLE` at `HIGH` and the
  remediation advises migrating to ML-KEM and ML-DSA, which is what the package
  already implements. Its RSA and AES entries are wrong outright: neither is a
  primitive the package offers. A project whose only crypto dependency is a PQC
  library is therefore told it has four HIGH findings. The classification of a
  classical primitive that appears only as a declared hybrid component is being
  fixed generally rather than for one package.

- **Maven coverage in the downloadable database is unstable.** The weekly
  refresh has published between 15 and 356 Maven packages over the last seven
  runs, because a partial result from the upstream search is committed as though
  it were a complete one. The 15 that are always present are a curated seed list.
  This affects `cryptodeps update` only; the binary's built-in database is
  unchanged by it.

- **Findings carry no line number.** JSON `location.file` is empty and
  `location.line` is zero for every finding, and SARIF results carry no
  `region`, so an alert lands on the manifest rather than on the line that
  declares the dependency.

- **A `GITHUB_TOKEN` in the environment breaks `analyze <url>`.** The GitHub API
  is called with whatever token is present, so an expired or wrongly-scoped one
  fails with `401 Unauthorized` against a public repository that needs no
  authentication at all. `GITHUB_TOKEN` is set by default in GitHub Actions.
  Clearing it for the command is the workaround.

- **The database download is unverified, and it is not opt-in.** `update --url`
  accepts any URL, and the database file carries no signature or checksum, so
  the update path is unauthenticated end to end. The download is also automatic
  and silent: the first `analyze` on a machine with no `~/.cryptodeps` fetches
  the database over the network and writes it there without printing anything,
  so a user who never runs `update` is still scanning against downloaded data.
  That is why the same project can be reported differently on two machines. Pass
  `--offline` to use only the database built into the binary, which is smaller
  (72 packages against 849) and carries none of the entries listed in the
  hybrid-PQC limitation above.

- **`--deep` requires `pip` on `PATH` for Python packages**, not `pip3`, so it
  fails on a default Homebrew macOS with `exec: "pip": executable file not
  found`. The failure is reported on stderr and the report now says the packages
  could not be read and points at those warnings, rather than suggesting the
  command that just failed, but the missing `pip3` fallback itself is not fixed.

- **A repository whose only manifests are of an unsupported type exits 2**, with
  the same status as a genuine analysis error. 1.3.0 now names the file and the
  reason rather than reporting that no manifest was found.

- **`--fail-on any` fails a project whose cryptography is entirely quantum
  safe, and reports it as a partial-risk exit.** The flag is described as
  exiting non-zero "when risk found", but it is implemented as any cryptographic
  usage at all, so a project whose only dependency is `bcrypt` exits 3 with
  `0 vulnerable | 0 partial` in its own summary and nothing on either stream
  explaining the failure. Exit 3 is documented as partial-risk findings, which
  this is not. Identical on 1.2.2. The default, `--fail-on vulnerable`, is
  unaffected and behaves as documented.

- **Two dependency names that differ only in characters the source cache
  replaces share one cache entry.** The cache path is built by replacing
  anything outside `[A-Za-z0-9._-]` with `_`, so `@scope/pkg` and `_scope_pkg`
  both give `_scope_pkg`, and the second package declared in a manifest is
  analyzed from the first one's source and reported under its own name. It
  needs a manifest that declares both spellings, and it misattributes findings
  rather than reaching anything outside the cache. Present in 1.2.2. Closing it
  changes the cache path of every Maven coordinate and every scoped npm name,
  and those paths appear in reported findings, so it is held for 1.3.1 rather
  than changed in a release whose output has already been verified.

- **`--offline` silently disables `--deep`, and the report then suggests
  `--deep`.** Source analysis fetches package archives, so it cannot run with
  downloads refused, but passing both prints no warning that one was ignored.
  Because no source analysis was attempted, a scan whose dependencies are all
  absent from the database ends at "Run with `--deep` to analyze package source
  code directly", which is the flag that was just passed. 1.2.2 answered the
  same invocation with "No cryptographic usage detected in dependencies", a
  clean verdict for a scan that examined nothing, so the verdict itself is
  fixed and the suggestion that follows it is not.

## [1.2.2] - 2025-12-27

### Fixed

- Docker image name in the release workflow now matches the repository, so the
  GHCR login succeeds and the container image publishes.

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

[1.3.0]: https://github.com/csnp/cryptodeps/compare/v1.2.2...v1.3.0
[1.2.2]: https://github.com/csnp/cryptodeps/compare/v1.2.1...v1.2.2
[1.2.1]: https://github.com/csnp/cryptodeps/compare/v1.2.0...v1.2.1
[1.2.0]: https://github.com/csnp/cryptodeps/compare/v1.1.0...v1.2.0
[1.1.0]: https://github.com/csnp/cryptodeps/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/csnp/cryptodeps/releases/tag/v1.0.0
