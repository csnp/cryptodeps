# Changelog

All notable changes to QRAMM CryptoDeps will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.3.0] - 2026-07-30

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

  The count is of files **parsed**, not files opened, which is a distinction the
  first version of this fix did not make. Three of the four analyzers are line
  scanners whose only failure was `os.Open`, so any openable file with a
  matching extension counted: a zero-byte `Empty.java`, or compiled class bytes
  under a `.java` name, each produced `filesAnalyzed: 1` and restored the exact
  verdict above. An extension is a descriptor rather than the thing itself, so a
  file now counts only if it holds text the analyzer can read.

  "Text the analyzer can read" then had to be corrected twice more. It first
  meant "the head is valid UTF-8", which accepted every NUL-free binary over the
  head size, because the allowance for a rune straddling the boundary shrank the
  head one byte at a time and `utf8.Valid` reports true for an empty slice: 2000
  bytes of `0xff` counted as a parsed file. Bounding that allowance then left the
  UTF-8 requirement itself, which was never the right question. These analyzers
  are line scanners matching ASCII identifiers, so they neither need nor check
  valid UTF-8, and requiring it refused legitimate source in any single-byte
  encoding: a `.java` or `.js` file holding one Latin-1 accent in a comment was
  reported as unreadable and the cryptography beside the accent was never looked
  for, where 1.2.2 had found it. A file is now text if it holds no NUL byte and
  its head is either valid UTF-8 or predominantly printable ASCII, which is the
  property a line scanner actually depends on. The threshold is measured: across
  140 real npm source files carrying non-ASCII characters, re-encoded to Latin-1,
  the lowest printable-ASCII fraction was 0.904 and the median 0.999, while
  random NUL-free bytes reached at most 0.453 and real binaries with their NUL
  bytes stripped reached 0.286.

- **A source file the analyzer refused was dropped silently, and the package was
  still reported as examined.** The count of failed files was incremented inside
  the directory walk and went no further, so a dependency holding one file that
  parsed and one that did not was described as examined and clean, on every
  stream and in every format, with zero bytes on stderr. Combined with the
  encoding defect above it made an evasion rather than an inconvenience: a
  dependency could hide its cryptography from this scanner by encoding the file
  that calls MD5 in Latin-1, and the report said the package had been examined
  and no cryptography was detected. The earlier coverage fix does not reach this
  state, because it asks its question of a dependency nothing examined, and a
  dependency read in part is counted as examined. The count now travels with the
  analysis as `analysis.filesUnreadable`, sums into the summary as
  `sourceFilesUnreadable`, is named on stderr per package, and reaches all five
  formats through the one classifier they share.

- **Source analysis of a PyPI dependency could execute code the scanned manifest
  chose.** `npm pack` runs with `--ignore-scripts` in this release, which closes
  that half of the class; pip had no equivalent. Resolving a PyPI name and version
  with no matching wheel makes pip install the project's build dependencies and
  run its build backend, which for a `setup.py` sdist is arbitrary code on the
  scanning host, from a package named by a manifest the operator did not write.
  Verified directly: `pip3 download --no-deps psycopg2==2.9.9` reports
  "Installing build dependencies" and "Preparing metadata". Fetching source in
  order to read it must not be a way to run it, so the fetch is now restricted to
  built wheels with `--only-binary=:all:`. Pre-existing rather than a regression;
  it is fixed here because the release would otherwise state that this class was
  closed while half of it was open. The cost is recorded under known limitations.

- **The npm name grammar refused 1,054 real, installable packages.** Introduced by
  this release. Holding a name to its registry's grammar was the right layer, and
  the pattern encoded the rules npm applies to a name from a NEW publisher: a
  scope and a name each beginning with a letter or a digit. npm grandfathered
  every name that predates those rules. Swept against the complete registry
  (4,240,864 names), the pattern refused 1,054 that are published and installable
  now, nine of them above 100,000 downloads a month, including `@lingo.dev/_spec`
  at 212,000, `@-xun/fs`, `@_sh/strapi-plugin-ckeditor` and `@~39/empty`. A
  refused dependency is silently never analyzed, so the scan reports a coverage it
  never had, which is this release's own false-clean defect arrived at from the
  other direction. The grammar now excludes what lets a name be read as something
  other than a name, which is the question a fetch guard exists to answer: an at
  sign separates a name from a spec, a slash or a backslash makes it a path, a
  colon makes it a scheme, and whitespace separates arguments. A leading dot is
  refused separately, so that loosening the grammar cannot quietly admit it. The
  same sweep over the other three ecosystems refuses nothing real: 0 of 860,284
  PyPI names, 0 of 16,279 Go module paths, 0 of 1,800 Maven coordinates.

- **A Maven property in a dependency's groupId or artifactId was never
  resolved.** Properties were expanded in the version alone, so
  `${project.groupId}`, which is how a multi-module build names a sibling module,
  survived into the coordinate and was then refused as a name that could steer a
  fetch. Across 2,099 real poms from Maven Central, 81 coordinates in 16 published
  artifacts use it. On one real pom the tool analyzed 6 of its dependencies where
  the same pom with the property expanded analyzed 11. Properties are now resolved
  in all three fields, and the project's own `groupId` and `artifactId` are
  available as properties alongside its version.

- **A manifest-declared version traversed out of the source cache behind any
  scheme.** The screen that refuses a local path skipped its traversal check
  whenever the value contained a colon, on the reasoning that a colon meant a
  remote reference such as `github:owner/repo`. An invented scheme defeats that:
  a version of `a1:../../../../../../../victim` carries a colon, so the check
  never ran, `npm pack` resolved a directory outside the cache, and the analyzer
  read it and published its absolute paths as that dependency's source.

  Reproduced against the candidate binary: `npm pack` resolves such a spec as a
  directory, consuming two `../` per level, and at eight the target sat two
  levels above the cache root. The scan exited 1 having copied the victim's
  source into the cache and published its `SECRET.js` as MD5 and RSA findings
  attributed to the declared dependency, with zero bytes on stderr. Present in
  1.2.2, where it additionally ran the target's `prepare` script, so the fourth
  spelling of this class was until now closed only in its execution half. The
  traversal check now runs on every value: no legitimate version carries a `..`
  path element, and whether a value is remote is decided by the scheme rather
  than by the presence of a punctuation mark.

- **A failed archive extraction was reported as an examined package on the next
  run.** The three download sites discard what a failed fetch left behind; the
  four extraction sites returned a bare error instead. Both `tar` and `unzip`
  extract partially before failing, so the cache entry was left holding a
  populated directory, which the cache-hit check accepts. The first scan reported
  the package as not examined and the second reported it as examined, with
  findings, from a partially extracted archive, with nothing on any stream saying
  so. `unzip` exits non-zero on warnings alone, so a benign real wheel could take
  this path too. All four sites now discard the entry.

- **A file with one line longer than 64 KiB contributed nothing, silently.**
  `bufio.Scanner`'s default token limit stops the scan and reports an error, the
  three line-scanning analyzers return it, and the walk discards every usage they
  had already found. Bundled and minified output is normally one very long line,
  so a `dist/*.js` of 70 KB on one line calling `crypto.createHash('md5')`
  produced no finding, no warning and a clean verdict, on this candidate and on
  1.2.2. The scanner is now given the same bound the file already has, and the
  per-file cap moves from 8 MiB to 32 MiB: `aws-sdk-go` v1.55.5 ships
  `service/ec2/api.go` at 7,771,273 bytes, within 8 percent of the old cap, and
  that file has grown every release. This does not reach a file named
  `*.min.js`, which the JavaScript walker skips by name before the analyzer sees
  it; see known limitations. What the larger cap costs was measured: a
  30 MiB single-line file dense with cryptographic calls peaks at about 309 MB of
  resident memory and takes 2.4 seconds. Files are read one at a time, so that is
  the bound for a scan rather than a per-archive total.

- **A Poetry or Pipfile dependency declared by location was fetched from PyPI
  under its bare name.** An inline table with no `version` key returned no
  version at all, discarding the `path`, `git`, `url` or `file` it was actually
  declared by, and the fetcher then downloaded whatever PyPI serves under that
  name. So `internal-lib = {path = "../internal-lib"}` was replaced by a public
  package of the same name, whose source was analyzed and reported as this
  project's. That is dependency confusion performed by the scanner: registering
  the name of an organisation's local package is enough to be handed the
  attribution, and because `pip` builds sdists, execution with it. New in this
  release, which is where these TOML parsers were added. The locator is now kept
  so the fetcher's own guards see what was declared.

- **`--fail-on` was validated one way and read another.** The validation added in
  this release trims and lowercases before deciding; the code that turns the value
  into an exit code only lowercased. So `" partial "` passed validation, matched
  no policy, and fell through to the default vulnerable-only gate: a project whose
  findings are partial risk exited 3 for `partial` and 0 for `" partial "`, with
  nothing on either stream. Whitespace around a value is the ordinary result of a
  YAML block scalar or a workflow expression, which is exactly where this flag is
  used, and the new validation is what made the padded value look accepted. Both
  readers now canonicalise through one function.

- **A symlink in an extracted archive was followed out of the source cache.**
  The directory walk lstats, so a symlink is not a directory and fell through to
  the file analyzer, which opened whatever it pointed at. Both `tar` and `unzip`
  restore absolute symlink targets, so a package could ship `Leak.java` pointing
  at any file the scanning process can read and have this tool read it, count it
  as evidence that the package was examined, and publish its contents as that
  dependency's source in JSON, SARIF and CBOM. Symlinks are no longer read: an
  extracted package is analyzed from its own contents.

- **CBOM and SARIF omitted the dependencies a scan could not examine, whenever
  it had findings for the others.** The coverage question was asked only of
  reports that produced nothing, and a partially examined project produces
  something. So a Maven scan that told the operator on three separate streams
  that it could not read one of its dependencies handed GitHub code scanning a
  SARIF run reporting success with no notification, and produced a CBOM listing
  the libraries it had findings for with no coverage property. The two formats
  that omitted it are the two that get uploaded. Incomplete coverage is now
  reported as a property of the scan, in the same place a withheld-findings
  filter already was, so it reaches every format whether or not findings were
  also produced.

- **`--fail-on` accepted any value and silently loosened the gate.** It was the
  one enum flag of the three that did not validate, and the only one that
  decides an exit code: a project exiting 3 under `--fail-on partial` exited 0
  under `--fail-on partail`, with nothing on either stream, because an
  unrecognised value fell through to the default policy. It now rejects an
  unknown value the way `--risk` and `--min-severity` do, naming the legal ones.

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

- **The same class reached the dependency name, not only the version, and
  through the name it reached code execution.** Reducing the name to a safe path
  segment kept the cache entry in place, which made the name look handled, but
  the name is also given to the package manager as a spec, and
  `npm pack ../../../../victim` resolves a directory. A manifest declaring
  `{"../../../../victim": ""}` packed a tree outside the project, walked it and
  published its file names and line numbers.

  Screening the name for the spellings of a local path did not close this,
  because the package manager parses a string the scanner treated as opaque.
  `npm pack` splits `name@spec` on the first `@` after index 0, so a dependency
  named `x@/path/to/victim` presented a passing string to the guard and a
  directory to npm. Reproduced end to end: npm packed the victim directory,
  **ran its `prepare` and `prepack` scripts on the scanning host**, and the
  analyzer published the victim's files as that dependency's findings, with
  nothing on stderr. The relative form needs no knowledge of absolute paths.
  The same shape reaches `pip download` as a PEP 508 direct reference, which
  arrives as a Poetry or Pipfile table key (`victimpkg @ file:///path`), and
  `git+file://` reached `npm pack` through the version, since it neither begins
  with `file:` nor contains a `..` segment.

  Names are now held to their own registry's grammar (npm's scope-and-name
  form, PEP 503 for PyPI, module-path form for Go, and Maven coordinates as
  before), which is a question with a single answer rather than a list of the
  ways a path can be spelled. `npm pack` additionally runs with
  `--ignore-scripts` and `pip download` with `--only-binary=:all:`, so neither the
  remote VCS references that remain fetchable nor a source distribution can
  execute anything during a fetch. The suite asserts that real npm, PyPI and Go names
  pass the grammars, including scoped npm names and versioned Go module paths.
  Two limits on that claim, both stated because an earlier draft of this entry
  overstated it: the assertion is that a grammar accepts a name, which is not the
  same as a completed fetch, and a dotted PyPI name reaches the grammar intact
  only through `pyproject.toml`. Declared in `requirements.txt`,
  `zope.interface` is split at the first dot by the requirements parser long
  before the grammar sees it, which is a separate pre-existing defect, recorded
  under known limitations below. An earlier draft of this sentence said it was
  recorded there when it was not.

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

- The root help no longer advertises "Full dependency tree analysis", and the
  README no longer claims transitive coverage. Neither was true: only declared
  dependencies are read. See known limitations.

### Added

- Regression tests for manifest discovery, the three Python formats, PEP 508
  requirement parsing, CBOM dependency attribution, version resolution, serial
  number uniqueness, and primitive enum conformance.

- `analysis.filesAnalyzed` on every deep-analyzed record, and `error` on any
  dependency source analysis could not examine, in JSON output. A
  document that claims a package was read now carries the count it was claimed
  from, and one that skips a package says why.

- `analysis.filesUnreadable` per dependency and `summary.sourceFilesUnreadable`
  per project, in JSON output, with a warning on stderr naming each
  package and a coverage note in the table, markdown, SARIF and CBOM. The
  evidence for an examination now carries its exceptions as well as its count,
  so a partial reading cannot be read as a complete one.

- `summary.notExamined` and `summary.deepAttempted` in JSON output, and
  a **Not Examined** row in the markdown summary table. How much of a tree a
  scan actually covered was previously only derivable, and only wrongly, from
  the count of packages missing from the database.

- Regression tests for the coverage verdict driven end to end through a real
  `--deep` scan against a pre-populated source cache, for cache entries that
  hold no extracted source, for an archive that carries no readable source at
  all, for the bounds of the cache reset, for a spec smuggled through a
  dependency name in each ecosystem, for `--ignore-scripts` reaching the npm
  process, for a symlink out of an extracted archive, for incomplete coverage in
  every output format, and for manifest-supplied paths in their Unix and Windows
  spellings. Each was confirmed to fail at runtime against the code it guards,
  never merely to fail compilation.

  Mutation matrices were run over these guards, and they are reported with their
  survivors rather than as a blanket claim, because an earlier draft of this entry
  said each guard had been mutation-tested while several mutations survived. Four
  rounds were run and each round's survivors were closed by a further test before
  the next. The ones that mattered: a threshold no fixture could pin from below, a
  bound whose removal no fixture could detect, three of the four
  archive-extraction sites with no test at all, and a disclosure asserted in only
  one of the five output formats. Real npm, PyPI and Go names are asserted to pass
  the grammars, so a guard tightened far enough to refuse a legitimate name fails
  in the suite rather than in a user's CI; that assertion covers the grammar
  rather than a completed fetch.

### Dependencies

- Added `github.com/BurntSushi/toml` for pyproject.toml and Pipfile parsing.

### Known limitations

Present in 1.2.2 as well unless noted. Each was reproduced by hand against both
the 1.2.2 and the 1.3.0 binary during the release test, and each is tracked.

- **NEW in 1.3.0: a PyPI package that publishes no wheel is no longer analyzed.**
  This is the cost of the fix above: `pip download` now runs with
  `--only-binary=:all:`, so a package distributed only as an sdist is reported as
  not examined rather than built. The reason is named on stderr and carried in
  every format. Preferring an unexamined dependency to an executed one is the
  trade this release makes deliberately; a source-build mode behind an explicit
  opt-in is the shape of the fix if the coverage turns out to matter.

- **Only the dependencies a manifest declares are analyzed, and the
  documentation said otherwise.** Lock files are not read: `package-lock.json`,
  `yarn.lock`, `pnpm-lock.yaml`, `poetry.lock`, `go.sum` and `Pipfile.lock` are
  all rejected as unsupported, so a package pulled in only by another package is
  never seen. `summary.totalDependencies` equals `summary.directDependencies` on
  every tree tested, and adding a `package-lock.json` declaring a transitive
  dependency changes neither number. The behaviour is unchanged from 1.2.2; what
  changed in this release is that the claim was corrected. The README described
  "Dependency tree analysis: Scans all transitive dependencies, not just direct
  ones" and the root help listed "Full dependency tree analysis", both of which
  overstated coverage in the same direction this release exists to correct. Both
  now state what is actually read. Enumerating a lock file is the fix, and it is
  not in this release.

- **A version can name any URL, and the scanner will fetch it.** npm's own
  semantics allow a dependency version to be a tarball URL or an alias
  (`npm:other@1.0.0`), and neither is screened beyond the local-path checks. So a
  manifest under scan can direct the fetch at a host of its choosing, including
  one on the scanning machine's own network, and the response bytes are then
  handed to `tar`. An alias additionally makes the report key a different
  package's findings to the declared name. Pre-existing. Closing it needs a host
  policy rather than a path check.

- **`--deep` on a Go project writes to the tree under scan.** `go mod download`
  is run without a working directory of its own, so it inherits the invocation
  directory and can write `go.sum` into the project being scanned. A read-only
  scanner that dirties the working tree breaks a `git diff --exit-code` check in
  CI. Pre-existing.

- **A database record can answer for a different version than the one declared,
  and nothing says so.** `github.com/cloudflare/circl v1.3.9` is reported with
  `ML-KEM` and `ML-DSA` as SAFE from a record built for v1.6.4. A full-text scan
  of the real v1.3.9 module finds no ML-KEM or ML-DSA at all: it ships round-3
  Kyber and Dilithium (`kem/kyber/kyber768`, `sign/dilithium/mode2`), which are
  not interoperable with the FIPS standards. `org.bouncycastle:bcprov-jdk18on
  1.78.1` is the same case: no `pqc.crypto.mlkem` package exists in it, only
  `pqc.crypto.crystals.kyber`. This is the worst direction for this tool to be
  wrong in, because a project appears post-quantum ready while shipping
  pre-standard primitives, and it reaches the README's own example, whose
  `go.mod` declares `circl v1.3.7`. Present identically in 1.2.2, and in the
  embedded database as well as the downloadable one, so `--offline` does not
  avoid it. Only `--format json` reveals the version a record was built for.

- **A file skipped by name is not analyzed and not counted.** The JavaScript
  walker skips `*.min.js` and `test/`, `tests/` and `__tests__/` directories
  before the analyzer sees them, so unlike a file that is refused, they appear in
  neither `filesAnalyzed` nor `filesUnreadable`, and nothing on any stream or in
  any format mentions them. A `bundle.min.js` of 162,025 bytes calling
  `crypto.createHash('md5')` produces no finding and no trace, while a file of
  byte-identical content named `dist/app.js` is analyzed and its MD5 reported.
  The difference is the filename alone. Present in 1.2.2, which additionally has
  no counts at all, so this is not a regression; it is disclosed here because it
  is the same silent-skip shape this release exists to close, and because
  renaming a file is a cheaper evasion than choosing an encoding. Counting a
  skip-by-policy alongside a refusal is the fix.

- **`requirements.txt` splits a dotted PyPI name at the first dot.**
  `zope.interface==6.1` parses as name `zope` and version `.interface==6.1`, and
  the version guard then refuses that as a local path, which is a misleading
  message for a parse defect upstream of it. Both `zope` and `ruamel` are real
  PyPI packages, so the wrong name reaches every output format. 323 of the top
  15,000 PyPI packages have a dotted canonical spelling. The same packages parse
  correctly through `pyproject.toml` and `Pipfile`, which normalise the name
  first, so only the `requirements.txt` path is affected. Present identically in
  1.2.2.

- **NEW in 1.3.0: a source file whose first 1024 bytes are mostly non-ASCII is
  not read.** The text check judges a file on its head, and accepts a head that
  is not valid UTF-8 only if it is predominantly printable ASCII. That covers
  source in a single-byte encoding, where the code is ASCII even when its
  comments are not, and it does not cover a file that opens with a long comment
  in a non-Latin single-byte encoding, such as a cp1251 licence header. UTF-16
  source is refused for a separate reason: it carries NUL bytes. In every case
  the file is now counted in `analysis.filesUnreadable`, named on stderr, and
  disclosed as a coverage note in all five formats, so the gap is stated rather
  than silent. Reading whole files, or detecting the encoding, is the larger fix.

- **A package that provides post-quantum cryptography is reported as
  quantum-vulnerable, from algorithms it does not contain.** A project whose only
  dependency is `@noble/post-quantum` is reported with four HIGH findings and
  advised to migrate to ML-KEM and ML-DSA, which is what the package implements.

  An earlier draft of this entry explained the classical findings as the hybrid
  halves of constructions such as X-Wing. That explanation was checked against
  the published artifact for this release and is wrong. In
  `@noble/post-quantum@0.2.0`, the version the database records: `ML-KEM`,
  `ML-DSA`, `SLH-DSA` and `X25519` are genuinely present, and `RSA`, `ECDSA`,
  `Ed25519`, `AES` and `ChaCha20-Poly1305` do not occur anywhere in its code.
  The package exports `ml-kem`, `ml-dsa`, `slh-dsa` and `utils` and nothing else.
  Only `X25519` is a real hybrid component. The other four are fabricated by the
  database's name inference, which supplies 780 of its 849 records.

  The inference appears to substring-match without word boundaries, the same
  defect the deep analyzers have: the only occurrence of the letters `rsa`
  anywhere in the package is inside the identifier `bitReversal`, and `ed25519`,
  `RSA` and `ChaCha` occur only in the README's prose comparing the package to
  others. `@noble/hashes@1.4.0`, a hashing library, is likewise credited with
  `RSA`, `ECDSA`, `Ed25519` and `X25519`, none of which occur in its 96 source
  files, and `@noble/ciphers@1.0.0` with the same four, none of which occur in
  its 70. Word-boundary matching and a verification pass over the inferred
  records are the fix, and neither is in this release.

- **Following the tool's own remediation advice does not change the verdict.**
  A five-dependency project that replaces `node-forge` and `elliptic` with the
  `@noble` libraries the report names in its own `Libraries:` field, removing
  DES, 3DES, MD5, SHA-1, secp256k1 and ECDH, produces a byte-identical summary
  and the same exit 1: `5 deps | 4 with crypto | 10 vulnerable | 3 partial`
  before and after. The cause is the inferred attribution above, which gives
  four single-purpose `@noble` libraries the same classical core, so the
  migration target carries the same findings as the thing being migrated away
  from. Identical on 1.2.2. Until the inferred records are corrected, treat the
  remediation list as a pointer to the right family of libraries rather than as
  a step that a rescan will confirm.

- **`--offline` does not prevent network access for a GitHub-shaped argument.**
  The flag is documented as "Only use local database, no downloads", and it does
  gate the database download, but the GitHub fetch path is not behind it:
  `analyze owner/repo --offline` clones the repository and scans it. A mistyped
  local path with exactly one slash is read as `owner/repo`, so a typo becomes an
  outbound request to api.github.com. Identical on 1.2.2. Anyone relying on
  `--offline` to mean no egress should not pass a repository argument.

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

- **The bundled GitHub Action scans against the built-in database and reports
  its version as `dev`.** `action.yml` passes `--offline` at both of its scan
  steps and a fresh runner has no `~/.cryptodeps`, so the Action sees the 72
  packages built into the binary rather than the 849 in the downloadable
  database. The coverage note fires, so the scan is not silently narrower, but
  nothing states that the Action's database is a twelfth of the one a local
  install downloads. Separately, the Action installs with
  `go install ...@latest`, which injects no ldflags, so the binary it runs
  reports version `dev` and the SARIF it uploads carries that as its driver
  version. That is the version-provenance defect this release fixes,
  reintroduced by the install method rather than by the binary.

- **The CBOM component list is not a complete bill of materials.** It carries
  the libraries a scan has findings for, so a dependency that was examined and
  found clean is absent from the components alongside one that could not be
  examined at all. Incomplete coverage is now reported as a property of the
  scan, so the gap is stated rather than silent, but a reader who takes the
  component list as the set of dependencies will undercount. Making the list
  complete is an output change held for a later release.

- **Some CBOM primitive values are schema-legal but not the closest available
  term.** `ML-KEM` is mapped to `key-agree` where the CycloneDX enum offers
  `kem`, AEAD ciphers to `other` where it offers `ae`, HMAC to `signature` where
  it offers `mac`, and bcrypt, scrypt and Argon2 to `hash` where it offers
  `kdf`. The document validates, and mapping the flagship post-quantum KEM
  imprecisely in a document whose purpose is post-quantum readiness is the one
  that matters.

- **The per-analysis provenance block carries zero values.** Every deep-analyzed
  record emits `"date": "0001-01-01T00:00:00Z"`, `"method": ""`, `"tool": ""`
  and `"toolVersion": ""` inside `analysis.analysis`. The tool version fixed in
  this release is the top-level `tool` object, the SARIF driver and the CBOM
  metadata, which are correct; this separate per-record block is unchanged and
  is a placeholder rendered where a reader looks for provenance. Identical in
  1.2.2. Either populate it at the point of analysis or omit it.

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
