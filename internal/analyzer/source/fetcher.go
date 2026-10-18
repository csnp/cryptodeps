// Copyright 2025-2026 CyberSecurity NonProfit (CSNP)
// SPDX-License-Identifier: Apache-2.0

// Package source provides functionality for fetching package source code.
package source

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"

	"github.com/csnp/qramm-cryptodeps/internal/netguard"
	"github.com/csnp/qramm-cryptodeps/pkg/types"
)

// Fetcher downloads package source code for analysis.
type Fetcher struct {
	mu       sync.Mutex
	cacheDir string
	// perUser is set while cacheDir is the per-user cache directory, which
	// gives way to a cache of the run's own if it cannot be created.
	perUser bool
	// perRun is set when there is no per-user cache directory. The cache is
	// then a directory of this run's own, made on first use and removed by
	// Close, never a fixed path that every user of the machine shares.
	perRun bool
	// rootLock is the lock this fetcher holds on the cache root while it may
	// stage a download there (see claimRoot), or nil where none was taken.
	// claimed is set once a fetch has tried to take it.
	rootLock *os.File
	claimed  bool
}

// Where the source cache lives. See defaultCacheDir and stagingDir.
const (
	cacheDirName  = "cryptodeps"         // under the per-user cache directory
	perRunPrefix  = "cryptodeps-source-" // a run's own cache, in the temporary directory
	stagingPrefix = ".fetch-"            // one fetch's download, inside the cache root
)

// Directory names that a fetched archive is expected to unpack to, when the
// ecosystem has a convention. Anything else is resolved by inspection.
const (
	npmExtractedDir  = "package"   // npm tarballs conventionally unpack to package/
	zipExtractedDir  = "extracted" // where this fetcher unzips wheels and JARs
	maxCacheSegment  = 96          // long enough for any real name or version
	pathTraversalMsg = "%s %q refers to a local path, which is not fetched: " +
		"deep analysis reads package archives, not directories on this machine"
)

// mavenCoordinatePart is the character set Maven allows in a groupId or an
// artifactId. Anything else in a coordinate is not a coordinate: it is a way to
// reach the URL the fetch is built from, or the path it is written to.
var mavenCoordinatePart = regexp.MustCompile(`^[A-Za-z0-9_.-]+$`)

// validMavenCoordinate rejects a groupId or artifactId that could steer the
// fetch rather than name an artifact.
//
// The Maven fetcher interpolates both into a URL and joins the artifactId into
// the path curl writes to. A '/' in the artifactId escapes that path, and a '?'
// splits the URL so that its path portion still names a real artifact while the
// file portion traverses, which is what turned a scanned pom.xml into an
// arbitrary file write: curl -f does not create on a 404, and the query-string
// trick supplies a 200. Validating the coordinate is the layer that closes it,
// because it holds for the URL and the path at once.
func validMavenCoordinate(groupID, artifactID string) error {
	for _, part := range [...]struct{ label, value string }{
		{"groupId", groupID},
		{"artifactId", artifactID},
	} {
		if !mavenCoordinatePart.MatchString(part.value) {
			return fmt.Errorf("%q is not a valid Maven coordinate: %s %q must match %s",
				groupID+":"+artifactID, part.label, part.value, mavenCoordinatePart)
		}
	}
	return nil
}

// packageNamePattern is what each registry says one of its names looks like.
//
// A name is not an arbitrary string. Every registry here defines a grammar for
// its names, and anything outside that grammar is not a name at all: it is a
// way to reach something other than the package it claims to be. Screening for
// the spellings of a local path could never close this, because the guard sees
// one string while the package manager sees a structured spec. `npm pack`
// splits `name@spec` on the first '@' after index 0, so a dependency named
// `x@/tmp/victim` presented a guard-passing string to the guard and a directory
// to npm, which packed it, ran its prepare script, and published its contents.
// The same shape reaches pip through a PEP 508 direct reference in a Poetry or
// Pipfile table key: `victimpkg @ file:///tmp/victim`.
//
// So the question asked here is the one Maven coordinates already answered: is
// this a name? An allowlist can be reasoned about; a denylist of the ways a
// path can be spelled cannot.
var packageNamePattern = map[types.Ecosystem]*regexp.Regexp{
	// npm: an optional @scope/ then the name. What is excluded is what lets a
	// name be read as something other than a name: '@' separates a name from a
	// spec, '/' and '\' make it a path, ':' makes it a scheme, and whitespace
	// separates arguments.
	//
	// Deliberately NOT npm's rules for a name it would accept today. Those
	// require a scope and a name to begin with a letter or a digit, and the
	// first version of this pattern said so, which refused 1,054 names that are
	// published and installable right now. npm grandfathered them: nine exceed
	// 100,000 downloads a month, including @lingo.dev/_spec at 212,000, @-xun/fs,
	// @_sh/strapi-plugin-ckeditor and @~39/empty. A scanner that silently stops
	// analyzing a real dependency reports a clean result it never established,
	// which is the same false clean this release exists to remove, arrived at
	// from the other direction. The question a fetch guard has to answer is what
	// the package manager can misread, not what the registry would accept from a
	// new publisher.
	types.EcosystemNPM: regexp.MustCompile(`^(@[^@/\\:\s]+/)?[^@/\\:\s]+$`),
	// PyPI, PEP 503: letters, digits, and . _ - between alphanumerics.
	types.EcosystemPyPI: regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9._-]*[A-Za-z0-9])?$`),
	// Go module path: dot-separated host, then slash-separated elements.
	types.EcosystemGo: regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._~-]*(/[A-Za-z0-9._~-]+)*$`),
}

// validPackageName rejects a dependency name that is not a name in its
// ecosystem's own terms.
func validPackageName(ecosystem types.Ecosystem, name string) error {
	// Maven is absent from the table because its names are coordinates, but it is
	// answered here rather than only inside the Maven fetcher, so that every
	// ecosystem's grammar is the FIRST thing a name meets. While this was reached
	// only later, the traversal screen ran first and refused a hostile coordinate
	// as a local path, which is a correct refusal that says the wrong thing and,
	// worse, left the coordinate validator unexercised by the test written to
	// pin it: one guard masking another is how the masked one comes to be
	// deleted with a green suite.
	if ecosystem == types.EcosystemMaven {
		groupID, artifactID, found := strings.Cut(name, ":")
		if !found || strings.Contains(artifactID, ":") {
			return fmt.Errorf("invalid Maven coordinate: %s (expected groupId:artifactId)", name)
		}
		return validMavenCoordinate(groupID, artifactID)
	}

	pattern, ok := packageNamePattern[ecosystem]
	if !ok {
		return nil
	}
	if !pattern.MatchString(name) {
		return fmt.Errorf("%q is not a valid %s package name: it must match %s, and a name "+
			"that does not is not fetched, because package managers read a name as part of a "+
			"spec that can also select a directory or a repository on this machine",
			name, ecosystem, pattern)
	}
	// A path element of ".." is legal under the Go pattern and is still a
	// traversal, so it is refused separately rather than by complicating the
	// grammar.
	for _, part := range strings.Split(name, "/") {
		if part == ".." || part == "." {
			return fmt.Errorf("%q is not a valid %s package name: %q is a directory reference",
				name, ecosystem, part)
		}
	}
	// A leading dot makes a name relative to the working directory, which for
	// these fetchers is inside the cache. Stated here rather than in the grammar
	// so that loosening the grammar to admit the names registries actually carry
	// cannot quietly admit this too. No npm name begins with a dot: the registry
	// returns an empty range between "." and "/".
	if strings.HasPrefix(name, ".") {
		return fmt.Errorf("%q is not a valid %s package name: a leading dot makes it a path "+
			"relative to the directory the fetch runs in", name, ecosystem)
	}
	return nil
}

// cacheSegment reduces a manifest-supplied name or version to one safe path
// segment.
//
// Both come from the manifest under scan, which is untrusted input. A
// dependency declared as {"ejs": "../../../somewhere"} made the cache path
// resolve outside the cache directory, and --deep then walked that directory
// and published its absolute file paths and line numbers as the dependency's
// source. Replacing everything outside a conservative set means the result
// cannot traverse, cannot be empty, and cannot be a relative marker.
func cacheSegment(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9',
			r == '.', r == '-', r == '_':
			b.WriteRune(r)
		default:
			b.WriteRune('_')
		}
	}

	out := b.String()
	if len(out) > maxCacheSegment {
		// Truncating alone would map two long names onto one cache entry, and
		// the second package would then be analyzed from the first one's
		// source. The suffix keeps distinct inputs distinct.
		sum := sha256.Sum256([]byte(s))
		out = out[:maxCacheSegment] + "-" + hex.EncodeToString(sum[:4])
	}
	// Replacement is many-to-one below that length, so two names can still
	// share one entry: "@scope/pkg" and "_scope_pkg" both give "_scope_pkg",
	// and the second package is then analyzed from the first one's source.
	// Tracked in qramm-cryptodeps-deep-fetch-path-primitives for 1.3.1, because
	// closing it changes the cache path of every Maven coordinate and every
	// scoped npm name, and those paths are reported to the user.
	//
	// "" collapses the path by one level, and "." and ".." are directory
	// references rather than names.
	if strings.Trim(out, ".") == "" {
		return "_"
	}
	return out
}

// localPathReference reports whether a manifest-supplied string points at a
// directory on this machine rather than at a published release.
//
// npm and pip both accept such a reference as a package spec, so passing one
// through to `npm pack` or `pip download` would fetch and analyze a local
// directory of the manifest author's choosing. Registry and VCS references
// (github:owner/repo, git+https://...) are left alone: those are remote, and
// deep analysis of them works.
//
// This applies to the NAME as well as the version. cacheSegment already keeps
// the name from steering the cache path, and that made the name look safe, but
// a path and a package spec are different guarantees: `npm pack ../../../x`
// resolves a directory no matter how the cache entry is named.
func localPathReference(v string) bool {
	v = strings.TrimSpace(v)
	if v == "" {
		return false
	}
	// file: is npm's own spelling of a directory. link: and portal: are the
	// Yarn and pnpm spellings of the same thing; npm pack rejects them today,
	// so this is defence in depth rather than a live vector, and it costs one
	// list entry to stop depending on another tool's parser staying strict.
	lower := strings.ToLower(v)
	for _, scheme := range [...]string{"file:", "link:", "portal:"} {
		if strings.HasPrefix(lower, scheme) {
			return true
		}
	}
	// A transport can be prefixed onto the scheme, and git+file:// is a local
	// path wearing a VCS reference's clothes: it passed the prefix test above
	// because it starts with "git+", and passed the traversal walk below
	// because it contains a colon. `npm pack` clones it from disk and runs its
	// prepare script.
	if scheme, _, found := strings.Cut(lower, ":"); found {
		for _, part := range strings.Split(scheme, "+") {
			if part == "file" {
				return true
			}
		}
	}
	if strings.HasPrefix(v, "/") || strings.HasPrefix(v, "~") || strings.HasPrefix(v, ".") {
		return true
	}
	// Windows spellings of an absolute path: a drive letter (C:\victim, C:/victim),
	// a rooted path (\victim) and a UNC share (\\host\share). Windows is a
	// shipped target of this tool, and the checks below never see these: a
	// drive letter contains a colon, which the registry-reference branch treats
	// as evidence that the value is remote.
	if windowsLocalPath(v) {
		return true
	}
	// A traversal, wherever it appears. This walk used to be skipped for any
	// value containing a colon, on the reasoning that a colon meant a registry
	// reference such as github:owner/repo. It only takes an invented scheme to
	// defeat that: a version of "a1:../../../../../../../victim" carries a colon,
	// so the walk never ran, and `npm pack left-pad@a1:../../../victim` packed a
	// directory outside the cache, which this tool then read and published as
	// that dependency's source with its absolute paths. Verified by sentinel at
	// traversal depth 7.
	//
	// No legitimate version carries a ".." path element, so the colon earns no
	// exemption here. Whether a value is a remote reference is decided by the
	// scheme test above, not by the presence of a punctuation mark.
	for _, part := range strings.FieldsFunc(v, func(r rune) bool { return r == '/' || r == '\\' }) {
		if part == ".." {
			return true
		}
	}
	return false
}

// windowsLocalPath reports whether v is a Windows path to this machine.
//
// Kept separate from the Unix forms because the shapes have nothing in common:
// a drive letter is two characters and a colon, and a UNC share starts with two
// separators. Both are absolute paths on a target this tool ships binaries for.
func windowsLocalPath(v string) bool {
	if strings.HasPrefix(v, `\`) { // \victim and \\host\share
		return true
	}
	if len(v) >= 3 && v[1] == ':' && (v[2] == '\\' || v[2] == '/') {
		c := v[0]
		return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')
	}
	return false
}

// isNonEmptyDir reports whether path is a directory holding at least one entry.
// An empty directory is not a source tree, and treating one as a cache hit is
// how a failed extraction came to be reported as a completed analysis.
func isNonEmptyDir(path string) bool {
	info, err := os.Stat(path)
	if err != nil || !info.IsDir() {
		return false
	}
	entries, err := os.ReadDir(path)
	return err == nil && len(entries) > 0
}

// ambiguousSourceError says a cache entry holds more than one candidate source
// directory, so which of them is the package cannot be established.
//
// It is a distinct type because the answer to it is the opposite of the answer
// to an entry that holds nothing: an entry that cannot be identified must be
// kept and reported, not cleared and fetched again. Clearing it destroyed a
// cache entry that may well have held the findings, and reported the deletion
// as whatever the refetch failed with afterwards.
type ambiguousSourceError struct {
	packageDir string
	candidates []string
}

func (e *ambiguousSourceError) Error() string {
	return fmt.Sprintf("cannot identify the extracted source in %s: %d candidate directories (%s)",
		e.packageDir, len(e.candidates), strings.Join(e.candidates, ", "))
}

// extractedSourceRoot resolves the directory inside packageDir that holds the
// extracted package.
//
// The cache-hit path and the post-extraction path must agree on the answer, or
// the same package is analyzed from one tree on the first run and a different
// one on every run after it. They did not agree: the npm fetcher returned
// packageDir/package after extracting, on the convention that a tarball unpacks
// to package/, and returned packageDir itself on a cache hit after asking only
// whether that directory existed. A version directory holding nothing but the
// downloaded tarball satisfies that question, so a package whose extraction had
// failed was counted as analyzed by source on every subsequent run, with no
// source file read and no warning printed. Both paths now resolve through here,
// and a directory that holds no extracted source is an error rather than a
// silent pass.
func extractedSourceRoot(packageDir string, preferred ...string) (string, error) {
	for _, name := range preferred {
		if candidate := filepath.Join(packageDir, name); isNonEmptyDir(candidate) {
			return candidate, nil
		}
	}

	entries, err := os.ReadDir(packageDir)
	if err != nil {
		return "", fmt.Errorf("no extracted source in %s: %w", packageDir, err)
	}

	var found []string
	for _, e := range entries {
		if !e.IsDir() || strings.HasPrefix(e.Name(), ".") {
			continue
		}
		if isNonEmptyDir(filepath.Join(packageDir, e.Name())) {
			found = append(found, e.Name())
		}
	}

	switch len(found) {
	case 0:
		return "", fmt.Errorf("no extracted source in %s", packageDir)
	case 1:
		return filepath.Join(packageDir, found[0]), nil
	default:
		// Guessing here would analyze a tree that may not be the package, and
		// report the result as if it were. Say so instead.
		return "", &ambiguousSourceError{packageDir: packageDir, candidates: found}
	}
}

// cacheEntryDepth is how many path elements one package's cache entry sits
// below the cache root: ecosystem, name, version.
const cacheEntryDepth = 3

// checkCacheEntry rejects a path that is not exactly one package's cache entry.
//
// This is the only destructive operation in the fetcher whose argument is
// built from manifest-supplied text, so its scope is checked rather than
// assumed. The check is what makes the scope testable: four separate mutations
// of the removal, up to and including RemoveAll of the entire cache root,
// previously left the suite green.
func (f *Fetcher) checkCacheEntry(packageDir string) error {
	root, err := filepath.Abs(f.cacheDir)
	if err != nil {
		return fmt.Errorf("cannot resolve the cache directory %s: %w", f.cacheDir, err)
	}
	entry, err := filepath.Abs(packageDir)
	if err != nil {
		return fmt.Errorf("cannot resolve the cache entry %s: %w", packageDir, err)
	}

	rel, err := filepath.Rel(root, entry)
	if err != nil {
		return fmt.Errorf("refusing to remove %s: it is not inside the cache directory %s", entry, root)
	}
	parts := strings.Split(rel, string(filepath.Separator))
	for _, part := range parts {
		if part == ".." {
			return fmt.Errorf("refusing to remove %s: it resolves outside the cache directory %s",
				entry, root)
		}
	}
	if rel == "." || len(parts) != cacheEntryDepth {
		return fmt.Errorf("refusing to remove %s: a cache entry is %d levels below the cache "+
			"directory %s (ecosystem, name, version), and this is %d",
			entry, cacheEntryDepth, root, len(parts))
	}
	return nil
}

// resetCacheEntry removes a cache entry that does not hold usable source, so
// that the caller can fetch it again instead of analyzing whatever is there.
func (f *Fetcher) resetCacheEntry(packageDir string) error {
	if err := f.checkCacheEntry(packageDir); err != nil {
		return err
	}
	if err := os.RemoveAll(packageDir); err != nil {
		return fmt.Errorf("failed to clear incomplete cache entry %s: %w", packageDir, err)
	}
	return nil
}

// cachedSourceRoot resolves a cache entry and decides what to do when it cannot.
//
// It returns the source root on a hit. On a miss it clears the unusable entry
// and returns an empty root, which tells the caller to fetch. It returns an
// error only when the entry must be left alone: when it is not a private
// directory (see checkPrivateDir), and in the ambiguous case, where the entry
// may hold the package, and deleting a tree because it could not be identified
// is a worse answer than refusing to guess.
//
// The three fetchers previously each discarded this error and fell through to a
// refetch, so the diagnostics written for it were unreachable and the user was
// shown whatever the refetch failed with instead.
func (f *Fetcher) cachedSourceRoot(packageDir string, preferred ...string) (string, error) {
	// The entry is checked before anything in it is read, as every directory
	// above it was by entryDir. Nothing there at all is a miss.
	info, err := os.Lstat(packageDir)
	if errors.Is(err, fs.ErrNotExist) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("cannot inspect the cache entry %s: %w", packageDir, err)
	}
	if err := checkPrivateDir(packageDir, info); err != nil {
		return "", err
	}

	root, err := extractedSourceRoot(packageDir, preferred...)
	if err == nil {
		return root, nil
	}

	var ambiguous *ambiguousSourceError
	if errors.As(err, &ambiguous) {
		return "", err
	}

	return "", f.resetCacheEntry(packageDir)
}

// refusedCacheDirError is checkPrivateDir's refusal of a source cache
// directory. It is a type of its own because the answer to it differs from the
// answer to a cache directory that cannot be created: a directory that is
// there and is not private is reported, never worked around.
type refusedCacheDirError struct {
	path    string
	problem string
}

func (e *refusedCacheDirError) Error() string {
	return fmt.Sprintf("refusing to use %s for the source cache: %s; remove it, and deep "+
		"analysis creates it again as a private directory", e.path, e.problem)
}

// checkPrivateDir refuses a source cache directory that anyone but the user
// running the scan could have put there or can change, given what Lstat
// reported for it. Whoever can write to a cache directory decides what is read
// from it as a package's source, and a link decides where the cache is.
//
// The ownership and mode half is Unix only (see ownerAndModeProblem). Windows
// relies on the per-user location to keep the cache to one user.
func checkPrivateDir(path string, info fs.FileInfo) error {
	var problem string
	switch {
	case info.Mode()&fs.ModeSymlink != 0:
		problem = "it is a symbolic link"
	case info.Mode().Type() != fs.ModeDir:
		problem = "it is not a directory"
	default:
		problem = ownerAndModeProblem(info)
	}
	if problem == "" {
		return nil
	}
	return &refusedCacheDirError{path: path, problem: problem}
}

// ensurePrivateDir checks the source cache directory at path, creating it 0700
// with mkdir first if nothing is there. What is found is checked either way, so
// a directory that appears between the two calls is held to the same terms as
// one that was there before.
func ensurePrivateDir(path string, mkdir func(string, fs.FileMode) error) error {
	info, err := os.Lstat(path)
	if errors.Is(err, fs.ErrNotExist) {
		if err := mkdir(path, 0o700); err != nil && !errors.Is(err, fs.ErrExist) {
			return fmt.Errorf("failed to create the source cache directory %s: %w", path, err)
		}
		info, err = os.Lstat(path)
	}
	if err != nil {
		return fmt.Errorf("cannot inspect the source cache directory %s: %w", path, err)
	}
	return checkPrivateDir(path, info)
}

// cacheRoot returns the cache root once it has been checked, creating it as a
// private directory if it does not exist yet. A per-run root is made here, on
// first use, so a scan that fetches nothing leaves nothing behind.
func (f *Fetcher) cacheRoot() (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	err := f.ensureRootLocked()
	var refused *refusedCacheDirError
	if err != nil && f.perUser && !errors.As(err, &refused) {
		// A per-user cache directory that cannot be created, as under a home
		// directory this account cannot write to, is no per-user cache
		// directory at all, so the run gets one of its own instead.
		f.cacheDir, f.perUser, f.perRun = "", false, true
		err = f.ensureRootLocked()
	}
	if err != nil {
		return "", err
	}
	// Taken once the root is settled and before this fetcher stages anything
	// in it, so that what claimRoot removes cannot be this fetcher's own.
	if !f.claimed {
		f.rootLock, f.claimed = claimRoot(f.cacheDir, f.perRun), true
	}
	return f.cacheDir, nil
}

// ensureRootLocked makes and checks the cache root. The caller holds f.mu.
func (f *Fetcher) ensureRootLocked() error {
	if f.cacheDir == "" && f.perRun {
		dir, err := os.MkdirTemp("", perRunPrefix)
		if err != nil {
			return fmt.Errorf("failed to create a source cache for this run: %w", err)
		}
		f.cacheDir = dir
	}
	return ensurePrivateDir(f.cacheDir, os.MkdirAll)
}

// entryDir returns the cache entry for one version of a package, after
// checking the root and the ecosystem and package directories above it and
// creating any of them that are missing. The entry itself is not created here:
// a fetch downloads into a staging directory and renames it into place.
func (f *Fetcher) entryDir(ecosystem, name, version string) (string, error) {
	dir, err := f.cacheRoot()
	if err != nil {
		return "", err
	}
	for _, part := range []string{ecosystem, cacheSegment(name)} {
		dir = filepath.Join(dir, part)
		if err := ensurePrivateDir(dir, os.Mkdir); err != nil {
			return "", err
		}
	}
	return filepath.Join(dir, cacheSegment(version)), nil
}

// stagingDir creates the directory one fetch downloads and extracts into. It
// is inside the cache root, so renaming it into place never crosses a file
// system, and MkdirTemp makes it 0700 under a name nobody can choose in
// advance. The caller removes it, which after a rename into place is a no-op.
// One whose scan ended before the caller could is removed by a later scan; see
// claimRoot.
func (f *Fetcher) stagingDir() (string, error) {
	root, err := f.cacheRoot()
	if err != nil {
		return "", err
	}
	dir, err := os.MkdirTemp(root, stagingPrefix)
	if err != nil {
		return "", fmt.Errorf("failed to create a staging directory in the source cache %s: %w", root, err)
	}
	return dir, nil
}

// install renames a staging directory into place as the cache entry once the
// extractor has finished with it, and resolves the source root from there. An
// entry therefore appears whole or not at all: a failed extraction stays in the
// staging directory, which its fetch removes, and an interrupted one never
// becomes an entry.
func (f *Fetcher) install(staging, packageDir string, preferred ...string) (string, error) {
	if err := os.Rename(staging, packageDir); err != nil {
		// Another scan can install the same entry first. That is not a failure
		// to fetch it, as long as what it installed resolves.
		if root, hitErr := f.cachedSourceRoot(packageDir, preferred...); hitErr == nil && root != "" {
			return root, nil
		}
		return "", fmt.Errorf("failed to move the fetched source into the cache entry %s: %w", packageDir, err)
	}
	return extractedSourceRoot(packageDir, preferred...)
}

// defaultCacheDir returns the source cache in the per-user cache directory:
// ~/Library/Caches/cryptodeps on macOS, $XDG_CACHE_HOME/cryptodeps or
// ~/.cache/cryptodeps on other Unix systems, and %LocalAppData%\cryptodeps on
// Windows.
//
// It used to be one fixed directory in the system temporary directory, which
// on most Unix systems every user of the machine shares and can write to. A
// relative answer is not used either: it would resolve against the working
// directory, which during a scan is usually the project being scanned.
func defaultCacheDir() (string, error) {
	dir, err := os.UserCacheDir()
	if err != nil {
		return "", err
	}
	if !filepath.IsAbs(dir) {
		return "", fmt.Errorf("the user cache directory %q is not an absolute path", dir)
	}
	return filepath.Join(dir, cacheDirName), nil
}

// NewFetcher creates a source fetcher that keeps its cache in cacheDir.
//
// An empty cacheDir means the per-user cache directory (see defaultCacheDir).
// Where there is none, or it cannot be created, the fetcher makes a directory
// of its own in the temporary directory on first use, and Close removes it.
func NewFetcher(cacheDir string) *Fetcher {
	if cacheDir != "" {
		return &Fetcher{cacheDir: cacheDir}
	}
	dir, err := defaultCacheDir()
	if err != nil {
		return &Fetcher{perRun: true}
	}
	return &Fetcher{cacheDir: dir, perUser: true}
}

// Close removes the cache when it is a directory of this run's own, made
// because there was no per-user cache directory. A per-user cache, or one the
// caller named, is a cache and is kept for the next scan. Either way the lock
// on the cache root is let go, after a cache of the run's own is removed, so
// that another scan does not find that cache unlocked while it is removed.
func (f *Fetcher) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	defer f.releaseRootLocked()

	if !f.perRun || f.cacheDir == "" {
		return nil
	}
	dir := f.cacheDir
	f.cacheDir = ""
	if err := os.RemoveAll(dir); err != nil {
		return fmt.Errorf("failed to remove this run's source cache %s: %w", dir, err)
	}
	return nil
}

// Fetch downloads the source code for a package and returns the local path.
func (f *Fetcher) Fetch(dep types.Dependency) (string, error) {
	// Both fields come from the manifest under scan, and both reach a package
	// manager as part of a spec.
	//
	// The name is held to its registry's grammar rather than screened for path
	// spellings, because the package manager parses the string this code treats
	// as opaque: `npm pack x@/tmp/victim` is one argument to this function and a
	// name plus a directory to npm. The version is screened, because its legal
	// forms genuinely include remote references that have no grammar in common.
	if err := validPackageName(dep.Ecosystem, dep.Name); err != nil {
		return "", err
	}
	if localPathReference(dep.Version) {
		return "", fmt.Errorf(pathTraversalMsg, "version", dep.Version)
	}
	if localPathReference(dep.Name) {
		return "", fmt.Errorf(pathTraversalMsg, "name", dep.Name)
	}

	switch dep.Ecosystem {
	case types.EcosystemGo:
		return f.fetchGoModule(dep)
	case types.EcosystemNPM:
		return f.fetchNpmPackage(dep)
	case types.EcosystemPyPI:
		return f.fetchPyPIPackage(dep)
	case types.EcosystemMaven:
		return f.fetchMavenArtifact(dep)
	default:
		return "", fmt.Errorf("unsupported ecosystem: %s", dep.Ecosystem)
	}
}

// fetchGoModule downloads a Go module using go mod download.
func (f *Fetcher) fetchGoModule(dep types.Dependency) (string, error) {
	// Use go mod download to get the module
	moduleSpec := dep.Name
	if dep.Version != "" {
		moduleSpec = dep.Name + "@" + dep.Version
	}

	// Get the module cache path (Go handles caching internally)
	cmd, err := netguard.Command("go", "mod", "download", "-json", moduleSpec)
	if err != nil {
		return "", err
	}
	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("go mod download failed: %w", err)
	}

	// Parse the JSON output to get the module directory
	// The output includes "Dir" field with the cached module path
	modDir := extractGoModDir(output)
	if modDir == "" {
		return "", fmt.Errorf("could not determine module directory")
	}
	// An empty or missing module directory would be walked, yield nothing, and
	// be reported as a package examined by source analysis.
	if !isNonEmptyDir(modDir) {
		return "", fmt.Errorf("module directory %s holds no source", modDir)
	}

	return modDir, nil
}

// extractGoModDir extracts the Dir field from go mod download JSON output.
func extractGoModDir(output []byte) string {
	// Simple parsing - look for "Dir": "..."
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, `"Dir":`) {
			// Extract the path
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				path := strings.TrimSpace(parts[1])
				path = strings.Trim(path, `",`)
				return path
			}
		}
	}
	return ""
}

// fetchNpmPackage downloads an npm package.
func (f *Fetcher) fetchNpmPackage(dep types.Dependency) (string, error) {
	// The cache entry for this package, once every directory above it has
	// been checked.
	packageDir, err := f.entryDir("npm", dep.Name, dep.Version)
	if err != nil {
		return "", err
	}

	// Check if already cached. A cache entry counts as a hit only if it holds
	// extracted source; see extractedSourceRoot. An empty root with no error
	// means the entry was unusable and has been cleared, so fetch it again.
	if root, err := f.cachedSourceRoot(packageDir, npmExtractedDir); err != nil || root != "" {
		return root, err
	}

	// Download and extract in a directory of this fetch's own, which becomes
	// the cache entry only once extraction has finished. Whatever a failed
	// fetch leaves there is removed with it.
	staging, err := f.stagingDir()
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(staging)

	// Use npm pack to download the package
	packageSpec := dep.Name
	if dep.Version != "" {
		packageSpec = dep.Name + "@" + dep.Version
	}

	// Change to cache directory and run npm pack
	// --ignore-scripts is the control, not an optimisation. npm runs a package's
	// prepare and prepack scripts for any spec it resolves from a directory or
	// a git repository, so fetching source for analysis was a way to execute
	// code chosen by the manifest under scan. The guards above stop such a spec
	// being built at all; this stops the remaining ones, including the
	// deliberately allowed remote git references, from running anything.
	// The "--" is not decoration. The name grammar admits the names npm's own
	// registry carries, and some of those begin with a hyphen: "-" is a real
	// package with 153,000 downloads a month, and "@-xun/debug" has 153,076. A
	// spec beginning with a hyphen is read by npm as a FLAG, so a dependency
	// named "--help" made npm print its help text instead of fetching anything,
	// and untrusted input parsed as a flag is the argument-injection half of the
	// same class as untrusted input parsed as a path. The separator ends flag
	// parsing, and ordinary and scoped specs are unaffected by it.
	cmd, err := netguard.Command("npm", "pack", "--ignore-scripts", "--", packageSpec)
	if err != nil {
		return "", fmt.Errorf("npm pack not run: %w", err)
	}
	cmd.Dir = staging
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("npm pack failed: %w", err)
	}

	// Find the tarball and extract it
	entries, err := os.ReadDir(staging)
	if err != nil {
		return "", err
	}

	for _, entry := range entries {
		if strings.HasSuffix(entry.Name(), ".tgz") {
			tarball := filepath.Join(staging, entry.Name())
			// Extract the tarball
			extractCmd := exec.Command("tar", "-xzf", tarball, "-C", staging)
			if err := extractCmd.Run(); err != nil {
				return "", fmt.Errorf("failed to extract tarball: %w", err)
			}
			// npm tarballs conventionally unpack to package/, but not all of
			// them do: ejs 3.1.10 unpacks to ejs-v3.1.10/. Returning the
			// convention unconditionally made the caller's lstat fail on those,
			// which is how the same package came to be analyzed from a
			// different root on the first run than on later ones.
			return f.install(staging, packageDir, npmExtractedDir)
		}
	}

	return "", fmt.Errorf("could not find npm package tarball")
}

// fetchPyPIPackage downloads a Python package from PyPI.
func (f *Fetcher) fetchPyPIPackage(dep types.Dependency) (string, error) {
	// The cache entry for this package, once every directory above it has
	// been checked.
	packageDir, err := f.entryDir("pypi", dep.Name, dep.Version)
	if err != nil {
		return "", err
	}

	// Check if already cached. Same shape as the npm fetcher: the directory
	// existing is not the same question as it holding extracted source.
	if root, err := f.cachedSourceRoot(packageDir, zipExtractedDir); err != nil || root != "" {
		return root, err
	}

	// Download and extract in a directory of this fetch's own, as the npm
	// fetcher does.
	staging, err := f.stagingDir()
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(staging)

	// Use pip download to get the package
	packageSpec := dep.Name
	if dep.Version != "" {
		packageSpec = dep.Name + "==" + dep.Version
	}

	// --only-binary=:all: is the pip half of the control that --ignore-scripts is
	// for npm, and it is here for the same reason.
	//
	// Resolving a source distribution makes pip install the project's build
	// dependencies and run its build backend, which for a setup.py sdist is
	// arbitrary code from a package named by the manifest under scan. Fetching
	// source in order to analyze it must not be a way to execute it: the operator
	// asked this tool to read a dependency, not to build it. Restricting the
	// fetch to built wheels closes that, at the cost of the packages that publish
	// no wheel, which are now reported as not examined with the reason named
	// rather than analyzed by running them.
	cmd, err := netguard.Command("pip", "download", "--no-deps", "--only-binary", ":all:",
		"-d", staging, packageSpec)
	if err != nil {
		return "", fmt.Errorf("pip download not run: %w", err)
	}
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("pip download failed (source distributions are not built, so a "+
			"package that publishes no wheel is reported as not examined): %w", err)
	}

	// Find and extract the wheel or tarball
	entries, err := os.ReadDir(staging)
	if err != nil {
		return "", err
	}

	for _, entry := range entries {
		name := entry.Name()
		if strings.HasSuffix(name, ".whl") {
			// Wheels are just zip files
			wheelPath := filepath.Join(staging, name)
			extractDir := filepath.Join(staging, zipExtractedDir)
			if err := os.MkdirAll(extractDir, 0755); err != nil {
				return "", err
			}
			cmd := exec.Command("unzip", "-q", wheelPath, "-d", extractDir)
			if err := cmd.Run(); err != nil {
				return "", fmt.Errorf("failed to extract wheel: %w", err)
			}
			return f.install(staging, packageDir, zipExtractedDir)
		} else if strings.HasSuffix(name, ".tar.gz") {
			tarball := filepath.Join(staging, name)
			cmd := exec.Command("tar", "-xzf", tarball, "-C", staging)
			if err := cmd.Run(); err != nil {
				return "", fmt.Errorf("failed to extract tarball: %w", err)
			}
			// Resolve the same way the cache-hit path does, so run 1 and run 2
			// analyze the same tree.
			return f.install(staging, packageDir, zipExtractedDir)
		}
	}

	return "", fmt.Errorf("could not find Python package archive")
}

// fetchMavenArtifact downloads a Maven artifact sources from Maven Central.
func (f *Fetcher) fetchMavenArtifact(dep types.Dependency) (string, error) {
	// Parse groupId:artifactId from dep.Name
	parts := strings.Split(dep.Name, ":")
	if len(parts) != 2 {
		return "", fmt.Errorf("invalid Maven coordinate: %s (expected groupId:artifactId)", dep.Name)
	}
	groupID := parts[0]
	artifactID := parts[1]
	if err := validMavenCoordinate(groupID, artifactID); err != nil {
		return "", err
	}

	// The cache entry for this artifact, once every directory above it has
	// been checked.
	packageDir, err := f.entryDir("maven", dep.Name, dep.Version)
	if err != nil {
		return "", err
	}

	// Check if already cached. An extraction that failed after the directory
	// was created leaves it empty, which the old existence check accepted.
	if root, err := f.cachedSourceRoot(packageDir, zipExtractedDir); err != nil || root != "" {
		return root, err
	}

	// Download and extract in a directory of this fetch's own, as the npm
	// fetcher does.
	staging, err := f.stagingDir()
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(staging)
	extractDir := filepath.Join(staging, zipExtractedDir)

	// Build Maven Central URL for sources JAR
	// https://repo1.maven.org/maven2/{groupId path}/{artifactId}/{version}/{artifactId}-{version}-sources.jar
	groupPath := strings.ReplaceAll(groupID, ".", "/")
	sourcesURL := fmt.Sprintf("https://repo1.maven.org/maven2/%s/%s/%s/%s-%s-sources.jar",
		groupPath, artifactID, dep.Version, artifactID, dep.Version)

	// Download the sources JAR. The coordinate is validated above, so this
	// cannot traverse today; it goes through cacheSegment anyway so that the
	// write target stays inside the cache even if the validation is ever
	// loosened. The file the process writes should not depend on a second
	// function staying strict.
	jarBase := cacheSegment(artifactID) + "-" + cacheSegment(dep.Version)
	jarPath := filepath.Join(staging, jarBase+"-sources.jar")

	// Use curl to download (available on most systems)
	cmd, err := netguard.Command("curl", "-sL", "-o", jarPath, "-f", sourcesURL)
	if err != nil {
		return "", fmt.Errorf("Maven artifact not downloaded: %w", err)
	}
	if err := cmd.Run(); err != nil {
		// Try without -sources suffix (main jar) as fallback
		mainURL := fmt.Sprintf("https://repo1.maven.org/maven2/%s/%s/%s/%s-%s.jar",
			groupPath, artifactID, dep.Version, artifactID, dep.Version)
		jarPath = filepath.Join(staging, jarBase+".jar")
		cmd, err = netguard.Command("curl", "-sL", "-o", jarPath, "-f", mainURL)
		if err != nil {
			return "", fmt.Errorf("Maven artifact not downloaded: %w", err)
		}
		if err := cmd.Run(); err != nil {
			return "", fmt.Errorf("failed to download Maven artifact (tried sources and main JAR): %w", err)
		}
	}

	// Extract the JAR (it's a zip file)
	if err := os.MkdirAll(extractDir, 0755); err != nil {
		return "", err
	}
	extractCmd := exec.Command("unzip", "-q", jarPath, "-d", extractDir)
	if err := extractCmd.Run(); err != nil {
		return "", fmt.Errorf("failed to extract JAR: %w", err)
	}

	return f.install(staging, packageDir, zipExtractedDir)
}

// CacheDir returns the cache directory path. For a cache of the run's own it
// is empty until the first fetch creates one, and again after Close.
func (f *Fetcher) CacheDir() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.cacheDir
}

// CleanCache removes all cached packages.
func (f *Fetcher) CleanCache() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	// The lock is on the directory removed here, so the next fetch takes one
	// on the directory made in its place.
	defer f.releaseRootLocked()
	return os.RemoveAll(f.cacheDir)
}

// releaseRootLocked lets go of the lock on the cache root, so that the next
// fetch takes it again. The caller holds f.mu.
func (f *Fetcher) releaseRootLocked() {
	if f.rootLock != nil {
		f.rootLock.Close()
		f.rootLock = nil
	}
	f.claimed = false
}
