// Copyright 2025-2026 CyberSecurity NonProfit (CSNP)
// SPDX-License-Identifier: Apache-2.0

// Package source provides functionality for fetching package source code.
package source

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/csnp/qramm-cryptodeps/pkg/types"
)

// Fetcher downloads package source code for analysis.
type Fetcher struct {
	cacheDir string
}

// Directory names that a fetched archive is expected to unpack to, when the
// ecosystem has a convention. Anything else is resolved by inspection.
const (
	npmExtractedDir  = "package"   // npm tarballs conventionally unpack to package/
	zipExtractedDir  = "extracted" // where this fetcher unzips wheels and JARs
	maxCacheSegment  = 96          // long enough for any real name or version
	pathTraversalMsg = "version %q refers to a local path, which is not fetched: " +
		"deep analysis reads package archives, not directories on this machine"
)

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
	// "" collapses the path by one level, and "." and ".." are directory
	// references rather than names.
	if strings.Trim(out, ".") == "" {
		return "_"
	}
	return out
}

// localPathVersion reports whether a version string points at a directory on
// this machine rather than at a published release.
//
// npm and pip both accept such a reference as a package spec, so passing one
// through to `npm pack` or `pip download` would fetch and analyze a local
// directory of the manifest author's choosing. Registry and VCS references
// (github:owner/repo, git+https://...) are left alone: those are remote, and
// deep analysis of them works.
func localPathVersion(v string) bool {
	v = strings.TrimSpace(v)
	if v == "" {
		return false
	}
	if strings.HasPrefix(strings.ToLower(v), "file:") {
		return true
	}
	if strings.HasPrefix(v, "/") || strings.HasPrefix(v, "~") || strings.HasPrefix(v, ".") {
		return true
	}
	// A bare relative path such as src/../../etc, as distinct from a registry
	// reference such as github:owner/repo.
	if !strings.Contains(v, ":") {
		for _, part := range strings.FieldsFunc(v, func(r rune) bool { return r == '/' || r == '\\' }) {
			if part == ".." {
				return true
			}
		}
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
		return "", fmt.Errorf("cannot identify the extracted source in %s: %d candidate directories (%s)",
			packageDir, len(found), strings.Join(found, ", "))
	}
}

// resetCacheEntry removes a cache entry that does not hold usable source, so
// that the caller can fetch it again instead of analyzing whatever is there.
func resetCacheEntry(packageDir string) error {
	if err := os.RemoveAll(packageDir); err != nil {
		return fmt.Errorf("failed to clear incomplete cache entry %s: %w", packageDir, err)
	}
	return nil
}

// NewFetcher creates a new source fetcher with the given cache directory.
func NewFetcher(cacheDir string) *Fetcher {
	if cacheDir == "" {
		cacheDir = filepath.Join(os.TempDir(), "cryptodeps-cache")
	}
	return &Fetcher{cacheDir: cacheDir}
}

// Fetch downloads the source code for a package and returns the local path.
func (f *Fetcher) Fetch(dep types.Dependency) (string, error) {
	if localPathVersion(dep.Version) {
		return "", fmt.Errorf(pathTraversalMsg, dep.Version)
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
	cmd := exec.Command("go", "mod", "download", "-json", moduleSpec)
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
	// Create cache directory for this package
	packageDir := filepath.Join(f.cacheDir, "npm", cacheSegment(dep.Name), cacheSegment(dep.Version))

	// Check if already cached. A cache entry counts as a hit only if it holds
	// extracted source; see extractedSourceRoot.
	if root, err := extractedSourceRoot(packageDir, npmExtractedDir); err == nil {
		return root, nil
	}
	if err := resetCacheEntry(packageDir); err != nil {
		return "", err
	}

	// Ensure cache directory exists
	if err := os.MkdirAll(packageDir, 0755); err != nil {
		return "", fmt.Errorf("failed to create cache dir: %w", err)
	}

	// Use npm pack to download the package
	packageSpec := dep.Name
	if dep.Version != "" {
		packageSpec = dep.Name + "@" + dep.Version
	}

	// Change to cache directory and run npm pack
	cmd := exec.Command("npm", "pack", packageSpec)
	cmd.Dir = packageDir
	if err := cmd.Run(); err != nil {
		os.RemoveAll(packageDir)
		return "", fmt.Errorf("npm pack failed: %w", err)
	}

	// Find the tarball and extract it
	entries, err := os.ReadDir(packageDir)
	if err != nil {
		return "", err
	}

	for _, entry := range entries {
		if strings.HasSuffix(entry.Name(), ".tgz") {
			tarball := filepath.Join(packageDir, entry.Name())
			// Extract the tarball
			extractCmd := exec.Command("tar", "-xzf", tarball, "-C", packageDir)
			if err := extractCmd.Run(); err != nil {
				return "", fmt.Errorf("failed to extract tarball: %w", err)
			}
			// npm tarballs conventionally unpack to package/, but not all of
			// them do: ejs 3.1.10 unpacks to ejs-v3.1.10/. Returning the
			// convention unconditionally made the caller's lstat fail on those,
			// which is how the same package came to be analyzed from a
			// different root on the first run than on later ones.
			return extractedSourceRoot(packageDir, npmExtractedDir)
		}
	}

	return "", fmt.Errorf("could not find npm package tarball")
}

// fetchPyPIPackage downloads a Python package from PyPI.
func (f *Fetcher) fetchPyPIPackage(dep types.Dependency) (string, error) {
	// Create cache directory for this package
	packageDir := filepath.Join(f.cacheDir, "pypi", cacheSegment(dep.Name), cacheSegment(dep.Version))

	// Check if already cached. Same shape as the npm fetcher: the directory
	// existing is not the same question as it holding extracted source.
	if root, err := extractedSourceRoot(packageDir, zipExtractedDir); err == nil {
		return root, nil
	}
	if err := resetCacheEntry(packageDir); err != nil {
		return "", err
	}

	// Ensure cache directory exists
	if err := os.MkdirAll(packageDir, 0755); err != nil {
		return "", fmt.Errorf("failed to create cache dir: %w", err)
	}

	// Use pip download to get the package
	packageSpec := dep.Name
	if dep.Version != "" {
		packageSpec = dep.Name + "==" + dep.Version
	}

	cmd := exec.Command("pip", "download", "--no-deps", "-d", packageDir, packageSpec)
	if err := cmd.Run(); err != nil {
		os.RemoveAll(packageDir)
		return "", fmt.Errorf("pip download failed: %w", err)
	}

	// Find and extract the wheel or tarball
	entries, err := os.ReadDir(packageDir)
	if err != nil {
		return "", err
	}

	for _, entry := range entries {
		name := entry.Name()
		if strings.HasSuffix(name, ".whl") {
			// Wheels are just zip files
			wheelPath := filepath.Join(packageDir, name)
			extractDir := filepath.Join(packageDir, zipExtractedDir)
			if err := os.MkdirAll(extractDir, 0755); err != nil {
				return "", err
			}
			cmd := exec.Command("unzip", "-q", wheelPath, "-d", extractDir)
			if err := cmd.Run(); err != nil {
				return "", fmt.Errorf("failed to extract wheel: %w", err)
			}
			return extractedSourceRoot(packageDir, zipExtractedDir)
		} else if strings.HasSuffix(name, ".tar.gz") {
			tarball := filepath.Join(packageDir, name)
			cmd := exec.Command("tar", "-xzf", tarball, "-C", packageDir)
			if err := cmd.Run(); err != nil {
				return "", fmt.Errorf("failed to extract tarball: %w", err)
			}
			// Resolve the same way the cache-hit path does, so run 1 and run 2
			// analyze the same tree.
			return extractedSourceRoot(packageDir, zipExtractedDir)
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

	// Create cache directory for this artifact
	packageDir := filepath.Join(f.cacheDir, "maven", cacheSegment(dep.Name), cacheSegment(dep.Version))

	// Check if already cached. An extraction that failed after the directory
	// was created leaves it empty, which the old existence check accepted.
	extractDir := filepath.Join(packageDir, zipExtractedDir)
	if root, err := extractedSourceRoot(packageDir, zipExtractedDir); err == nil {
		return root, nil
	}
	if err := resetCacheEntry(packageDir); err != nil {
		return "", err
	}

	// Ensure cache directory exists
	if err := os.MkdirAll(packageDir, 0755); err != nil {
		return "", fmt.Errorf("failed to create cache dir: %w", err)
	}

	// Build Maven Central URL for sources JAR
	// https://repo1.maven.org/maven2/{groupId path}/{artifactId}/{version}/{artifactId}-{version}-sources.jar
	groupPath := strings.ReplaceAll(groupID, ".", "/")
	sourcesURL := fmt.Sprintf("https://repo1.maven.org/maven2/%s/%s/%s/%s-%s-sources.jar",
		groupPath, artifactID, dep.Version, artifactID, dep.Version)

	// Download the sources JAR
	jarPath := filepath.Join(packageDir, artifactID+"-"+dep.Version+"-sources.jar")

	// Use curl to download (available on most systems)
	cmd := exec.Command("curl", "-sL", "-o", jarPath, "-f", sourcesURL)
	if err := cmd.Run(); err != nil {
		// Try without -sources suffix (main jar) as fallback
		mainURL := fmt.Sprintf("https://repo1.maven.org/maven2/%s/%s/%s/%s-%s.jar",
			groupPath, artifactID, dep.Version, artifactID, dep.Version)
		jarPath = filepath.Join(packageDir, artifactID+"-"+dep.Version+".jar")
		cmd = exec.Command("curl", "-sL", "-o", jarPath, "-f", mainURL)
		if err := cmd.Run(); err != nil {
			os.RemoveAll(packageDir)
			return "", fmt.Errorf("failed to download Maven artifact: %w (tried sources and main JAR)", err)
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

	return extractedSourceRoot(packageDir, zipExtractedDir)
}

// CacheDir returns the cache directory path.
func (f *Fetcher) CacheDir() string {
	return f.cacheDir
}

// CleanCache removes all cached packages.
func (f *Fetcher) CleanCache() error {
	return os.RemoveAll(f.cacheDir)
}
