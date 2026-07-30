// Copyright 2025-2026 CyberSecurity NonProfit (CSNP)
// SPDX-License-Identifier: Apache-2.0

package source

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/csnp/qramm-cryptodeps/pkg/types"
)

func TestNewFetcher(t *testing.T) {
	// With empty cache dir
	f := NewFetcher("")
	if f == nil {
		t.Fatal("NewFetcher returned nil")
	}
	if f.cacheDir == "" {
		t.Error("cacheDir should have default value")
	}

	// With custom cache dir
	f = NewFetcher("/custom/cache")
	if f.cacheDir != "/custom/cache" {
		t.Errorf("cacheDir = %q, want /custom/cache", f.cacheDir)
	}
}

func TestFetcherCacheDir(t *testing.T) {
	f := NewFetcher("/test/cache")
	if f.CacheDir() != "/test/cache" {
		t.Errorf("CacheDir() = %q, want /test/cache", f.CacheDir())
	}
}

func TestFetcherCleanCache(t *testing.T) {
	tmpDir, _ := os.MkdirTemp("", "fetcher-test")
	defer os.RemoveAll(tmpDir)

	cacheDir := filepath.Join(tmpDir, "cache")
	os.MkdirAll(cacheDir, 0755)
	os.WriteFile(filepath.Join(cacheDir, "test.txt"), []byte("test"), 0644)

	f := NewFetcher(cacheDir)
	err := f.CleanCache()
	if err != nil {
		t.Errorf("CleanCache error: %v", err)
	}

	if _, err := os.Stat(cacheDir); !os.IsNotExist(err) {
		t.Error("Cache directory should be removed")
	}
}

func TestFetchUnsupportedEcosystem(t *testing.T) {
	f := NewFetcher("")
	_, err := f.Fetch(types.Dependency{
		Name:      "test",
		Ecosystem: "unsupported",
	})
	if err == nil {
		t.Error("Expected error for unsupported ecosystem")
	}
}

func TestExtractGoModDir(t *testing.T) {
	tests := []struct {
		name   string
		output string
		want   string
	}{
		{
			name: "valid output",
			output: `{
	"Path": "test",
	"Dir": "/path/to/module",
	"Version": "v1.0.0"
}`,
			want: "/path/to/module",
		},
		{
			name: "multiline indented",
			output: `{
	"Path": "github.com/test/pkg",
	"Dir": "/Users/test/go/pkg/mod/github.com/test/pkg@v1.0.0",
	"Version": "v1.0.0"
}`,
			want: "/Users/test/go/pkg/mod/github.com/test/pkg@v1.0.0",
		},
		{
			name: "no dir",
			output: `{
	"Path": "test",
	"Version": "v1.0.0"
}`,
			want: "",
		},
		{
			name:   "empty",
			output: "",
			want:   "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractGoModDir([]byte(tt.output))
			if got != tt.want {
				t.Errorf("extractGoModDir() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestFetcherInterfaceMethods(t *testing.T) {
	f := NewFetcher("")

	// Test that Fetch method exists and returns error for missing dependencies
	// (We don't actually fetch in tests to avoid network calls)

	// Go module - will fail but shouldn't panic
	_, err := f.Fetch(types.Dependency{
		Name:      "nonexistent.example.com/missing/pkg",
		Version:   "v999.999.999",
		Ecosystem: types.EcosystemGo,
	})
	// This will fail because the module doesn't exist, which is expected
	if err == nil {
		t.Log("Note: go mod download succeeded unexpectedly (might be cached)")
	}
}

func TestFetchMavenInvalidCoordinate(t *testing.T) {
	f := NewFetcher("")
	_, err := f.Fetch(types.Dependency{
		Name:      "invalid-no-colon",
		Version:   "1.0.0",
		Ecosystem: types.EcosystemMaven,
	})
	if err == nil {
		t.Error("Expected error for invalid Maven coordinate")
	}
}

// writeCacheEntry lays out a cache entry the way the fetcher itself writes one:
// the downloaded archive beside the directory it was extracted into.
func writeCacheEntry(t *testing.T, packageDir, archive, extractedDir, sourceFile string) string {
	t.Helper()
	if err := os.MkdirAll(packageDir, 0755); err != nil {
		t.Fatalf("create cache entry: %v", err)
	}
	if archive != "" {
		if err := os.WriteFile(filepath.Join(packageDir, archive), []byte("archive"), 0644); err != nil {
			t.Fatalf("write archive: %v", err)
		}
	}
	if extractedDir == "" {
		return packageDir
	}
	root := filepath.Join(packageDir, extractedDir)
	if err := os.MkdirAll(root, 0755); err != nil {
		t.Fatalf("create extracted dir: %v", err)
	}
	if sourceFile != "" {
		if err := os.WriteFile(filepath.Join(root, sourceFile), []byte("source"), 0644); err != nil {
			t.Fatalf("write source file: %v", err)
		}
	}
	return root
}

func TestFetchNpmCached(t *testing.T) {
	// Create a temp cache directory with pre-cached npm package
	tmpDir, _ := os.MkdirTemp("", "fetcher-npm-test")
	defer os.RemoveAll(tmpDir)

	// Pre-create the cache entry the way the fetcher writes one. The fixture
	// used to put index.js straight into the version directory, which is a
	// layout the fetcher never produces, and asserting that it was a cache hit
	// was asserting the defect: the same shape is what a failed extraction
	// leaves behind.
	packageDir := filepath.Join(tmpDir, "npm", "test-package", "1.0.0")
	cachedDir := writeCacheEntry(t, packageDir, "test-package-1.0.0.tgz", npmExtractedDir, "index.js")

	f := NewFetcher(tmpDir)
	dir, err := f.Fetch(types.Dependency{
		Name:      "test-package",
		Version:   "1.0.0",
		Ecosystem: types.EcosystemNPM,
	})

	if err != nil {
		t.Fatalf("Fetch cached npm package failed: %v", err)
	}
	if dir != cachedDir {
		t.Errorf("Expected cached dir %s, got %s", cachedDir, dir)
	}
}

func TestFetchPyPICached(t *testing.T) {
	// Create a temp cache directory with pre-cached PyPI package
	tmpDir, _ := os.MkdirTemp("", "fetcher-pypi-test")
	defer os.RemoveAll(tmpDir)

	packageDir := filepath.Join(tmpDir, "pypi", "test-package", "1.0.0")
	cachedDir := writeCacheEntry(t, packageDir, "test_package-1.0.0-py3-none-any.whl",
		zipExtractedDir, "__init__.py")

	f := NewFetcher(tmpDir)
	dir, err := f.Fetch(types.Dependency{
		Name:      "test-package",
		Version:   "1.0.0",
		Ecosystem: types.EcosystemPyPI,
	})

	if err != nil {
		t.Fatalf("Fetch cached pypi package failed: %v", err)
	}
	if dir != cachedDir {
		t.Errorf("Expected cached dir %s, got %s", cachedDir, dir)
	}
}

func TestFetchMavenCached(t *testing.T) {
	// Create a temp cache directory with pre-cached Maven artifact
	tmpDir, _ := os.MkdirTemp("", "fetcher-maven-test")
	defer os.RemoveAll(tmpDir)

	// Pre-create the cache directory to simulate a cached package
	// Maven looks for an "extracted" subdirectory
	cachedDir := filepath.Join(tmpDir, "maven", "com.example_artifact", "1.0.0", "extracted")
	os.MkdirAll(cachedDir, 0755)
	os.WriteFile(filepath.Join(cachedDir, "Example.java"), []byte("class Example {}"), 0644)

	f := NewFetcher(tmpDir)
	dir, err := f.Fetch(types.Dependency{
		Name:      "com.example:artifact",
		Version:   "1.0.0",
		Ecosystem: types.EcosystemMaven,
	})

	if err != nil {
		t.Fatalf("Fetch cached maven artifact failed: %v", err)
	}
	if dir != cachedDir {
		t.Errorf("Expected cached dir %s, got %s", cachedDir, dir)
	}
}

func TestFetchGoCached(t *testing.T) {
	// For Go, the caching is handled by go mod, so we test that it calls
	// the go mod download correctly. We can't easily mock this without
	// network access, so just test that it doesn't panic.
	tmpDir, _ := os.MkdirTemp("", "fetcher-go-test")
	defer os.RemoveAll(tmpDir)

	f := NewFetcher(tmpDir)
	// This will fail because the module doesn't exist, but we're testing
	// that the path through the code works correctly
	_, err := f.Fetch(types.Dependency{
		Name:      "example.invalid/pkg",
		Version:   "v1.0.0",
		Ecosystem: types.EcosystemGo,
	})

	// Expected to fail since module doesn't exist
	if err == nil {
		t.Log("Note: go mod download unexpectedly succeeded")
	}
}

func TestFetchNpmWithSlash(t *testing.T) {
	// Test scoped packages like @org/package
	tmpDir, _ := os.MkdirTemp("", "fetcher-npm-slash-test")
	defer os.RemoveAll(tmpDir)

	// Every character outside [A-Za-z0-9._-] becomes an underscore now, so the
	// leading @ of a scope does too. Cache keys are internal and disposable;
	// what matters is that a manifest cannot steer the path.
	packageDir := filepath.Join(tmpDir, "npm", "_org_package", "1.0.0")
	cachedDir := writeCacheEntry(t, packageDir, "org-package-1.0.0.tgz", npmExtractedDir, "index.js")

	f := NewFetcher(tmpDir)
	dir, err := f.Fetch(types.Dependency{
		Name:      "@org/package",
		Version:   "1.0.0",
		Ecosystem: types.EcosystemNPM,
	})

	if err != nil {
		t.Fatalf("Fetch cached scoped npm package failed: %v", err)
	}
	if dir != cachedDir {
		t.Errorf("Expected cached dir %s, got %s", cachedDir, dir)
	}
}

func TestCleanCacheNonexistent(t *testing.T) {
	// Test cleaning a cache that doesn't exist - should not error
	f := NewFetcher("/nonexistent/path/that/does/not/exist")
	err := f.CleanCache()
	if err != nil {
		t.Errorf("CleanCache on nonexistent dir should not error: %v", err)
	}
}

func TestExtractGoModDir_EdgeCases(t *testing.T) {
	tests := []struct {
		name   string
		output string
		want   string
	}{
		{
			name: "dir with spaces",
			output: `{
	"Path": "test",
	"Dir": "/path/to/my module",
	"Version": "v1.0.0"
}`,
			want: "/path/to/my module",
		},
		{
			name: "dir with special chars",
			output: `{
	"Path": "test",
	"Dir": "/path/to/module@v1.2.3",
	"Version": "v1.2.3"
}`,
			want: "/path/to/module@v1.2.3",
		},
		{
			name:   "only whitespace",
			output: "   \n\t   ",
			want:   "",
		},
		{
			name: "malformed json",
			output: `{
	"Dir": "/path/to/module",`,
			want: "/path/to/module",
		},
		{
			name: "dir with trailing comma",
			output: `{
	"Dir": "/path/to/module",
	"Path": "test"
}`,
			want: "/path/to/module",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractGoModDir([]byte(tt.output))
			if got != tt.want {
				t.Errorf("extractGoModDir() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestFetchNpmWithoutVersion(t *testing.T) {
	// Test npm fetch without version (should still cache correctly)
	tmpDir, _ := os.MkdirTemp("", "fetcher-npm-noversion-test")
	defer os.RemoveAll(tmpDir)

	// An unpinned dependency gets its own segment rather than none. Joining an
	// empty segment collapsed the path by one level, so an unversioned package
	// and the package's version directories shared a parent.
	packageDir := filepath.Join(tmpDir, "npm", "test-package", "_")
	cachedDir := writeCacheEntry(t, packageDir, "test-package-1.0.0.tgz", npmExtractedDir, "index.js")

	f := NewFetcher(tmpDir)
	dir, err := f.Fetch(types.Dependency{
		Name:      "test-package",
		Version:   "", // No version
		Ecosystem: types.EcosystemNPM,
	})

	if err != nil {
		t.Fatalf("Fetch cached npm package without version failed: %v", err)
	}
	if dir != cachedDir {
		t.Errorf("Expected cached dir %s, got %s", cachedDir, dir)
	}
}

// TestFetchPyPIWithSlash previously asserted that a PyPI name containing
// slashes was sanitized into a cache path and fetched.
//
// It is now asserted to be refused. PyPI names cannot contain a slash, so such
// a string is not a name that failed to resolve, it is a path or a spec wearing
// a name's place in the manifest, and sanitizing it for the cache never made it
// safe to hand to pip. The old expectation restated what cacheSegment did
// rather than a judgement about what should be fetched.
func TestFetchPyPIWithSlash(t *testing.T) {
	tmpDir, _ := os.MkdirTemp("", "fetcher-pypi-slash-test")
	defer os.RemoveAll(tmpDir)

	packageDir := filepath.Join(tmpDir, "pypi", "google_cloud_storage", "2.0.0")
	cachedDir := writeCacheEntry(t, packageDir, "google-cloud-storage-2.0.0.tar.gz",
		"google-cloud-storage-2.0.0", "__init__.py")

	f := NewFetcher(tmpDir)
	dir, err := f.Fetch(types.Dependency{
		Name:      "google/cloud/storage",
		Version:   "2.0.0",
		Ecosystem: types.EcosystemPyPI,
	})

	if err == nil {
		t.Fatalf("a PyPI name containing slashes was fetched, to %q", dir)
	}
	if !strings.Contains(err.Error(), "not a valid pypi package name") {
		t.Errorf("refused for the wrong reason: %v", err)
	}
	// The cache entry that a sanitized name would have resolved to is still
	// there, so this test is refusing a fetch that would otherwise have
	// succeeded rather than one that had nothing to return.
	if !isNonEmptyDir(cachedDir) {
		t.Fatalf("fixture cache entry %s is missing, so this test proves nothing", cachedDir)
	}

	// The real name for the same package is still fetched from that entry.
	ok, err := f.Fetch(types.Dependency{
		Name:      "google-cloud-storage",
		Version:   "2.0.0",
		Ecosystem: types.EcosystemPyPI,
	})
	if err == nil || ok != "" {
		// There is no cache entry under the real name, so this must fail at the
		// download rather than at the guard.
		t.Logf("fetch under the real name returned %q, %v", ok, err)
	}
	if err != nil && strings.Contains(err.Error(), "not a valid pypi package name") {
		t.Errorf("the guard refuses a legitimate PyPI name: %v", err)
	}
}

func TestFetchMavenWithComplexCoordinate(t *testing.T) {
	// Test Maven with complex groupId (nested packages like org.apache.logging.log4j)
	tmpDir, _ := os.MkdirTemp("", "fetcher-maven-complex-test")
	defer os.RemoveAll(tmpDir)

	cachedDir := filepath.Join(tmpDir, "maven", "org.apache.logging.log4j_log4j-core", "2.17.0", "extracted")
	os.MkdirAll(cachedDir, 0755)
	os.WriteFile(filepath.Join(cachedDir, "Log4j.java"), []byte("class Log4j {}"), 0644)

	f := NewFetcher(tmpDir)
	dir, err := f.Fetch(types.Dependency{
		Name:      "org.apache.logging.log4j:log4j-core",
		Version:   "2.17.0",
		Ecosystem: types.EcosystemMaven,
	})

	if err != nil {
		t.Fatalf("Fetch cached maven artifact failed: %v", err)
	}
	if dir != cachedDir {
		t.Errorf("Expected cached dir %s, got %s", cachedDir, dir)
	}
}

func TestFetchGoWithVersion(t *testing.T) {
	// Test Go module fetch with explicit version
	tmpDir, _ := os.MkdirTemp("", "fetcher-go-version-test")
	defer os.RemoveAll(tmpDir)

	f := NewFetcher(tmpDir)
	// This will fail because the module doesn't exist, but tests the code path
	_, err := f.Fetch(types.Dependency{
		Name:      "nonexistent.invalid/pkg",
		Version:   "v1.2.3",
		Ecosystem: types.EcosystemGo,
	})

	if err == nil {
		t.Log("Note: go mod download unexpectedly succeeded")
	} else {
		// Expected - verify error message contains useful info
		if err.Error() == "" {
			t.Error("Error message should not be empty")
		}
	}
}

func TestFetchGoWithoutVersion(t *testing.T) {
	// Test Go module fetch without version (should get latest)
	tmpDir, _ := os.MkdirTemp("", "fetcher-go-noversion-test")
	defer os.RemoveAll(tmpDir)

	f := NewFetcher(tmpDir)
	// This will fail, but tests the code path for no-version case
	_, err := f.Fetch(types.Dependency{
		Name:      "nonexistent.invalid/pkg",
		Version:   "", // No version
		Ecosystem: types.EcosystemGo,
	})

	if err == nil {
		t.Log("Note: go mod download unexpectedly succeeded")
	}
}

func TestFetchMavenMissingColon(t *testing.T) {
	// Test Maven with missing colon (invalid coordinate)
	tmpDir, _ := os.MkdirTemp("", "fetcher-maven-invalid-test")
	defer os.RemoveAll(tmpDir)

	f := NewFetcher(tmpDir)
	_, err := f.Fetch(types.Dependency{
		Name:      "nogroup-noartifact",
		Version:   "1.0.0",
		Ecosystem: types.EcosystemMaven,
	})

	if err == nil {
		t.Error("Expected error for invalid Maven coordinate without colon")
	}
	// Verify error message mentions the issue
	if err != nil && !filepath.IsAbs(err.Error()) {
		// Error should mention "invalid Maven coordinate"
		t.Logf("Got expected error: %v", err)
	}
}

func TestFetchMavenMultipleColons(t *testing.T) {
	// Test Maven with multiple colons should fail (only groupId:artifactId format supported)
	tmpDir, _ := os.MkdirTemp("", "fetcher-maven-multicolon-test")
	defer os.RemoveAll(tmpDir)

	f := NewFetcher(tmpDir)
	_, err := f.Fetch(types.Dependency{
		Name:      "com.example:artifact:extra", // Multiple colons - invalid
		Version:   "1.0.0",
		Ecosystem: types.EcosystemMaven,
	})

	if err == nil {
		t.Error("Expected error for Maven coordinate with multiple colons")
	}
}

func TestNewFetcherDefaultCacheDir(t *testing.T) {
	f := NewFetcher("")

	// Should have a default cache dir
	if f.cacheDir == "" {
		t.Error("Expected non-empty default cache dir")
	}

	// Should be in temp directory
	if !filepath.IsAbs(f.cacheDir) {
		t.Error("Cache dir should be absolute path")
	}
}

func TestFetchNpmEmptyVersion(t *testing.T) {
	// Test that empty version still creates proper cache path
	tmpDir, _ := os.MkdirTemp("", "fetcher-npm-empty-version")
	defer os.RemoveAll(tmpDir)

	// Create cache with the placeholder segment an empty version resolves to
	packageDir := filepath.Join(tmpDir, "npm", "my-package", "_")
	cachedDir := writeCacheEntry(t, packageDir, "my-package-1.0.0.tgz", npmExtractedDir, "index.js")

	f := NewFetcher(tmpDir)
	dir, err := f.Fetch(types.Dependency{
		Name:      "my-package",
		Version:   "",
		Ecosystem: types.EcosystemNPM,
	})

	if err != nil {
		t.Fatalf("Fetch failed: %v", err)
	}

	if dir != cachedDir {
		t.Errorf("Expected %s, got %s", cachedDir, dir)
	}
}

// ============================================================================
// Network Integration Tests (require network access)
// Run with: go test -v -run TestIntegration
// ============================================================================

func TestIntegration_FetchGoModule(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	tmpDir, _ := os.MkdirTemp("", "fetcher-go-integration")
	defer os.RemoveAll(tmpDir)

	f := NewFetcher(tmpDir)

	// Fetch a small, real Go module
	dir, err := f.Fetch(types.Dependency{
		Name:      "golang.org/x/text",
		Version:   "v0.14.0",
		Ecosystem: types.EcosystemGo,
	})

	if err != nil {
		t.Fatalf("Failed to fetch Go module: %v", err)
	}

	// Verify directory exists and contains Go files
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		t.Error("Expected module directory to exist")
	}

	// Check for expected files
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("Failed to read module directory: %v", err)
	}

	if len(entries) == 0 {
		t.Error("Expected module directory to contain files")
	}

	// Verify go.mod exists
	if _, err := os.Stat(filepath.Join(dir, "go.mod")); os.IsNotExist(err) {
		t.Error("Expected go.mod file in fetched module")
	}
}

func TestIntegration_FetchNpmPackage(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	// Check if npm is available
	if _, err := exec.LookPath("npm"); err != nil {
		t.Skip("npm not available, skipping test")
	}

	tmpDir, _ := os.MkdirTemp("", "fetcher-npm-integration")
	defer os.RemoveAll(tmpDir)

	f := NewFetcher(tmpDir)

	// Fetch a small, common npm package
	dir, err := f.Fetch(types.Dependency{
		Name:      "is-odd",
		Version:   "3.0.1",
		Ecosystem: types.EcosystemNPM,
	})

	if err != nil {
		t.Fatalf("Failed to fetch npm package: %v", err)
	}

	// Verify directory exists
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		t.Error("Expected package directory to exist")
	}

	// Check for package.json
	if _, err := os.Stat(filepath.Join(dir, "package.json")); os.IsNotExist(err) {
		t.Error("Expected package.json in fetched package")
	}
}

func TestIntegration_FetchPyPIPackage(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	// Check if pip is available
	if _, err := exec.LookPath("pip"); err != nil {
		t.Skip("pip not available, skipping test")
	}

	tmpDir, _ := os.MkdirTemp("", "fetcher-pypi-integration")
	defer os.RemoveAll(tmpDir)

	f := NewFetcher(tmpDir)

	// Fetch a small Python package
	dir, err := f.Fetch(types.Dependency{
		Name:      "six",
		Version:   "1.16.0",
		Ecosystem: types.EcosystemPyPI,
	})

	if err != nil {
		t.Fatalf("Failed to fetch PyPI package: %v", err)
	}

	// Verify directory exists
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		t.Error("Expected package directory to exist")
	}

	// Check that directory is not empty
	entries, _ := os.ReadDir(dir)
	if len(entries) == 0 {
		t.Error("Expected package directory to contain files")
	}
}

func TestIntegration_FetchMavenArtifact(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	// Check if curl is available
	if _, err := exec.LookPath("curl"); err != nil {
		t.Skip("curl not available, skipping test")
	}
	if _, err := exec.LookPath("unzip"); err != nil {
		t.Skip("unzip not available, skipping test")
	}

	tmpDir, _ := os.MkdirTemp("", "fetcher-maven-integration")
	defer os.RemoveAll(tmpDir)

	f := NewFetcher(tmpDir)

	// Fetch a small Maven artifact with sources
	dir, err := f.Fetch(types.Dependency{
		Name:      "com.google.code.gson:gson",
		Version:   "2.10.1",
		Ecosystem: types.EcosystemMaven,
	})

	if err != nil {
		t.Fatalf("Failed to fetch Maven artifact: %v", err)
	}

	// Verify directory exists
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		t.Error("Expected artifact directory to exist")
	}

	// Check that directory contains Java files
	entries, _ := os.ReadDir(dir)
	if len(entries) == 0 {
		t.Error("Expected artifact directory to contain files")
	}

	// Look for .java files
	hasJava := false
	filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if filepath.Ext(path) == ".java" {
			hasJava = true
			return filepath.SkipDir
		}
		return nil
	})

	if !hasJava {
		t.Log("Note: No .java files found - sources JAR may not be available")
	}
}

// ============================================================================
// Cache-entry resolution and manifest-controlled paths
//
// Every test below fails against the code as it stood at 4d6227b.
// ============================================================================

// withoutFetchTools makes every external downloader unreachable, so that a
// fetch which does NOT hit the cache fails immediately instead of going to the
// network. It lets a cache-behaviour test be both hermetic and end to end.
func withoutFetchTools(t *testing.T) {
	t.Helper()
	t.Setenv("PATH", t.TempDir())
}

// TestCacheHitRequiresExtractedSource covers the defect that made a package
// which had never been read count as analyzed.
//
// The cache-hit check asked whether the version directory existed. A directory
// holding nothing but the downloaded tarball answers yes, so the fetcher handed
// that directory to the AST walker, the walker found no source files, and the
// dependency was recorded as deep-analyzed with zero findings. Nothing warned,
// because nothing failed. Asserted through Fetch rather than through the helper
// so that the test states the behaviour and not the implementation.
func TestCacheHitRequiresExtractedSource(t *testing.T) {
	withoutFetchTools(t)
	tmpDir := t.TempDir()

	// The layout an interrupted extraction leaves: archive present, nothing
	// unpacked. Also the layout the npm fetcher leaves when its own tar step
	// fails.
	packageDir := filepath.Join(tmpDir, "npm", "ejs", "3.1.10")
	writeCacheEntry(t, packageDir, "ejs-3.1.10.tgz", "", "")

	// Guard the fixture: the directory the old check asked about does exist,
	// so this test cannot pass for the trivial reason that it is absent.
	if _, err := os.Stat(packageDir); err != nil {
		t.Fatalf("fixture does not create the cache directory: %v", err)
	}

	f := NewFetcher(tmpDir)
	root, err := f.Fetch(types.Dependency{
		Name:      "ejs",
		Version:   "3.1.10",
		Ecosystem: types.EcosystemNPM,
	})
	if err == nil {
		t.Errorf("a cache entry holding only an archive was accepted as source at %q; "+
			"the package is then reported as analyzed without a byte of it being read", root)
	}
}

// TestMavenCacheHitRequiresExtractedContent is the same defect in the fetcher
// that did keep both paths on one directory name. The extracted directory is
// created before the unzip runs, so a failed unzip leaves it there and empty,
// and the existence check accepted it on every later run.
func TestMavenCacheHitRequiresExtractedContent(t *testing.T) {
	withoutFetchTools(t)
	tmpDir := t.TempDir()

	packageDir := filepath.Join(tmpDir, "maven", "com.example_artifact", "1.0.0")
	extractDir := writeCacheEntry(t, packageDir, "artifact-1.0.0.jar", zipExtractedDir, "")

	if _, err := os.Stat(extractDir); err != nil {
		t.Fatalf("fixture does not create the extracted directory: %v", err)
	}

	f := NewFetcher(tmpDir)
	root, err := f.Fetch(types.Dependency{
		Name:      "com.example:artifact",
		Version:   "1.0.0",
		Ecosystem: types.EcosystemMaven,
	})
	if err == nil {
		t.Errorf("an empty extracted directory was accepted as source at %q; a scan of it "+
			"reports no findings and calls the artifact examined", root)
	}
}

// TestCacheHitIsStableAcrossRuns pins the property the two paths disagreed on:
// the same cache entry must resolve to the same source root every time, for a
// tarball that does not follow the npm package/ convention.
func TestCacheHitIsStableAcrossRuns(t *testing.T) {
	withoutFetchTools(t)
	tmpDir := t.TempDir()

	packageDir := filepath.Join(tmpDir, "npm", "ejs", "3.1.10")
	want := writeCacheEntry(t, packageDir, "ejs-3.1.10.tgz", "ejs-v3.1.10", "index.js")

	f := NewFetcher(tmpDir)
	dep := types.Dependency{Name: "ejs", Version: "3.1.10", Ecosystem: types.EcosystemNPM}

	first, err := f.Fetch(dep)
	if err != nil {
		t.Fatalf("first fetch: %v", err)
	}
	second, err := f.Fetch(dep)
	if err != nil {
		t.Fatalf("second fetch: %v", err)
	}

	if first != want || second != want {
		t.Errorf("cache resolved to %q then %q, want %q both times; a package analyzed from "+
			"two different roots reports two different results for one scan", first, second, want)
	}
}

// TestExtractedSourceRootResolvesBothLayouts pins the agreement between the
// cold and warm paths.
//
// npm tarballs conventionally unpack to package/, and the post-extraction path
// returned that name unconditionally. ejs 3.1.10 unpacks to ejs-v3.1.10/, so
// the first run failed with lstat and every later run silently analyzed a
// different root. Both runs must resolve to the same directory.
func TestExtractedSourceRootResolvesBothLayouts(t *testing.T) {
	tests := []struct {
		name      string
		extracted string
	}{
		{"npm convention", npmExtractedDir},
		{"tarball with its own root, as ejs 3.1.10 has", "ejs-v3.1.10"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			packageDir := filepath.Join(t.TempDir(), "npm", "ejs", "3.1.10")
			want := writeCacheEntry(t, packageDir, "ejs-3.1.10.tgz", tt.extracted, "index.js")

			got, err := extractedSourceRoot(packageDir, npmExtractedDir)
			if err != nil {
				t.Fatalf("extractedSourceRoot: %v", err)
			}
			if got != want {
				t.Errorf("extractedSourceRoot = %q, want %q", got, want)
			}
		})
	}
}

// TestExtractedSourceRootRejectsEmptyAndAmbiguous covers the two states where
// no answer is better than a guess.
func TestExtractedSourceRootRejectsEmptyAndAmbiguous(t *testing.T) {
	t.Run("empty extracted directory", func(t *testing.T) {
		// What a failed unzip leaves behind: the JAR fetcher creates extracted/
		// before unzipping into it, so the directory exists and holds nothing.
		packageDir := filepath.Join(t.TempDir(), "maven", "com.example_artifact", "1.0.0")
		writeCacheEntry(t, packageDir, "artifact-1.0.0.jar", zipExtractedDir, "")

		if root, err := extractedSourceRoot(packageDir, zipExtractedDir); err == nil {
			t.Errorf("an empty extracted directory resolved to %q; a scan of it reports "+
				"no findings and calls the package examined", root)
		}
	})

	t.Run("two candidate directories", func(t *testing.T) {
		packageDir := filepath.Join(t.TempDir(), "pypi", "example", "1.0.0")
		writeCacheEntry(t, packageDir, "example-1.0.0.tar.gz", "example-1.0.0", "mod.py")
		writeCacheEntry(t, packageDir, "", "example-1.0.0.data", "payload")

		root, err := extractedSourceRoot(packageDir)
		if err == nil {
			t.Errorf("ambiguous cache entry resolved to %q; the tool would analyze one "+
				"tree and report the result as if it were the package", root)
		}
	})
}

// TestFetchRefusesLocalPathVersion is the security regression test.
//
// The cache path was built from the dependency name and version exactly as the
// manifest under scan declared them, so {"ejs": "../../../somewhere"} resolved
// the cache entry outside the cache directory. That directory then existed, the
// existence check accepted it as a cache hit, and --deep walked it and
// published its absolute file paths and line numbers as the dependency's
// source. A scan of an untrusted repository could read any directory the
// process could read and put what it found in the SARIF that CI uploads.
func TestFetchRefusesLocalPathVersion(t *testing.T) {
	// No downloader on PATH, so any fetch that is not answered from the cache
	// fails without touching the network. The escape below is answered from the
	// cache, which is the whole point: it needs no network at all.
	withoutFetchTools(t)

	root := t.TempDir()
	cacheDir := filepath.Join(root, "cache")
	if err := os.MkdirAll(cacheDir, 0755); err != nil {
		t.Fatalf("create cache dir: %v", err)
	}

	// The directory the manifest is aiming at, outside the cache, holding
	// something a scan would report.
	victim := filepath.Join(root, "victim")
	if err := os.MkdirAll(victim, 0755); err != nil {
		t.Fatalf("create victim dir: %v", err)
	}
	secret := filepath.Join(victim, "leak.js")
	if err := os.WriteFile(secret, []byte("crypto.createHash('md5')"), 0644); err != nil {
		t.Fatalf("write victim file: %v", err)
	}

	// The traversal has to be deep enough to actually land on the victim, or
	// this test passes because npm is unavailable rather than because the
	// fetcher refused. escape is <cache>/npm/ejs/<version> resolving to victim.
	const escape = "../../../victim"
	if got := filepath.Join(cacheDir, "npm", "ejs", escape); got != victim {
		t.Fatalf("fixture does not aim at the victim directory: %q != %q; the test would "+
			"pass without exercising the escape", got, victim)
	}

	f := NewFetcher(cacheDir)
	dir, err := f.Fetch(types.Dependency{
		Name:      "ejs",
		Version:   escape,
		Ecosystem: types.EcosystemNPM,
	})
	if err == nil {
		t.Fatalf("a manifest-declared version resolved deep analysis to %q, outside the "+
			"cache; the tool would read that directory and publish its file paths and "+
			"line numbers as the dependency's source", dir)
	}
	// The reason matters, not just the failure. Without this the test passes
	// whenever npm happens to be unavailable, which is exactly the condition
	// the rest of the test sets up, so an implementation that dropped the
	// refusal entirely would still look green.
	if !strings.Contains(err.Error(), "refers to a local path") {
		t.Errorf("fetch failed for the wrong reason: %v; the local-path reference has to be "+
			"refused on its own terms, not incidentally by the downloader", err)
	}
	if dir != "" {
		t.Errorf("returned path %q alongside an error", dir)
	}

	// The refusal must not have disturbed the target either.
	if _, err := os.Stat(secret); err != nil {
		t.Errorf("the target directory was modified while refusing to fetch it: %v", err)
	}
}

// TestFetchNeverResolvesOutsideTheCache states the invariant the test above
// exercises through one input, over the forms a manifest can use.
//
// Nothing a manifest declares may steer a fetch out of the cache directory,
// whether by traversing out of it or by naming a path directly for npm or pip
// to resolve.
func TestFetchNeverResolvesOutsideTheCache(t *testing.T) {
	withoutFetchTools(t)

	root := t.TempDir()
	cacheDir := filepath.Join(root, "cache")
	if err := os.MkdirAll(cacheDir, 0755); err != nil {
		t.Fatalf("create cache dir: %v", err)
	}
	// Populate a plausible target at every depth the traversals below reach, so
	// that a fetcher which resolves one of them finds a real directory and
	// returns it rather than failing for an unrelated reason.
	for _, d := range []string{"victim", "cache/victim", "cache/npm/victim"} {
		dir := filepath.Join(root, d)
		if err := os.MkdirAll(dir, 0755); err != nil {
			t.Fatalf("create %s: %v", d, err)
		}
		if err := os.WriteFile(filepath.Join(dir, "index.js"), []byte("x"), 0644); err != nil {
			t.Fatalf("write into %s: %v", d, err)
		}
	}

	f := NewFetcher(cacheDir)
	for _, ecosystem := range []types.Ecosystem{types.EcosystemNPM, types.EcosystemPyPI} {
		for _, version := range []string{
			"../victim", "../../victim", "../../../victim",
			"file:../../../victim", "/etc", "~/.ssh", "1.0.0/../../../victim",
		} {
			t.Run(string(ecosystem)+" "+version, func(t *testing.T) {
				dir, err := f.Fetch(types.Dependency{
					Name:      "pkg",
					Version:   version,
					Ecosystem: ecosystem,
				})
				if err != nil {
					return // refused, which is the intended outcome
				}
				if !strings.HasPrefix(filepath.Clean(dir), filepath.Clean(cacheDir)+string(filepath.Separator)) {
					t.Errorf("version %q resolved to %q, outside the cache directory %q",
						version, dir, cacheDir)
				}
			})
		}
	}
}

// TestCacheSegmentCannotEscape checks the property directly, including inputs
// that reach the fetcher through a package name rather than a version.
func TestCacheSegmentCannotEscape(t *testing.T) {
	for _, in := range []string{
		"..", ".", "../..", "../../etc/passwd", "/absolute", "~", "",
		"a/b", `a\b`, "@scope/pkg", "com.example:artifact", "1.0.0",
	} {
		t.Run(in, func(t *testing.T) {
			seg := cacheSegment(in)
			if seg == "" {
				t.Fatalf("cacheSegment(%q) is empty, which collapses the cache path", in)
			}
			if strings.ContainsAny(seg, `/\`) {
				t.Errorf("cacheSegment(%q) = %q, which spans more than one path element", in, seg)
			}
			if strings.Trim(seg, ".") == "" {
				t.Errorf("cacheSegment(%q) = %q, which is a directory reference", in, seg)
			}

			base := filepath.Join("/cache", "npm", "pkg")
			joined := filepath.Join(base, seg)
			if !strings.HasPrefix(joined, base+string(filepath.Separator)) {
				t.Errorf("cacheSegment(%q) escapes the cache directory: %q", in, joined)
			}
		})
	}
}

// TestLocalPathReferenceLeavesRemoteReferencesAlone guards the other direction:
// narrowing what is fetched must not stop the references that legitimately
// resolve to a remote package.
func TestLocalPathReferenceLeavesRemoteReferencesAlone(t *testing.T) {
	local := []string{"../x", "./x", "/x", "~/x", "file:../x", "FILE:../x", "a/../../x",
		`C:\x`, "C:/x", `c:\x`, `\x`, `\\host\share`, "link:../x", "portal:../x", "LINK:../x",
		// A transport prefixed onto the scheme. git+file:// passed both earlier
		// checks: it does not start with "file:", and the colon suppressed the
		// traversal walk. npm pack clones it from disk and runs its prepare
		// script, so this was code execution chosen by the scanned manifest.
		"git+file:///x", "GIT+FILE:///x", "git+file://../x"}
	// A Maven coordinate carries a colon and is not a Windows path; so does an
	// alias and a VCS reference. Refusing any of these would stop deep analysis
	// of packages that fetch correctly today.
	remote := []string{"1.2.3", "^1.2.3", ">=1.0,<2.0", "v0.14.0", "latest", "",
		"github:owner/repo", "git+https://github.com/owner/repo.git", "npm:alias@1.0.0",
		"com.google.guava:guava", "a:b", "org.apache.logging.log4j:log4j-core"}

	for _, v := range local {
		if !localPathReference(v) {
			t.Errorf("localPathReference(%q) = false, want true", v)
		}
	}
	for _, v := range remote {
		if localPathReference(v) {
			t.Errorf("localPathReference(%q) = true, want false; this reference resolves to a "+
				"published package and deep analysis of it works", v)
		}
	}
}

// TestFetchRefusesLocalPathName covers the half of the traversal class that the
// version guard did not reach.
//
// cacheSegment sanitizes the name for the cache PATH, so the cache entry stays
// where it belongs and the defect is invisible there. The name is also handed
// to the package manager as a SPEC, and `npm pack ../../../../victim` resolves
// a directory. Path safety and spec safety are different guarantees, and only
// the first one was in place: a manifest declaring
// {"../../../../victim": ""} packed a tree outside the project, walked it, and
// published its file names and line numbers as the dependency's source.
func TestFetchRefusesLocalPathName(t *testing.T) {
	// No downloader on PATH, so nothing here touches the network. That is also
	// why the assertion below is on the refusal REASON: without it this test
	// would pass on a machine with no npm even if the guard were deleted.
	withoutFetchTools(t)

	root := t.TempDir()
	cacheDir := filepath.Join(root, "cache")
	if err := os.MkdirAll(cacheDir, 0755); err != nil {
		t.Fatalf("create cache dir: %v", err)
	}

	f := NewFetcher(cacheDir)
	for _, name := range []string{
		"../../../../victim",
		"./victim",
		"/tmp/victim",
		"~/victim",
		"file:../victim",
		"pkg/../../../victim",
		// Windows spellings of the same thing, on a target this tool ships
		// binaries for. A drive letter contains a colon, which the guard read
		// as evidence that the reference was remote.
		`C:\victim`,
		"C:/victim",
		`c:\victim`,
		`\victim`,
		`\\host\share\victim`,
		// The Yarn and pnpm spellings. npm pack rejects them today, so these
		// hold the guard rather than close a live vector.
		"link:../victim",
		"portal:../victim",
	} {
		t.Run(name, func(t *testing.T) {
			dir, err := f.Fetch(types.Dependency{
				Name:      name,
				Ecosystem: types.EcosystemNPM,
			})
			if err == nil {
				t.Fatalf("dependency name %q was fetched to %q; npm resolves a name that "+
					"names a directory, so the tool reads and publishes a tree the "+
					"manifest author chose", name, dir)
			}
			// Either guard is an answer on the name's own terms: the grammar
			// says it is not a name, or the path check says it is a local path.
			// What must never satisfy this test is an incidental failure from a
			// missing downloader, which is what the pre-fix code produced.
			refused := strings.Contains(err.Error(), "refers to a local path") ||
				strings.Contains(err.Error(), "is not a valid")
			if !refused {
				t.Errorf("name %q failed for the wrong reason: %v; it has to be refused on "+
					"its own terms, not incidentally by a missing downloader", name, err)
			}
			if dir != "" {
				t.Errorf("returned path %q alongside an error", dir)
			}
		})
	}
}

// TestMavenFetchNeverWritesOutsideTheCache covers the write primitive.
//
// fetchMavenArtifact built the curl -o target by joining the artifactId from
// the scanned pom.xml straight onto the cache directory. filepath.Join resolves
// .. lexically, so the download target escaped, and a '?' in the artifactId
// split the Maven URL so that its path portion still named a real artifact
// while the file portion traversed: curl -f then got its 200 and wrote. That is
// an arbitrary file write and truncate driven by a scanned manifest, which is a
// different and worse class than the read the version guard closed.
func TestMavenFetchNeverWritesOutsideTheCache(t *testing.T) {
	withoutFetchTools(t)

	root := t.TempDir()
	cacheDir := filepath.Join(root, "cache")
	if err := os.MkdirAll(cacheDir, 0755); err != nil {
		t.Fatalf("create cache dir: %v", err)
	}

	const version = "1"
	artifactID := "junit/4.13.2/junit-4.13.2-sources.jar?a=" +
		strings.Repeat("/..", 8) + "/pwned"
	name := "junit:" + artifactID

	// Guard: the fixture has to actually land outside the cache. If it does
	// not, every assertion below passes for the wrong reason and the test is
	// decorative. This mirrors the join the fetcher performs.
	packageDir := filepath.Join(cacheDir, "maven", cacheSegment(name), cacheSegment(version))
	wouldWrite := filepath.Join(packageDir, artifactID+"-"+version+"-sources.jar")
	if strings.HasPrefix(filepath.Clean(wouldWrite), filepath.Clean(cacheDir)+string(filepath.Separator)) {
		t.Fatalf("fixture does not escape the cache: %q is inside %q, so this test would "+
			"not exercise the write primitive", wouldWrite, cacheDir)
	}

	f := NewFetcher(cacheDir)
	dir, err := f.Fetch(types.Dependency{
		Name:      name,
		Version:   version,
		Ecosystem: types.EcosystemMaven,
	})
	if err == nil {
		t.Fatalf("a manifest-declared Maven coordinate was fetched to %q; the download "+
			"target resolves to %q, outside the cache", dir, wouldWrite)
	}
	if !strings.Contains(err.Error(), "not a valid Maven coordinate") {
		t.Errorf("failed for the wrong reason: %v; the coordinate has to be refused on its "+
			"own terms, not incidentally by a missing downloader", err)
	}

	// Nothing may have been created along the escape path, at any depth.
	if _, statErr := os.Stat(wouldWrite); statErr == nil {
		t.Errorf("the refused fetch still created %q", wouldWrite)
	}
}

// TestFetchAcceptsOrdinaryNames guards the test above from over-reaching: a
// refusal that also rejects real package names would be a worse defect than the
// one being fixed, and would not show up in a test that only feeds it attacks.
func TestFetchAcceptsOrdinaryNames(t *testing.T) {
	for _, name := range []string{
		"ejs", "lodash", "@scope/pkg", "zope.interface", "python-dateutil",
		"com.google.guava:guava", "github.com/spf13/cobra",
	} {
		if localPathReference(name) {
			t.Errorf("ordinary package name %q was treated as a local path reference", name)
		}
	}
}

// TestMavenCoordinateValidationAcceptsRealArtifacts is the companion guard: the
// validator must not reject the coordinates the tool exists to read.
func TestMavenCoordinateValidationAcceptsRealArtifacts(t *testing.T) {
	for _, name := range []string{
		"junit:junit",
		"com.google.guava:guava",
		"org.bouncycastle:bcprov-jdk18on",
		"io.jsonwebtoken:jjwt-api",
		"com.squareup.okhttp3:okhttp",
	} {
		parts := strings.SplitN(name, ":", 2)
		if err := validMavenCoordinate(parts[0], parts[1]); err != nil {
			t.Errorf("real Maven coordinate %q was rejected: %v", name, err)
		}
	}
	for _, bad := range [][2]string{
		{"junit", "junit/../../../x"},
		{"junit", "junit?a=b"},
		{"../../etc", "junit"},
		{"junit", ""},
		{"", "junit"},
		{"junit", "junit\x00"},
	} {
		if err := validMavenCoordinate(bad[0], bad[1]); err == nil {
			t.Errorf("coordinate %q:%q was accepted", bad[0], bad[1])
		}
	}
}

// TestVersionTraversalIsRefusedBehindAnyScheme is the regression test for the
// fourth spelling of the local-path class.
//
// localPathReference skipped its traversal walk for any value containing a
// colon, on the reasoning that a colon meant a remote reference such as
// github:owner/repo. An invented scheme defeats that: a version of
// "a1:../../../../../../../victim" carries a colon, so the walk never ran, and
// `npm pack left-pad@a1:../../../victim` packed a directory outside the cache,
// which the analyzer then read and published as that dependency's source with
// its absolute paths. Reproduced by sentinel at traversal depth 7 against the
// 1.3.0 candidate.
func TestVersionTraversalIsRefusedBehindAnyScheme(t *testing.T) {
	withoutFetchTools(t)
	f := NewFetcher(t.TempDir())

	for _, version := range []string{
		"a1:../../../../../../../victim",        // an invented scheme
		"npm:../../../victim",                   // a real scheme npm does accept
		"github:owner/../../../../../../victim", // a remote form carrying a traversal
		"1.0.0/../../../../../../../../victim",  // no scheme at all, for the baseline
	} {
		t.Run(version, func(t *testing.T) {
			// Guard the fixture: without a ".." element this case is not a traversal
			// and proves nothing about the walk.
			if !strings.Contains(version, "..") {
				t.Fatalf("fixture %q carries no traversal", version)
			}
			_, err := f.Fetch(types.Dependency{
				Name:      "left-pad",
				Version:   version,
				Ecosystem: types.EcosystemNPM,
			})
			if err == nil {
				t.Fatalf("a version traversing out of the cache was fetched")
			}
			// The REASON matters: PATH is empty here, so "npm not found" would
			// satisfy err != nil while the guard was absent.
			if !strings.Contains(err.Error(), "refers to a local path") {
				t.Errorf("refused for the wrong reason: %v; the traversal has to be refused on "+
					"its own terms, not incidentally by a missing downloader", err)
			}
		})
	}
}

// TestRemoteReferencesWithoutTraversalStillFetch is the inverse question.
//
// Removing the colon exemption must not refuse the remote references it was
// written to admit, or --deep loses every git and registry-shorthand dependency.
func TestRemoteReferencesWithoutTraversalStillFetch(t *testing.T) {
	withoutFetchTools(t)
	f := NewFetcher(t.TempDir())

	for _, version := range []string{
		"github:owner/repo",
		"git+https://github.com/owner/repo.git#v1.2.3",
		"npm:left-pad@1.3.0",
		"https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz",
		"^1.2.3",
		">=1.0.0 <2.0.0",
		"1.2.3-beta.1+build.5",
	} {
		t.Run(version, func(t *testing.T) {
			_, err := f.Fetch(types.Dependency{
				Name:      "left-pad",
				Version:   version,
				Ecosystem: types.EcosystemNPM,
			})
			// The fetch cannot succeed with no downloader on PATH. What must not
			// happen is a refusal by the guard, which would mean this legitimate
			// version is never fetched on a real machine either.
			if err != nil && strings.Contains(err.Error(), "refers to a local path") {
				t.Errorf("a legitimate remote reference was refused as a local path: %v", err)
			}
		})
	}
}

// TestFailedExtractionLeavesNoUsableCacheEntry is the regression test for a
// fail-open that turned an error into a clean examination on the next run.
//
// The three download sites route failure through discardPartialFetch; the four
// extraction sites returned a bare error. Both tar and unzip extract partially
// before failing, so the entry was left holding a non-empty package directory,
// which the cache-hit check accepts. The first scan reported the package as not
// examined and the second reported it as examined, with findings, from a
// partially extracted archive and no warning on any stream.
func TestFailedExtractionLeavesNoUsableCacheEntry(t *testing.T) {
	// Every ecosystem that extracts an archive, because the same bare error was
	// returned at all four sites and a test covering only npm left three of them
	// deletable with a green suite.
	cases := []struct {
		name string
		dep  types.Dependency
		// stubs maps an executable this path shells out to onto a script. The
		// downloader must succeed and produce an archive; the extractor must
		// extract something and then fail, which is what a truncated or hostile
		// archive does.
		stubs map[string]string
		// extracted is the directory the extractor half-fills, relative to the
		// package cache entry.
		extracted string
	}{
		{
			name: "npm",
			dep:  types.Dependency{Name: "left-pad", Version: "1.3.0", Ecosystem: types.EcosystemNPM},
			stubs: map[string]string{
				"npm": "#!/bin/sh\n: > left-pad-1.3.0.tgz\n",
				"tar": "#!/bin/sh\nwhile [ $# -gt 0 ]; do case \"$1\" in -C) shift; D=\"$1\";; esac; shift; done\n" +
					"/bin/mkdir -p \"$D/package\"\nprintf 'module.exports=1;\\n' > \"$D/package/index.js\"\nexit 1\n",
			},
			extracted: npmExtractedDir,
		},
		{
			name: "maven",
			dep:  types.Dependency{Name: "org.tukaani:xz", Version: "1.9", Ecosystem: types.EcosystemMaven},
			stubs: map[string]string{
				"curl": "#!/bin/sh\nwhile [ $# -gt 0 ]; do case \"$1\" in -o) shift; O=\"$1\";; esac; shift; done\n: > \"$O\"\n",
				"unzip": "#!/bin/sh\nwhile [ $# -gt 0 ]; do case \"$1\" in -d) shift; D=\"$1\";; esac; shift; done\n" +
					"/bin/mkdir -p \"$D/org\"\nprintf 'class A {}\\n' > \"$D/org/A.java\"\nexit 1\n",
			},
			extracted: zipExtractedDir,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			bin := t.TempDir()
			for name, script := range tc.stubs {
				if err := os.WriteFile(filepath.Join(bin, name), []byte(script), 0755); err != nil {
					t.Fatalf("write stub %s: %v", name, err)
				}
			}
			// The stubs come first so they shadow any real tool, but the rest of
			// PATH stays: emptying it left the stubs' own mkdir unresolvable, so
			// nothing was ever extracted and this test passed while the defect
			// was present.
			t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))

			cacheDir := filepath.Join(t.TempDir(), "cache")
			f := NewFetcher(cacheDir)

			_, err := f.Fetch(tc.dep)
			if err == nil {
				t.Fatal("a failed extraction was reported as a successful fetch")
			}
			// Guard the fixture: the fetch has to have failed AT EXTRACTION. If
			// the stub downloader produced no archive, the fetch fails earlier,
			// nothing is half-extracted, and every assertion below is answered by
			// an empty cache.
			if !strings.Contains(err.Error(), "extract") {
				t.Fatalf("the fixture did not reach extraction, so it cannot detect a "+
					"partial one: %v", err)
			}

			packageDir := filepath.Join(cacheDir, string(tc.dep.Ecosystem),
				cacheSegment(tc.dep.Name), cacheSegment(tc.dep.Version))
			if entries, err := os.ReadDir(filepath.Join(packageDir, tc.extracted)); err == nil &&
				len(entries) > 0 {
				t.Fatalf("the partially extracted directory survives at %q with %d entries, "+
					"so the next scan will accept it as a cache hit", packageDir, len(entries))
			}

			// The second attempt must not silently succeed from what the first left.
			root, err := f.Fetch(tc.dep)
			if err == nil {
				t.Errorf("the second fetch succeeded from a partially extracted entry and "+
					"returned %q; a scan that could not read a package must not report it "+
					"as read on the next run", root)
			}
		})
	}
}

// TestFetchDoesNotBuildSourceDistributions pins the pip half of the
// execute-nothing control.
//
// --ignore-scripts stops npm running a package's prepare script. pip had no
// equivalent: resolving a PyPI name with no matching wheel makes pip install the
// project's build dependencies and run its build backend, which for a setup.py
// sdist is arbitrary code from a package the scanned manifest chose. Fetching
// source in order to read it must not be a way to run it.
//
// Asserted on the argv, because the property is what the tool asks pip to do.
func TestFetchDoesNotBuildSourceDistributions(t *testing.T) {
	bin := t.TempDir()
	argv := filepath.Join(t.TempDir(), "argv")
	// A stub pip that records its arguments and then fails, so no network is
	// touched and the fetch ends immediately.
	script := "#!/bin/sh\nprintf '%s\\n' \"$@\" > " + argv + "\nexit 1\n"
	if err := os.WriteFile(filepath.Join(bin, "pip"), []byte(script), 0755); err != nil {
		t.Fatalf("write stub pip: %v", err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))

	f := NewFetcher(t.TempDir())
	if _, err := f.Fetch(types.Dependency{
		Name:      "psycopg2",
		Version:   "2.9.9",
		Ecosystem: types.EcosystemPyPI,
	}); err == nil {
		t.Fatal("the stub pip failed, so the fetch should have failed with it")
	}

	recorded, err := os.ReadFile(argv)
	if err != nil {
		t.Fatalf("the stub pip was never run, so this test cannot say what it was asked "+
			"to do: %v", err)
	}
	args := strings.Fields(string(recorded))
	// Guard the fixture: these are the arguments of the fetch under test.
	if len(args) == 0 || args[0] != "download" {
		t.Fatalf("the recorded argv is not a pip download: %q", args)
	}

	var onlyBinary bool
	for i, a := range args {
		if a == "--only-binary" && i+1 < len(args) && args[i+1] == ":all:" {
			onlyBinary = true
		}
		if strings.HasPrefix(a, "--only-binary=") && strings.HasSuffix(a, ":all:") {
			onlyBinary = true
		}
	}
	if !onlyBinary {
		t.Errorf("pip is invoked without --only-binary=:all: (%q), so a dependency with no "+
			"wheel has its build backend executed on the scanning host", args)
	}
}
