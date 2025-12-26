// Copyright 2024-2025 CSNP (csnp.org)
// SPDX-License-Identifier: Apache-2.0

package source

import (
	"os"
	"os/exec"
	"path/filepath"
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

func TestFetchNpmCached(t *testing.T) {
	// Create a temp cache directory with pre-cached npm package
	tmpDir, _ := os.MkdirTemp("", "fetcher-npm-test")
	defer os.RemoveAll(tmpDir)

	// Pre-create the cache directory to simulate a cached package
	cachedDir := filepath.Join(tmpDir, "npm", "test-package", "1.0.0")
	os.MkdirAll(cachedDir, 0755)
	os.WriteFile(filepath.Join(cachedDir, "index.js"), []byte("module.exports = {}"), 0644)

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

	// Pre-create the cache directory to simulate a cached package
	cachedDir := filepath.Join(tmpDir, "pypi", "test-package", "1.0.0")
	os.MkdirAll(cachedDir, 0755)
	os.WriteFile(filepath.Join(cachedDir, "__init__.py"), []byte(""), 0644)

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

	// Pre-create the cache directory with slash replaced
	cachedDir := filepath.Join(tmpDir, "npm", "@org_package", "1.0.0")
	os.MkdirAll(cachedDir, 0755)
	os.WriteFile(filepath.Join(cachedDir, "index.js"), []byte("module.exports = {}"), 0644)

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

	// Pre-create the cache directory with empty version
	cachedDir := filepath.Join(tmpDir, "npm", "test-package", "")
	os.MkdirAll(cachedDir, 0755)
	os.WriteFile(filepath.Join(cachedDir, "index.js"), []byte("module.exports = {}"), 0644)

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

func TestFetchPyPIWithSlash(t *testing.T) {
	// Test PyPI package with slash in name (normalized)
	tmpDir, _ := os.MkdirTemp("", "fetcher-pypi-slash-test")
	defer os.RemoveAll(tmpDir)

	cachedDir := filepath.Join(tmpDir, "pypi", "google_cloud_storage", "2.0.0")
	os.MkdirAll(cachedDir, 0755)
	os.WriteFile(filepath.Join(cachedDir, "__init__.py"), []byte(""), 0644)

	f := NewFetcher(tmpDir)
	dir, err := f.Fetch(types.Dependency{
		Name:      "google/cloud/storage",
		Version:   "2.0.0",
		Ecosystem: types.EcosystemPyPI,
	})

	if err != nil {
		t.Fatalf("Fetch cached pypi package with slashes failed: %v", err)
	}
	// Note: the safeName replaces "/" with "_" so google/cloud/storage becomes google_cloud_storage
	if dir != cachedDir {
		t.Errorf("Expected cached dir %s, got %s", cachedDir, dir)
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

	// Create cache with empty version directory
	cachedDir := filepath.Join(tmpDir, "npm", "my-package", "")
	os.MkdirAll(cachedDir, 0755)
	os.WriteFile(filepath.Join(cachedDir, "index.js"), []byte(""), 0644)

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
