// Copyright 2024-2025 CSNP (csnp.org)
// SPDX-License-Identifier: Apache-2.0

// Package source provides functionality for fetching package source code.
package source

import (
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

// NewFetcher creates a new source fetcher with the given cache directory.
func NewFetcher(cacheDir string) *Fetcher {
	if cacheDir == "" {
		cacheDir = filepath.Join(os.TempDir(), "cryptodeps-cache")
	}
	return &Fetcher{cacheDir: cacheDir}
}

// Fetch downloads the source code for a package and returns the local path.
func (f *Fetcher) Fetch(dep types.Dependency) (string, error) {
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
	if modDir != "" {
		return modDir, nil
	}

	return "", fmt.Errorf("could not determine module directory")
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
	safeName := strings.ReplaceAll(dep.Name, "/", "_")
	packageDir := filepath.Join(f.cacheDir, "npm", safeName, dep.Version)

	// Check if already cached
	if _, err := os.Stat(packageDir); err == nil {
		return packageDir, nil
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
			// npm packs to a "package" subdirectory
			return filepath.Join(packageDir, "package"), nil
		}
	}

	return "", fmt.Errorf("could not find npm package tarball")
}

// fetchPyPIPackage downloads a Python package from PyPI.
func (f *Fetcher) fetchPyPIPackage(dep types.Dependency) (string, error) {
	// Create cache directory for this package
	safeName := strings.ReplaceAll(dep.Name, "/", "_")
	packageDir := filepath.Join(f.cacheDir, "pypi", safeName, dep.Version)

	// Check if already cached
	if _, err := os.Stat(packageDir); err == nil {
		return packageDir, nil
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
			extractDir := filepath.Join(packageDir, "extracted")
			if err := os.MkdirAll(extractDir, 0755); err != nil {
				return "", err
			}
			cmd := exec.Command("unzip", "-q", wheelPath, "-d", extractDir)
			if err := cmd.Run(); err != nil {
				return "", fmt.Errorf("failed to extract wheel: %w", err)
			}
			return extractDir, nil
		} else if strings.HasSuffix(name, ".tar.gz") {
			tarball := filepath.Join(packageDir, name)
			cmd := exec.Command("tar", "-xzf", tarball, "-C", packageDir)
			if err := cmd.Run(); err != nil {
				return "", fmt.Errorf("failed to extract tarball: %w", err)
			}
			// Find the extracted directory
			newEntries, _ := os.ReadDir(packageDir)
			for _, e := range newEntries {
				if e.IsDir() && !strings.HasPrefix(e.Name(), ".") {
					return filepath.Join(packageDir, e.Name()), nil
				}
			}
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
	safeName := strings.ReplaceAll(dep.Name, ":", "_")
	packageDir := filepath.Join(f.cacheDir, "maven", safeName, dep.Version)

	// Check if already cached
	extractDir := filepath.Join(packageDir, "extracted")
	if _, err := os.Stat(extractDir); err == nil {
		return extractDir, nil
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

	return extractDir, nil
}

// CacheDir returns the cache directory path.
func (f *Fetcher) CacheDir() string {
	return f.cacheDir
}

// CleanCache removes all cached packages.
func (f *Fetcher) CleanCache() error {
	return os.RemoveAll(f.cacheDir)
}
