// Copyright 2025-2026 CyberSecurity NonProfit (CSNP)
// SPDX-License-Identifier: Apache-2.0

// Package manifest provides parsers for dependency manifest files.
package manifest

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/csnp/qramm-cryptodeps/pkg/types"
)

// Parser represents a manifest file parser.
type Parser interface {
	// Parse parses a manifest file and returns the list of dependencies.
	Parse(path string) ([]types.Dependency, error)
	// Ecosystem returns the ecosystem this parser handles.
	Ecosystem() types.Ecosystem
	// Filenames returns the manifest filenames this parser handles.
	Filenames() []string
}

// Manifest represents a parsed manifest file.
type Manifest struct {
	Path         string
	Ecosystem    types.Ecosystem
	Dependencies []types.Dependency
}

// DetectAndParse detects the manifest type and parses it.
func DetectAndParse(path string) (*Manifest, error) {
	// Check if path is a directory
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("cannot access path: %w", err)
	}

	var manifestPath string
	if info.IsDir() {
		// Look for known manifest files in directory
		manifestPath, err = findManifest(path)
		if err != nil {
			return nil, err
		}
	} else {
		manifestPath = path
	}

	// Detect ecosystem from filename
	parser, err := getParser(filepath.Base(manifestPath))
	if err != nil {
		return nil, err
	}

	// Parse the manifest
	deps, err := parser.Parse(manifestPath)
	if err != nil {
		return nil, fmt.Errorf("failed to parse %s: %w", manifestPath, err)
	}

	return &Manifest{
		Path:         manifestPath,
		Ecosystem:    parser.Ecosystem(),
		Dependencies: deps,
	}, nil
}

// findManifest looks for a manifest file in a directory.
func findManifest(dir string) (string, error) {
	// Priority order of manifest files
	manifestFiles := []string{
		"go.mod",
		"package.json",
		"requirements.txt",
		"pyproject.toml",
		"Pipfile",
		"pom.xml",
		"build.gradle",
		"Cargo.toml",
		"Gemfile",
	}

	for _, filename := range manifestFiles {
		path := filepath.Join(dir, filename)
		if _, err := os.Stat(path); err == nil {
			return path, nil
		}
	}

	return "", fmt.Errorf("no supported manifest file found in %s", dir)
}

// getParser returns the appropriate parser for a manifest filename.
func getParser(filename string) (Parser, error) {
	switch strings.ToLower(filename) {
	case "go.mod":
		return &GoModParser{}, nil
	case "package.json":
		return &NPMParser{}, nil
	case "requirements.txt", "pyproject.toml", "pipfile":
		return &PythonParser{}, nil
	case "pom.xml":
		return &MavenParser{}, nil
	}

	// The requirements.txt family carries no fixed name. Matching only the exact
	// filename silently skipped requirements-dev.txt, requirements-prod.txt and
	// the requirements/*.txt layout.
	if isRequirementsFile(filename) {
		return &PythonParser{}, nil
	}

	return nil, fmt.Errorf("unsupported manifest file: %s", filename)
}

// getParserForPath selects a parser using the whole path, so that layouts whose
// meaning depends on the parent directory resolve correctly. A pip requirements
// file at requirements/base.txt is named base.txt and is indistinguishable from
// any other text file by name alone.
func getParserForPath(path string) (Parser, error) {
	if parser, err := getParser(filepath.Base(path)); err == nil {
		return parser, nil
	}
	if isManifestPath(path) && strings.EqualFold(filepath.Ext(path), ".txt") {
		return &PythonParser{}, nil
	}
	return nil, fmt.Errorf("unsupported manifest file: %s", path)
}

// SupportedManifests returns a list of supported manifest filenames.
func SupportedManifests() []string {
	return []string{
		"go.mod",
		"package.json",
		"requirements.txt",
		"pyproject.toml",
		"pom.xml",
	}
}

// DetectAndParseAll discovers all manifests in a directory (including workspaces)
// and parses each one.
//
// It returns the parsed manifests and every manifest that was found but could
// not be used, so that the caller can report the skips rather than hiding them.
// Both a validation rejection during discovery and a parse failure here produce
// a SkippedManifest.
func DetectAndParseAll(path string) ([]*Manifest, []types.SkippedManifest, error) {
	// Check if path is a directory
	info, err := os.Stat(path)
	if err != nil {
		return nil, nil, fmt.Errorf("cannot access path: %w", err)
	}

	// If it's a file, just parse that single file
	if !info.IsDir() {
		manifest, err := DetectAndParse(path)
		if err != nil {
			return nil, nil, err
		}
		return []*Manifest{manifest}, nil, nil
	}

	// Discover all manifests in the directory tree
	manifestPaths, skipped, err := DiscoverManifests(path)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to discover manifests: %w", err)
	}

	if len(manifestPaths) == 0 && len(skipped) == 0 {
		return nil, nil, fmt.Errorf("no supported manifest files found in %s", path)
	}

	var manifests []*Manifest

	for _, manifestPath := range manifestPaths {
		parser, err := getParserForPath(manifestPath)
		if err != nil {
			// Recognised by discovery but not by any parser. Report it, because
			// the user is entitled to know a file that looks like a manifest was
			// not read, but mark it unsupported so it does not make the scan
			// look incomplete. cryptodeps never claimed to read Cargo.toml, and
			// erroring on one turned every polyglot repository into a build
			// failure.
			skipped = append(skipped, newSkip(manifestPath, "no parser for this manifest type"))
			continue
		}

		deps, err := parser.Parse(manifestPath)
		if err != nil {
			skipped = append(skipped, newSkip(manifestPath, err.Error()))
			continue
		}

		manifests = append(manifests, &Manifest{
			Path:         manifestPath,
			Ecosystem:    parser.Ecosystem(),
			Dependencies: deps,
		})
	}

	if len(manifests) == 0 && len(skipped) > 0 {
		// "could not be read" is only true of a manifest that should have been
		// readable. A tree holding nothing but a Cargo.toml is not a broken
		// tree, it is an ecosystem cryptodeps does not support, and saying
		// otherwise sends the user to look for a defect in a healthy file.
		if !types.IncompleteScan(skipped) {
			return nil, skipped, fmt.Errorf("no supported manifest files found in %s: %s",
				path, describeSkipped(skipped))
		}
		return nil, skipped, fmt.Errorf("found %d manifest file(s) but none could be read: %s",
			len(skipped), describeSkipped(skipped))
	}

	return manifests, skipped, nil
}

// describeSkipped renders skipped manifests for an error message.
func describeSkipped(skipped []types.SkippedManifest) string {
	parts := make([]string, 0, len(skipped))
	for _, s := range skipped {
		parts = append(parts, fmt.Sprintf("%s (%s)", s.Path, s.Reason))
	}
	return strings.Join(parts, "; ")
}
