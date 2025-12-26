// Copyright 2024-2025 CSNP (csnp.org)
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
	default:
		return nil, fmt.Errorf("unsupported manifest file: %s", filename)
	}
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
