// Copyright 2025-2026 CyberSecurity NonProfit (CSNP)
// SPDX-License-Identifier: Apache-2.0

// Package manifest provides parsers for dependency manifest files.
package manifest

import (
	"errors"
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
	// Unread lists the lines that declare dependencies the parser did not
	// read. Only requirements.txt fills it today.
	Unread []types.UnreadLine
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
		if lockErr := lockFileError(manifestPath); lockErr != nil {
			return nil, lockErr
		}
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
		Unread:       unreadLines(manifestPath),
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

	return "", noManifestError(dir, "file")
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

// lockFileManifests maps a lock file, by its lower-case name, to the manifest
// CryptoDeps reads in its place. No lock file is parsed in any ecosystem.
var lockFileManifests = map[string]string{
	"go.sum":              "go.mod",
	"package-lock.json":   "package.json",
	"npm-shrinkwrap.json": "package.json",
	"yarn.lock":           "package.json",
	"pnpm-lock.yaml":      "package.json",
	"pipfile.lock":        "Pipfile",
	"poetry.lock":         "pyproject.toml",
}

// noManifestError is the error for a directory that holds no manifest
// CryptoDeps reads. When the directory holds a lock file the error names it,
// as the error for a lock file passed as the argument does: a directory
// holding only yarn.lock got the same bare message as an empty one.
func noManifestError(dir, files string) error {
	msg := fmt.Sprintf("no supported manifest %s found in %s", files, dir)
	locks, manifests := lockFilesIn(dir)
	switch len(locks) {
	case 0:
		return errors.New(msg)
	case 1:
		return fmt.Errorf("%s: %s is a lock file, and CryptoDeps reads %s instead, which this directory does not hold",
			msg, locks[0], manifests[0])
	default:
		return fmt.Errorf("%s: %s are lock files, and CryptoDeps reads %s instead, which this directory does not hold",
			msg, joinWithAnd(locks), joinWithAnd(manifests))
	}
}

// lockFilesIn returns the lock files directly in dir, in name order, and the
// manifests CryptoDeps reads in their place, each named once.
func lockFilesIn(dir string) (locks, manifests []string) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, nil
	}
	seen := make(map[string]bool)
	for _, e := range entries {
		manifest, ok := lockFileManifests[strings.ToLower(e.Name())]
		if !ok || !e.Type().IsRegular() {
			continue
		}
		locks = append(locks, e.Name())
		if !seen[manifest] {
			seen[manifest] = true
			manifests = append(manifests, manifest)
		}
	}
	return locks, manifests
}

// joinWithAnd joins names as a sentence lists them: "a", "a and b",
// "a, b and c".
func joinWithAnd(names []string) string {
	if len(names) < 2 {
		return strings.Join(names, "")
	}
	return strings.Join(names[:len(names)-1], ", ") + " and " + names[len(names)-1]
}

// lockFileError returns the error for a lock file passed as the manifest, or
// nil when path is not one. The suggested command is built from the path the
// user gave, so it runs as printed from the same directory.
func lockFileError(path string) error {
	manifest, ok := lockFileManifests[strings.ToLower(filepath.Base(path))]
	if !ok {
		return nil
	}
	next := filepath.Join(filepath.Dir(path), manifest)
	return fmt.Errorf("%s is a lock file, and CryptoDeps does not read lock files (it reads %s); to scan this project, run: cryptodeps analyze %s",
		path, manifest, shellQuote(next))
}

// shellQuote returns s as a single shell word, quoting it only when it holds a
// character the shell would split on or expand. "~" and "=" are not left bare:
// bash and zsh expand a "~" at the start of a word, and zsh reads a word
// starting with "=", such as =eq/go.mod, as a lookup of the command eq/go.mod.
func shellQuote(s string) string {
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("-_./:+,@%", r)) {
			return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
		}
	}
	return s
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
		return nil, nil, noManifestError(path, "files")
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
			Unread:       unreadLines(manifestPath),
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
