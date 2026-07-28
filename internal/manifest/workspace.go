// Copyright 2025-2026 CyberSecurity NonProfit (CSNP)
// SPDX-License-Identifier: Apache-2.0

package manifest

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/csnp/qramm-cryptodeps/pkg/types"
)

// DefaultSkipDirs contains directories that should be skipped during manifest discovery.
var DefaultSkipDirs = map[string]bool{
	"node_modules":     true,
	"vendor":           true,
	".git":             true,
	".svn":             true,
	".hg":              true,
	"dist":             true,
	"build":            true,
	".next":            true,
	"__pycache__":      true,
	".venv":            true,
	"venv":             true,
	".tox":             true,
	"target":           true, // Maven/Rust
	"bin":              true,
	"obj":              true, // .NET
	".idea":            true,
	".vscode":          true,
	"coverage":         true,
	".nyc_output":      true,
	".pytest_cache":    true,
	".mypy_cache":      true,
	".ruff_cache":      true,
	".gradle":          true,
	".m2":              true,
	"bower_components": true,
}

// ManifestFiles maps a manifest filename to whether cryptodeps can parse it.
// Discovery only picks up the names mapped to true.
//
// The false entries are listed rather than deleted because the reason they are
// excluded is not obvious. Discovering a manifest cryptodeps has no parser for
// turned it into a reported skip, and a skip forces exit 2. That made every
// polyglot repository an analysis error: a tree with a go.mod beside a
// Cargo.toml reported exit 2 rather than the exit 1 its two real quantum
// vulnerable findings had earned, so the CI signal the tool exists to emit was
// replaced by an error about a file cryptodeps never claimed to read.
// SupportedManifests has never listed these names.
//
// go.work is false for the same reason: workspace membership is resolved by
// parseGoWorkspace, which reads it directly and contributes the member go.mod
// files. The workspace file itself holds no dependencies to scan.
var ManifestFiles = map[string]bool{
	"go.mod":           true,
	"package.json":     true,
	"requirements.txt": true,
	"pyproject.toml":   true,
	"Pipfile":          true,
	"pom.xml":          true,

	"go.work":          false,
	"build.gradle":     false,
	"build.gradle.kts": false,
	"Cargo.toml":       false,
	"Gemfile":          false,
	"composer.json":    false,
}

// DiscoverManifests finds all manifest files in a directory tree.
// It uses a smart multi-layer approach:
// 1. Parse workspace configuration files (package.json workspaces, go.work, pnpm-workspace.yaml)
// 2. Recursively walk the directory tree for any manifests not covered by workspace config
// 3. Deduplicate and validate results
//
// It returns the usable manifests and, separately, every file that was
// recognised as a manifest by name but rejected by validation. The second
// return used to be discarded, which is what made a corrupt package.json
// invisible: it was dropped here, before any parser ran, so no parse error was
// ever produced and the scan reported a clean summary for the files that
// happened to survive.
func DiscoverManifests(root string) ([]string, []types.SkippedManifest, error) {
	root, err := filepath.Abs(root)
	if err != nil {
		return nil, nil, err
	}

	info, err := os.Stat(root)
	if err != nil {
		return nil, nil, err
	}

	// If it's a file, return just that file if it's a manifest
	if !info.IsDir() {
		if isManifestPath(root) {
			if err := validateManifest(root); err != nil {
				return nil, []types.SkippedManifest{{Path: root, Reason: err.Error()}}, nil
			}
			return []string{root}, nil, nil
		}
		return nil, nil, nil
	}

	seen := make(map[string]bool)
	var manifests []string

	// Layer 1: Parse workspace configurations
	workspaceManifests, err := parseWorkspaceConfigs(root)
	if err == nil {
		for _, m := range workspaceManifests {
			absPath, _ := filepath.Abs(m)
			if !seen[absPath] {
				seen[absPath] = true
				manifests = append(manifests, absPath)
			}
		}
	}

	// Layer 2: Recursive walk for any manifests not in workspace config
	walkManifests, err := walkForManifests(root)
	if err == nil {
		for _, m := range walkManifests {
			absPath, _ := filepath.Abs(m)
			if !seen[absPath] {
				seen[absPath] = true
				manifests = append(manifests, absPath)
			}
		}
	}

	// Layer 3: Validate, keeping the rejects so the caller can report them.
	// Sorted so that discovery order does not depend on how the two layers
	// above happened to interleave.
	sort.Strings(manifests)
	var validated []string
	var skipped []types.SkippedManifest
	for _, m := range manifests {
		if err := validateManifest(m); err != nil {
			skipped = append(skipped, types.SkippedManifest{Path: m, Reason: err.Error()})
			continue
		}
		validated = append(validated, m)
	}

	return validated, skipped, nil
}

// parseWorkspaceConfigs detects and parses workspace configuration files.
func parseWorkspaceConfigs(root string) ([]string, error) {
	var manifests []string

	// Check for npm/yarn workspaces in package.json
	pkgJSON := filepath.Join(root, "package.json")
	if npmManifests, err := parseNPMWorkspaces(pkgJSON); err == nil {
		manifests = append(manifests, npmManifests...)
	}

	// Check for pnpm workspaces
	pnpmWorkspace := filepath.Join(root, "pnpm-workspace.yaml")
	if pnpmManifests, err := parsePNPMWorkspaces(pnpmWorkspace, root); err == nil {
		manifests = append(manifests, pnpmManifests...)
	}

	// Check for Go workspaces
	goWork := filepath.Join(root, "go.work")
	if goManifests, err := parseGoWorkspace(goWork, root); err == nil {
		manifests = append(manifests, goManifests...)
	}

	return manifests, nil
}

// parseNPMWorkspaces parses the workspaces field from package.json.
func parseNPMWorkspaces(pkgJSONPath string) ([]string, error) {
	data, err := os.ReadFile(pkgJSONPath)
	if err != nil {
		return nil, err
	}

	var pkg struct {
		Workspaces interface{} `json:"workspaces"`
	}
	if err := json.Unmarshal(data, &pkg); err != nil {
		return nil, err
	}

	if pkg.Workspaces == nil {
		return nil, nil
	}

	var patterns []string

	// Workspaces can be an array or an object with "packages" field
	switch ws := pkg.Workspaces.(type) {
	case []interface{}:
		for _, p := range ws {
			if s, ok := p.(string); ok {
				patterns = append(patterns, s)
			}
		}
	case map[string]interface{}:
		if packages, ok := ws["packages"].([]interface{}); ok {
			for _, p := range packages {
				if s, ok := p.(string); ok {
					patterns = append(patterns, s)
				}
			}
		}
	}

	// Expand glob patterns and find package.json files
	root := filepath.Dir(pkgJSONPath)
	var manifests []string

	for _, pattern := range patterns {
		// Handle patterns like "packages/*" or "apps/**"
		matches, err := filepath.Glob(filepath.Join(root, pattern))
		if err != nil {
			continue
		}

		for _, match := range matches {
			pkgFile := filepath.Join(match, "package.json")
			if _, err := os.Stat(pkgFile); err == nil {
				manifests = append(manifests, pkgFile)
			}
		}
	}

	// Also include the root package.json
	manifests = append(manifests, pkgJSONPath)

	return manifests, nil
}

// parsePNPMWorkspaces parses pnpm-workspace.yaml.
func parsePNPMWorkspaces(workspacePath, root string) ([]string, error) {
	data, err := os.ReadFile(workspacePath)
	if err != nil {
		return nil, err
	}

	var workspace struct {
		Packages []string `yaml:"packages"`
	}
	if err := yaml.Unmarshal(data, &workspace); err != nil {
		return nil, err
	}

	var manifests []string
	for _, pattern := range workspace.Packages {
		// Skip negation patterns
		if strings.HasPrefix(pattern, "!") {
			continue
		}

		matches, err := filepath.Glob(filepath.Join(root, pattern))
		if err != nil {
			continue
		}

		for _, match := range matches {
			pkgFile := filepath.Join(match, "package.json")
			if _, err := os.Stat(pkgFile); err == nil {
				manifests = append(manifests, pkgFile)
			}
		}
	}

	// Include root package.json if exists
	rootPkg := filepath.Join(root, "package.json")
	if _, err := os.Stat(rootPkg); err == nil {
		manifests = append(manifests, rootPkg)
	}

	return manifests, nil
}

// parseGoWorkspace parses go.work file.
func parseGoWorkspace(goWorkPath, root string) ([]string, error) {
	data, err := os.ReadFile(goWorkPath)
	if err != nil {
		return nil, err
	}

	var manifests []string
	lines := strings.Split(string(data), "\n")
	inUseBlock := false

	for _, line := range lines {
		line = strings.TrimSpace(line)

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "//") {
			continue
		}

		// Handle use block
		if line == "use (" {
			inUseBlock = true
			continue
		}
		if line == ")" {
			inUseBlock = false
			continue
		}

		// Handle single use directive or lines within use block
		var modulePath string
		if strings.HasPrefix(line, "use ") {
			modulePath = strings.TrimPrefix(line, "use ")
		} else if inUseBlock {
			modulePath = line
		}

		if modulePath != "" {
			// Clean up the path (remove quotes if present)
			modulePath = strings.Trim(modulePath, `"'`)
			modulePath = strings.TrimSpace(modulePath)

			goModPath := filepath.Join(root, modulePath, "go.mod")
			if _, err := os.Stat(goModPath); err == nil {
				manifests = append(manifests, goModPath)
			}
		}
	}

	return manifests, nil
}

// walkForManifests recursively walks the directory tree to find manifest files.
func walkForManifests(root string) ([]string, error) {
	var manifests []string

	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil // Skip errors, continue walking
		}

		// Skip hidden directories (except .git which is already in skip list)
		name := info.Name()
		if info.IsDir() {
			// Skip directories in the skip list
			if DefaultSkipDirs[name] {
				return filepath.SkipDir
			}
			// Skip hidden directories
			if strings.HasPrefix(name, ".") && name != "." {
				return filepath.SkipDir
			}
			return nil
		}

		// Check if this is a manifest file
		if isManifestPath(path) {
			// Skip go.work files in the recursive walk (handled separately)
			if name == "go.work" {
				return nil
			}
			manifests = append(manifests, path)
		}

		return nil
	})

	return manifests, err
}

// requirementsFilePattern matches the requirements.txt family. Python projects
// routinely split dependencies across requirements-dev.txt, requirements-prod.txt,
// requirements_test.txt and similar, and an exact match on "requirements.txt"
// silently skips all of them.
var requirementsFilePattern = regexp.MustCompile(`^requirements([-_.][^/]*)?\.txt$`)

// isRequirementsFile reports whether a filename belongs to the requirements.txt
// family.
func isRequirementsFile(name string) bool {
	return requirementsFilePattern.MatchString(strings.ToLower(name))
}

// isManifestFile checks if a filename is a recognized manifest file.
func isManifestFile(name string) bool {
	return ManifestFiles[name] || isRequirementsFile(name)
}

// isManifestPath checks whether a path is a manifest, including layouts that
// only make sense with the parent directory in hand. The common
// requirements/base.txt and requirements/dev.txt layout puts pip requirements in
// files whose own names carry no hint of their contents.
func isManifestPath(path string) bool {
	name := filepath.Base(path)
	if isManifestFile(name) {
		return true
	}
	if strings.EqualFold(filepath.Base(filepath.Dir(path)), "requirements") &&
		strings.EqualFold(filepath.Ext(name), ".txt") {
		return true
	}
	return false
}

// validateManifest reports whether a manifest file is usable, and returns the
// reason when it is not. The reason is shown to the user, so it names the defect
// rather than just saying the file was skipped.
func validateManifest(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("cannot read file: %w", err)
	}

	if info.Size() == 0 {
		return errors.New("file is empty")
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("cannot read file: %w", err)
	}

	filename := filepath.Base(path)

	// Basic validation based on file type
	switch filename {
	case "package.json":
		var pkg map[string]interface{}
		if err := json.Unmarshal(data, &pkg); err != nil {
			return fmt.Errorf("not valid JSON: %w", err)
		}
		return nil
	case "go.mod":
		if !strings.Contains(string(data), "module ") {
			return errors.New("no module directive")
		}
		return nil
	case "pom.xml":
		if !strings.Contains(string(data), "<project") {
			return errors.New("no <project> element")
		}
		return nil
	default:
		// requirements.txt family, pyproject.toml, Pipfile and anything else
		// recognised by name: non-empty is all we can check cheaply. Real
		// defects surface as parse errors, which are reported the same way.
		return nil
	}
}

// GetRelativePath returns a relative path from root to the manifest.
func GetRelativePath(root, manifest string) string {
	rel, err := filepath.Rel(root, manifest)
	if err != nil {
		return manifest
	}
	return rel
}
