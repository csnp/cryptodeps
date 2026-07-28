// Copyright 2025-2026 CyberSecurity NonProfit (CSNP)
// SPDX-License-Identifier: Apache-2.0

package manifest

import (
	"encoding/json"
	"os"
	"sort"
	"strings"

	"github.com/csnp/qramm-cryptodeps/pkg/types"
)

// NPMParser parses npm package.json files.
type NPMParser struct{}

// Ecosystem returns the ecosystem this parser handles.
func (p *NPMParser) Ecosystem() types.Ecosystem {
	return types.EcosystemNPM
}

// Filenames returns the manifest filenames this parser handles.
func (p *NPMParser) Filenames() []string {
	return []string{"package.json", "package-lock.json"}
}

// packageJSON represents the structure of a package.json file.
type packageJSON struct {
	Name            string            `json:"name"`
	Version         string            `json:"version"`
	Dependencies    map[string]string `json:"dependencies"`
	DevDependencies map[string]string `json:"devDependencies"`
	PeerDependencies map[string]string `json:"peerDependencies"`
	OptionalDependencies map[string]string `json:"optionalDependencies"`
}

// Parse parses a package.json file and returns the list of dependencies.
func (p *NPMParser) Parse(path string) ([]types.Dependency, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var pkg packageJSON
	if err := json.Unmarshal(data, &pkg); err != nil {
		return nil, err
	}

	var deps []types.Dependency

	// Each block is emitted in sorted order. Go randomises map iteration, so
	// ranging over these maps directly made the whole report shuffle between
	// runs of the same scan, which breaks diffable CI output and reproducible
	// SBOMs even though the finding set itself was stable.
	for _, block := range []map[string]string{
		pkg.Dependencies,
		pkg.DevDependencies,
		pkg.PeerDependencies,
		pkg.OptionalDependencies,
	} {
		for _, name := range sortedKeys(block) {
			deps = append(deps, types.Dependency{
				Name:      name,
				Version:   cleanNPMVersion(block[name]),
				Ecosystem: types.EcosystemNPM,
				Direct:    true,
			})
		}
	}

	return deps, nil
}

// sortedKeys returns a map's keys in a stable order.
func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// cleanNPMVersion normalizes npm version strings.
func cleanNPMVersion(version string) string {
	version = strings.TrimSpace(version)

	// Remove semver range prefixes for database lookups
	// ^1.2.3 -> 1.2.3
	// ~1.2.3 -> 1.2.3
	// >=1.2.3 -> 1.2.3
	// 1.2.x -> 1.2.x (keep wildcards)
	prefixes := []string{"^", "~", ">=", ">", "<=", "<", "="}
	for _, prefix := range prefixes {
		version = strings.TrimPrefix(version, prefix)
	}

	// Handle version ranges (e.g., "1.0.0 - 2.0.0")
	if idx := strings.Index(version, " - "); idx != -1 {
		version = strings.TrimSpace(version[:idx])
	}

	// Handle OR ranges (e.g., "1.0.0 || 2.0.0")
	if idx := strings.Index(version, " || "); idx != -1 {
		version = strings.TrimSpace(version[:idx])
	}

	return version
}
