// Copyright 2024-2025 CSNP (csnp.org)
// SPDX-License-Identifier: Apache-2.0

package manifest

import (
	"encoding/json"
	"os"
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

	// Parse production dependencies (direct)
	for name, version := range pkg.Dependencies {
		deps = append(deps, types.Dependency{
			Name:      name,
			Version:   cleanNPMVersion(version),
			Ecosystem: types.EcosystemNPM,
			Direct:    true,
		})
	}

	// Parse dev dependencies (direct but dev-only)
	for name, version := range pkg.DevDependencies {
		deps = append(deps, types.Dependency{
			Name:      name,
			Version:   cleanNPMVersion(version),
			Ecosystem: types.EcosystemNPM,
			Direct:    true,
		})
	}

	// Parse peer dependencies
	for name, version := range pkg.PeerDependencies {
		deps = append(deps, types.Dependency{
			Name:      name,
			Version:   cleanNPMVersion(version),
			Ecosystem: types.EcosystemNPM,
			Direct:    true,
		})
	}

	// Parse optional dependencies
	for name, version := range pkg.OptionalDependencies {
		deps = append(deps, types.Dependency{
			Name:      name,
			Version:   cleanNPMVersion(version),
			Ecosystem: types.EcosystemNPM,
			Direct:    true,
		})
	}

	return deps, nil
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
