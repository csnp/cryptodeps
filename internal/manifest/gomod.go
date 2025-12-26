// Copyright 2024-2025 CSNP (csnp.org)
// SPDX-License-Identifier: Apache-2.0

package manifest

import (
	"bufio"
	"os"
	"regexp"
	"strings"

	"github.com/csnp/qramm-cryptodeps/pkg/types"
)

// GoModParser parses Go module files (go.mod).
type GoModParser struct{}

// Ecosystem returns the ecosystem this parser handles.
func (p *GoModParser) Ecosystem() types.Ecosystem {
	return types.EcosystemGo
}

// Filenames returns the manifest filenames this parser handles.
func (p *GoModParser) Filenames() []string {
	return []string{"go.mod"}
}

// Parse parses a go.mod file and returns the list of dependencies.
func (p *GoModParser) Parse(path string) ([]types.Dependency, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var deps []types.Dependency
	var inRequireBlock bool
	var inIndirectBlock bool

	// Regex to match require lines
	// Examples:
	//   require github.com/pkg/errors v0.9.1
	//   github.com/pkg/errors v0.9.1
	//   github.com/pkg/errors v0.9.1 // indirect
	singleRequire := regexp.MustCompile(`^require\s+(\S+)\s+(\S+)`)
	blockEntry := regexp.MustCompile(`^\s*(\S+)\s+(\S+)(?:\s+//\s*indirect)?`)

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "//") {
			continue
		}

		// Check for require block start
		if strings.HasPrefix(line, "require (") || line == "require(" {
			inRequireBlock = true
			continue
		}

		// Check for block end
		if line == ")" {
			inRequireBlock = false
			inIndirectBlock = false
			continue
		}

		// Single-line require
		if matches := singleRequire.FindStringSubmatch(line); matches != nil {
			dep := types.Dependency{
				Name:      matches[1],
				Version:   cleanVersion(matches[2]),
				Ecosystem: types.EcosystemGo,
				Direct:    !strings.Contains(line, "// indirect"),
			}
			deps = append(deps, dep)
			continue
		}

		// Inside require block
		if inRequireBlock {
			// Check for indirect marker
			if strings.Contains(line, "// indirect") {
				inIndirectBlock = true
			}

			if matches := blockEntry.FindStringSubmatch(line); matches != nil {
				// Skip module directive and other non-dependency lines
				if matches[1] == "module" || matches[1] == "go" || matches[1] == "toolchain" {
					continue
				}

				dep := types.Dependency{
					Name:      matches[1],
					Version:   cleanVersion(matches[2]),
					Ecosystem: types.EcosystemGo,
					Direct:    !strings.Contains(line, "// indirect") && !inIndirectBlock,
				}
				deps = append(deps, dep)
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return deps, nil
}

// cleanVersion removes any prefixes or suffixes from version strings.
func cleanVersion(version string) string {
	// Remove leading 'v' if present for normalization
	// But keep it for Go modules as it's the standard
	version = strings.TrimSpace(version)

	// Handle replace directives (e.g., "=> ./local")
	if idx := strings.Index(version, "=>"); idx != -1 {
		version = strings.TrimSpace(version[:idx])
	}

	return version
}
