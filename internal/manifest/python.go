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

// PythonParser parses Python dependency files (requirements.txt, pyproject.toml).
type PythonParser struct{}

// Ecosystem returns the ecosystem this parser handles.
func (p *PythonParser) Ecosystem() types.Ecosystem {
	return types.EcosystemPyPI
}

// Filenames returns the manifest filenames this parser handles.
func (p *PythonParser) Filenames() []string {
	return []string{"requirements.txt", "pyproject.toml", "Pipfile"}
}

// Parse parses a Python requirements file and returns the list of dependencies.
func (p *PythonParser) Parse(path string) ([]types.Dependency, error) {
	// Determine file type
	if strings.HasSuffix(path, "requirements.txt") {
		return p.parseRequirementsTxt(path)
	}
	// TODO: Implement pyproject.toml and Pipfile parsing
	return p.parseRequirementsTxt(path)
}

// parseRequirementsTxt parses a requirements.txt file.
func (p *PythonParser) parseRequirementsTxt(path string) ([]types.Dependency, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var deps []types.Dependency

	// Regex patterns for requirements.txt
	// package==1.0.0
	// package>=1.0.0
	// package~=1.0.0
	// package[extra]==1.0.0
	requirementPattern := regexp.MustCompile(`^([a-zA-Z0-9_-]+)(?:\[[^\]]+\])?([<>=!~]+)?(.+)?`)

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Skip options like -r, -e, --index-url, etc.
		if strings.HasPrefix(line, "-") {
			continue
		}

		// Skip URLs
		if strings.Contains(line, "://") {
			continue
		}

		// Parse requirement line
		if matches := requirementPattern.FindStringSubmatch(line); matches != nil {
			name := matches[1]
			version := ""
			if len(matches) > 3 && matches[3] != "" {
				version = strings.TrimSpace(matches[3])
				// Remove comments from version
				if idx := strings.Index(version, "#"); idx != -1 {
					version = strings.TrimSpace(version[:idx])
				}
				// Remove environment markers
				if idx := strings.Index(version, ";"); idx != -1 {
					version = strings.TrimSpace(version[:idx])
				}
			}

			deps = append(deps, types.Dependency{
				Name:      name,
				Version:   version,
				Ecosystem: types.EcosystemPyPI,
				Direct:    true,
			})
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return deps, nil
}
