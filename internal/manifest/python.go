// Copyright 2025-2026 CyberSecurity NonProfit (CSNP)
// SPDX-License-Identifier: Apache-2.0

package manifest

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/BurntSushi/toml"
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

// Parse parses a Python dependency file and returns the list of dependencies.
//
// Each format is parsed by its own reader. Falling back to the requirements.txt
// line parser for TOML files produced entries named after TOML keys, so a
// pyproject.toml declaring cryptography as a dependency yielded a dependency
// literally named "dependencies" and the real package was never analyzed.
func (p *PythonParser) Parse(path string) ([]types.Dependency, error) {
	switch base := strings.ToLower(filepath.Base(path)); {
	case base == "pyproject.toml":
		return p.parsePyProject(path)
	case base == "pipfile":
		return p.parsePipfile(path)
	default:
		return p.parseRequirementsTxt(path)
	}
}

// pyProject models the dependency-bearing sections of pyproject.toml, covering
// both the PEP 621 standard layout and Poetry's own layout.
type pyProject struct {
	Project struct {
		Dependencies         []string            `toml:"dependencies"`
		OptionalDependencies map[string][]string `toml:"optional-dependencies"`
	} `toml:"project"`
	Tool struct {
		Poetry struct {
			Dependencies    map[string]any `toml:"dependencies"`
			DevDependencies map[string]any `toml:"dev-dependencies"`
			Group           map[string]struct {
				Dependencies map[string]any `toml:"dependencies"`
			} `toml:"group"`
		} `toml:"poetry"`
	} `toml:"tool"`
}

// parsePyProject reads PEP 621 and Poetry dependency declarations.
func (p *PythonParser) parsePyProject(path string) ([]types.Dependency, error) {
	var doc pyProject
	if _, err := toml.DecodeFile(path, &doc); err != nil {
		return nil, fmt.Errorf("parse pyproject.toml: %w", err)
	}

	var deps []types.Dependency
	seen := make(map[string]bool)

	add := func(name, version string, direct bool) {
		name = normalizePyPIName(name)
		if name == "" || seen[name] {
			return
		}
		seen[name] = true
		deps = append(deps, types.Dependency{
			Name:      name,
			Version:   strings.TrimSpace(version),
			Ecosystem: types.EcosystemPyPI,
			Direct:    direct,
		})
	}

	// PEP 621: dependencies are PEP 508 requirement strings.
	for _, spec := range doc.Project.Dependencies {
		name, version := splitRequirement(spec)
		add(name, version, true)
	}
	for _, group := range doc.Project.OptionalDependencies {
		for _, spec := range group {
			name, version := splitRequirement(spec)
			add(name, version, false)
		}
	}

	// Poetry: dependencies are a table keyed by package name, whose value is
	// either a version string or an inline table carrying a version field.
	poetry := doc.Tool.Poetry
	for name, constraint := range poetry.Dependencies {
		if strings.EqualFold(name, "python") {
			continue // the interpreter requirement, not a package
		}
		add(name, poetryVersion(constraint), true)
	}
	for name, constraint := range poetry.DevDependencies {
		add(name, poetryVersion(constraint), false)
	}
	for _, group := range poetry.Group {
		for name, constraint := range group.Dependencies {
			add(name, poetryVersion(constraint), false)
		}
	}

	sort.Slice(deps, func(i, j int) bool { return deps[i].Name < deps[j].Name })
	return deps, nil
}

// pipfile models the dependency sections of a Pipfile, which is also TOML.
type pipfile struct {
	Packages    map[string]any `toml:"packages"`
	DevPackages map[string]any `toml:"dev-packages"`
}

// parsePipfile reads a Pipfile.
func (p *PythonParser) parsePipfile(path string) ([]types.Dependency, error) {
	var doc pipfile
	if _, err := toml.DecodeFile(path, &doc); err != nil {
		return nil, fmt.Errorf("parse Pipfile: %w", err)
	}

	var deps []types.Dependency
	seen := make(map[string]bool)

	add := func(name string, constraint any, direct bool) {
		name = normalizePyPIName(name)
		if name == "" || seen[name] {
			return
		}
		seen[name] = true
		version := poetryVersion(constraint)
		if version == "*" {
			version = "" // Pipfile wildcard means unpinned
		}
		deps = append(deps, types.Dependency{
			Name:      name,
			Version:   strings.TrimSpace(version),
			Ecosystem: types.EcosystemPyPI,
			Direct:    direct,
		})
	}

	for name, constraint := range doc.Packages {
		add(name, constraint, true)
	}
	for name, constraint := range doc.DevPackages {
		add(name, constraint, false)
	}

	sort.Slice(deps, func(i, j int) bool { return deps[i].Name < deps[j].Name })
	return deps, nil
}

// poetryVersion extracts a version constraint from a Poetry or Pipfile value,
// which may be a bare string or an inline table such as
// {version = "^1.0", optional = true}.
func poetryVersion(constraint any) string {
	switch v := constraint.(type) {
	case string:
		return stripVersionOperator(v)
	case map[string]any:
		if version, ok := v["version"].(string); ok {
			return stripVersionOperator(version)
		}
		// A dependency declared by location rather than by version keeps its
		// locator, because dropping it does not merely lose information: it
		// leaves a name with no version, and the fetcher then downloads whatever
		// PyPI serves under that name. A `path = "../internal-lib"` dependency
		// was replaced by a public package of the same name, whose source was
		// then analyzed and reported as this project's. That is dependency
		// confusion performed by the scanner, and an attacker only has to
		// register the name of a company's local package to be handed the
		// attribution, and with pip building sdists, execution.
		//
		// Returned raw so the guards in the fetcher see what was really
		// declared: a path is refused as a local reference, and a URL or a
		// repository fails to resolve under its own name rather than silently
		// becoming a different package.
		for _, key := range [...]string{"path", "file", "url", "git"} {
			if locator, ok := v[key].(string); ok && strings.TrimSpace(locator) != "" {
				return locator
			}
		}
		return ""
	default:
		return ""
	}
}

// requirementNamePattern captures the package name and the remainder of a
// PEP 508 requirement string such as "cryptography[ssh]>=41.0.0; python_version<'4'".
var requirementNamePattern = regexp.MustCompile(`^([A-Za-z0-9][A-Za-z0-9._-]*)`)

// splitRequirement separates a PEP 508 requirement into name and version
// constraint, discarding extras and environment markers.
func splitRequirement(spec string) (name, version string) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return "", ""
	}

	// Drop environment markers, which follow a semicolon.
	if idx := strings.Index(spec, ";"); idx != -1 {
		spec = strings.TrimSpace(spec[:idx])
	}

	match := requirementNamePattern.FindStringSubmatch(spec)
	if match == nil {
		return "", ""
	}
	name = match[1]

	rest := strings.TrimSpace(spec[len(name):])
	// Drop extras such as [ssh].
	if strings.HasPrefix(rest, "[") {
		if idx := strings.Index(rest, "]"); idx != -1 {
			rest = strings.TrimSpace(rest[idx+1:])
		}
	}
	return name, stripVersionOperator(rest)
}

// stripVersionOperator removes the comparison operator from a version
// constraint, leaving the version it names.
//
// The requirements.txt reader has always done this, because its regex captures
// the operator separately and keeps only what follows. The pyproject.toml and
// Pipfile readers kept the whole constraint, so the same two packages declared
// in the two formats produced pycryptodome@3.20.0 from one and
// pycryptodome@==3.20.0 from the other. The CBOM emitter normalises the purl
// and the JSON and SARIF documents do not, so a single scan disagreed with
// itself and a consumer could not join the two by version. It also reached the
// fetcher, which builds a pip spec as name==version and would have asked for
// pycryptodome===3.20.0.
//
// Multi-constraint strings such as ">=1.0,<2.0" keep everything after the
// leading operator, which is what requirements.txt already produced for them.
func stripVersionOperator(constraint string) string {
	trimmed := strings.TrimLeft(strings.TrimSpace(constraint), "<>=!~^")
	return strings.TrimSpace(trimmed)
}

// normalizePyPIName applies PEP 503 normalization so that the same package
// written as Foo.Bar, foo-bar or foo_bar resolves to one entry.
func normalizePyPIName(name string) string {
	name = strings.TrimSpace(name)
	if name == "" {
		return ""
	}
	name = pypiSeparatorPattern.ReplaceAllString(name, "-")
	return strings.ToLower(name)
}

var pypiSeparatorPattern = regexp.MustCompile(`[-_.]+`)

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
