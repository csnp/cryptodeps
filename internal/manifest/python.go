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
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var doc pyProject
	if _, err := toml.Decode(string(data), &doc); err != nil {
		return nil, fmt.Errorf("parse pyproject.toml: %w", err)
	}

	var deps []types.Dependency
	seen := make(map[string]bool)
	lines := pyprojectDeclarationLines(data)

	add := func(section, name, version string, direct bool) {
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
			Line:      lines[section][name],
		})
	}

	// PEP 621: dependencies are PEP 508 requirement strings.
	for _, spec := range doc.Project.Dependencies {
		name, version := splitRequirement(spec)
		add("project.dependencies", name, version, true)
	}
	for _, group := range doc.Project.OptionalDependencies {
		for _, spec := range group {
			name, version := splitRequirement(spec)
			add("project.optional-dependencies", name, version, false)
		}
	}

	// Poetry: dependencies are a table keyed by package name, whose value is
	// either a version string or an inline table carrying a version field.
	poetry := doc.Tool.Poetry
	for name, constraint := range poetry.Dependencies {
		if strings.EqualFold(name, "python") {
			continue // the interpreter requirement, not a package
		}
		add("tool.poetry.dependencies", name, poetryVersion(constraint), true)
	}
	for name, constraint := range poetry.DevDependencies {
		add("tool.poetry.dev-dependencies", name, poetryVersion(constraint), false)
	}
	for _, group := range poetry.Group {
		for name, constraint := range group.Dependencies {
			add("tool.poetry.group", name, poetryVersion(constraint), false)
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
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var doc pipfile
	if _, err := toml.Decode(string(data), &doc); err != nil {
		return nil, fmt.Errorf("parse Pipfile: %w", err)
	}

	var deps []types.Dependency
	seen := make(map[string]bool)
	lines := pipfileDeclarationLines(data)

	add := func(section, name string, constraint any, direct bool) {
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
			Line:      lines[section][name],
		})
	}

	for name, constraint := range doc.Packages {
		add("packages", name, constraint, true)
	}
	for name, constraint := range doc.DevPackages {
		add("dev-packages", name, constraint, false)
	}

	sort.Slice(deps, func(i, j int) bool { return deps[i].Name < deps[j].Name })
	return deps, nil
}

// pyprojectDeclarationLines maps each pyproject.toml dependency section to the
// line declaring each package in it, by PEP 503 name.
//
// The TOML decoder keeps no positions, so the raw text is scanned for the
// sections the decoder reads, and only those: a name is located where the
// section declares it, not wherever it first appears in the file, which is as
// often a comment, a description or the project's own name. Sections are kept
// apart because the same package can be declared in two of them, and the line
// reported must be the declaration that produced the dependency.
func pyprojectDeclarationLines(data []byte) map[string]map[string]int {
	lines := make(map[string]map[string]int)
	for _, d := range scanTOMLDecls(data) {
		p := d.path
		switch {
		case pathIs(p, "project", "dependencies"):
			for _, s := range d.strings {
				name, _ := splitRequirement(s.value)
				recordDeclarationLine(lines, "project.dependencies", name, s.line)
			}
		case len(p) == 3 && p[0] == "project" && p[1] == "optional-dependencies":
			for _, s := range d.strings {
				name, _ := splitRequirement(s.value)
				recordDeclarationLine(lines, "project.optional-dependencies", name, s.line)
			}
		// A Poetry dependency is a key of its section, written as a key line,
		// as a dotted key on a parent table, or as a sub-table of its own. All
		// three put the package name at the same depth of the path.
		case len(p) >= 4 && p[0] == "tool" && p[1] == "poetry" &&
			(p[2] == "dependencies" || p[2] == "dev-dependencies"):
			recordDeclarationLine(lines, "tool.poetry."+p[2], p[3], d.line)
		case len(p) >= 6 && p[0] == "tool" && p[1] == "poetry" && p[2] == "group" && p[4] == "dependencies":
			recordDeclarationLine(lines, "tool.poetry.group", p[5], d.line)
		}
	}
	return lines
}

// pipfileDeclarationLines is pyprojectDeclarationLines for a Pipfile, whose
// packages are keys of its [packages] and [dev-packages] tables.
func pipfileDeclarationLines(data []byte) map[string]map[string]int {
	lines := make(map[string]map[string]int)
	for _, d := range scanTOMLDecls(data) {
		if len(d.path) >= 2 && (d.path[0] == "packages" || d.path[0] == "dev-packages") {
			recordDeclarationLine(lines, d.path[0], d.path[1], d.line)
		}
	}
	return lines
}

// recordDeclarationLine keeps the first line a section declares name on.
func recordDeclarationLine(lines map[string]map[string]int, section, name string, line int) {
	name = normalizePyPIName(name)
	if name == "" {
		return
	}
	if lines[section] == nil {
		lines[section] = make(map[string]int)
	}
	if _, ok := lines[section][name]; !ok {
		lines[section][name] = line
	}
}

// tomlDecl is one key or table header of a TOML document: its full dotted path
// from the root, the line it is written on, and every string in its value
// together with the line that string is on.
type tomlDecl struct {
	path    []string
	line    int
	strings []tomlString
}

type tomlString struct {
	value string
	line  int
}

// tomlToken is a lexical token of a TOML document. kind is 's' for a string,
// 'w' for a bare word, 'n' for a newline, or the punctuation byte itself.
type tomlToken struct {
	kind byte
	text string
	line int
}

// scanTOMLDecls lists the keys and table headers of a TOML document that has
// already decoded successfully, with their lines.
//
// It is a reader of positions and not a TOML parser: the decoder has already
// decided what the document means, and this only says where. It does have to
// read strings and arrays properly, because a line that merely looks like a
// header or a key inside a multi-line string or a multi-line array is not one.
// Inline tables are not entered: their keys are not reported.
func scanTOMLDecls(data []byte) []tomlDecl {
	toks := lexTOML(string(data))
	var decls []tomlDecl
	var table []string
	for i := 0; i < len(toks); {
		t := toks[i]
		switch t.kind {
		case 'n':
			i++
		case '[':
			// [table] or [[array.of.tables]]
			j := i + 1
			if j < len(toks) && toks[j].kind == '[' {
				j++
			}
			parts, next := readTOMLKey(toks, j)
			table = parts
			decls = append(decls, tomlDecl{path: parts, line: t.line})
			i = skipTOMLLine(toks, next)
		case 's', 'w':
			parts, next := readTOMLKey(toks, i)
			if next >= len(toks) || toks[next].kind != '=' {
				i = skipTOMLLine(toks, next)
				continue
			}
			decl := tomlDecl{path: append(append([]string{}, table...), parts...), line: t.line}
			depth := 0
			for i = next + 1; i < len(toks); i++ {
				v := toks[i]
				if v.kind == 'n' && depth == 0 {
					break
				}
				switch v.kind {
				case '[', '{':
					depth++
				case ']', '}':
					if depth > 0 {
						depth--
					}
				case 's':
					decl.strings = append(decl.strings, tomlString{value: v.text, line: v.line})
				}
			}
			decls = append(decls, decl)
		default:
			i = skipTOMLLine(toks, i+1)
		}
	}
	return decls
}

// readTOMLKey reads a dotted key starting at toks[i] and returns its parts and
// the index after it.
func readTOMLKey(toks []tomlToken, i int) ([]string, int) {
	var parts []string
	for i < len(toks) && (toks[i].kind == 's' || toks[i].kind == 'w') {
		parts = append(parts, toks[i].text)
		i++
		if i < len(toks) && toks[i].kind == '.' {
			i++
			continue
		}
		break
	}
	return parts, i
}

// skipTOMLLine returns the index of the next newline token at or after i.
func skipTOMLLine(toks []tomlToken, i int) int {
	for i < len(toks) && toks[i].kind != 'n' {
		i++
	}
	return i
}

// lexTOML splits a TOML document into tokens, dropping whitespace and comments.
func lexTOML(src string) []tomlToken {
	var toks []tomlToken
	line := 1
	for i := 0; i < len(src); {
		c := src[i]
		switch {
		case c == '\n':
			toks = append(toks, tomlToken{kind: 'n', line: line})
			line++
			i++
		case c == ' ' || c == '\t' || c == '\r':
			i++
		case c == '#':
			for i < len(src) && src[i] != '\n' {
				i++
			}
		case strings.HasPrefix(src[i:], `"""`) || strings.HasPrefix(src[i:], "'''"):
			delim := src[i : i+3]
			end := strings.Index(src[i+3:], delim)
			if end < 0 {
				return toks // unterminated, so nothing after it can be placed
			}
			body := src[i+3 : i+3+end]
			toks = append(toks, tomlToken{kind: 's', text: body, line: line})
			line += strings.Count(body, "\n")
			i += 3 + end + 3
		case c == '"':
			var b strings.Builder
			j := i + 1
			for j < len(src) && src[j] != '"' && src[j] != '\n' {
				if src[j] == '\\' && j+1 < len(src) {
					b.WriteByte(src[j+1])
					j += 2
					continue
				}
				b.WriteByte(src[j])
				j++
			}
			toks = append(toks, tomlToken{kind: 's', text: b.String(), line: line})
			if j < len(src) && src[j] == '"' {
				j++
			}
			i = j
		case c == '\'':
			j := i + 1
			for j < len(src) && src[j] != '\'' && src[j] != '\n' {
				j++
			}
			toks = append(toks, tomlToken{kind: 's', text: src[i+1 : j], line: line})
			if j < len(src) && src[j] == '\'' {
				j++
			}
			i = j
		case strings.IndexByte("[]{}=,.", c) >= 0:
			toks = append(toks, tomlToken{kind: c, line: line})
			i++
		default:
			j := i
			for j < len(src) && strings.IndexByte(" \t\r\n#[]{}=,.\"'", src[j]) < 0 {
				j++
			}
			toks = append(toks, tomlToken{kind: 'w', text: src[i:j], line: line})
			i = j
		}
	}
	return toks
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

// directReferencePattern matches the name of a PEP 508 direct reference such
// as "paramiko @ https://example.org/paramiko.tar.gz".
var directReferencePattern = regexp.MustCompile(`^([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*@`)

// unreadLines lists the lines of a requirements.txt that declare dependencies
// parseRequirementsTxt does not read: "-r" includes, editable installs and URL
// requirements. It returns nil for every other manifest.
//
// parseRequirementsTxt skips these lines, and the scan used to say nothing
// about them, so a requirements.txt holding "-r extra.txt" was reported as
// though extra.txt did not exist. A URL is never copied into the result,
// because one in a manifest can carry credentials. That holds for an "-r"
// include as well: pip fetches "-r https://host/reqs.txt", so such a line is
// listed by its kind and line number only, while "-r extra.txt" names the file.
func unreadLines(path string) []types.UnreadLine {
	if strings.ToLower(filepath.Base(path)) != "requirements.txt" {
		return nil
	}
	file, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer file.Close()

	var unread []types.UnreadLine
	scanner := bufio.NewScanner(file)
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		line := strings.TrimSpace(scanner.Text())
		if idx := strings.Index(line, " #"); idx != -1 {
			line = strings.TrimSpace(line[:idx])
		}
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		if include, ok := requirementOption(line, "-r", "--requirement"); ok {
			if strings.Contains(include, "://") {
				unread = append(unread, types.UnreadLine{Line: lineNo,
					Reason: "included requirements URLs are not followed, so the dependencies it declares are not analyzed"})
				continue
			}
			unread = append(unread, types.UnreadLine{Line: lineNo, Name: include,
				Reason: "included requirements files are not followed, so the dependencies it declares are not analyzed"})
			continue
		}
		if _, ok := requirementOption(line, "-e", "--editable"); ok {
			unread = append(unread, types.UnreadLine{Line: lineNo,
				Reason: "editable installs (-e) are not read, so this dependency is not analyzed"})
			continue
		}
		if strings.HasPrefix(line, "-") {
			// Other options (--index-url, -c, --hash) declare no dependency.
			continue
		}
		if strings.Contains(line, "://") {
			if m := directReferencePattern.FindStringSubmatch(line); m != nil {
				unread = append(unread, types.UnreadLine{Line: lineNo, Name: m[1],
					Reason: "name @ URL references are not read, so this dependency is not analyzed"})
			} else {
				unread = append(unread, types.UnreadLine{Line: lineNo,
					Reason: "URL requirements are not read, so this dependency is not analyzed"})
			}
		}
	}
	return unread
}

// requirementOption reports whether line is the option short or long, and
// returns its value. It accepts "-r file", "-rfile", "--requirement file" and
// "--requirement=file".
func requirementOption(line, short, long string) (string, bool) {
	switch {
	case strings.HasPrefix(line, long+"="):
		return strings.TrimSpace(line[len(long)+1:]), true
	case line == long || strings.HasPrefix(line, long+" ") || strings.HasPrefix(line, long+"\t"):
		return strings.TrimSpace(line[len(long):]), true
	case strings.HasPrefix(line, short) && !strings.HasPrefix(line, "--"):
		return strings.TrimSpace(line[len(short):]), true
	}
	return "", false
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
	lineNo := 0
	for scanner.Scan() {
		lineNo++
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
				Line:      lineNo,
			})
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return deps, nil
}
