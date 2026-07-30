// Copyright 2025-2026 CyberSecurity NonProfit (CSNP)
// SPDX-License-Identifier: Apache-2.0

package manifest

import (
	"os"
	"path/filepath"
	"testing"
)

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

// TestRequirementsFamilyIsRecognized is the regression guard for issue #1.
// Matching only the exact name "requirements.txt" silently skipped the
// requirements-dev.txt and requirements-prod.txt files that most Python
// projects actually use.
func TestRequirementsFamilyIsRecognized(t *testing.T) {
	tests := []struct {
		name string
		want bool
	}{
		{"requirements.txt", true},
		{"requirements-dev.txt", true},
		{"requirements-prod.txt", true},
		{"requirements_test.txt", true},
		{"requirements.dev.txt", true},
		{"REQUIREMENTS-DEV.TXT", true},
		{"notrequirements.txt", false},
		{"requirements.md", false},
		{"readme.txt", false},
		{"requirements", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isRequirementsFile(tt.name); got != tt.want {
				t.Errorf("isRequirementsFile(%q) = %v, want %v", tt.name, got, tt.want)
			}
		})
	}
}

// TestRequirementsDirectoryLayoutIsRecognized covers the requirements/base.txt
// layout, where the filename alone carries no hint of its contents.
func TestRequirementsDirectoryLayoutIsRecognized(t *testing.T) {
	if !isManifestPath(filepath.Join("proj", "requirements", "base.txt")) {
		t.Error("requirements/base.txt not recognized as a manifest")
	}
	if !isManifestPath(filepath.Join("proj", "requirements", "dev.txt")) {
		t.Error("requirements/dev.txt not recognized as a manifest")
	}
	if isManifestPath(filepath.Join("proj", "docs", "notes.txt")) {
		t.Error("docs/notes.txt wrongly recognized as a manifest")
	}
}

// TestDiscoverFindsRequirementsFamily walks a real tree, which is what the
// reporter was doing.
func TestDiscoverFindsRequirementsFamily(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "requirements.txt"), "requests==2.31.0\n")
	writeFile(t, filepath.Join(dir, "requirements-dev.txt"), "cryptography==41.0.0\n")
	writeFile(t, filepath.Join(dir, "requirements-prod.txt"), "pyjwt>=2.0\n")
	writeFile(t, filepath.Join(dir, "requirements", "base.txt"), "pycryptodome==3.19.0\n")

	found, skipped, err := DiscoverManifests(dir)
	if err != nil {
		t.Fatalf("discover: %v", err)
	}
	if len(skipped) != 0 {
		t.Errorf("no manifest should have been skipped, got %v", skipped)
	}

	seen := make(map[string]bool)
	for _, path := range found {
		seen[filepath.Base(path)] = true
	}
	for _, want := range []string{
		"requirements.txt", "requirements-dev.txt", "requirements-prod.txt", "base.txt",
	} {
		if !seen[want] {
			t.Errorf("%s was not discovered; found %v", want, found)
		}
	}
}

// TestPyProjectIsNotParsedAsRequirements guards a silent data-integrity defect.
// pyproject.toml was advertised as supported but fell through to the
// requirements.txt line parser, which produced dependencies named after TOML
// keys. A project depending on cryptography reported no cryptographic usage at
// all, which is a false negative on this tool's core purpose.
func TestPyProjectIsNotParsedAsRequirements(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "pyproject.toml")
	writeFile(t, path, `
[project]
name = "demo"
requires-python = ">=3.11"
dependencies = ["cryptography==41.0.0", "pyjwt>=2.0"]

[project.optional-dependencies]
dev = ["pytest>=7.0"]

[build-system]
requires = ["setuptools>=61"]
`)

	deps, err := (&PythonParser{}).Parse(path)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	byName := make(map[string]string)
	for _, d := range deps {
		byName[d.Name] = d.Version
	}

	// The real dependencies must be present.
	if _, ok := byName["cryptography"]; !ok {
		t.Errorf("cryptography not parsed; got %v", byName)
	}
	if _, ok := byName["pyjwt"]; !ok {
		t.Errorf("pyjwt not parsed; got %v", byName)
	}
	if _, ok := byName["pytest"]; !ok {
		t.Errorf("optional dependency pytest not parsed; got %v", byName)
	}

	// TOML keys must not appear as dependencies.
	for _, bogus := range []string{"name", "dependencies", "requires-python", "requires", "build-system"} {
		if _, ok := byName[bogus]; ok {
			t.Errorf("TOML key %q was parsed as a dependency; got %v", bogus, byName)
		}
	}

	// setuptools is a build requirement, not a project dependency.
	if _, ok := byName["setuptools"]; ok {
		t.Errorf("build-system requirement leaked into dependencies; got %v", byName)
	}
}

// TestPyProjectPoetryLayout covers Poetry projects, which declare dependencies
// as a TOML table rather than PEP 508 strings.
func TestPyProjectPoetryLayout(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "pyproject.toml")
	writeFile(t, path, `
[tool.poetry]
name = "demo"

[tool.poetry.dependencies]
python = "^3.11"
cryptography = "41.0.0"
requests = {version = "^2.31", optional = true}

[tool.poetry.group.dev.dependencies]
pytest = "^7.0"
`)

	deps, err := (&PythonParser{}).Parse(path)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	byName := make(map[string]string)
	for _, d := range deps {
		byName[d.Name] = d.Version
	}

	if got := byName["cryptography"]; got != "41.0.0" {
		t.Errorf("cryptography version = %q, want 41.0.0; got all %v", got, byName)
	}
	// The caret is a constraint operator, not part of the version. Keeping it
	// put "^2.31" in the JSON version field and in the pip spec the fetcher
	// builds, while the same package declared in requirements.txt gave "2.31".
	if got, ok := byName["requests"]; !ok || got != "2.31" {
		t.Errorf("requests from inline table = %q (present=%v), want 2.31", got, ok)
	}
	if _, ok := byName["pytest"]; !ok {
		t.Errorf("dev group dependency pytest missing; got %v", byName)
	}
	// The interpreter constraint is not a package.
	if _, ok := byName["python"]; ok {
		t.Errorf("python interpreter constraint parsed as a dependency; got %v", byName)
	}
}

// TestPipfileIsParsedAsTOML covers Pipfile, which was also falling through to
// the requirements parser.
func TestPipfileIsParsedAsTOML(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "Pipfile")
	writeFile(t, path, `
[[source]]
url = "https://pypi.org/simple"

[packages]
cryptography = "==41.0.0"
requests = "*"

[dev-packages]
pytest = ">=7.0"
`)

	deps, err := (&PythonParser{}).Parse(path)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	byName := make(map[string]string)
	for _, d := range deps {
		byName[d.Name] = d.Version
	}

	// requirements.txt has always yielded "41.0.0" for the same declaration.
	// The two formats disagreeing meant one scan's SARIF said
	// cryptography@==41.0.0 while its CBOM purl said cryptography@41.0.0.
	if got := byName["cryptography"]; got != "41.0.0" {
		t.Errorf("cryptography = %q, want 41.0.0; got all %v", got, byName)
	}
	if got, ok := byName["requests"]; !ok || got != "" {
		t.Errorf("wildcard requests = %q (present=%v), want an empty version", got, ok)
	}
	if _, ok := byName["pytest"]; !ok {
		t.Errorf("dev package pytest missing; got %v", byName)
	}
	if _, ok := byName["url"]; ok {
		t.Errorf("source url parsed as a dependency; got %v", byName)
	}
}

// TestSplitRequirementHandlesPEP508 checks extras and environment markers are
// stripped rather than becoming part of the package name, and that the version
// field carries a version.
//
// The comparison operator belongs to the constraint, not to the version. The
// requirements.txt reader drops it, the TOML readers kept it, and the same two
// packages therefore appeared as pycryptodome@3.20.0 in one scan and
// pycryptodome@==3.20.0 in another. Within a single scan the CBOM normalised
// the purl and JSON and SARIF did not, so a consumer could not join the two
// documents by version.
func TestSplitRequirementHandlesPEP508(t *testing.T) {
	tests := []struct {
		spec        string
		wantName    string
		wantVersion string
	}{
		{"cryptography==41.0.0", "cryptography", "41.0.0"},
		{"cryptography[ssh]>=41.0.0", "cryptography", "41.0.0"},
		{`pyjwt>=2.0; python_version<"4"`, "pyjwt", "2.0"},
		{"requests", "requests", ""},
		{"  flask == 3.0  ", "flask", "3.0"},
		// Everything after the leading operator is kept, which is what the
		// requirements.txt reader has always produced for a compound
		// constraint.
		{"urllib3>=1.26,<2.0", "urllib3", "1.26,<2.0"},
	}

	for _, tt := range tests {
		t.Run(tt.spec, func(t *testing.T) {
			name, version := splitRequirement(tt.spec)
			if name != tt.wantName {
				t.Errorf("name = %q, want %q", name, tt.wantName)
			}
			if version != tt.wantVersion {
				t.Errorf("version = %q, want %q", version, tt.wantVersion)
			}
		})
	}
}

// TestPoetryLocationDependencyKeepsItsLocator is the regression test for a
// dependency confusion the new TOML parser introduced.
//
// poetryVersion returned "" for an inline table with no version key, which
// discarded the path or repository the dependency was actually declared by. The
// fetcher then had a name with no version and downloaded whatever PyPI serves
// under that name, so a `path = "../internal-lib"` dependency was replaced by a
// public package of the same name and that package's source was analyzed and
// reported as this project's. An attacker only has to register the name of a
// company's local package to be handed the attribution, and because pip builds
// sdists, the execution too.
//
// The locator is kept so the fetcher's own guards see what was declared: a path
// is refused as a local reference rather than silently substituted.
func TestPoetryLocationDependencyKeepsItsLocator(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "pyproject.toml")
	writeFile(t, path, `
[tool.poetry]
name = "demo"

[tool.poetry.dependencies]
python = "^3.11"
cryptography = "41.0.0"
internal-lib = {path = "../internal-lib", develop = true}
forked-dep = {git = "https://github.com/owner/forked-dep.git", rev = "abc123"}
vendored = {url = "https://example.invalid/vendored-1.0.0.tar.gz"}
`)

	deps, err := (&PythonParser{}).Parse(path)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	byName := make(map[string]string)
	for _, d := range deps {
		byName[d.Name] = d.Version
	}

	// Guard the fixture: the ordinary dependency must still parse, or a failure
	// below could just mean the file was not read.
	if got := byName["cryptography"]; got != "41.0.0" {
		t.Fatalf("cryptography version = %q, want 41.0.0; got all %v", got, byName)
	}

	for _, tc := range []struct{ name, want string }{
		{"internal-lib", "../internal-lib"},
		{"forked-dep", "https://github.com/owner/forked-dep.git"},
		{"vendored", "https://example.invalid/vendored-1.0.0.tar.gz"},
	} {
		got, ok := byName[tc.name]
		if !ok {
			t.Errorf("%s is missing from the parsed dependencies; got %v", tc.name, byName)
			continue
		}
		if got == "" {
			t.Errorf("%s has an empty version, so the fetcher will download whatever PyPI "+
				"serves under the name %q instead of the %q it was declared as",
				tc.name, tc.name, tc.want)
			continue
		}
		if got != tc.want {
			t.Errorf("%s version = %q, want the declared locator %q", tc.name, got, tc.want)
		}
	}
}
