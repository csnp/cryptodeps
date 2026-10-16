// Copyright 2025-2026 CyberSecurity NonProfit (CSNP)
// SPDX-License-Identifier: Apache-2.0

package analyzer

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/csnp/qramm-cryptodeps/internal/database"
	"github.com/csnp/qramm-cryptodeps/pkg/output"
	"github.com/csnp/qramm-cryptodeps/pkg/types"
)

// writeManifest writes a manifest under dir, creating any parent directory.
func writeManifest(t *testing.T, dir, rel, content string) {
	t.Helper()
	path := filepath.Join(dir, rel)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", rel, err)
	}
}

const locationGoMod = "module example.com/app\n" + // 1
	"\n" + // 2
	"go 1.22\n" + // 3
	"\n" + // 4
	"require (\n" + // 5
	"\tgithub.com/golang-jwt/jwt/v5 v5.2.0\n" + // 6
	"\tgolang.org/x/crypto v0.21.0\n" + // 7
	")\n" // 8

const locationPackageJSON = "{\n" + // 1
	"  \"name\": \"web\",\n" + // 2
	"  \"dependencies\": {\n" + // 3
	"    \"jsonwebtoken\": \"^8.0.0\"\n" + // 4
	"  }\n" + // 5
	"}\n" // 6

// TestDatabaseFindingsCarryTheirDeclaration is the regression test for every
// finding reporting "location": {"file": "", "line": 0}.
//
// A database finding is a statement about a dependency, and the only place in
// the user's project that the statement can point at is the line declaring that
// dependency. It is relative to the scan root, the directory the report's
// Verify command is run from, so that a report produced in CI does not carry
// the runner's workspace path.
func TestDatabaseFindingsCarryTheirDeclaration(t *testing.T) {
	root := t.TempDir()
	writeManifest(t, root, "go.mod", locationGoMod)
	writeManifest(t, root, filepath.Join("web", "package.json"), locationPackageJSON)

	multi, err := New(database.NewEmbedded(), Options{}).AnalyzeAll(root)
	if err != nil {
		t.Fatalf("AnalyzeAll: %v", err)
	}

	want := map[string]types.Location{
		"github.com/golang-jwt/jwt/v5": {File: "go.mod", Line: 6},
		"golang.org/x/crypto":          {File: "go.mod", Line: 7},
		"jsonwebtoken":                 {File: "web/package.json", Line: 4},
	}
	seen := make(map[string]bool)
	for _, project := range multi.Projects {
		for _, dep := range project.Dependencies {
			w, ok := want[dep.Dependency.Name]
			if !ok || dep.Analysis == nil {
				continue
			}
			if dep.Dependency.Line != w.Line {
				t.Errorf("%s: dependency line %d, want %d", dep.Dependency.Name, dep.Dependency.Line, w.Line)
			}
			if len(dep.Analysis.Crypto) == 0 {
				t.Fatalf("%s: expected database findings to check", dep.Dependency.Name)
			}
			for _, c := range dep.Analysis.Crypto {
				if c.Location != w {
					t.Errorf("%s %s: location %+v, want %+v", dep.Dependency.Name, c.Algorithm, c.Location, w)
				}
			}
			seen[dep.Dependency.Name] = true
		}
	}
	for name := range want {
		if !seen[name] {
			t.Errorf("%s: no database findings were produced, so nothing was checked", name)
		}
	}

	// The same through the JSON document a consumer actually reads.
	var buf bytes.Buffer
	if err := (&output.JSONFormatter{}).FormatMulti(multi, &buf); err != nil {
		t.Fatalf("json: %v", err)
	}
	var doc struct {
		Projects []struct {
			Dependencies []struct {
				Dependency struct {
					Name string `json:"name"`
					Line int    `json:"line"`
				} `json:"dependency"`
				Analysis *struct {
					Crypto []struct {
						Location struct {
							File string `json:"file"`
							Line int    `json:"line"`
						} `json:"location"`
					} `json:"crypto"`
				} `json:"analysis"`
			} `json:"dependencies"`
		} `json:"projects"`
	}
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("JSON output does not decode: %v", err)
	}
	checked := 0
	for _, p := range doc.Projects {
		for _, d := range p.Dependencies {
			w, ok := want[d.Dependency.Name]
			if !ok || d.Analysis == nil {
				continue
			}
			for _, c := range d.Analysis.Crypto {
				if c.Location.File != w.File || c.Location.Line != w.Line {
					t.Errorf("JSON %s: location {%q %d}, want {%q %d}",
						d.Dependency.Name, c.Location.File, c.Location.Line, w.File, w.Line)
				}
				checked++
			}
		}
	}
	if checked == 0 {
		t.Fatal("JSON output carried no findings to check")
	}
}

// TestSingleManifestLocationIsRelativeToItsDirectory covers --no-workspaces,
// where the scan root may be the manifest file itself.
func TestSingleManifestLocationIsRelativeToItsDirectory(t *testing.T) {
	root := t.TempDir()
	writeManifest(t, root, "go.mod", locationGoMod)

	for _, target := range []string{root, filepath.Join(root, "go.mod")} {
		result, err := New(database.NewEmbedded(), Options{}).Analyze(target)
		if err != nil {
			t.Fatalf("Analyze(%s): %v", target, err)
		}
		checked := 0
		for _, dep := range result.Dependencies {
			if dep.Dependency.Name != "golang.org/x/crypto" || dep.Analysis == nil {
				continue
			}
			for _, c := range dep.Analysis.Crypto {
				if c.Location.File != "go.mod" || c.Location.Line != 7 {
					t.Errorf("Analyze(%s) %s: location %+v, want go.mod:7", target, c.Algorithm, c.Location)
				}
				checked++
			}
		}
		if checked == 0 {
			t.Errorf("Analyze(%s): no golang.org/x/crypto findings to check", target)
		}
	}
}

// TestDeclarationDoesNotLeakBetweenManifests pins that two manifests resolving
// to the same database record each keep their own line. The database hands out
// one record per package, so a location written into shared state would show
// the second manifest's line on the first manifest's findings.
func TestDeclarationDoesNotLeakBetweenManifests(t *testing.T) {
	root := t.TempDir()
	writeManifest(t, root, filepath.Join("a", "go.mod"), "module a\n\nrequire golang.org/x/crypto v0.21.0\n")
	writeManifest(t, root, filepath.Join("b", "go.mod"), "module b\n\n\n\nrequire golang.org/x/crypto v0.21.0\n")

	multi, err := New(database.NewEmbedded(), Options{}).AnalyzeAll(root)
	if err != nil {
		t.Fatalf("AnalyzeAll: %v", err)
	}
	want := map[string]types.Location{
		"a": {File: "a/go.mod", Line: 3},
		"b": {File: "b/go.mod", Line: 5},
	}
	for _, project := range multi.Projects {
		w := want[filepath.Base(filepath.Dir(project.Manifest))]
		for _, dep := range project.Dependencies {
			if dep.Analysis == nil {
				t.Fatalf("%s: expected a database record", project.Manifest)
			}
			for _, c := range dep.Analysis.Crypto {
				if c.Location != w {
					t.Errorf("%s %s: location %+v, want %+v", project.Manifest, c.Algorithm, c.Location, w)
				}
			}
		}
	}
}
