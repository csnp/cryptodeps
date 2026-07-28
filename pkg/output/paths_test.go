// Copyright 2025-2026 CyberSecurity NonProfit (CSNP)
// SPDX-License-Identifier: Apache-2.0

package output

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/csnp/qramm-cryptodeps/pkg/types"
)

// chdir moves into dir for the duration of the test and returns the working
// directory as the OS reports it, which on macOS is the resolved path behind
// /var. Both sides of a path comparison have to come from the same place or the
// assertion measures the symlink rather than the code.
func chdir(t *testing.T, dir string) string {
	t.Helper()
	previous, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatalf("chdir %s: %v", dir, err)
	}
	t.Cleanup(func() {
		if err := os.Chdir(previous); err != nil {
			t.Fatalf("restore cwd: %v", err)
		}
	})
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd after chdir: %v", err)
	}
	return cwd
}

// skippedUnderRelativeRoot builds the scan a user gets from `cryptodeps analyze .`:
// a root exactly as typed, and manifest paths absolutized by discovery.
func skippedUnderRelativeRoot(root string) *types.MultiProjectResult {
	return &types.MultiProjectResult{
		RootPath: ".",
		Projects: []*types.ScanResult{{
			Project:   filepath.Join(root, "good"),
			Manifest:  filepath.Join(root, "good", "package.json"),
			Ecosystem: types.EcosystemNPM,
			Dependencies: []types.DependencyResult{{
				Dependency: types.Dependency{Name: "node-forge", Version: "1.3.1"},
				InDatabase: true,
				Analysis: &types.PackageAnalysis{Package: "node-forge", Crypto: []types.CryptoUsage{
					{Algorithm: "DES", QuantumRisk: types.RiskVulnerable, Severity: types.SeverityCritical},
				}},
			}},
			Summary: types.ScanSummary{TotalDependencies: 1, DirectDependencies: 1, WithCrypto: 1,
				QuantumVulnerable: 1},
		}},
		Skipped: []types.SkippedManifest{
			{Path: filepath.Join(root, "corrupt", "package.json"),
				Reason: "not valid JSON: unexpected end of JSON input"},
		},
	}
}

// TestCBOMPathsAreRelativeUnderARelativeScanRoot is the regression test for a
// privacy fix that only worked for the invocation nobody uses.
//
// The relativization compared an absolute manifest path against the scan root
// exactly as the user typed it. `cryptodeps analyze /abs/path` therefore
// produced repository-relative paths, while `cryptodeps analyze .`, which is the
// default invocation and the one the GitHub Action runs, fell through to the
// absolute path and published the operator's home directory or the CI runner's
// workspace layout inside a document meant to be shared.
func TestCBOMPathsAreRelativeUnderARelativeScanRoot(t *testing.T) {
	root := chdir(t, t.TempDir())
	out := renderMulti(t, FormatCBOM, skippedUnderRelativeRoot(root))

	var doc struct {
		Metadata struct {
			Properties []struct {
				Name  string `json:"name"`
				Value string `json:"value"`
			} `json:"properties"`
		} `json:"metadata"`
	}
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("CBOM is not valid JSON: %v", err)
	}

	var found bool
	for _, p := range doc.Metadata.Properties {
		if p.Name != "cryptodeps:manifestNotAnalyzed" {
			continue
		}
		found = true
		if !strings.HasPrefix(p.Value, "corrupt/package.json:") {
			t.Errorf("cryptodeps:manifestNotAnalyzed = %q, want a path relative to the scan "+
				"root; an absolute path publishes the local filesystem layout", p.Value)
		}
		if strings.Contains(p.Value, root) {
			t.Errorf("cryptodeps:manifestNotAnalyzed carries the absolute scan root %q: %q", root, p.Value)
		}
	}
	// Without this the test passes on an implementation that emits no coverage
	// properties at all, which is the defect the properties exist to prevent.
	if !found {
		t.Fatalf("CBOM has no cryptodeps:manifestNotAnalyzed property, so this cannot "+
			"guard how one is rendered: %+v", doc.Metadata.Properties)
	}
}

// TestSARIFPathsAreRelativeUnderARelativeScanRoot is a preservation guard, not a
// regression test: SARIF absolutized the root before comparing and was correct
// throughout. It exists so the shared helper both formats now call cannot be
// changed to fix CBOM at SARIF's expense.
//
// The absolute root legitimately appears once, in originalUriBaseIds, which is
// what a consumer needs to resolve the relative uris. The uris themselves must
// not repeat it.
func TestSARIFPathsAreRelativeUnderARelativeScanRoot(t *testing.T) {
	root := chdir(t, t.TempDir())
	out := renderMulti(t, FormatSARIF, skippedUnderRelativeRoot(root))

	var doc struct {
		Runs []struct {
			Invocations []struct {
				ToolExecutionNotifications []struct {
					Locations []struct {
						PhysicalLocation struct {
							ArtifactLocation struct {
								URI       string `json:"uri"`
								URIBaseID string `json:"uriBaseId"`
							} `json:"artifactLocation"`
						} `json:"physicalLocation"`
					} `json:"locations"`
				} `json:"toolExecutionNotifications"`
			} `json:"invocations"`
			Results []struct {
				Locations []struct {
					PhysicalLocation struct {
						ArtifactLocation struct {
							URI       string `json:"uri"`
							URIBaseID string `json:"uriBaseId"`
						} `json:"artifactLocation"`
					} `json:"physicalLocation"`
				} `json:"locations"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("SARIF is not valid JSON: %v", err)
	}
	if len(doc.Runs) != 1 {
		t.Fatalf("got %d runs, want 1", len(doc.Runs))
	}

	var checked int
	for _, n := range doc.Runs[0].Invocations[0].ToolExecutionNotifications {
		for _, l := range n.Locations {
			a := l.PhysicalLocation.ArtifactLocation
			checked++
			if a.URIBaseID != sarifURIBaseID || strings.Contains(a.URI, root) {
				t.Errorf("notification uri %q (base %q) is not relative to the scan root",
					a.URI, a.URIBaseID)
			}
		}
	}
	for _, r := range doc.Runs[0].Results {
		for _, l := range r.Locations {
			a := l.PhysicalLocation.ArtifactLocation
			checked++
			if a.URIBaseID != sarifURIBaseID || strings.Contains(a.URI, root) {
				t.Errorf("result uri %q (base %q) is not relative to the scan root",
					a.URI, a.URIBaseID)
			}
		}
	}
	if checked == 0 {
		t.Fatal("SARIF carried no located notification or result, so this asserts nothing")
	}
}

// TestRelativeToRootKeepsPathsOutsideTheRootAbsolute pins the other half of the
// contract. A manifest that does not sit under the scan root cannot be described
// relative to it, and inventing a "../../.." path would be a lie a consumer
// would then try to resolve.
func TestRelativeToRootKeepsPathsOutsideTheRootAbsolute(t *testing.T) {
	root := chdir(t, t.TempDir())
	outside := filepath.Join(filepath.Dir(root), "elsewhere", "package.json")

	got, underRoot := relativeToRoot(root, outside)
	if underRoot {
		t.Errorf("relativeToRoot(%q, %q) claims the manifest is under the root", root, outside)
	}
	if !filepath.IsAbs(got) {
		t.Errorf("relativeToRoot(%q, %q) = %q, want the absolute path", root, outside, got)
	}

	// A directory whose name merely starts with ".." is under the root and must
	// stay relative. A HasPrefix(rel, "..") test gets this wrong.
	dotted := filepath.Join(root, "..config", "package.json")
	got, underRoot = relativeToRoot(root, dotted)
	if !underRoot || got != "..config/package.json" {
		t.Errorf("relativeToRoot(%q, %q) = %q, %v; want \"..config/package.json\", true",
			root, dotted, got, underRoot)
	}
}

// TestScanRootDirTreatsAManifestFileAsItsDirectory guards the second
// normalization. `cryptodeps analyze ./package.json` passes a file as the scan
// root, and using it as a base directory made every path relative to itself.
func TestScanRootDirTreatsAManifestFileAsItsDirectory(t *testing.T) {
	dir := chdir(t, t.TempDir())
	manifest := filepath.Join(dir, "package.json")
	if err := os.WriteFile(manifest, []byte(`{"name":"x"}`), 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	if got := scanRootDir(manifest); got != dir {
		t.Errorf("scanRootDir(%q) = %q, want the containing directory %q", manifest, got, dir)
	}
	if got := scanRootDir("."); got != dir {
		t.Errorf("scanRootDir(\".\") = %q, want the absolute working directory %q", got, dir)
	}
}
