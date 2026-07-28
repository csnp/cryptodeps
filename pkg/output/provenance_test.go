// Copyright 2025-2026 CyberSecurity NonProfit (CSNP)
// SPDX-License-Identifier: Apache-2.0

package output

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/csnp/qramm-cryptodeps/pkg/types"
	"github.com/csnp/qramm-cryptodeps/pkg/version"
)

// withVersion sets the reported build version for the duration of a test.
//
// The value is deliberately not any version this tool has ever shipped, so a
// formatter that carries its own literal cannot accidentally agree with it.
func withVersion(t *testing.T, v string) {
	t.Helper()
	original := version.Version()
	version.Set(v, "testcommit", "testdate")
	t.Cleanup(func() { version.Set(original, "", "") })
}

// sampleResult builds a scan result with one vulnerable finding.
func sampleResult(projectDir, manifestPath string) *types.ScanResult {
	return &types.ScanResult{
		Project:   projectDir,
		Manifest:  manifestPath,
		Ecosystem: types.EcosystemNPM,
		Dependencies: []types.DependencyResult{
			{
				Dependency: types.Dependency{
					Name: "node-forge", Version: "1.3.1",
					Ecosystem: types.EcosystemNPM, Direct: true,
				},
				InDatabase: true,
				Analysis: &types.PackageAnalysis{
					Package: "node-forge",
					Crypto: []types.CryptoUsage{
						{
							Algorithm:   "RSA",
							Type:        "key-exchange",
							QuantumRisk: types.RiskVulnerable,
							Severity:    types.SeverityHigh,
						},
					},
				},
			},
		},
		Summary: types.ScanSummary{TotalDependencies: 1, WithCrypto: 1, QuantumVulnerable: 1},
	}
}

// TestEveryEmitterReportsTheRunningVersion pins the single source of truth.
//
// Before pkg/version existed, one binary gave four answers: the version command
// said 1.3.0, SARIF said 1.0.0, CBOM said 1.0.0 and JSON carried no version at
// all. SARIF and CBOM are provenance artifacts, so a stale literal there is a
// false record of what produced the document.
func TestEveryEmitterReportsTheRunningVersion(t *testing.T) {
	const want = "9.9.9-provenance-test"
	withVersion(t, want)

	dir := t.TempDir()
	result := sampleResult(dir, filepath.Join(dir, "package.json"))

	t.Run("sarif", func(t *testing.T) {
		var buf bytes.Buffer
		if err := (&SARIFFormatter{}).Format(result, &buf); err != nil {
			t.Fatalf("format: %v", err)
		}
		var doc struct {
			Runs []struct {
				Tool struct {
					Driver struct {
						Version         string `json:"version"`
						SemanticVersion string `json:"semanticVersion"`
					} `json:"driver"`
				} `json:"tool"`
			} `json:"runs"`
		}
		if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if got := doc.Runs[0].Tool.Driver.Version; got != want {
			t.Errorf("sarif driver.version = %q, want %q", got, want)
		}
		if got := doc.Runs[0].Tool.Driver.SemanticVersion; got != want {
			t.Errorf("sarif driver.semanticVersion = %q, want %q", got, want)
		}
	})

	t.Run("cbom", func(t *testing.T) {
		var buf bytes.Buffer
		if err := (&CBOMFormatter{}).Format(result, &buf); err != nil {
			t.Fatalf("format: %v", err)
		}
		var doc struct {
			Metadata struct {
				Tools []struct {
					Version string `json:"version"`
				} `json:"tools"`
			} `json:"metadata"`
		}
		if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if len(doc.Metadata.Tools) == 0 {
			t.Fatal("cbom declared no tools")
		}
		if got := doc.Metadata.Tools[0].Version; got != want {
			t.Errorf("cbom metadata.tools[0].version = %q, want %q", got, want)
		}
	})

	t.Run("json", func(t *testing.T) {
		var buf bytes.Buffer
		if err := (&JSONFormatter{}).Format(result, &buf); err != nil {
			t.Fatalf("format: %v", err)
		}
		var doc struct {
			Tool struct {
				Name    string `json:"name"`
				Version string `json:"version"`
			} `json:"tool"`
			Manifest string `json:"manifest"`
		}
		if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if got := doc.Tool.Version; got != want {
			t.Errorf("json tool.version = %q, want %q", got, want)
		}
		if doc.Tool.Name == "" {
			t.Error("json tool.name is empty")
		}
		// The wrapper must not shadow the scan result's own fields.
		if doc.Manifest == "" {
			t.Error("json lost the manifest field when the tool object was added")
		}
	})
}

// TestSARIFLocationsPointAtRealManifests guards the "multiple" literal.
//
// Multi-project runs flattened every project into one synthetic result whose
// manifest was the string "multiple", so every alert in the file pointed at a
// path that does not exist and nothing could be ingested.
func TestSARIFLocationsPointAtRealManifests(t *testing.T) {
	root := t.TempDir()
	projectA := filepath.Join(root, "a")
	projectB := filepath.Join(root, "b")

	multi := &types.MultiProjectResult{
		RootPath: root,
		Projects: []*types.ScanResult{
			sampleResult(projectA, filepath.Join(projectA, "package.json")),
			sampleResult(projectB, filepath.Join(projectB, "package.json")),
		},
	}

	var buf bytes.Buffer
	if err := (&SARIFFormatter{}).FormatMulti(multi, &buf); err != nil {
		t.Fatalf("format: %v", err)
	}

	if strings.Contains(buf.String(), `"multiple"`) {
		t.Error(`SARIF still contains the placeholder location "multiple"`)
	}

	var doc struct {
		Runs []struct {
			OriginalURIBaseIDs map[string]struct {
				URI string `json:"uri"`
			} `json:"originalUriBaseIds"`
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
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(doc.Runs[0].Results) == 0 {
		t.Fatal("fixture produced no SARIF results, so this test proves nothing")
	}

	got := make(map[string]bool)
	for _, r := range doc.Runs[0].Results {
		if len(r.Locations) == 0 {
			t.Fatal("result carries no location")
		}
		loc := r.Locations[0].PhysicalLocation.ArtifactLocation
		if loc.URIBaseID != sarifURIBaseID {
			t.Errorf("uriBaseId = %q, want %q", loc.URIBaseID, sarifURIBaseID)
		}
		got[loc.URI] = true
	}

	for _, want := range []string{"a/package.json", "b/package.json"} {
		if !got[want] {
			t.Errorf("no result located at %q; got %v", want, got)
		}
	}
	if _, ok := doc.Runs[0].OriginalURIBaseIDs[sarifURIBaseID]; !ok {
		t.Errorf("run does not declare %s, so the relative uris cannot be resolved", sarifURIBaseID)
	}
}

// TestSARIFReportsSkippedManifests checks that an unread manifest reaches SARIF
// and clears executionSuccessful, so a consumer can tell an incomplete scan from
// a complete one.
func TestSARIFReportsSkippedManifests(t *testing.T) {
	root := t.TempDir()
	project := filepath.Join(root, "good")

	multi := &types.MultiProjectResult{
		RootPath: root,
		Projects: []*types.ScanResult{sampleResult(project, filepath.Join(project, "package.json"))},
		Skipped: []types.SkippedManifest{
			{Path: filepath.Join(root, "broken", "package.json"), Reason: "not valid JSON"},
		},
	}

	var buf bytes.Buffer
	if err := (&SARIFFormatter{}).FormatMulti(multi, &buf); err != nil {
		t.Fatalf("format: %v", err)
	}

	var doc struct {
		Runs []struct {
			Invocations []struct {
				ExecutionSuccessful        bool `json:"executionSuccessful"`
				ToolExecutionNotifications []struct {
					Level   string `json:"level"`
					Message struct {
						Text string `json:"text"`
					} `json:"message"`
				} `json:"toolExecutionNotifications"`
			} `json:"invocations"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(doc.Runs[0].Invocations) == 0 {
		t.Fatal("no invocation recorded, so a skipped manifest is invisible to SARIF consumers")
	}
	inv := doc.Runs[0].Invocations[0]
	if inv.ExecutionSuccessful {
		t.Error("executionSuccessful is true even though a manifest was not read")
	}
	if len(inv.ToolExecutionNotifications) != 1 {
		t.Fatalf("got %d notifications, want 1", len(inv.ToolExecutionNotifications))
	}
	if !strings.Contains(inv.ToolExecutionNotifications[0].Message.Text, "not valid JSON") {
		t.Errorf("notification does not carry the reason: %q",
			inv.ToolExecutionNotifications[0].Message.Text)
	}
}
