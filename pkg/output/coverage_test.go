// Copyright 2025-2026 CyberSecurity NonProfit (CSNP)
// SPDX-License-Identifier: Apache-2.0

package output

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/csnp/qramm-cryptodeps/pkg/types"
)

// These tests exist because the first version of the false-clean fix was
// table-only.
//
// The table learned to distinguish "we looked and found nothing" from "we
// looked at nothing" and from "we withheld everything", while markdown, CBOM and
// SARIF kept reporting the clean result. Markdown still printed the exact
// sentence the table fix removed, and SARIF asserted executionSuccessful with an
// empty result set, which a code-scanning consumer reads as a clean bill of
// health. A user who asks for --format markdown is not reading the table, so a
// fix that only reaches one of five formats has not fixed the defect.
//
// Every case below is asserted against every format that can express it, so a
// future formatter cannot quietly opt out.

// writeTestFile writes a fixture file, failing the test if it cannot.
func writeTestFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

// renderMulti formats a multi-project result in the named format.
func renderMulti(t *testing.T, format Format, result *types.MultiProjectResult) string {
	t.Helper()
	f, err := GetFormatter(format)
	if err != nil {
		t.Fatalf("GetFormatter(%s): %v", format, err)
	}
	var buf bytes.Buffer
	if err := f.FormatMulti(result, &buf); err != nil {
		t.Fatalf("FormatMulti(%s): %v", format, err)
	}
	return buf.String()
}

// filteredScan is a scan where every finding was detected and then withheld by a
// filter. Nothing survives to be reported, but the tree is not clean.
func filteredScan() *types.MultiProjectResult {
	return types.AggregateResults("/repo", []*types.ScanResult{{
		Project:   "/repo/a",
		Manifest:  "/repo/a/package.json",
		Ecosystem: types.EcosystemNPM,
		Dependencies: []types.DependencyResult{{
			Dependency: types.Dependency{Name: "node-forge", Version: "1.3.1"},
			InDatabase: true,
			Analysis:   &types.PackageAnalysis{Package: "node-forge"},
		}},
		Summary: types.ScanSummary{TotalDependencies: 1, DirectDependencies: 1, FilteredOut: 9},
	}})
}

// nothingExaminedScan is a scan where no dependency was in the database, so no
// conclusion about cryptographic usage was drawn.
func nothingExaminedScan() *types.MultiProjectResult {
	return types.AggregateResults("/repo", []*types.ScanResult{{
		Project:   "/repo/a",
		Manifest:  "/repo/a/requirements.txt",
		Ecosystem: types.EcosystemPyPI,
		Dependencies: []types.DependencyResult{
			{Dependency: types.Dependency{Name: "rsa", Version: "4.9"}},
			{Dependency: types.Dependency{Name: "certifi"}},
		},
		Summary: types.ScanSummary{TotalDependencies: 2, DirectDependencies: 2, NotInDatabase: 2},
	}})
}

// TestEveryFormatSaysFindingsWereWithheld covers the filtered-to-empty case.
func TestEveryFormatSaysFindingsWereWithheld(t *testing.T) {
	for _, format := range []Format{FormatTable, FormatMarkdown, FormatJSON, FormatCBOM, FormatSARIF} {
		t.Run(string(format), func(t *testing.T) {
			out := renderMulti(t, format, filteredScan())

			if strings.Contains(out, "No cryptographic usage detected in dependencies.") {
				t.Errorf("%s reports a clean scan while 9 findings were withheld by a filter:\n%s",
					format, out)
			}
			// The withheld count has to appear somewhere a consumer of this
			// format can find it. A format that renders an empty result set and
			// says nothing else is indistinguishable from a clean tree.
			if !strings.Contains(out, "9") {
				t.Errorf("%s never mentions the 9 withheld findings:\n%s", format, out)
			}
		})
	}
}

// TestEveryFormatSaysNothingWasExamined covers the all-unknown case, which is
// the defect the table verdict was originally written for.
func TestEveryFormatSaysNothingWasExamined(t *testing.T) {
	for _, format := range []Format{FormatTable, FormatMarkdown, FormatJSON, FormatCBOM, FormatSARIF} {
		t.Run(string(format), func(t *testing.T) {
			out := renderMulti(t, format, nothingExaminedScan())

			if strings.Contains(out, "No cryptographic usage detected in dependencies.") {
				t.Errorf("%s reports a clean scan when no dependency was examined:\n%s", format, out)
			}
		})
	}
}

// TestFilteredScanIsNotAssertedAsAFullySuccessfulRun checks the SARIF signal a
// code-scanning consumer actually reads.
func TestFilteredScanIsNotAssertedAsAFullySuccessfulRun(t *testing.T) {
	var doc struct {
		Runs []struct {
			Results     []any `json:"results"`
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
	out := renderMulti(t, FormatSARIF, filteredScan())
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("SARIF is not valid JSON: %v", err)
	}
	if len(doc.Runs) != 1 || len(doc.Runs[0].Invocations) != 1 {
		t.Fatalf("expected one run with one invocation, got %+v", doc)
	}
	if len(doc.Runs[0].Results) != 0 {
		t.Fatalf("fixture did not filter everything away: %d results", len(doc.Runs[0].Results))
	}
	notifications := doc.Runs[0].Invocations[0].ToolExecutionNotifications
	if len(notifications) == 0 {
		t.Fatal("SARIF emitted zero results and zero notifications, so a consumer cannot " +
			"tell a filtered run from a clean one")
	}
	var mentionsWithheld bool
	for _, n := range notifications {
		if strings.Contains(n.Message.Text, "withheld") {
			mentionsWithheld = true
		}
	}
	if !mentionsWithheld {
		t.Errorf("no notification says findings were withheld: %+v", notifications)
	}
}

// TestSARIFBaseIDIsADirectoryWhenRootIsAFile guards the documented
// `cryptodeps analyze ./package.json` invocation.
//
// A uriBaseId names a directory. Passing the manifest file through unchanged
// declared a base of "file:///.../package.json/" and made every result relative
// to itself, so each one resolved to the literal ".". That is the same
// unusable-literal defect as the "multiple" path it replaced: a real string in a
// well-formed document that points at nothing.
func TestSARIFBaseIDIsADirectoryWhenRootIsAFile(t *testing.T) {
	dir := t.TempDir()
	manifest := filepath.Join(dir, "package.json")
	writeTestFile(t, manifest, `{"name":"x","dependencies":{"node-forge":"1.3.1"}}`)

	result := &types.ScanResult{
		Project:   manifest,
		Manifest:  manifest,
		Ecosystem: types.EcosystemNPM,
		Dependencies: []types.DependencyResult{{
			Dependency: types.Dependency{Name: "node-forge", Version: "1.3.1"},
			InDatabase: true,
			Analysis: &types.PackageAnalysis{Package: "node-forge", Crypto: []types.CryptoUsage{
				{Algorithm: "DES", QuantumRisk: types.RiskVulnerable, Severity: types.SeverityCritical},
			}},
		}},
		Summary: types.ScanSummary{TotalDependencies: 1, DirectDependencies: 1, WithCrypto: 1},
	}

	var buf bytes.Buffer
	if err := (&SARIFFormatter{Options: DefaultOptions()}).Format(result, &buf); err != nil {
		t.Fatalf("format: %v", err)
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
							URI string `json:"uri"`
						} `json:"artifactLocation"`
					} `json:"physicalLocation"`
				} `json:"locations"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("SARIF is not valid JSON: %v", err)
	}
	if len(doc.Runs[0].Results) == 0 {
		t.Fatal("fixture produced no results, so it cannot guard result locations")
	}

	base := doc.Runs[0].OriginalURIBaseIDs["SRCROOT"].URI
	if strings.HasSuffix(base, "package.json/") {
		t.Errorf("SRCROOT names a file, not a directory: %s", base)
	}
	for _, res := range doc.Runs[0].Results {
		uri := res.Locations[0].PhysicalLocation.ArtifactLocation.URI
		if uri == "." || uri == "" {
			t.Errorf("result location is the literal %q, which points at no file", uri)
		}
		if uri != "package.json" {
			t.Errorf("result location = %q, want %q relative to SRCROOT", uri, "package.json")
		}
	}
}

// TestMarkdownRemediationOrderIsStable covers the one format still shuffling
// after the determinism sweep.
//
// The other four were made deterministic, and the change was described as
// covering all five, but the markdown remediation table ranged over a map. Ten
// runs of the same scan produced ten different documents.
func TestMarkdownRemediationOrderIsStable(t *testing.T) {
	result := &types.ScanResult{
		Project:   "/repo",
		Manifest:  "/repo/package.json",
		Ecosystem: types.EcosystemNPM,
		Dependencies: []types.DependencyResult{{
			Dependency: types.Dependency{Name: "node-forge", Version: "1.3.1"},
			InDatabase: true,
			Analysis: &types.PackageAnalysis{Package: "node-forge", Crypto: []types.CryptoUsage{
				{Algorithm: "DES", QuantumRisk: types.RiskVulnerable, Severity: types.SeverityCritical, Remediation: "Replace with AES-256"},
				{Algorithm: "MD5", QuantumRisk: types.RiskVulnerable, Severity: types.SeverityCritical, Remediation: "Replace with SHA-256"},
				{Algorithm: "RSA", QuantumRisk: types.RiskVulnerable, Severity: types.SeverityHigh, Remediation: "Migrate to ML-KEM"},
				{Algorithm: "SHA-1", QuantumRisk: types.RiskVulnerable, Severity: types.SeverityHigh, Remediation: "Replace with SHA-256"},
				{Algorithm: "3DES", QuantumRisk: types.RiskVulnerable, Severity: types.SeverityHigh, Remediation: "Replace with AES-256"},
				{Algorithm: "AES", QuantumRisk: types.RiskPartial, Severity: types.SeverityInfo, Remediation: "Use AES-256"},
			}},
		}},
		Summary: types.ScanSummary{TotalDependencies: 1, DirectDependencies: 1, WithCrypto: 1, QuantumVulnerable: 5, QuantumPartial: 1},
	}

	var first string
	for i := 0; i < 20; i++ {
		var buf bytes.Buffer
		if err := (&MarkdownFormatter{Options: DefaultOptions()}).Format(result, &buf); err != nil {
			t.Fatalf("format: %v", err)
		}
		if i == 0 {
			first = buf.String()
			continue
		}
		if buf.String() != first {
			t.Fatalf("markdown output changed between runs of the same scan; " +
				"reproducible reports and golden-file CI both depend on it being stable")
		}
	}
	// Guard the fixture: without a remediation table there is nothing to shuffle.
	if !strings.Contains(first, "Remediation Guidance") {
		t.Fatal("fixture produced no remediation table, so it cannot guard its ordering")
	}
}
