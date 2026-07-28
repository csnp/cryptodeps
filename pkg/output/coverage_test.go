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

// withheldAssertion checks, per format, that the withheld findings are actually
// reported in a way a consumer of THAT format can act on.
//
// Each assertion names the concrete field or sentence, never a bare substring.
// The first version of this test asserted strings.Contains(out, "9"), which the
// CBOM's random v4 serialNumber and the JSON scanDate satisfy by accident: it
// passed against an implementation with the CBOM property and the JSON
// aggregation both deliberately disabled, and was flaky besides. A count is the
// wrong assertion, and so is a digit.
var withheldAssertion = map[Format]func(*testing.T, string){
	FormatTable: func(t *testing.T, out string) {
		if !strings.Contains(out, "9 finding(s) were detected") {
			t.Errorf("table does not state the withheld findings:\n%s", out)
		}
	},
	FormatMarkdown: func(t *testing.T, out string) {
		if !strings.Contains(out, "9 finding(s) were detected") {
			t.Errorf("markdown does not state the withheld findings:\n%s", out)
		}
	},
	FormatJSON: func(t *testing.T, out string) {
		var doc struct {
			TotalSummary struct {
				FilteredOut int `json:"filteredOut"`
			} `json:"totalSummary"`
		}
		if err := json.Unmarshal([]byte(out), &doc); err != nil {
			t.Fatalf("JSON is not valid: %v", err)
		}
		if doc.TotalSummary.FilteredOut != 9 {
			t.Errorf("totalSummary.filteredOut = %d, want 9; a consumer reading the "+
				"aggregate cannot tell this filtered scan from a clean one",
				doc.TotalSummary.FilteredOut)
		}
	},
	FormatCBOM: func(t *testing.T, out string) {
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
		for _, p := range doc.Metadata.Properties {
			if p.Name == "cryptodeps:findingsWithheld" {
				// The exact count. Contains(value, "9") passed against an
				// implementation multiplying the count by 100, and the CBOM's
				// random v4 serialNumber contains a 9 most runs anyway.
				if !strings.HasPrefix(p.Value, "9 finding(s)") {
					t.Errorf("cryptodeps:findingsWithheld does not state 9 withheld: %q", p.Value)
				}
				return
			}
		}
		t.Errorf("CBOM has no cryptodeps:findingsWithheld property, so it asserts a "+
			"complete bill of materials for a filtered scan: %+v", doc.Metadata.Properties)
	},
	FormatSARIF: func(t *testing.T, out string) {
		if !strings.Contains(out, "9 finding(s) were detected and withheld") {
			t.Errorf("SARIF does not state the 9 withheld findings:\n%s", out)
		}
	},
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
			withheldAssertion[format](t, out)
		})
	}
}

// TestCoverageNotesDoNotContradictResults is the guard for a statement that was
// false on the face of the document that carried it.
//
// SARIF and CBOM evaluated "nothing was examined" over the whole run and without
// checking whether findings existed, so a --deep scan that found two CRITICAL
// algorithms in packages absent from the database emitted both those findings
// AND a notice saying no conclusion about cryptographic usage could be drawn.
// A project with findings gets no coverage note.
func TestCoverageNotesDoNotContradictResults(t *testing.T) {
	withFindings := &types.ScanResult{
		Manifest: "/repo/a/go.mod",
		Dependencies: []types.DependencyResult{{
			Dependency: types.Dependency{Name: "github.com/google/uuid", Version: "v1.6.0"},
			Analysis: &types.PackageAnalysis{Package: "github.com/google/uuid", Crypto: []types.CryptoUsage{
				{Algorithm: "MD5", QuantumRisk: types.RiskVulnerable, Severity: types.SeverityCritical},
			}},
		}},
		// Deliberately the shape --deep produces: findings exist even though
		// every dependency is absent from the database.
		Summary: types.ScanSummary{TotalDependencies: 1, DirectDependencies: 1, WithCrypto: 1,
			QuantumVulnerable: 1, NotInDatabase: 1},
	}

	if notes := coverageNotes([]*types.ScanResult{withFindings}); len(notes) != 0 {
		t.Fatalf("a project with findings produced coverage notes %+v; the document would "+
			"assert that nothing was examined beside the findings it just reported", notes)
	}

	for _, format := range []Format{FormatSARIF, FormatCBOM, FormatTable, FormatMarkdown} {
		t.Run(string(format), func(t *testing.T) {
			out := renderMulti(t, format, types.AggregateResults("/repo", []*types.ScanResult{withFindings}))
			if strings.Contains(out, "nothing was examined") ||
				strings.Contains(out, "no conclusion about cryptographic usage") {
				t.Errorf("%s claims nothing was examined while reporting findings:\n%s", format, out)
			}
			if !strings.Contains(out, "MD5") {
				t.Fatalf("fixture produced no MD5 finding in %s, so it cannot detect the "+
					"contradiction:\n%s", format, out)
			}
		})
	}
}

// TestCoverageIsJudgedPerProject guards the opposite direction of the same bug.
//
// Summing notInDatabase and totalDependencies across a whole workspace hid a
// project that was entirely unexamined behind a sibling that was fully analyzed:
// 21 of 24 dependencies went unexamined and no machine-readable format said so,
// while the table said it plainly.
func TestCoverageIsJudgedPerProject(t *testing.T) {
	unexamined := &types.ScanResult{
		Manifest: "/repo/unknown/package.json",
		Dependencies: []types.DependencyResult{
			{Dependency: types.Dependency{Name: "left-pad"}},
			{Dependency: types.Dependency{Name: "is-odd"}},
		},
		Summary: types.ScanSummary{TotalDependencies: 2, DirectDependencies: 2, NotInDatabase: 2},
	}
	analyzed := &types.ScanResult{
		Manifest: "/repo/known/go.mod",
		Dependencies: []types.DependencyResult{{
			Dependency: types.Dependency{Name: "golang.org/x/crypto", Version: "v0.31.0"},
			InDatabase: true,
			Analysis: &types.PackageAnalysis{Package: "golang.org/x/crypto", Crypto: []types.CryptoUsage{
				{Algorithm: "RSA", QuantumRisk: types.RiskVulnerable, Severity: types.SeverityHigh},
			}},
		}},
		Summary: types.ScanSummary{TotalDependencies: 1, DirectDependencies: 1, WithCrypto: 1, QuantumVulnerable: 1},
	}
	multi := types.AggregateResults("/repo", []*types.ScanResult{unexamined, analyzed})

	// Guard the fixture: the aggregate must NOT satisfy notInDatabase == total,
	// or the old whole-run test would have caught this and there is no bug.
	if multi.TotalSummary.NotInDatabase >= multi.TotalSummary.TotalDependencies {
		t.Fatalf("fixture does not mix examined and unexamined projects: %+v", multi.TotalSummary)
	}

	notes := coverageNotes(multi.Projects)
	if len(notes) != 1 || notes[0].Case != caseNothingExamined {
		t.Fatalf("expected exactly one nothing-examined note for the unexamined project, got %+v", notes)
	}

	for _, format := range []Format{FormatSARIF, FormatCBOM} {
		t.Run(string(format), func(t *testing.T) {
			out := renderMulti(t, format, multi)
			if !strings.Contains(out, "nothing was examined") {
				t.Errorf("%s does not report the project where no dependency was examined:\n%s",
					format, out)
			}
		})
	}
}

// TestClassifyNoFindingsChecksFilterFirst pins the ordering the package
// documents as its safety property.
//
// Nothing else in the suite fails if the cases are reordered, yet a summary of
// {Total: 2, NotInDatabase: 2, FilteredOut: 2} is reachable whenever --deep finds
// crypto in packages absent from the database and a filter withholds it. Ordered
// wrongly, that scan reports "not analyzed" and never mentions the two withheld
// findings.
func TestClassifyNoFindingsChecksFilterFirst(t *testing.T) {
	both := types.ScanSummary{TotalDependencies: 2, NotInDatabase: 2, FilteredOut: 2}
	if got := classifyNoFindings(both); got != caseFiltered {
		t.Errorf("classifyNoFindings(%+v) = %v, want caseFiltered; withheld findings must "+
			"outrank every other explanation for an empty report", both, got)
	}

	// And each other case in isolation, so the test above cannot be satisfied by
	// always returning caseFiltered.
	for _, tc := range []struct {
		name    string
		summary types.ScanSummary
		want    noFindingsCase
	}{
		{"no dependencies", types.ScanSummary{}, caseNoDependencies},
		{"all unknown", types.ScanSummary{TotalDependencies: 3, NotInDatabase: 3}, caseNothingExamined},
		{"examined and clean", types.ScanSummary{TotalDependencies: 3, NotInDatabase: 1}, caseGenuinelyClean},
	} {
		if got := classifyNoFindings(tc.summary); got != tc.want {
			t.Errorf("%s: classifyNoFindings(%+v) = %v, want %v", tc.name, tc.summary, got, tc.want)
		}
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

// TestWithheldFindingsAreReportedEvenWhenSomeSurvive is the regression test for
// the case the whole filtered-scan fix missed.
//
// Withholding findings is a property of the scan, not of an empty report, but it
// was routed through classifyNoFindings, which by contract only speaks about
// scans that produced nothing. So the moment one finding survived the filter,
// SARIF and CBOM stopped mentioning the withheld ones entirely: 28 withheld
// beside 38 reported, and a machine consumer read the run as complete. The table
// and JSON said it plainly, which is what made the divergence invisible in
// review.
func TestWithheldFindingsAreReportedEvenWhenSomeSurvive(t *testing.T) {
	partial := types.AggregateResults("/repo", []*types.ScanResult{{
		Project:   "/repo/a",
		Manifest:  "/repo/a/package.json",
		Ecosystem: types.EcosystemNPM,
		Dependencies: []types.DependencyResult{{
			Dependency: types.Dependency{Name: "node-forge", Version: "1.3.1"},
			InDatabase: true,
			Analysis: &types.PackageAnalysis{Package: "node-forge", Crypto: []types.CryptoUsage{
				{Algorithm: "DES", QuantumRisk: types.RiskVulnerable, Severity: types.SeverityCritical},
			}},
		}},
		Summary: types.ScanSummary{TotalDependencies: 1, DirectDependencies: 1, WithCrypto: 1,
			QuantumVulnerable: 1, FilteredOut: 7},
	}})

	// Guard the fixture: findings must SURVIVE, or this is the filtered-to-empty
	// case that was already covered and the test proves nothing.
	if !hasAnyCrypto(partial.Projects[0].Dependencies) {
		t.Fatal("fixture has no surviving finding, so it cannot exercise the partial-filter case")
	}

	for _, format := range []Format{FormatTable, FormatMarkdown, FormatJSON, FormatCBOM, FormatSARIF} {
		t.Run(string(format), func(t *testing.T) {
			out := renderMulti(t, format, partial)
			if !strings.Contains(out, "7") {
				t.Errorf("%s never mentions the 7 withheld findings beside the 1 reported:\n%s",
					format, out)
			}
			if !strings.Contains(out, "DES") {
				t.Fatalf("fixture produced no surviving finding in %s:\n%s", format, out)
			}
		})
	}
}

// TestCoverageNotesAreEmittedPerProjectNotJustFirst pins the plural.
//
// The previous per-project test had exactly one note-producing project, so an
// implementation returning after the first note passed it.
func TestCoverageNotesAreEmittedPerProjectNotJustFirst(t *testing.T) {
	mk := func(manifest string) *types.ScanResult {
		return &types.ScanResult{
			Manifest: manifest,
			Dependencies: []types.DependencyResult{
				{Dependency: types.Dependency{Name: "left-pad"}},
			},
			Summary: types.ScanSummary{TotalDependencies: 1, DirectDependencies: 1, NotInDatabase: 1},
		}
	}
	multi := types.AggregateResults("/repo", []*types.ScanResult{
		mk("/repo/a/package.json"), mk("/repo/b/package.json"), mk("/repo/c/package.json"),
	})

	notes := coverageNotes(multi.Projects)
	if len(notes) != 3 {
		t.Fatalf("got %d coverage notes, want 3 (one per unexamined project); an "+
			"implementation that stops after the first would satisfy a single-project fixture", len(notes))
	}
	for _, format := range []Format{FormatSARIF, FormatCBOM} {
		t.Run(string(format), func(t *testing.T) {
			out := renderMulti(t, format, multi)
			for _, name := range []string{"a/package.json", "b/package.json", "c/package.json"} {
				if !strings.Contains(out, name) {
					t.Errorf("%s does not attribute a coverage note to %s:\n%s", format, name, out)
				}
			}
		})
	}
}
