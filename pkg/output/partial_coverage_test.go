// Copyright 2025-2026 CyberSecurity NonProfit (CSNP)
// SPDX-License-Identifier: Apache-2.0

package output

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/csnp/qramm-cryptodeps/pkg/types"
)

// partiallyExaminedScan is a project where one dependency was read and carried
// a finding, and a second could not be examined at all.
//
// This is the shape that was invisible: the coverage question was only asked of
// reports that produced nothing, and this one produces something.
func partiallyExaminedScan() *types.ScanResult {
	return &types.ScanResult{
		Project:   "demo",
		Manifest:  "pom.xml",
		Ecosystem: types.EcosystemMaven,
		Dependencies: []types.DependencyResult{
			{
				Dependency:   types.Dependency{Name: "org.tukaani:xz", Version: "1.9", Ecosystem: types.EcosystemMaven},
				DeepAnalyzed: true,
				Analysis: &types.PackageAnalysis{
					Package: "org.tukaani:xz",
					Analysis: types.AnalysisMetadata{
						FilesAnalyzed: 103,
					},
					Crypto: []types.CryptoUsage{{
						Algorithm:   "SHA-256",
						Type:        "hash",
						QuantumRisk: types.RiskPartial,
						Severity:    types.SeverityMedium,
						Location:    types.Location{File: "SHA256.java", Line: 18},
					}},
				},
			},
			{
				Dependency: types.Dependency{
					Name:      "com.google.guava:listenablefuture",
					Version:   "9999.0-empty-to-avoid-conflict-with-guava",
					Ecosystem: types.EcosystemMaven,
				},
				Error: "source analysis read no files it can parse in the fetched archive for " +
					"com.google.guava:listenablefuture",
			},
		},
		Summary: types.ScanSummary{
			TotalDependencies: 2,
			WithCrypto:        1,
			QuantumPartial:    1,
			NotInDatabase:     2,
			NotExamined:       1,
			DeepAttempted:     true,
		},
	}
}

// TestPartialCoverageReachesEveryFormat is the regression test for the gap the
// v1.3.0 fresh-user pass found.
//
// A three-dependency Maven scan where one artifact publishes no sources JAR
// said so on stdout, on stderr and in JSON, and said nothing at all in the two
// formats that are uploaded to GitHub code scanning and to compliance systems:
// the CBOM listed the libraries it had findings for and carried no coverage
// property, and the SARIF run reported executionSuccessful with no
// notification. A bill of materials that omits a dependency without saying so
// is a false bill of materials.
//
// The cause is the same shape as an earlier defect in this file: the coverage
// question was asked only of reports that produced no findings, and a partially
// examined project produces findings.
func TestPartialCoverageReachesEveryFormat(t *testing.T) {
	result := partiallyExaminedScan()

	// Guard the fixture on both sides, or a passing assertion below could be
	// describing a scan that examined everything or nothing.
	if result.Summary.NotExamined == 0 ||
		result.Summary.NotExamined >= result.Summary.TotalDependencies {
		t.Fatalf("fixture is not partially examined: %+v", result.Summary)
	}
	if !hasAnyCrypto(result.Dependencies) {
		t.Fatalf("fixture has no findings, so it does not reach the case under test")
	}

	t.Run("sarif", func(t *testing.T) {
		var buf bytes.Buffer
		if err := (&SARIFFormatter{Options: DefaultOptions()}).Format(result, &buf); err != nil {
			t.Fatalf("format: %v", err)
		}
		var doc struct {
			Runs []struct {
				Results     []json.RawMessage `json:"results"`
				Invocations []struct {
					ToolExecutionNotifications []struct {
						Message struct {
							Text string `json:"text"`
						} `json:"message"`
						Level string `json:"level"`
					} `json:"toolExecutionNotifications"`
				} `json:"invocations"`
			} `json:"runs"`
		}
		if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
			t.Fatalf("parse SARIF: %v", err)
		}
		if len(doc.Runs) != 1 {
			t.Fatalf("expected one run, got %d", len(doc.Runs))
		}
		if len(doc.Runs[0].Results) == 0 {
			t.Fatal("the finding is missing, so this document is not the case under test")
		}
		if len(doc.Runs[0].Invocations) == 0 || len(doc.Runs[0].Invocations[0].ToolExecutionNotifications) == 0 {
			t.Fatalf("SARIF reports no notification for a scan that could not examine %d of %d "+
				"dependencies; GitHub code scanning is told the run was complete",
				result.Summary.NotExamined, result.Summary.TotalDependencies)
		}
		notification := doc.Runs[0].Invocations[0].ToolExecutionNotifications[0]
		if !strings.Contains(notification.Message.Text, "could not be examined") {
			t.Errorf("the notification does not say coverage was incomplete: %q",
				notification.Message.Text)
		}
		if notification.Level != "warning" {
			t.Errorf("notification level = %q, want warning: an incomplete scan is not a note",
				notification.Level)
		}
	})

	t.Run("cbom", func(t *testing.T) {
		var buf bytes.Buffer
		if err := (&CBOMFormatter{}).Format(result, &buf); err != nil {
			t.Fatalf("format: %v", err)
		}
		var doc struct {
			Metadata struct {
				Properties []struct {
					Name  string `json:"name"`
					Value string `json:"value"`
				} `json:"properties"`
			} `json:"metadata"`
			Components []struct {
				Type string `json:"type"`
				Name string `json:"name"`
			} `json:"components"`
		}
		if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
			t.Fatalf("parse CBOM: %v", err)
		}

		var libraries int
		for _, c := range doc.Components {
			if c.Type == "library" {
				libraries++
			}
		}
		if libraries == 0 {
			t.Fatal("the examined library is missing, so this document is not the case under test")
		}

		var coverage string
		for _, p := range doc.Metadata.Properties {
			if p.Name == "cryptodeps:coverage" {
				coverage = p.Value
			}
		}
		if coverage == "" {
			t.Fatalf("CBOM carries no cryptodeps:coverage property while listing %d of %d "+
				"declared dependencies: a bill of materials that omits one without saying so "+
				"is a false bill of materials", libraries, result.Summary.TotalDependencies)
		}
		if !strings.Contains(coverage, "could not be examined") {
			t.Errorf("the coverage property does not say what was missed: %q", coverage)
		}
	})

	// The human formats already carried this, which is what made the gap in the
	// machine ones hard to see: the operator running the scan was told, and the
	// document their CI uploaded was not. Asserted here so that a change to the
	// machine formats cannot be made by quietly removing the human ones.
	t.Run("table and markdown already said so", func(t *testing.T) {
		for name, want := range map[string]string{
			"table":    "could not be read by source analysis",
			"markdown": "were not examined",
		} {
			var f Formatter
			if name == "table" {
				f = &TableFormatter{Options: DefaultOptions()}
			} else {
				f = &MarkdownFormatter{Options: DefaultOptions()}
			}
			var buf bytes.Buffer
			if err := f.Format(result, &buf); err != nil {
				t.Fatalf("%s: %v", name, err)
			}
			if !strings.Contains(buf.String(), want) {
				t.Errorf("%s does not account for the dependency nothing read, expected %q:\n%s",
					name, want, buf.String())
			}
		}
	})
}

// TestPartiallyReadPackageIsDisclosedInEveryFormat is the same question asked of
// a package that WAS examined and was read incompletely.
//
// casePartialCoverage covers a dependency nothing reached. A dependency holding
// one file the analyzer parsed and one it refused is not that: it is examined, so
// it is absent from NotExamined, and every format described a partial reading as
// a complete one. The count that proved otherwise was incremented inside the
// walk and discarded there.
func TestPartiallyReadPackageIsDisclosedInEveryFormat(t *testing.T) {
	result := partiallyExaminedScan()
	// Same fixture, with the second dependency examined in part rather than not
	// at all: three files read, one refused.
	result.Dependencies[1].DeepAnalyzed = true
	result.Dependencies[1].Error = ""
	result.Dependencies[1].Analysis = &types.PackageAnalysis{
		Package:  "com.google.guava:listenablefuture",
		Analysis: types.AnalysisMetadata{FilesAnalyzed: 3, FilesUnreadable: 1},
	}
	result.Summary.NotExamined = 0
	result.Summary.SourceFilesUnreadable = 1

	// Guard the fixture: this must be the partial-READ state and not the
	// partial-COVERAGE state, or the assertions below are satisfied by the note
	// that already existed.
	if result.Summary.NotExamined != 0 {
		t.Fatalf("fixture still has an unexamined dependency, so casePartialCoverage answers "+
			"these assertions instead: %+v", result.Summary)
	}
	if result.Summary.SourceFilesUnreadable == 0 {
		t.Fatalf("fixture has no unreadable source file, so it does not reach the case under test")
	}
	if !hasAnyCrypto(result.Dependencies) {
		t.Fatalf("fixture has no findings; the no-findings path is covered elsewhere and the " +
			"formats that omitted this state only did so when findings existed")
	}

	notes := coverageNotes([]*types.ScanResult{result})
	var partialSource *coverageNote
	for i := range notes {
		if notes[i].Case == casePartialSource {
			partialSource = &notes[i]
		}
	}
	if partialSource == nil {
		t.Fatalf("no note is produced for a package read in part, so no format can report it: %+v",
			notes)
	}
	if partialSource.Level() != "warning" {
		t.Errorf("note level = %q, want warning: an incomplete reading is not a note",
			partialSource.Level())
	}

	t.Run("sarif", func(t *testing.T) {
		var buf bytes.Buffer
		if err := (&SARIFFormatter{Options: DefaultOptions()}).Format(result, &buf); err != nil {
			t.Fatalf("format: %v", err)
		}
		var doc struct {
			Runs []struct {
				Results     []json.RawMessage `json:"results"`
				Invocations []struct {
					ToolExecutionNotifications []struct {
						Message struct {
							Text string `json:"text"`
						} `json:"message"`
					} `json:"toolExecutionNotifications"`
				} `json:"invocations"`
			} `json:"runs"`
		}
		if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
			t.Fatalf("parse SARIF: %v", err)
		}
		if len(doc.Runs) != 1 || len(doc.Runs[0].Results) == 0 {
			t.Fatal("the finding is missing, so this document is not the case under test")
		}
		var found bool
		for _, inv := range doc.Runs[0].Invocations {
			for _, n := range inv.ToolExecutionNotifications {
				if strings.Contains(n.Message.Text, "could not be read") {
					found = true
				}
			}
		}
		if !found {
			t.Errorf("SARIF reports no notification for %d source file(s) that could not be "+
				"read; code scanning is told the reading was complete:\n%s",
				result.Summary.SourceFilesUnreadable, buf.String())
		}
	})

	t.Run("cbom", func(t *testing.T) {
		var buf bytes.Buffer
		if err := (&CBOMFormatter{}).Format(result, &buf); err != nil {
			t.Fatalf("format: %v", err)
		}
		var doc struct {
			Metadata struct {
				Properties []struct {
					Name  string `json:"name"`
					Value string `json:"value"`
				} `json:"properties"`
			} `json:"metadata"`
		}
		if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
			t.Fatalf("parse CBOM: %v", err)
		}
		var found bool
		for _, p := range doc.Metadata.Properties {
			if p.Name == "cryptodeps:coverage" && strings.Contains(p.Value, "could not be read") {
				found = true
			}
		}
		if !found {
			t.Errorf("CBOM carries no coverage property for a package read in part:\n%s", buf.String())
		}
	})

	t.Run("table and markdown", func(t *testing.T) {
		for name, f := range map[string]Formatter{
			"table":    &TableFormatter{Options: DefaultOptions()},
			"markdown": &MarkdownFormatter{Options: DefaultOptions()},
		} {
			var buf bytes.Buffer
			if err := f.Format(result, &buf); err != nil {
				t.Fatalf("%s: %v", name, err)
			}
			if !strings.Contains(buf.String(), "could not be read") {
				t.Errorf("%s does not say a source file went unread:\n%s", name, buf.String())
			}
			// The note is a blockquote under a heading. Without the heading it is
			// still readable prose but no longer a section, and this fixture has
			// nothing else that would produce one: NotExamined is zero.
			if name == "markdown" && !strings.Contains(buf.String(), "## Notes") {
				t.Errorf("markdown emits the note with no section heading to carry it:\n%s",
					buf.String())
			}
		}
	})

	// JSON is where a consumer audits the claim per dependency, so the two
	// counts have to travel together rather than only in aggregate.
	t.Run("json carries both counts per dependency", func(t *testing.T) {
		var buf bytes.Buffer
		if err := (&JSONFormatter{Indent: true}).Format(result, &buf); err != nil {
			t.Fatalf("format: %v", err)
		}
		if !strings.Contains(buf.String(), `"filesUnreadable": 1`) {
			t.Errorf("JSON does not carry filesUnreadable for the dependency read in part:\n%s",
				buf.String())
		}
	})
}

// TestCleanVerdictDisclosesAPartialReadInEveryHumanFormat covers the shape the
// defect actually took.
//
// The damaging case is a package with no findings, because that is the verdict
// that says nothing was found: a dependency whose only cryptography sat in a
// refused file reached "no cryptographic usage detected in the 1 of 1
// dependencies that were examined". Both human formats reach that sentence
// through their own no-findings branch, so both need asserting.
func TestCleanVerdictDisclosesAPartialReadInEveryHumanFormat(t *testing.T) {
	result := partiallyExaminedScan()
	// One dependency, examined in part, carrying no findings at all.
	result.Dependencies = result.Dependencies[:1]
	result.Dependencies[0].Analysis.Crypto = nil
	result.Summary = types.ScanSummary{
		TotalDependencies:     1,
		NotInDatabase:         1,
		DeepAttempted:         true,
		SourceFilesUnreadable: 2,
	}

	// Guard the fixture: with a finding present, or with an unexamined
	// dependency, a different branch answers these assertions.
	if hasAnyCrypto(result.Dependencies) {
		t.Fatalf("fixture has findings, so the no-findings verdict is never reached")
	}
	if classifyNoFindings(result.Summary) != caseGenuinelyClean {
		t.Fatalf("fixture does not reach the clean verdict, it classifies as %v",
			classifyNoFindings(result.Summary))
	}

	for name, f := range map[string]Formatter{
		"table":    &TableFormatter{Options: DefaultOptions()},
		"markdown": &MarkdownFormatter{Options: DefaultOptions()},
	} {
		var buf bytes.Buffer
		if err := f.Format(result, &buf); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		out := buf.String()
		// The clean sentence itself is expected: the package WAS examined. What
		// must not happen is that sentence standing alone.
		if !strings.Contains(out, "could not be read") {
			t.Errorf("%s reports a clean examination and never says that 2 source files in it "+
				"were not read:\n%s", name, out)
		}
	}
}

// TestFullyReadPackageCarriesNoPartialReadWarning is the inverse question.
//
// A package every file of which was read must not acquire a warning, or the
// signal is worth nothing on the reports that are actually complete.
func TestFullyReadPackageCarriesNoPartialReadWarning(t *testing.T) {
	result := partiallyExaminedScan()
	result.Summary.SourceFilesUnreadable = 0

	for _, n := range coverageNotes([]*types.ScanResult{result}) {
		if n.Case == casePartialSource {
			t.Errorf("a scan that read every file carries a partial-read note: %q", n.Text())
		}
	}
}

// TestFullyExaminedScanCarriesNoCoverageWarning is the inverse question.
//
// Adding a note for partial coverage must not attach one to a scan that read
// everything, or every complete report acquires a warning and the signal is
// worth nothing.
func TestFullyExaminedScanCarriesNoCoverageWarning(t *testing.T) {
	result := partiallyExaminedScan()
	// Same fixture, with the unexamined dependency read.
	result.Dependencies[1].DeepAnalyzed = true
	result.Dependencies[1].Error = ""
	result.Dependencies[1].Analysis = &types.PackageAnalysis{
		Package:  "com.google.guava:listenablefuture",
		Analysis: types.AnalysisMetadata{FilesAnalyzed: 7},
	}
	result.Summary.NotExamined = 0

	notes := coverageNotes([]*types.ScanResult{result})
	for _, n := range notes {
		if n.Case == casePartialCoverage {
			t.Errorf("a fully examined scan carries a partial-coverage note: %q", n.Text())
		}
	}
}
