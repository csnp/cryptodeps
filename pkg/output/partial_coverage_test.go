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
