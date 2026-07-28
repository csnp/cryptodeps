// Copyright 2025-2026 CyberSecurity NonProfit (CSNP)
// SPDX-License-Identifier: Apache-2.0

package output

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/csnp/qramm-cryptodeps/pkg/types"
)

// mixedSkips is a scan holding one of each kind of skip: a manifest that should
// have been readable and was not, and a manifest for an ecosystem cryptodeps has
// no parser for.
//
// The two are genuinely different and the difference is load-bearing. Only the
// first means the scan failed to cover its input, so only the first forces exit
// 2. Counting them together made the table say "2 manifest file(s) found but NOT
// analyzed" about a corrupt package.json and a healthy Cargo.toml in the same
// breath, and asserted that the Cargo.toml could not be read.
func mixedSkips() *types.MultiProjectResult {
	return &types.MultiProjectResult{
		RootPath: "/repo",
		Projects: []*types.ScanResult{{
			Project:   "/repo/good",
			Manifest:  "/repo/good/package.json",
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
			{Path: "/repo/corrupt/package.json", Reason: "not valid JSON: unexpected end of JSON input"},
			{Path: "/repo/Cargo.toml", Reason: "no parser for this manifest type", Unsupported: true},
		},
	}
}

// TestUnsupportedManifestsAreReportedSeparatelyInEveryFormat is the guard for
// the reporting half of the unread/unsupported split.
//
// The exit-code half is guarded in internal/manifest. This half had nothing:
// deleting the unsupported section from the table and from markdown outright
// left the whole suite green, which is how a build.gradle full of crypto
// dependencies could go back to vanishing from the report at exit 0. That silent
// skip is the defect this branch exists to remove.
//
// Every count below is asserted with its number, because a conflated count is
// exactly what the split fixes and a bare "the file is named somewhere" check
// passes on the conflated implementation too.
func TestUnsupportedManifestsAreReportedSeparatelyInEveryFormat(t *testing.T) {
	result := mixedSkips()

	t.Run("table", func(t *testing.T) {
		out := renderMulti(t, FormatTable, result)
		if !strings.Contains(out, "1 manifest file(s) found but NOT analyzed") {
			t.Errorf("table does not report exactly 1 unread manifest, so it counts the "+
				"unsupported one as a gap in the scan:\n%s", out)
		}
		if !strings.Contains(out, "1 manifest file(s) found for ecosystems cryptodeps does not support") {
			t.Errorf("table does not report the unsupported manifest, so a Cargo.toml "+
				"vanishes from the report entirely:\n%s", out)
		}
		if !strings.Contains(out, "This does not affect the exit code.") {
			t.Errorf("table does not say an unsupported ecosystem is not a failure:\n%s", out)
		}
		for _, path := range []string{"./corrupt/package.json", "./Cargo.toml"} {
			if !strings.Contains(out, path) {
				t.Errorf("table does not name %s:\n%s", path, out)
			}
		}
	})

	t.Run("markdown", func(t *testing.T) {
		out := renderMulti(t, FormatMarkdown, result)
		if !strings.Contains(out, "1 manifest file(s) were found but could not be read") {
			t.Errorf("markdown does not report exactly 1 unread manifest:\n%s", out)
		}
		if !strings.Contains(out, "## Unsupported ecosystems") ||
			!strings.Contains(out, "1 manifest file(s) belong to ecosystems cryptodeps does not parse") {
			t.Errorf("markdown does not report the unsupported manifest:\n%s", out)
		}
		for _, path := range []string{"./corrupt/package.json", "./Cargo.toml"} {
			if !strings.Contains(out, path) {
				t.Errorf("markdown does not name %s:\n%s", path, out)
			}
		}
	})

	t.Run("cbom", func(t *testing.T) {
		out := renderMulti(t, FormatCBOM, result)
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
		byName := map[string]string{}
		for _, p := range doc.Metadata.Properties {
			byName[p.Name] = p.Value
		}
		if got := byName["cryptodeps:manifestNotAnalyzed"]; !strings.HasPrefix(got, "corrupt/package.json:") {
			t.Errorf("cryptodeps:manifestNotAnalyzed = %q, want the corrupt package.json", got)
		}
		if got := byName["cryptodeps:manifestNotSupported"]; !strings.HasPrefix(got, "Cargo.toml:") {
			t.Errorf("cryptodeps:manifestNotSupported = %q, want the Cargo.toml", got)
		}
		if got := byName["cryptodeps:coverage"]; !strings.Contains(got, "1 manifest(s) were found but could not be read") {
			t.Errorf("cryptodeps:coverage = %q, want it to count 1 unread manifest; counting "+
				"the unsupported one makes this document disagree with the table for the same run", got)
		}
	})

	t.Run("sarif", func(t *testing.T) {
		out := renderMulti(t, FormatSARIF, result)
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
		if err := json.Unmarshal([]byte(out), &doc); err != nil {
			t.Fatalf("SARIF is not valid JSON: %v", err)
		}
		inv := doc.Runs[0].Invocations[0]
		if inv.ExecutionSuccessful {
			t.Error("executionSuccessful is true while a manifest could not be read, so a " +
				"code-scanning consumer reads an incomplete scan as a complete one")
		}
		levels := map[string]string{}
		for _, n := range inv.ToolExecutionNotifications {
			switch {
			case strings.HasPrefix(n.Message.Text, "manifest found but not analyzed:"):
				levels["unread"] = n.Level
			case strings.HasPrefix(n.Message.Text, "manifest found but not supported:"):
				levels["unsupported"] = n.Level
			}
		}
		if levels["unread"] != "error" {
			t.Errorf("unread manifest notification level = %q, want error", levels["unread"])
		}
		if levels["unsupported"] != "warning" {
			t.Errorf("unsupported manifest notification level = %q, want warning; it is a "+
				"declared limit of the tool, not a failure to read the file", levels["unsupported"])
		}
	})
}

// TestOnlyUnsupportedSkipsLeaveTheScanComplete pins the direction of the split
// that decides the exit code, from the formatter's side.
func TestOnlyUnsupportedSkipsLeaveTheScanComplete(t *testing.T) {
	unsupportedOnly := []types.SkippedManifest{
		{Path: "/repo/Cargo.toml", Reason: "no parser for this manifest type", Unsupported: true},
		{Path: "/repo/Gemfile", Reason: "no parser for this manifest type", Unsupported: true},
	}
	if types.IncompleteScan(unsupportedOnly) {
		t.Error("a tree whose only skips are unsupported ecosystems reports an incomplete " +
			"scan, which is the exit 2 that made every polyglot repository a build failure")
	}

	result := mixedSkips()
	result.Skipped = unsupportedOnly
	out := renderMulti(t, FormatTable, result)
	if strings.Contains(out, "found but NOT analyzed") {
		t.Errorf("table calls an unsupported ecosystem an unread manifest:\n%s", out)
	}
	if !strings.Contains(out, "2 manifest file(s) found for ecosystems cryptodeps does not support") {
		t.Errorf("table does not report both unsupported manifests:\n%s", out)
	}
}

// TestCoverageNoteLevels pins which coverage statements warn.
//
// Every note used to be a warning, so a healthy npm workspace produced three
// warnings saying "this package.json declares no dependencies" and buried the
// one that matters. A filtered report and an empty manifest are complete and
// correct states that need explaining; a scan that drew no conclusion is not.
func TestCoverageNoteLevels(t *testing.T) {
	for _, tc := range []struct {
		name string
		note coverageNote
		want string
	}{
		{"filtered", coverageNote{Case: caseFiltered}, "note"},
		{"no dependencies", coverageNote{Case: caseNoDependencies}, "note"},
		{"nothing examined", coverageNote{Case: caseNothingExamined}, "warning"},
	} {
		if got := tc.note.Level(); got != tc.want {
			t.Errorf("%s: Level() = %q, want %q", tc.name, got, tc.want)
		}
	}
}

// TestEveryFormatNamesTheSameManifestPath is the guard for an inconsistency the
// path consolidation claimed to have removed and had not.
//
// scanRootDir and relativeToRoot were shared by CBOM and SARIF only. The table
// kept a third implementation, getRelativePath, which compared the raw scan root
// against absolutized manifest paths with a string prefix, and markdown did not
// relativize at all. So one scan of one tree, published two ways, disagreed about
// where a file is: `cryptodeps analyze .` put "corrupt/package.json" in the CBOM
// and the operator's absolute home directory in the table and the markdown for
// the same manifest. The privacy rationale for the CBOM change applies to the
// markdown report too, which the README documents and the Action publishes.
func TestEveryFormatNamesTheSameManifestPath(t *testing.T) {
	result := mixedSkips()

	for _, format := range []Format{FormatTable, FormatMarkdown, FormatCBOM, FormatSARIF} {
		t.Run(string(format), func(t *testing.T) {
			out := renderMulti(t, format, result)
			if !strings.Contains(out, "corrupt/package.json") {
				t.Fatalf("%s does not name the skipped manifest at all:\n%s", format, out)
			}
			// The scan root is /repo, so the manifest is corrupt/package.json.
			// Any format still carrying the absolute form is publishing the
			// local layout its siblings deliberately stopped publishing.
			if strings.Contains(out, "/repo/corrupt/package.json") {
				t.Errorf("%s renders the skipped manifest as an absolute path while other "+
					"formats render it relative to the scan root:\n%s", format, out)
			}
		})
	}
}

// TestGetRelativePathDoesNotInventPathsAcrossASharedPrefix pins the bug the
// string-prefix implementation had. "/repository" is not inside "/repo".
func TestGetRelativePathDoesNotInventPathsAcrossASharedPrefix(t *testing.T) {
	if got := getRelativePath("/repo", "/repository/go.mod"); got != "/repository/go.mod" {
		t.Errorf("getRelativePath(\"/repo\", \"/repository/go.mod\") = %q, want the path "+
			"unchanged; a shared string prefix is not containment", got)
	}
	if got := getRelativePath("/repo", "/repo/a/go.mod"); got != "./a/go.mod" {
		t.Errorf("getRelativePath(\"/repo\", \"/repo/a/go.mod\") = %q, want \"./a/go.mod\"", got)
	}
}
