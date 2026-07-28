// Copyright 2025-2026 CyberSecurity NonProfit (CSNP)
// SPDX-License-Identifier: Apache-2.0

package output

import (
	"strconv"
	"strings"
	"testing"

	"github.com/csnp/qramm-cryptodeps/pkg/types"
)

// injectedHeading is what a hostile directory name tries to put in the report.
// A filesystem path may contain any byte except NUL and the separator, so a
// repository can name a directory with embedded newlines and markdown.
const injectedHeading = "## Scan result: CLEAN"

// hostilePathScan is a scan of a tree holding a directory whose name carries
// newlines and markdown, plus one whose name carries a pipe and a backtick.
func hostilePathScan() *types.MultiProjectResult {
	injected := "/repo/x\n\n" + injectedHeading + "\n\nNo issues found.\n\nignore/package.json"
	return &types.MultiProjectResult{
		RootPath: "/repo",
		Projects: []*types.ScanResult{{
			Project:   "/repo/a|b`c",
			Manifest:  "/repo/a|b`c/package.json",
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
			{Path: injected, Reason: "not valid JSON: unexpected end of JSON input"},
		},
	}
}

// TestAScannedRepositoryCannotWriteItsOwnReport is the regression test for a
// report-forgery vector.
//
// A path is attacker-controlled input: the tool is pointed at repositories it
// does not trust, and the bundled GitHub Action publishes the markdown report.
// Every path was interpolated raw, so a directory named with an embedded
// "## Scan result: CLEAN" put that heading in the report, above the findings
// that contradict it. Reproduced end to end before this fix: the injected
// heading appeared in the markdown report for a tree containing one corrupt
// manifest, and in the table report as free-standing lines.
//
// The three machine-readable formats were never affected, because encoding/json
// escapes what it emits. They are asserted here anyway, so that a future change
// away from the encoder cannot reintroduce it quietly.
func TestAScannedRepositoryCannotWriteItsOwnReport(t *testing.T) {
	result := hostilePathScan()

	for _, format := range []Format{FormatTable, FormatMarkdown, FormatJSON, FormatCBOM, FormatSARIF} {
		t.Run(string(format), func(t *testing.T) {
			out := renderMulti(t, format, result)

			// The heading must never appear at the start of a line, which is
			// the only position markdown reads it as a heading, and the only
			// position it is forged from.
			for _, line := range strings.Split(out, "\n") {
				if strings.HasPrefix(strings.TrimSpace(line), injectedHeading) {
					t.Errorf("%s carries a heading forged by the scanned tree:\n%s", format, out)
					break
				}
			}
			// Guard the fixture: the hostile path must actually have reached
			// the document, or this asserts nothing.
			if !strings.Contains(out, "ignore/package.json") &&
				!strings.Contains(out, `ignore/package.json`) {
				t.Fatalf("%s does not report the hostile manifest at all, so this test "+
					"cannot show how it is rendered:\n%s", format, out)
			}
		})
	}
}

// TestMarkdownTableCellsSurviveAPipeInAPath pins the other half. GitHub-flavoured
// markdown splits a table cell on an unescaped pipe even inside a code span, so
// a directory named "a|b" silently shifted the Reason column into a third cell.
func TestMarkdownTableCellsSurviveAPipeInAPath(t *testing.T) {
	out := renderMulti(t, FormatMarkdown, hostilePathScan())

	var checked int
	for _, line := range strings.Split(out, "\n") {
		if !strings.HasPrefix(line, "| `") {
			continue
		}
		checked++
		// A row of the "Not analyzed" table is | path | reason |, which is
		// three empty fields around two cells once split.
		if got := strings.Count(line, "|") - strings.Count(line, `\|`); got != 3 {
			t.Errorf("markdown table row has %d unescaped pipes, want 3 (two cells):\n%s",
				got, line)
		}
	}
	if checked == 0 {
		t.Fatal("no markdown table row carried a path, so this asserts nothing")
	}
}

// TestOrdinaryPathsAreRenderedUnchanged is the paired guard. Escaping must be
// invisible for every real path, or it would churn the output of every scan and
// make the reports harder to read to fix a case that does not occur.
func TestOrdinaryPathsAreRenderedUnchanged(t *testing.T) {
	for _, p := range []string{
		"/repo/a/package.json",
		"relative/path/go.mod",
		"/repo/with space/pom.xml",
		"/repo/dot.dir/requirements.txt",
		`C:\repo\package.json`,
	} {
		if got := reportSafe(p); got != p {
			t.Errorf("reportSafe(%q) = %q, want it unchanged", p, got)
		}
		if got := markdownSafe(p); got != p {
			t.Errorf("markdownSafe(%q) = %q, want it unchanged", p, got)
		}
	}
}

// TestHostilePathsAreEscapedNotDropped checks the escaping is reversible. A
// scanner that silently dropped or truncated the name would be hiding the file
// it is reporting, which is the silent skip this branch exists to remove.
func TestHostilePathsAreEscapedNotDropped(t *testing.T) {
	for _, tc := range []struct{ name, in string }{
		{"newline", "/repo/x\n## heading/package.json"},
		{"carriage return", "/repo/x\r## heading/package.json"},
		{"pipe", "/repo/a|b/package.json"},
		{"backtick", "/repo/a`b/package.json"},
		{"tab", "/repo/a\tb/package.json"},
		{"del", "/repo/a\x7fb/package.json"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := reportSafe(tc.in)
			if got == tc.in {
				t.Fatalf("reportSafe(%q) returned it unchanged", tc.in)
			}
			if strings.ContainsAny(got, "\n\r\t\x7f") {
				t.Errorf("reportSafe(%q) = %q still carries a control character", tc.in, got)
			}
			// Reversible: the quoted form unquotes back to the original, so the
			// user can still identify the file. strconv, not encoding/json:
			// Go's quoting renders DEL as \x7f, which JSON does not accept.
			back, err := strconv.Unquote(got)
			if err != nil {
				t.Fatalf("reportSafe(%q) = %q is not a decodable quoted string: %v", tc.in, got, err)
			}
			if back != tc.in {
				t.Errorf("reportSafe(%q) decodes to %q, so the real path is lost", tc.in, back)
			}

			md := markdownSafe(tc.in)
			if strings.Contains(md, "`") {
				t.Errorf("markdownSafe(%q) = %q carries a backtick and would close the code span",
					tc.in, md)
			}
			if strings.Count(md, "|") != strings.Count(md, `\|`) {
				t.Errorf("markdownSafe(%q) = %q carries an unescaped pipe", tc.in, md)
			}
		})
	}
}
