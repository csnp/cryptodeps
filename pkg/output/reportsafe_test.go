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
	// The pipe and the backtick are in the SKIPPED path, because that is the one
	// the "Not analyzed" table renders and the one the table-cell test inspects.
	// They were on a project manifest before, which no table row carries, so the
	// pipe assertion ran against a row that had no pipe in it.
	injected := "/repo/x\n\n" + injectedHeading + "\n\nNo issues found.\n\nig|nore`x/package.json"
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
			if !strings.Contains(out, "nore") {
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

// TestMarkdownRendersUntrustedPathsInertly is the regression test for the half
// of the injection fix that the first attempt missed.
//
// Escaping characters one at a time only works if you enumerate every character
// the surrounding context makes active. The first version escaped control
// characters, backticks and pipes, which is the right set for the inside of a
// code span, and then interpolated the result into a bare "##" heading and a
// bare table cell, where every markdown construct is live. A directory named
// "**CLEAN**" rendered as bold, and one named "[no findings](https://...)"
// rendered as a link, in the report the bundled Action publishes.
//
// The fix is the context, not the character list: every untrusted string in the
// markdown report is inside a code span, so only a backtick and a pipe are
// active, and markdownSafe handles exactly those two.
func TestMarkdownRendersUntrustedPathsInertly(t *testing.T) {
	result := mixedSkips()
	result.Projects[0].Manifest = "/repo/**CLEAN**/package.json"
	result.Skipped[0].Path = "/repo/[no findings](https://evil.invalid)/package.json"

	out := renderMulti(t, FormatMarkdown, result)

	for _, line := range strings.Split(out, "\n") {
		if !strings.HasPrefix(line, "## ") && !strings.HasPrefix(line, "| `") &&
			!strings.HasPrefix(line, "- `") {
			continue
		}
		// Anything a scanned tree contributed has to sit between backticks. A
		// heading or a cell that carries it bare renders it as markup.
		if strings.Contains(line, "**CLEAN**") || strings.Contains(line, "[no findings]") {
			if strings.Count(line, "`") < 2 {
				t.Errorf("markdown renders an untrusted path outside a code span, so the "+
					"scanned tree controls the markup:\n%s", line)
			}
		}
	}
	// Guard the fixture: the hostile names must have reached the document.
	if !strings.Contains(out, "CLEAN") || !strings.Contains(out, "no findings") {
		t.Fatalf("fixture names did not reach the report, so this asserts nothing:\n%s", out)
	}
	// Every heading that names a project must be a code span.
	for _, line := range strings.Split(out, "\n") {
		if !strings.HasPrefix(line, "## ") {
			continue
		}
		heading := strings.TrimPrefix(line, "## ")
		if strings.Contains(heading, "/") && !strings.HasPrefix(heading, "`") {
			t.Errorf("project heading %q names a path outside a code span", line)
		}
	}
}

// TestNeedsEscapingCoversNonASCIILineAndBidiControls pins the set. ASCII control
// characters are not the whole vocabulary a filename can use against a report:
// U+2028 and U+2029 are line breaks to a renderer, the bidi overrides reverse the
// visible order of a name so the report displays a file it is not talking about,
// and the zero-width characters make two different paths look identical.
func TestNeedsEscapingCoversNonASCIILineAndBidiControls(t *testing.T) {
	for _, tc := range []struct {
		name string
		r    rune
	}{
		{"line separator", 0x2028},
		{"paragraph separator", 0x2029},
		{"next line", 0x85},
		{"right-to-left override", 0x202e},
		{"left-to-right embedding", 0x202a},
		{"first strong isolate", 0x2068},
		{"zero width space", 0x200b},
		{"zero width joiner", 0x200d},
		{"byte order mark", 0xfeff},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := "/repo/a" + string(tc.r) + "b/package.json"
			if !needsEscaping(path) {
				t.Fatalf("needsEscaping(%q) is false, so U+%04X reaches the report raw", path, tc.r)
			}
			if got := reportSafe(path); strings.ContainsRune(got, tc.r) {
				t.Errorf("reportSafe(%q) = %q still carries U+%04X", path, got, tc.r)
			}
		})
	}
}

// TestInvalidUTF8InAPathIsFlagged is the U+FFFD case, which is different in kind
// from the rest of the set.
//
// A filesystem does not require valid UTF-8, and Go decodes an invalid byte to
// U+FFFD. That character injects nothing and reverses nothing, so it is not
// removed: it is printable, and strconv.Quote leaves it alone. What matters is
// that the path is marked as an escaped rendering rather than presented as the
// literal name, because the bytes behind it cannot be recovered from the report.
func TestInvalidUTF8InAPathIsFlagged(t *testing.T) {
	path := "/repo/a\xff" + "b/package.json"
	decoded := string([]rune(path)) // what a reader of the report sees

	if !needsEscaping(decoded) {
		t.Fatalf("needsEscaping(%q) is false, so an unrepresentable filename is presented "+
			"as though it were the literal name", decoded)
	}
	got := reportSafe(decoded)
	if !strings.HasPrefix(got, `"`) {
		t.Errorf("reportSafe(%q) = %q, want it quoted so the reader knows the name was "+
			"not rendered literally", decoded, got)
	}
}
