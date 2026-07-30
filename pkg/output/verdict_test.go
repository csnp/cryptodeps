// Copyright 2025-2026 CyberSecurity NonProfit (CSNP)
// SPDX-License-Identifier: Apache-2.0

package output

import (
	"bytes"
	"strings"
	"testing"
	"unicode"

	"github.com/csnp/qramm-cryptodeps/pkg/types"
)

// renderTable formats a scan result the way the CLI does.
func renderTable(t *testing.T, result *types.ScanResult) string {
	t.Helper()
	var buf bytes.Buffer
	if err := (&TableFormatter{Options: DefaultOptions()}).Format(result, &buf); err != nil {
		t.Fatalf("format: %v", err)
	}
	return buf.String()
}

// cleanVerdict is the phrase the tool uses when it has looked and found nothing.
// It must not appear when the tool has not looked.
const cleanVerdict = "No cryptographic usage detected"

// TestAllUnknownIsNotReportedAsClean covers the case where every dependency is
// absent from the database.
//
// The scan examined nothing, and reporting "No cryptographic usage detected" is
// a false negative on the tool's core question. The JSON for the same scan said
// notInDatabase: 3 while the table said the project was clean.
func TestAllUnknownIsNotReportedAsClean(t *testing.T) {
	result := &types.ScanResult{
		Manifest:  "requirements.txt",
		Ecosystem: types.EcosystemPyPI,
		Dependencies: []types.DependencyResult{
			{Dependency: types.Dependency{Name: "rsa", Version: "4.9"}},
			{Dependency: types.Dependency{Name: "requests"}},
			{Dependency: types.Dependency{Name: "certifi"}},
		},
		Summary: types.ScanSummary{TotalDependencies: 3, DirectDependencies: 3, NotInDatabase: 3,
			NotExamined: 3},
	}

	out := renderTable(t, result)

	if strings.Contains(out, cleanVerdict) {
		t.Errorf("scan that examined nothing reported a clean result:\n%s", out)
	}
	if !strings.Contains(out, "--deep") {
		t.Errorf("verdict does not tell the user how to actually analyze these packages:\n%s", out)
	}
}

// TestFilteredToEmptyIsNotReportedAsClean covers findings that exist but were
// withheld by --risk or --min-severity.
//
// This is the same false-clean verdict as the all-unknown case reached from a
// different direction, and it was introduced by the fix that made those flags
// work at all.
func TestFilteredToEmptyIsNotReportedAsClean(t *testing.T) {
	result := &types.ScanResult{
		Manifest:  "package.json",
		Ecosystem: types.EcosystemNPM,
		Dependencies: []types.DependencyResult{
			{
				Dependency: types.Dependency{Name: "node-forge", Version: "1.3.1"},
				InDatabase: true,
				Analysis:   &types.PackageAnalysis{Package: "node-forge"},
			},
		},
		Summary: types.ScanSummary{TotalDependencies: 1, FilteredOut: 13},
	}

	out := renderTable(t, result)

	if strings.Contains(out, cleanVerdict) {
		t.Errorf("filtered-away findings reported as a clean result:\n%s", out)
	}
	if !strings.Contains(out, "13") {
		t.Errorf("verdict does not say how many findings were withheld:\n%s", out)
	}
	if !strings.Contains(out, "--risk") {
		t.Errorf("verdict does not name the filter responsible:\n%s", out)
	}
}

// TestGenuinelyCleanScanStillSaysSo guards the opposite direction: the honest
// clean verdict must survive. Without this, a test suite could be satisfied by a
// tool that never reports anything as clean.
func TestGenuinelyCleanScanStillSaysSo(t *testing.T) {
	result := &types.ScanResult{
		Manifest:  "package.json",
		Ecosystem: types.EcosystemNPM,
		Dependencies: []types.DependencyResult{
			{
				Dependency: types.Dependency{Name: "left-pad", Version: "1.3.0"},
				InDatabase: true,
				Analysis:   &types.PackageAnalysis{Package: "left-pad"},
			},
		},
		Summary: types.ScanSummary{TotalDependencies: 1, DirectDependencies: 1},
	}

	out := renderTable(t, result)

	if !strings.Contains(out, cleanVerdict) {
		t.Errorf("a genuinely clean scan no longer reports a clean result:\n%s", out)
	}
}

// TestSkippedManifestsAreReported checks the skip notice reaches the reader and
// names both the file and the reason.
func TestSkippedManifestsAreReported(t *testing.T) {
	multi := &types.MultiProjectResult{
		RootPath: "/repo",
		Projects: []*types.ScanResult{{
			Manifest: "/repo/good/package.json",
			Summary:  types.ScanSummary{TotalDependencies: 1, DirectDependencies: 1},
			Dependencies: []types.DependencyResult{{
				Dependency: types.Dependency{Name: "left-pad"},
				InDatabase: true,
				Analysis:   &types.PackageAnalysis{Package: "left-pad"},
			}},
		}},
		Skipped: []types.SkippedManifest{
			{Path: "/repo/broken/package.json", Reason: "not valid JSON: unexpected end of JSON input"},
		},
	}

	var buf bytes.Buffer
	if err := (&TableFormatter{Options: DefaultOptions()}).FormatMulti(multi, &buf); err != nil {
		t.Fatalf("format: %v", err)
	}
	out := buf.String()

	if !strings.Contains(out, "./broken/package.json") {
		t.Errorf("skipped manifest is not named in the output:\n%s", out)
	}
	if !strings.Contains(out, "not valid JSON") {
		t.Errorf("skipped manifest carries no reason:\n%s", out)
	}
}

// TestTableOutputCarriesNoEmoji enforces the CSNP no-emoji standard on the one
// format that had them.
//
// The markers also have to survive a pipe into a file, a terminal without an
// emoji font, and a screen reader, none of which was true of the coloured
// circles. Box-drawing characters used for rules are not emoji and are allowed.
func TestTableOutputCarriesNoEmoji(t *testing.T) {
	result := &types.ScanResult{
		Manifest:  "package.json",
		Ecosystem: types.EcosystemNPM,
		Dependencies: []types.DependencyResult{{
			Dependency: types.Dependency{Name: "node-forge", Version: "1.3.1"},
			InDatabase: true,
			Analysis: &types.PackageAnalysis{
				Package: "node-forge",
				Crypto: []types.CryptoUsage{
					{Algorithm: "RSA", QuantumRisk: types.RiskVulnerable, Severity: types.SeverityHigh},
					{Algorithm: "AES", QuantumRisk: types.RiskPartial, Severity: types.SeverityMedium},
					{Algorithm: "Ed25519", QuantumRisk: types.RiskSafe, Severity: types.SeverityInfo},
					{Algorithm: "Mystery", QuantumRisk: types.RiskUnknown, Severity: types.SeverityInfo},
				},
			},
		}},
		Summary: types.ScanSummary{TotalDependencies: 1, WithCrypto: 1, QuantumVulnerable: 1, QuantumPartial: 1},
	}

	out := renderTable(t, result)

	// Confirm the fixture actually reached the rows under test, so this cannot
	// pass by rendering nothing.
	for _, section := range []string{"VULNERABLE", "PARTIAL RISK", "QUANTUM SAFE", "UNKNOWN RISK"} {
		if !strings.Contains(out, section) {
			t.Fatalf("fixture did not reach the %s section, so the emoji check proves nothing:\n%s", section, out)
		}
	}

	for _, r := range out {
		if isEmoji(r) {
			t.Errorf("emoji %U (%q) present in table output", r, string(r))
		}
	}

	for _, want := range []string{"[!]", "[~]", "[OK]", "[?]"} {
		if !strings.Contains(out, want) {
			t.Errorf("ASCII risk token %q missing from output:\n%s", want, out)
		}
	}
}

// isEmoji reports whether a rune is a pictographic character.
func isEmoji(r rune) bool {
	switch {
	case r >= 0x1F300 && r <= 0x1FAFF: // pictographs, symbols, supplemental
		return true
	case r >= 0x2600 && r <= 0x27BF: // misc symbols and dingbats
		return true
	case r == 0xFE0F: // variation selector 16, the emoji presentation marker
		return true
	case r >= 0x2B00 && r <= 0x2BFF: // arrows and geometric shapes used as emoji
		return true
	default:
		return false
	}
}

// TestRiskIconIsASCIIAndUnique checks the single mapping point.
func TestRiskIconIsASCIIAndUnique(t *testing.T) {
	seen := make(map[string]types.QuantumRisk)
	for _, risk := range []types.QuantumRisk{
		types.RiskVulnerable, types.RiskPartial, types.RiskSafe, types.RiskUnknown,
	} {
		token := riskIcon(risk)
		for _, r := range token {
			if r > unicode.MaxASCII {
				t.Errorf("riskIcon(%s) = %q contains non-ASCII rune %U", risk, token, r)
			}
		}
		if prev, dup := seen[token]; dup {
			t.Errorf("riskIcon(%s) and riskIcon(%s) both return %q", risk, prev, token)
		}
		seen[token] = risk
	}
}

// deepAnalyzedCleanScan is a scan where the database carried none of the
// dependencies and source analysis read all of them, finding no cryptography.
//
// This is the ordinary outcome of `analyze <tree> --deep` on a project whose
// dependencies are not cryptographic, and the state the verdict got wrong.
func deepAnalyzedCleanScan() *types.ScanResult {
	return &types.ScanResult{
		Project:   "/repo",
		Manifest:  "/repo/package.json",
		Ecosystem: types.EcosystemNPM,
		Dependencies: []types.DependencyResult{
			{Dependency: types.Dependency{Name: "chalk", Version: "5.3.0"}, DeepAnalyzed: true,
				Analysis: &types.PackageAnalysis{Package: "chalk"}},
			{Dependency: types.Dependency{Name: "commander", Version: "12.1.0"}, DeepAnalyzed: true,
				Analysis: &types.PackageAnalysis{Package: "commander"}},
			{Dependency: types.Dependency{Name: "lodash", Version: "4.17.21"}, DeepAnalyzed: true,
				Analysis: &types.PackageAnalysis{Package: "lodash"}},
		},
		Summary: types.ScanSummary{
			TotalDependencies: 3, DirectDependencies: 3,
			// Absent from the database, and examined anyway.
			NotInDatabase: 3, NotExamined: 0, DeepAttempted: true,
		},
	}
}

// TestDeepAnalyzedCleanScanIsReportedAsClean is the regression test for the
// defect that held the v1.3.0 tag.
//
// `analyze <tree> --deep` over three dependencies absent from the database
// printed "Not analyzed. All 3 dependencies are absent from the crypto
// database, so no conclusion about cryptographic usage can be drawn from this
// scan. Run with --deep to analyze package source code directly." Every clause
// of that was false for the run that produced it, the JSON for the same
// invocation reported deepAnalyzed on all three, and the released 1.2.2 got the
// case right. The classifier was asking a question about the database lookup in
// order to answer a question about examination.
func TestDeepAnalyzedCleanScanIsReportedAsClean(t *testing.T) {
	result := deepAnalyzedCleanScan()

	// Guard the fixture. If the database count and the examination count agree,
	// this fixture cannot tell the two predicates apart and the test proves
	// nothing.
	if result.Summary.NotInDatabase == result.Summary.NotExamined {
		t.Fatalf("fixture does not separate the database count from the examination count: %+v",
			result.Summary)
	}
	if got := classifyNoFindings(result.Summary); got != caseGenuinelyClean {
		t.Fatalf("classifyNoFindings = %v, want caseGenuinelyClean", got)
	}

	out := renderTable(t, result)

	if !strings.Contains(out, cleanVerdict) {
		t.Errorf("a scan that read every dependency and found no cryptography did not report "+
			"a clean result:\n%s", out)
	}
	if strings.Contains(out, "no conclusion about cryptographic usage") {
		t.Errorf("scan drew a conclusion and then said it could not:\n%s", out)
	}
	if strings.Contains(out, "--deep") {
		t.Errorf("the user ran --deep and the only suggested next step is --deep:\n%s", out)
	}
	if !strings.Contains(out, "3 of 3") {
		t.Errorf("verdict does not say how much of the tree was examined:\n%s", out)
	}
}

// TestDeepAnalyzedCleanScanIsCleanInEveryFormat carries the same case through
// the formats that re-derived the verdict independently once before.
func TestDeepAnalyzedCleanScanIsCleanInEveryFormat(t *testing.T) {
	multi := types.AggregateResults("/repo", []*types.ScanResult{deepAnalyzedCleanScan()})

	if multi.TotalSummary.NotExamined != 0 || !multi.TotalSummary.DeepAttempted {
		t.Fatalf("aggregation dropped the coverage fields: %+v", multi.TotalSummary)
	}

	for _, format := range []Format{FormatTable, FormatMarkdown, FormatSARIF, FormatCBOM, FormatJSON} {
		t.Run(string(format), func(t *testing.T) {
			out := renderMulti(t, format, multi)
			if out == "" {
				t.Fatalf("%s produced no output", format)
			}
			for _, phrase := range []string{
				"nothing was examined",
				"no conclusion about cryptographic usage",
				"not in the crypto database. Run with",
			} {
				if strings.Contains(out, phrase) {
					t.Errorf("%s says %q about a scan that examined every dependency:\n%s",
						format, phrase, out)
				}
			}
			if format != FormatJSON && strings.Contains(out, "--deep") {
				t.Errorf("%s tells a user who ran --deep to run --deep:\n%s", format, out)
			}
		})
	}
}

// TestUnfetchablePackagesDoNotSuggestDeepAgain covers the other half of the
// dead end: --deep was given, the fetch failed, nothing was examined.
//
// "Run with --deep" is wrong here for the same reason, and the correct next
// step is the warning the scan already printed.
func TestUnfetchablePackagesDoNotSuggestDeepAgain(t *testing.T) {
	result := &types.ScanResult{
		Manifest:  "/repo/package.json",
		Ecosystem: types.EcosystemNPM,
		Dependencies: []types.DependencyResult{
			{Dependency: types.Dependency{Name: "left-pad"}},
			{Dependency: types.Dependency{Name: "is-odd"}},
		},
		Summary: types.ScanSummary{
			TotalDependencies: 2, DirectDependencies: 2,
			NotInDatabase: 2, NotExamined: 2, DeepAttempted: true,
		},
	}

	out := renderTable(t, result)

	if strings.Contains(out, cleanVerdict) {
		t.Errorf("scan that examined nothing reported a clean result:\n%s", out)
	}
	if !strings.Contains(out, "Not analyzed") {
		t.Errorf("scan that examined nothing does not say so:\n%s", out)
	}
	if strings.Contains(out, "--deep") {
		t.Errorf("the user ran --deep and the tool suggests running --deep:\n%s", out)
	}
	if !strings.Contains(out, "warnings") {
		t.Errorf("verdict gives no next step for packages that could not be read:\n%s", out)
	}
}

// TestPartiallyExaminedScanSaysWhatItMissed is the inverse question.
//
// Narrowing the trigger for "nothing was examined" moves a project that is
// partly examined into the clean case. The clean case must then account for the
// dependencies nothing reached, or the narrowing has traded a false alarm for a
// silence.
func TestPartiallyExaminedScanSaysWhatItMissed(t *testing.T) {
	result := &types.ScanResult{
		Manifest:  "/repo/package.json",
		Ecosystem: types.EcosystemNPM,
		Dependencies: []types.DependencyResult{
			{Dependency: types.Dependency{Name: "chalk"}, InDatabase: true,
				Analysis: &types.PackageAnalysis{Package: "chalk"}},
			{Dependency: types.Dependency{Name: "left-pad"}},
			{Dependency: types.Dependency{Name: "is-odd"}},
		},
		Summary: types.ScanSummary{
			TotalDependencies: 3, DirectDependencies: 3,
			NotInDatabase: 2, NotExamined: 2,
		},
	}

	if got := classifyNoFindings(result.Summary); got != caseGenuinelyClean {
		t.Fatalf("fixture does not land in the clean case: %v", got)
	}

	out := renderTable(t, result)

	if !strings.Contains(out, "1 of 3") {
		t.Errorf("clean verdict does not say how much of the tree it covers:\n%s", out)
	}
	if !strings.Contains(out, "2 could not be examined") {
		t.Errorf("clean verdict does not account for the dependencies nothing reached:\n%s", out)
	}
	if !strings.Contains(out, "--deep") {
		t.Errorf("no next step offered for the unexamined dependencies:\n%s", out)
	}
}
