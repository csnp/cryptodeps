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
		Summary: types.ScanSummary{TotalDependencies: 3, DirectDependencies: 3, NotInDatabase: 3},
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
