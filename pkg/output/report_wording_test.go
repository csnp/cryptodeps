// Copyright 2025-2026 CyberSecurity NonProfit (CSNP)
// SPDX-License-Identifier: Apache-2.0

package output

import (
	"bytes"
	"strings"
	"testing"

	"github.com/csnp/qramm-cryptodeps/pkg/types"
	"github.com/csnp/qramm-cryptodeps/pkg/version"
)

// oneOfTwoUnknownScan is a project of two dependencies, one with a finding and
// one the database does not carry, with the hint the analyzer writes for it.
func oneOfTwoUnknownScan() *types.ScanResult {
	return &types.ScanResult{
		Project:   "/repo",
		Manifest:  "/repo/go.mod",
		Ecosystem: types.EcosystemGo,
		Dependencies: []types.DependencyResult{
			{
				Dependency: types.Dependency{Name: "golang.org/x/crypto", Version: "v0.17.0", Line: 6},
				InDatabase: true,
				Analysis: &types.PackageAnalysis{Package: "golang.org/x/crypto", Crypto: []types.CryptoUsage{
					{Algorithm: "Ed25519", QuantumRisk: types.RiskVulnerable, Severity: types.SeverityHigh},
				}},
			},
			{Dependency: types.Dependency{Name: "github.com/spf13/cobra", Version: "v1.8.0", Line: 7}},
		},
		Summary: types.ScanSummary{TotalDependencies: 2, WithCrypto: 1, QuantumVulnerable: 1,
			NotInDatabase: 1, NotExamined: 1},
		Hints: []string{"1 package (50%) not in database. Run with --deep for source code analysis."},
	}
}

// TestCountsOfOneAreSingular covers "found 1 dependencies", "1 packages not in
// database" and "1 packages (17%) were not examined".
func TestCountsOfOneAreSingular(t *testing.T) {
	one := oneOfTwoUnknownScan()
	one.Dependencies = one.Dependencies[:1]
	one.Summary.TotalDependencies, one.Summary.NotInDatabase, one.Summary.NotExamined = 1, 0, 0
	one.Hints = nil
	if out := renderTable(t, one); !strings.Contains(out, "found 1 dependency\n") {
		t.Errorf("the table does not say \"found 1 dependency\":\n%s", out)
	}

	scan := oneOfTwoUnknownScan()
	table := renderTable(t, scan)
	if !strings.Contains(table, "1 package not in database") {
		t.Errorf("the table does not say \"1 package not in database\":\n%s", table)
	}
	markdown := renderSingle(t, FormatMarkdown, scan)
	if !strings.Contains(markdown, "Packages that were not examined: 1 of 2 (50%).") {
		t.Errorf("the markdown notes do not say \"Packages that were not examined: 1 of 2 (50%%).\":\n%s", markdown)
	}
	for name, out := range map[string]string{"table": table, "markdown": markdown} {
		for _, wrong := range []string{"1 packages", "1 dependencies"} {
			if strings.Contains(out, wrong) {
				t.Errorf("%s says %q:\n%s", name, wrong, out)
			}
		}
	}
}

// TestNotInDatabaseNoticeIsSaidOnce covers the table following "[!] 1 packages
// not in database (use --deep to analyze)" with the analyzer's hint "1 packages
// (50%) not in database. Run with --deep...", and marking the notice with [!],
// the mark of a quantum-vulnerable finding.
func TestNotInDatabaseNoticeIsSaidOnce(t *testing.T) {
	out := renderTable(t, oneOfTwoUnknownScan())

	var notices []string
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, "not in database") {
			notices = append(notices, line)
		}
	}
	if len(notices) != 1 {
		t.Fatalf("want one line saying the package is not in the database, got %d: %q\n%s",
			len(notices), notices, out)
	}
	if !strings.HasPrefix(notices[0], "[?] ") {
		t.Errorf("the notice is marked %q, want [?]:\n%s", notices[0], out)
	}

	// The hint still reaches the formats that carry hints as data.
	var buf bytes.Buffer
	if err := (&JSONFormatter{}).Format(oneOfTwoUnknownScan(), &buf); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "not in database. Run with --deep") {
		t.Errorf("JSON lost the hint:\n%s", buf.String())
	}
}

// confirmedScan is a Go project in which reachability analysis confirmed each
// of findings, each through two traces from main, as two calls in one function
// produce.
func confirmedScan(findings ...types.CryptoUsage) *types.ScanResult {
	for i := range findings {
		findings[i].Reachability = types.ReachabilityConfirmed
		trace := types.CallTrace{EntryPoint: "example.com/app.main",
			Path: []string{"example.com/app.main", "example.com/app.hash"}, TargetFunc: "example.com/app.hash"}
		findings[i].Traces = []types.CallTrace{trace, trace}
	}
	return &types.ScanResult{
		Project:   "/repo",
		Manifest:  "/repo/go.mod",
		Ecosystem: types.EcosystemGo,
		Dependencies: []types.DependencyResult{{
			Dependency: types.Dependency{Name: "golang.org/x/crypto", Version: "v0.17.0", Line: 6},
			InDatabase: true,
			Analysis:   &types.PackageAnalysis{Package: "golang.org/x/crypto", Crypto: findings},
		}},
		Summary: types.ScanSummary{TotalDependencies: 1, WithCrypto: 1, ReachabilityAnalyzed: true,
			ConfirmedCrypto: len(findings)},
	}
}

// TestConfirmedHeadingAsksForActionOnlyWhenARowNeedsIt covers the heading
// "[!] CONFIRMED - Actually used by your code (requires action):" above a
// single "[OK] bcrypt SAFE" row.
func TestConfirmedHeadingAsksForActionOnlyWhenARowNeedsIt(t *testing.T) {
	safe := renderTable(t, confirmedScan(types.CryptoUsage{Algorithm: "bcrypt", QuantumRisk: types.RiskSafe,
		Severity: types.SeverityInfo}))
	if !strings.Contains(safe, "CONFIRMED - Actually used by your code") || !strings.Contains(safe, "bcrypt") {
		t.Fatalf("the fixture did not reach the CONFIRMED section:\n%s", safe)
	}
	if strings.Contains(safe, "requires action") {
		t.Errorf("a CONFIRMED section holding only a quantum-safe row asks for action:\n%s", safe)
	}

	for _, risk := range []types.QuantumRisk{types.RiskVulnerable, types.RiskPartial} {
		out := renderTable(t, confirmedScan(
			types.CryptoUsage{Algorithm: "bcrypt", QuantumRisk: types.RiskSafe, Severity: types.SeverityInfo},
			types.CryptoUsage{Algorithm: "Ed25519", QuantumRisk: risk, Severity: types.SeverityHigh}))
		if !strings.Contains(out, "[!] CONFIRMED - Actually used by your code (requires action):") {
			t.Errorf("a CONFIRMED section holding a %s row does not ask for action:\n%s", risk, out)
		}
	}
}

// TestCalledFromLinesAreNotRepeated covers "Called from: vulnerable-demo.main"
// printed three times for one algorithm, once per trace.
func TestCalledFromLinesAreNotRepeated(t *testing.T) {
	out := renderTable(t, confirmedScan(types.CryptoUsage{Algorithm: "bcrypt", QuantumRisk: types.RiskSafe,
		Severity: types.SeverityInfo}))
	if n := strings.Count(out, "> Called from: app.main\n"); n != 1 {
		t.Errorf("\"Called from: app.main\" printed %d times for two traces from main, want once:\n%s", n, out)
	}
}

// TestMarkdownWorkspaceReportHasOneTitleAndOneFooter covers a workspace report
// that rendered each project as a complete report: an H1 title, a NIST table
// and a footer per project, so 11 projects gave 12 H1 headings.
func TestMarkdownWorkspaceReportHasOneTitleAndOneFooter(t *testing.T) {
	second := oneOfTwoUnknownScan()
	second.Project, second.Manifest = "/repo/b", "/repo/b/go.mod"
	scan := types.AggregateResults("/repo", []*types.ScanResult{oneOfTwoUnknownScan(), second})
	out := renderMulti(t, FormatMarkdown, scan)

	counts := map[string]int{}
	for _, line := range strings.Split(out, "\n") {
		switch {
		case strings.HasPrefix(line, "# "):
			counts["H1 heading"]++
		case strings.Contains(line, "NIST Post-Quantum Cryptography Standards"):
			counts["NIST table"]++
		case strings.HasPrefix(line, "*Generated by "):
			counts["footer"]++
		case line == "### Summary":
			counts["project Summary under its project heading"]++
		}
	}
	for what, want := range map[string]int{"H1 heading": 1, "NIST table": 1, "footer": 1,
		"project Summary under its project heading": 2} {
		if counts[what] != want {
			t.Errorf("%d %s, want %d:\n%s", counts[what], what, want, out)
		}
	}
}

// TestMarkdownSingleProjectWorkspaceReportStatesTotalsOnce covers a workspace
// report of one project, whose Overview and Summary tables stated the same
// counts one after the other.
func TestMarkdownSingleProjectWorkspaceReportStatesTotalsOnce(t *testing.T) {
	out := renderMulti(t, FormatMarkdown, types.AggregateResults("/repo", []*types.ScanResult{oneOfTwoUnknownScan()}))
	for _, row := range []string{"| **Total Dependencies** |", "| **Using Crypto** |",
		"| **Quantum Vulnerable** |", "| **Quantum Partial** |"} {
		if n := strings.Count(out, row); n != 1 {
			t.Errorf("%q appears %d times, want once:\n%s", row, n, out)
		}
	}
	if !strings.Contains(out, "| **Manifest** | `./go.mod` |") {
		t.Errorf("the project Summary lost its Manifest row:\n%s", out)
	}
}

// TestMarkdownFooterNamesTheVersion covers a footer that named no version, so
// a published report could not be traced to the build that wrote it. A report
// with no findings had no footer at all.
func TestMarkdownFooterNamesTheVersion(t *testing.T) {
	want := "*Generated by [CryptoDeps](" + version.InformationURI + ") version `" + version.Version() + "`"
	for name, out := range map[string]string{
		"findings":    renderSingle(t, FormatMarkdown, oneOfTwoUnknownScan()),
		"no findings": renderSingle(t, FormatMarkdown, &types.ScanResult{Manifest: "/repo/go.mod"}),
		"workspace":   renderMulti(t, FormatMarkdown, types.AggregateResults("/repo", []*types.ScanResult{oneOfTwoUnknownScan()})),
	} {
		if !strings.Contains(out, want) {
			t.Errorf("%s: the footer does not start %q:\n%s", name, want, out)
		}
	}
}
