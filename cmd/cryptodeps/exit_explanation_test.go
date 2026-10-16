// Copyright 2025-2026 CyberSecurity NonProfit (CSNP)
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"strings"
	"testing"

	"github.com/csnp/qramm-cryptodeps/pkg/types"
)

// projectWith builds a one-dependency scan result carrying the given findings,
// with its summary counted the way analyzeManifest counts it.
func projectWith(withheldVulnerable int, reachabilityRan bool, findings ...types.CryptoUsage) *types.ScanResult {
	r := &types.ScanResult{
		Dependencies: []types.DependencyResult{{
			Dependency: types.Dependency{Name: "example.com/dep", Version: "1.0.0"},
			Analysis:   &types.PackageAnalysis{Package: "example.com/dep", Crypto: findings},
			InDatabase: true,
		}},
	}
	r.Summary.TotalDependencies = 1
	if len(findings) > 0 {
		r.Summary.WithCrypto = 1
	}
	for _, f := range findings {
		switch f.QuantumRisk {
		case types.RiskVulnerable:
			r.Summary.QuantumVulnerable++
		case types.RiskPartial:
			r.Summary.QuantumPartial++
		}
	}
	r.Summary.WithheldVulnerable = withheldVulnerable
	r.Summary.FilteredOut = withheldVulnerable
	r.Summary.ReachabilityAnalyzed = reachabilityRan
	return r
}

func finding(algorithm string, risk types.QuantumRisk, reach types.Reachability) types.CryptoUsage {
	return types.CryptoUsage{Algorithm: algorithm, QuantumRisk: risk, Reachability: reach}
}

// explainSingle computes the exit code exactly as the CLI does, then the line.
func explainSingle(t *testing.T, r *types.ScanResult, threshold string) (int, string) {
	t.Helper()
	code := determineExitCode(r, threshold)
	return code, exitExplanation(code, threshold, r.Summary, []*types.ScanResult{r})
}

func assertContainsAll(t *testing.T, line string, wants ...string) {
	t.Helper()
	for _, want := range wants {
		if !strings.Contains(line, want) {
			t.Errorf("explanation does not contain %q:\n%s", want, line)
		}
	}
}

// Two vulnerable findings survive the filter and six were withheld. The exit
// code counts all eight; the line must name the two in the report and the six
// that were hidden, or a reader sees "2 vulnerable" above an exit code that
// describes eight.
func TestExplanationNamesShownAndWithheldCounts(t *testing.T) {
	r := projectWith(6, false,
		finding("RSA", types.RiskVulnerable, ""),
		finding("ECDSA", types.RiskVulnerable, ""),
	)
	code, line := explainSingle(t, r, "vulnerable")
	if code != ExitVulnerable {
		t.Fatalf("exit %d, want %d", code, ExitVulnerable)
	}
	assertContainsAll(t, line,
		"Exit code 1",
		"8 quantum-vulnerable findings",
		"2 are in the report",
		"The other 6 were hidden by --risk or --min-severity",
		"still count toward the exit code",
	)
	if strings.Contains(line, "\n") {
		t.Errorf("explanation is more than one line:\n%s", line)
	}
}

// Every vulnerable finding was withheld: the summary reads "0 vulnerable" and
// the exit code is 1. This is the shape from the new-user report.
func TestExplanationWhenEveryFindingWasWithheld(t *testing.T) {
	r := projectWith(2, false, finding("AES-128", types.RiskPartial, ""))
	code, line := explainSingle(t, r, "vulnerable")
	if code != ExitVulnerable {
		t.Fatalf("exit %d, want %d", code, ExitVulnerable)
	}
	assertContainsAll(t, line,
		"Exit code 1",
		"2 quantum-vulnerable findings",
		"None of them is in the report",
		"--risk or --min-severity",
	)
	// The partial finding that IS shown did not set exit 1 and must not be
	// offered as the reason.
	if strings.Contains(line, "partial") {
		t.Errorf("exit 1 explanation mentions partial findings:\n%s", line)
	}
}

// One vulnerable finding is CONFIRMED and one is AVAILABLE. The line splits
// them, so a reader can tell the finding to act on from the one to plan for.
func TestExplanationNamesTheReachabilitySplit(t *testing.T) {
	r := projectWith(0, true,
		finding("Ed25519", types.RiskVulnerable, types.ReachabilityConfirmed),
		finding("X25519", types.RiskVulnerable, types.ReachabilityAvailable),
		finding("bcrypt", types.RiskSafe, types.ReachabilityConfirmed),
	)
	code, line := explainSingle(t, r, "vulnerable")
	if code != ExitVulnerable {
		t.Fatalf("exit %d, want %d", code, ExitVulnerable)
	}
	assertContainsAll(t, line,
		"Exit code 1",
		"2 quantum-vulnerable findings",
		"1 is called from your code",
		"1 is in a dependency where no call from your code was found",
	)
	if strings.Contains(line, "hidden") {
		t.Errorf("nothing was withheld, yet the line mentions hidden findings:\n%s", line)
	}
}

// The split includes REACHABLE findings and findings that reachability did not
// classify, and its parts add up to the shown count.
func TestExplanationSplitCoversEveryShownFinding(t *testing.T) {
	r := projectWith(0, true,
		finding("RSA", types.RiskVulnerable, types.ReachabilityConfirmed),
		finding("ECDSA", types.RiskVulnerable, types.ReachabilityReachable),
		finding("ECDH", types.RiskVulnerable, types.ReachabilityReachable),
		finding("DSA", types.RiskVulnerable, types.ReachabilityAvailable),
		finding("DH", types.RiskVulnerable, ""),
	)
	_, line := explainSingle(t, r, "vulnerable")
	assertContainsAll(t, line,
		"5 quantum-vulnerable findings",
		"1 is called from your code",
		"2 are reached from your code through other calls",
		"1 is in a dependency where no call from your code was found",
		"1 was not checked for calls from your code",
	)
}

// Exit 3 under --fail-on partial names the partial findings, not vulnerable.
func TestExplanationForPartialExit(t *testing.T) {
	r := projectWith(0, false,
		finding("AES-128", types.RiskPartial, ""),
		finding("SHA-256", types.RiskPartial, ""),
		finding("Argon2", types.RiskSafe, ""),
	)
	code, line := explainSingle(t, r, "partial")
	if code != ExitPartial {
		t.Fatalf("exit %d, want %d", code, ExitPartial)
	}
	assertContainsAll(t, line, "Exit code 3", "--fail-on partial", "2 partial-risk findings")
}

// Exit 3 under --fail-on any with only quantum-safe cryptography names the
// dependencies that use cryptography and the policy that counts them.
func TestExplanationForAnyCryptoExit(t *testing.T) {
	r := projectWith(0, false, finding("Argon2", types.RiskSafe, ""))
	code, line := explainSingle(t, r, "any")
	if code != ExitPartial {
		t.Fatalf("exit %d, want %d", code, ExitPartial)
	}
	assertContainsAll(t, line, "Exit code 3", "--fail-on any", "1 dependency")
}

// Exit 0 explains nothing, and neither does exit 2, which keeps its own messages.
func TestNoExplanationForExitZeroOrTwo(t *testing.T) {
	clean := projectWith(0, false)
	code, line := explainSingle(t, clean, "vulnerable")
	if code != ExitSuccess || line != "" {
		t.Errorf("clean result: exit %d, line %q; want exit 0 and no line", code, line)
	}

	vulnerable := projectWith(0, false, finding("RSA", types.RiskVulnerable, ""))
	if code, line := explainSingle(t, vulnerable, "none"); code != ExitSuccess || line != "" {
		t.Errorf("--fail-on none: exit %d, line %q; want exit 0 and no line", code, line)
	}
	if line := exitExplanation(ExitError, "vulnerable", vulnerable.Summary,
		[]*types.ScanResult{vulnerable}); line != "" {
		t.Errorf("exit 2 printed an explanation: %q", line)
	}
}

// The workspace path reads TotalSummary and walks every project, so the line
// for a workspace adds up across projects the same way the gate does.
func TestExplanationAcrossWorkspaceProjects(t *testing.T) {
	a := projectWith(3, true, finding("RSA", types.RiskVulnerable, types.ReachabilityConfirmed))
	b := projectWith(0, false, finding("ECDSA", types.RiskVulnerable, ""))
	multi := types.AggregateResults("root", []*types.ScanResult{a, b})

	code := determineExitCodeMulti(multi, "vulnerable")
	line := exitExplanation(code, "vulnerable", multi.TotalSummary, multi.Projects)
	assertContainsAll(t, line,
		"Exit code 1",
		"5 quantum-vulnerable findings",
		"Of the 2 in the report",
		"1 is called from your code",
		"1 was not checked for calls from your code",
		"The other 3 were hidden",
	)
}
