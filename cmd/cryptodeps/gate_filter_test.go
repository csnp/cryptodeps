// Copyright 2025-2026 CyberSecurity NonProfit (CSNP)
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/csnp/qramm-cryptodeps/internal/analyzer"
	"github.com/csnp/qramm-cryptodeps/internal/database"
)

// The gate must describe the scan, not the view.
//
// Making --risk and --min-severity actually filter, in this release, let them
// decide the exit code, because the gate read a summary that counted only
// survivors. `analyze . --fail-on vulnerable` exited 1 and the same command with
// `--risk safe` exited 0, while stdout printed "This is not a clean result".
// Released 1.2.2 exits 1 for both, because its filters did nothing at all, so
// this was a regression in the one flag that decides CI outcomes.
//
// The invariant asserted here is the whole fix in one line: **a reporting filter
// never changes the exit code.** It is asserted across both code paths, because
// the single-project and workspace gates read different summaries and the
// workspace one is what the CLI uses by default. An earlier version of these
// tests covered the workspace path with a struct literal, which meant the three
// aggregation lines that carry the withheld counts could all be deleted with the
// suite still green, restoring the exact bug on the default path.
//
// These tests deliberately use database.NewEmbedded() rather than
// NewWithCachedData(): the latter reads the developer's real ~/.cryptodeps, so a
// cache that happened to classify these packages differently would turn the only
// runtime protection for a CI gate into a silent skip.

// gateFixture is a project whose findings sit at known risk levels in the
// embedded database, so that each filter has something to withhold.
type gateFixture struct {
	name string
	deps map[string]string
}

var gateFixtures = []gateFixture{
	// Vulnerable AND partial: the shape where --risk safe withholds everything
	// and the default policy must still fail.
	{"vulnerable-and-partial", map[string]string{
		"crypto-js": "4.2.0", "node-forge": "1.3.1"}},
	// Partial only: the shape that distinguishes --fail-on partial from the
	// default, and the one that detects a gate ignoring withheld PARTIAL counts.
	{"partial-only", map[string]string{
		"aes-js": "3.1.2", "pbkdf2": "3.1.2"}},
	// Safe only: --fail-on any must still fail here, which is the only shape
	// that detects a gate ignoring the withheld with-crypto count.
	{"safe-only", map[string]string{
		"argon2": "0.31.2", "bcrypt": "5.1.1"}},
	// Mixed within one dependency, so a partially-filtered package is covered.
	{"mixed", map[string]string{
		"tweetnacl": "1.0.3", "aes-js": "3.1.2"}},
}

// filters are the reporting filters, each of which withholds a different slice
// of the findings. The empty entry is the unfiltered baseline.
var gateFilters = []struct {
	name string
	opts analyzer.Options
}{
	{"none", analyzer.Options{}},
	{"risk=safe", analyzer.Options{RiskFilter: "safe"}},
	{"risk=vulnerable", analyzer.Options{RiskFilter: "vulnerable"}},
	{"risk=partial", analyzer.Options{RiskFilter: "partial"}},
	{"minSeverity=critical", analyzer.Options{MinSeverity: "critical"}},
	{"minSeverity=high", analyzer.Options{MinSeverity: "high"}},
}

var gateThresholds = []string{"vulnerable", "partial", "any", "none"}

func writeManifest(t *testing.T, dir string, deps map[string]string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", dir, err)
	}
	body := `{"name":"gate","version":"1.0.0","dependencies":{`
	first := true
	for name, version := range deps {
		if !first {
			body += ","
		}
		body += `"` + name + `":"` + version + `"`
		first = false
	}
	body += `}}`
	if err := os.WriteFile(filepath.Join(dir, "package.json"), []byte(body), 0o644); err != nil {
		t.Fatalf("write manifest: %v", err)
	}
}

func newGateAnalyzer(opts analyzer.Options) *analyzer.Analyzer {
	opts.Offline = true
	return analyzer.New(database.NewEmbedded(), opts)
}

// TestReportingFilterNeverChangesTheExitCode covers the single-project path.
func TestReportingFilterNeverChangesTheExitCode(t *testing.T) {
	for _, fx := range gateFixtures {
		t.Run(fx.name, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "proj")
			writeManifest(t, dir, fx.deps)

			base, err := newGateAnalyzer(analyzer.Options{}).Analyze(dir)
			if err != nil {
				t.Fatalf("baseline analyze: %v", err)
			}
			// Guard the fixture: it must actually produce findings, or every
			// comparison below is between two empty scans.
			if base.Summary.WithCrypto == 0 {
				t.Fatalf("fixture %q produced no findings from the embedded database "+
					"(summary %+v); it cannot exercise a filter", fx.name, base.Summary)
			}

			for _, f := range gateFilters {
				result, err := newGateAnalyzer(f.opts).Analyze(dir)
				if err != nil {
					t.Fatalf("analyze with %s: %v", f.name, err)
				}
				// Guard again: a filter that withheld nothing tests nothing.
				if f.name != "none" && result.Summary.FilteredOut == 0 &&
					base.Summary.WithCrypto > 0 {
					t.Logf("note: %s withheld nothing on %s", f.name, fx.name)
				}
				for _, th := range gateThresholds {
					want := determineExitCode(base, th)
					got := determineExitCode(result, th)
					if got != want {
						t.Errorf("--fail-on %s with %s: exit %d, want %d (unfiltered). "+
							"A reporting filter changed the CI verdict; the scan withheld "+
							"%d finding(s)", th, f.name, got, want, result.Summary.FilteredOut)
					}
				}
			}
		})
	}
}

// TestWorkspaceReportingFilterNeverChangesTheExitCode covers the workspace path,
// which is what the CLI runs by default and which reads TotalSummary rather than
// a project summary. Without this, the three lines in AggregateResults that carry
// the withheld counts can each be deleted with the suite still green.
func TestWorkspaceReportingFilterNeverChangesTheExitCode(t *testing.T) {
	root := t.TempDir()
	// A workspace of several projects, so the aggregate has something to sum and
	// so no single project's summary can stand in for the total.
	for _, fx := range gateFixtures {
		writeManifest(t, filepath.Join(root, fx.name), fx.deps)
	}

	base, err := newGateAnalyzer(analyzer.Options{}).AnalyzeAll(root)
	if err != nil {
		t.Fatalf("baseline AnalyzeAll: %v", err)
	}
	if len(base.Projects) < 2 {
		t.Fatalf("workspace discovered %d project(s); the aggregate path is not "+
			"exercised by fewer than 2", len(base.Projects))
	}
	if base.TotalSummary.WithCrypto == 0 {
		t.Fatalf("workspace baseline found no cryptography (total %+v)", base.TotalSummary)
	}

	for _, f := range gateFilters {
		result, err := newGateAnalyzer(f.opts).AnalyzeAll(root)
		if err != nil {
			t.Fatalf("AnalyzeAll with %s: %v", f.name, err)
		}
		for _, th := range gateThresholds {
			want := determineExitCodeMulti(base, th)
			got := determineExitCodeMulti(result, th)
			if got != want {
				t.Errorf("workspace --fail-on %s with %s: exit %d, want %d (unfiltered). "+
					"The aggregate gate read the filtered totals; %d finding(s) withheld",
					th, f.name, got, want, result.TotalSummary.FilteredOut)
			}
		}
	}
}

// TestFailOnNoneStaysOff guards the other direction: the fix must not switch on
// a gate the operator switched off, and must not invent findings on a clean tree.
func TestFailOnNoneStaysOff(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "proj")
	writeManifest(t, dir, map[string]string{"crypto-js": "4.2.0"})
	for _, f := range gateFilters {
		result, err := newGateAnalyzer(f.opts).Analyze(dir)
		if err != nil {
			t.Fatalf("analyze: %v", err)
		}
		if got := determineExitCode(result, "none"); got != ExitSuccess {
			t.Errorf("--fail-on none with %s: exit %d, want %d", f.name, got, ExitSuccess)
		}
	}

	clean := filepath.Join(t.TempDir(), "clean")
	writeManifest(t, clean, map[string]string{"left-pad": "1.3.0"})
	result, err := newGateAnalyzer(analyzer.Options{}).Analyze(clean)
	if err != nil {
		t.Fatalf("analyze clean: %v", err)
	}
	if result.Summary.WithCrypto != 0 {
		t.Fatalf("the clean fixture is not clean (summary %+v)", result.Summary)
	}
	for _, th := range gateThresholds {
		if got := determineExitCode(result, th); got != ExitSuccess {
			t.Errorf("clean project --fail-on %s: exit %d, want %d; the fix invented a "+
				"finding", th, got, ExitSuccess)
		}
	}
}
