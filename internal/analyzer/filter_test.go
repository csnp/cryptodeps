// Copyright 2025-2026 CyberSecurity NonProfit (CSNP)
// SPDX-License-Identifier: Apache-2.0

package analyzer

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/csnp/qramm-cryptodeps/internal/database"
	"github.com/csnp/qramm-cryptodeps/pkg/types"
)

// filterFixture writes a package.json whose dependencies are in the embedded
// database and therefore produce findings across several risk levels.
func filterFixture(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "package.json")
	content := `{"name":"fx","version":"1.0.0","dependencies":{"node-forge":"1.3.1","crypto-js":"4.2.0"}}`
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	return dir
}

// findingKeys renders a scan's findings as a comparable set. Comparing sets
// rather than counts is deliberate: a count can match exactly while the filter
// is swapping one finding for another.
func findingKeys(result *types.ScanResult) map[string]bool {
	keys := make(map[string]bool)
	for _, dep := range result.Dependencies {
		if dep.Analysis == nil {
			continue
		}
		for _, c := range dep.Analysis.Crypto {
			keys[fmt.Sprintf("%s|%s|%s|%s",
				dep.Dependency.Name, c.Algorithm, c.QuantumRisk, c.Severity)] = true
		}
	}
	return keys
}

func sortedSet(set map[string]bool) []string {
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// analyzeWith runs a scan with the given options against the fixture.
func analyzeWith(t *testing.T, dir string, opts Options) *types.ScanResult {
	t.Helper()
	opts.Offline = true
	a := New(database.NewWithCachedData(), opts)
	result, err := a.Analyze(dir)
	if err != nil {
		t.Fatalf("analyze: %v", err)
	}
	return result
}

// TestRiskFilterActuallyFilters is the regression test for two flags that were
// stored in Options and never read.
//
// Every value, including a misspelt one, produced byte-identical output, so a
// user who asked for a filtered report got an unfiltered one and had no way to
// tell.
func TestRiskFilterActuallyFilters(t *testing.T) {
	dir := filterFixture(t)

	unfiltered := findingKeys(analyzeWith(t, dir, Options{}))
	if len(unfiltered) == 0 {
		t.Fatal("fixture produced no findings, so this test proves nothing")
	}

	var haveVulnerable, havePartial bool
	for k := range unfiltered {
		if strings.Contains(k, string(types.RiskVulnerable)) {
			haveVulnerable = true
		}
		if strings.Contains(k, string(types.RiskPartial)) {
			havePartial = true
		}
	}
	if !haveVulnerable || !havePartial {
		t.Fatalf("fixture must contain both vulnerable and partial findings to exercise the filter; got %v",
			sortedSet(unfiltered))
	}

	filtered := findingKeys(analyzeWith(t, dir, Options{RiskFilter: "vulnerable"}))
	if len(filtered) == 0 {
		t.Fatal("--risk vulnerable removed everything")
	}
	if len(filtered) == len(unfiltered) {
		t.Errorf("--risk vulnerable changed nothing: %d findings either way", len(filtered))
	}

	// Every surviving finding must match the filter.
	for k := range filtered {
		if !strings.Contains(k, string(types.RiskVulnerable)) {
			t.Errorf("--risk vulnerable kept a non-vulnerable finding: %s", k)
		}
	}
	// The filtered set must be a subset of the unfiltered one. A filter that
	// adds or alters findings is a different bug from one that does nothing.
	for k := range filtered {
		if !unfiltered[k] {
			t.Errorf("--risk vulnerable produced a finding absent from the full scan: %s", k)
		}
	}
}

// TestMinSeverityActuallyFilters checks the severity threshold.
func TestMinSeverityActuallyFilters(t *testing.T) {
	dir := filterFixture(t)

	unfiltered := findingKeys(analyzeWith(t, dir, Options{}))
	filtered := findingKeys(analyzeWith(t, dir, Options{MinSeverity: "critical"}))

	if len(unfiltered) == 0 {
		t.Fatal("fixture produced no findings")
	}
	if len(filtered) == len(unfiltered) {
		t.Errorf("--min-severity critical changed nothing: %d findings either way", len(filtered))
	}
	for k := range filtered {
		if !unfiltered[k] {
			t.Errorf("--min-severity produced a finding absent from the full scan: %s", k)
		}
		if !strings.Contains(k, string(types.SeverityCritical)) {
			t.Errorf("--min-severity critical kept a lower severity finding: %s", k)
		}
	}
}

// TestFilteredOutIsCounted checks that withheld findings are counted, which is
// what lets the report say "filtered" instead of "clean".
func TestFilteredOutIsCounted(t *testing.T) {
	dir := filterFixture(t)

	full := analyzeWith(t, dir, Options{})
	filtered := analyzeWith(t, dir, Options{RiskFilter: "vulnerable"})

	fullCount := 0
	for _, dep := range full.Dependencies {
		if dep.Analysis != nil {
			fullCount += len(dep.Analysis.Crypto)
		}
	}
	keptCount := 0
	for _, dep := range filtered.Dependencies {
		if dep.Analysis != nil {
			keptCount += len(dep.Analysis.Crypto)
		}
	}

	if got, want := filtered.Summary.FilteredOut, fullCount-keptCount; got != want {
		t.Errorf("FilteredOut = %d, want %d (full %d, kept %d)", got, want, fullCount, keptCount)
	}
	if filtered.Summary.FilteredOut == 0 {
		t.Error("filter withheld nothing, so the fixture does not exercise the counter")
	}
	if full.Summary.FilteredOut != 0 {
		t.Errorf("unfiltered scan reports %d filtered out, want 0", full.Summary.FilteredOut)
	}
}

// TestNoFilterIsUnchanged guards the default path. A filter that silently
// applies when unset would be a suppression bug.
func TestNoFilterIsUnchanged(t *testing.T) {
	dir := filterFixture(t)

	base := findingKeys(analyzeWith(t, dir, Options{}))
	for _, value := range []string{"", "all", "ALL", "  "} {
		got := findingKeys(analyzeWith(t, dir, Options{RiskFilter: value}))
		if len(got) != len(base) {
			t.Errorf("--risk %q changed the finding count: %d vs %d", value, len(got), len(base))
		}
		for k := range base {
			if !got[k] {
				t.Errorf("--risk %q dropped finding %s", value, k)
			}
		}
	}
}

// TestFilteringDoesNotMutateTheDatabase catches a filter that writes through the
// shared analysis pointer. Two dependencies resolving to the same database entry
// would then see each other's filtered results.
func TestFilteringDoesNotMutateTheDatabase(t *testing.T) {
	dir := filterFixture(t)
	db := database.NewWithCachedData()

	filtered, err := New(db, Options{Offline: true, RiskFilter: "vulnerable"}).Analyze(dir)
	if err != nil {
		t.Fatalf("filtered analyze: %v", err)
	}
	if filtered.Summary.FilteredOut == 0 {
		t.Fatal("filter withheld nothing, so mutation could not be observed")
	}

	// Same database instance, no filter. If the filtered run had written
	// through the shared pointer, findings would now be missing.
	after, err := New(db, Options{Offline: true}).Analyze(dir)
	if err != nil {
		t.Fatalf("second analyze: %v", err)
	}

	fresh, err := New(database.NewWithCachedData(), Options{Offline: true}).Analyze(dir)
	if err != nil {
		t.Fatalf("fresh analyze: %v", err)
	}

	afterKeys, freshKeys := findingKeys(after), findingKeys(fresh)
	if len(afterKeys) != len(freshKeys) {
		t.Errorf("filtering corrupted the shared database: %d findings after a filtered run, %d on a fresh one",
			len(afterKeys), len(freshKeys))
	}
	for k := range freshKeys {
		if !afterKeys[k] {
			t.Errorf("finding %s lost from the shared database after a filtered run", k)
		}
	}
}

// TestFilterValidationRejectsUnknownValues checks that a typo is refused rather
// than ignored. Silently accepting one is how a user ends up trusting a report
// they believe was filtered.
func TestFilterValidationRejectsUnknownValues(t *testing.T) {
	for _, tc := range []struct {
		name    string
		fn      func(string) error
		good    []string
		bad     []string
		wantMsg string
	}{
		{
			name:    "risk",
			fn:      ValidateRiskFilter,
			good:    []string{"", "all", "vulnerable", "VULNERABLE", "partial", "safe", "unknown"},
			bad:     []string{"banana", "vuln", "high", "critical"},
			wantMsg: "--risk",
		},
		{
			name:    "min-severity",
			fn:      ValidateMinSeverity,
			good:    []string{"", "info", "low", "medium", "high", "critical", "CRITICAL"},
			bad:     []string{"banana", "vulnerable", "sev1"},
			wantMsg: "--min-severity",
		},
		{
			// --fail-on was the one enum flag of the three that did not
			// validate, and it is the one that decides the exit code. A typo
			// fell through to the default policy, so a project that exits 3
			// under --fail-on partial exited 0 under --fail-on partail, with
			// nothing on either stream. The others mislead a reader; this one
			// silently loosens a CI gate.
			name:    "fail-on",
			fn:      ValidateFailOn,
			good:    []string{"", "none", "any", "partial", "vulnerable", "VULNERABLE", " partial "},
			bad:     []string{"partail", "banana", "safe", "unknown", "all", "critical", "1"},
			wantMsg: "--fail-on",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, v := range tc.good {
				if err := tc.fn(v); err != nil {
					t.Errorf("%q rejected: %v", v, err)
				}
			}
			for _, v := range tc.bad {
				err := tc.fn(v)
				if err == nil {
					t.Errorf("%q accepted; a typo produces an unfiltered report the user believes is filtered", v)
					continue
				}
				if !strings.Contains(err.Error(), tc.wantMsg) {
					t.Errorf("error for %q does not name the flag: %v", v, err)
				}
			}
		})
	}
}

// TestSeverityRankingIsCaseInsensitive guards --min-severity against a database
// record whose severity is not upper case.
//
// severityRank is keyed by the upper-case types.Severity constants, and a Go map
// returns the zero value for an absent key. Ranking an unrecognised severity
// therefore gave 0, which is INFO, so every threshold above INFO discarded the
// finding. Database records arrive from a remote feed and are unmarshalled with
// no normalisation, so a record carrying "critical" was thrown away by the exact
// filter a user reaches for to see critical findings, and it was not even
// counted as withheld.
func TestSeverityRankingIsCaseInsensitive(t *testing.T) {
	for _, severity := range []types.Severity{"critical", "CRITICAL", "Critical", "cRiTiCaL"} {
		for _, threshold := range []string{"info", "low", "medium", "high", "critical"} {
			a := &Analyzer{options: Options{MinSeverity: threshold}}
			if !a.keepCrypto(types.CryptoUsage{Algorithm: "DES", Severity: severity}) {
				t.Errorf("severity %q was withheld by --min-severity %s; a CRITICAL finding "+
					"must not be discarded because of its case", severity, threshold)
			}
		}
	}
}

// TestUnrankableSeverityIsReportedNotWithheld pins the fail-safe direction.
//
// A severity this build cannot rank has not been shown to be below the
// threshold, so it is reported. Withholding it would let an unrecognised value
// in remote data silently suppress a finding.
func TestUnrankableSeverityIsReportedNotWithheld(t *testing.T) {
	for _, severity := range []types.Severity{"", "SEV1", "urgent", "  "} {
		a := &Analyzer{options: Options{MinSeverity: "critical"}}
		if !a.keepCrypto(types.CryptoUsage{Algorithm: "DES", Severity: severity}) {
			t.Errorf("severity %q was withheld; an unrankable severity must fail towards "+
				"reporting, not towards silence", severity)
		}
	}
}

// TestRankableSeveritiesBelowThresholdAreStillWithheld proves the two tests
// above did not simply disable the filter.
//
// Without this, making keepCrypto always return true would pass them both.
func TestRankableSeveritiesBelowThresholdAreStillWithheld(t *testing.T) {
	a := &Analyzer{options: Options{MinSeverity: "high"}}
	for _, severity := range []types.Severity{types.SeverityInfo, types.SeverityLow, types.SeverityMedium, "low", "medium"} {
		if a.keepCrypto(types.CryptoUsage{Algorithm: "AES", Severity: severity}) {
			t.Errorf("severity %q survived --min-severity high; the filter is not filtering", severity)
		}
	}
	for _, severity := range []types.Severity{types.SeverityHigh, types.SeverityCritical} {
		if !a.keepCrypto(types.CryptoUsage{Algorithm: "DES", Severity: severity}) {
			t.Errorf("severity %q was withheld by --min-severity high", severity)
		}
	}
}
