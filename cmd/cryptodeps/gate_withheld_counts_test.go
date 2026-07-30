// Copyright 2025-2026 CyberSecurity NonProfit (CSNP)
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"path/filepath"
	"testing"

	"github.com/csnp/qramm-cryptodeps/internal/analyzer"
)

// This file is separate from gate_filter_test.go on purpose. It names the
// withheld counters directly, so it cannot compile against the code before they
// existed. gate_filter_test.go deliberately names none of them: it asserts the
// BEHAVIOUR (a reporting filter never changes the exit code), so it compiles
// against the pre-fix commit and fails there at runtime, which is the only form
// of proof that a test detects the defect it was written for. Keeping the two in
// one file made the behavioural test unprovable by a plain revert.

// TestWithheldCountsReconcile pins the counters themselves rather than only
// their effect, so that a counter which stops being populated fails here with a
// reason instead of somewhere downstream.
func TestWithheldCountsReconcile(t *testing.T) {
	root := t.TempDir()
	for _, fx := range gateFixtures {
		writeManifest(t, filepath.Join(root, fx.name), fx.deps)
	}
	base, err := newGateAnalyzer(analyzer.Options{}).AnalyzeAll(root)
	if err != nil {
		t.Fatalf("baseline: %v", err)
	}

	for _, f := range gateFilters {
		result, err := newGateAnalyzer(f.opts).AnalyzeAll(root)
		if err != nil {
			t.Fatalf("AnalyzeAll with %s: %v", f.name, err)
		}
		checks := []struct {
			label      string
			shown, hid int
			unfiltered int
		}{
			{"withCrypto", result.TotalSummary.WithCrypto,
				result.TotalSummary.WithheldWithCrypto, base.TotalSummary.WithCrypto},
			{"quantumVulnerable", result.TotalSummary.QuantumVulnerable,
				result.TotalSummary.WithheldVulnerable, base.TotalSummary.QuantumVulnerable},
			{"quantumPartial", result.TotalSummary.QuantumPartial,
				result.TotalSummary.WithheldPartial, base.TotalSummary.QuantumPartial},
		}
		for _, c := range checks {
			if c.shown+c.hid != c.unfiltered {
				t.Errorf("%s with %s: shown %d + withheld %d = %d, but an unfiltered scan "+
					"found %d. The withheld breakdown does not account for what the filter "+
					"removed, so the gate cannot recover it",
					c.label, f.name, c.shown, c.hid, c.shown+c.hid, c.unfiltered)
			}
		}
	}
}
