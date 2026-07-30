// Copyright 2025-2026 CyberSecurity NonProfit (CSNP)
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"testing"

	"github.com/csnp/qramm-cryptodeps/internal/analyzer"
	"github.com/csnp/qramm-cryptodeps/pkg/types"
)

// partialRiskScan is a project whose only findings are partial risk, which is
// the one shape in which --fail-on partial and the default policy disagree. A
// project with a vulnerable finding exits 1 under every threshold, so it cannot
// detect a threshold that was ignored.
func partialRiskScan() *types.ScanResult {
	return &types.ScanResult{
		Summary: types.ScanSummary{
			TotalDependencies: 1,
			WithCrypto:        1,
			QuantumPartial:    1,
		},
	}
}

// TestFailOnIsReadTheSameWayItWasValidated is the regression test for a silent
// loosening of the CI gate by whitespace.
//
// ValidateFailOn trimmed and lowercased before deciding, and determineExitCode
// only lowercased. So " partial " passed validation, matched no case, and fell
// through to the default vulnerable-only policy: a project with partial-risk
// findings exited 3 for "partial" and 0 for " partial ", with nothing on either
// stream. Whitespace around a value is the ordinary result of a YAML block
// scalar or a workflow expression, which is exactly where this flag is used, and
// the validation added in this release is what made the value look accepted.
func TestFailOnIsReadTheSameWayItWasValidated(t *testing.T) {
	result := partialRiskScan()

	// Guard the fixture: the two policies have to disagree on it, or every
	// assertion below passes for the wrong reason.
	if got := determineExitCode(result, "partial"); got != ExitPartial {
		t.Fatalf("determineExitCode(partial) = %d, want %d; the fixture does not exercise "+
			"the partial policy", got, ExitPartial)
	}
	if got := determineExitCode(result, "vulnerable"); got != ExitSuccess {
		t.Fatalf("determineExitCode(vulnerable) = %d, want %d; the fixture does not "+
			"distinguish the two policies", got, ExitSuccess)
	}

	for _, threshold := range []string{" partial", "partial ", " partial ", "\tpartial", "PARTIAL", " Partial\n"} {
		t.Run(threshold, func(t *testing.T) {
			// Whatever the validator accepts, the exit code must honour.
			if err := analyzer.ValidateFailOn(threshold); err != nil {
				t.Fatalf("ValidateFailOn(%q) rejected it, so this case is not the one under "+
					"test: %v", threshold, err)
			}
			if got := determineExitCode(result, threshold); got != ExitPartial {
				t.Errorf("determineExitCode(%q) = %d, want %d: the value was accepted as valid "+
					"and then ignored, reverting the gate to the default policy",
					threshold, got, ExitPartial)
			}
		})
	}
}

// TestFailOnRejectsWhatItCannotHonour is the inverse: canonicalising must not
// turn a typo into a valid value, because a gate that silently accepts "partail"
// is the defect the validation exists to prevent.
func TestFailOnRejectsWhatItCannotHonour(t *testing.T) {
	for _, threshold := range []string{"partail", "vulnerble", "maybe", "partial risk", "1"} {
		if err := analyzer.ValidateFailOn(threshold); err == nil {
			t.Errorf("ValidateFailOn(%q) accepted a value that determineExitCode reads as the "+
				"default policy", threshold)
		}
	}
}
