// Copyright 2025-2026 CyberSecurity NonProfit (CSNP)
// SPDX-License-Identifier: Apache-2.0

package output

import "github.com/csnp/qramm-cryptodeps/pkg/types"

// noFindingsCase says why a scan produced no findings.
//
// This lives in one place because the first version of the fix did not. The
// table formatter learned to distinguish these cases while markdown, JSON, CBOM
// and SARIF kept reporting a clean scan, so the same false-clean verdict the fix
// was written to remove survived in four of the five formats a user can ask for.
// Every formatter now classifies through this function and only chooses its own
// wording, so a new case cannot reach one format and miss the others.
type noFindingsCase int

const (
	// caseFiltered means findings exist and a filter withheld them. It is
	// deliberately first: an absence produced by a filter must never be
	// reported as an absence of findings. Order is the safety property, so the
	// question "did we withhold anything" is asked before any conclusion about
	// what is present.
	caseFiltered noFindingsCase = iota
	// caseNoDependencies means the manifest declared nothing to analyze.
	caseNoDependencies
	// caseNothingExamined means every dependency was absent from the database,
	// so the scan drew no conclusion. Reporting this as clean is a false
	// negative on the tool's core question.
	caseNothingExamined
	// caseGenuinelyClean means dependencies were examined and carried no
	// cryptography.
	caseGenuinelyClean
)

// classifyNoFindings decides which case a findings-free summary falls into.
// Callers must only reach it when no finding survived to be reported.
func classifyNoFindings(s types.ScanSummary) noFindingsCase {
	switch {
	case s.FilteredOut > 0:
		return caseFiltered
	case s.TotalDependencies == 0:
		return caseNoDependencies
	case s.NotInDatabase >= s.TotalDependencies:
		return caseNothingExamined
	default:
		return caseGenuinelyClean
	}
}

// hasAnyCrypto reports whether any dependency carried a surviving finding.
func hasAnyCrypto(deps []types.DependencyResult) bool {
	for _, dep := range deps {
		if dep.Analysis != nil && len(dep.Analysis.Crypto) > 0 {
			return true
		}
	}
	return false
}
