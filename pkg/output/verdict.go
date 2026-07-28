// Copyright 2025-2026 CyberSecurity NonProfit (CSNP)
// SPDX-License-Identifier: Apache-2.0

package output

import (
	"fmt"

	"github.com/csnp/qramm-cryptodeps/pkg/types"
)

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

// coverageNote is what one project's scan failed to establish.
//
// The machine-readable formats need this as data rather than prose, but they
// must reach it through the same classification the human formats use. The first
// attempt at this re-derived the conditions inline in sarif.go and cbom.go
// instead, with the test applied to the whole run rather than per project and
// without checking whether the project had findings at all. The result was a
// SARIF document carrying two CRITICAL findings alongside a notification saying
// no conclusion about cryptographic usage could be drawn, and a mixed workspace
// where 21 of 24 dependencies went unexamined without either format saying so.
type coverageNote struct {
	// Manifest is the project the note is about, empty for a single-project run.
	Manifest string
	// Case is the shared classification.
	Case noFindingsCase
	// Summary is that project's summary, for rendering the numbers.
	Summary types.ScanSummary
}

// coverageNotes returns a note for each project that produced no findings and
// whose emptiness therefore needs explaining.
//
// A project with findings gets no note: its results speak for it, and saying
// "nothing was examined" beside a populated result set is simply false.
// caseGenuinelyClean also gets no note, because an empty result set is exactly
// what it means.
func coverageNotes(projects []*types.ScanResult) []coverageNote {
	var notes []coverageNote
	for _, p := range projects {
		if p == nil || hasAnyCrypto(p.Dependencies) {
			continue
		}
		c := classifyNoFindings(p.Summary)
		if c == caseGenuinelyClean {
			continue
		}
		notes = append(notes, coverageNote{Manifest: p.Manifest, Case: c, Summary: p.Summary})
	}
	return notes
}

// Text renders a note for a machine-readable consumer.
func (n coverageNote) Text() string {
	switch n.Case {
	case caseFiltered:
		return fmt.Sprintf("%d finding(s) were detected and withheld by --risk or --min-severity. "+
			"This is a filtered subset, not every finding.", n.Summary.FilteredOut)
	case caseNoDependencies:
		return "No dependencies were declared, so nothing was analyzed."
	case caseNothingExamined:
		return fmt.Sprintf("None of the %d dependencies are present in the crypto database, so no "+
			"conclusion about cryptographic usage was drawn. An empty result set here means "+
			"nothing was examined, not that nothing was found.", n.Summary.TotalDependencies)
	default:
		return ""
	}
}

// Level maps a note to a SARIF notification level.
func (n coverageNote) Level() string {
	if n.Case == caseFiltered {
		return "note"
	}
	return "warning"
}
