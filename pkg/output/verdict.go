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
	// caseNothingExamined means no dependency was reached by any means of
	// examination, so the scan drew no conclusion. Reporting this as clean is a
	// false negative on the tool's core question.
	caseNothingExamined
	// caseGenuinelyClean means dependencies were examined and carried no
	// cryptography.
	caseGenuinelyClean
	// casePartialCoverage means some dependencies were examined and others were
	// not. It is not a no-findings case: it can and does occur beside a
	// populated result set, which is exactly why it was missing. A document
	// listing two of three dependencies without saying the third was never read
	// is a false bill of materials, and the two formats that omitted it are the
	// two that get uploaded to code scanning and to compliance systems.
	casePartialCoverage
)

// classifyNoFindings decides which case a findings-free summary falls into.
// Callers must only reach it when no finding survived to be reported.
//
// The examination question is asked of NotExamined, not of NotInDatabase. The
// two were the same number while a database lookup was the only way to examine
// a package; --deep made them differ, and asking the database question meant a
// scan that read every dependency's source reported that it had examined
// nothing. A predicate that merely correlates with the question is a proxy, and
// this one stopped correlating the moment a second answer path existed.
func classifyNoFindings(s types.ScanSummary) noFindingsCase {
	switch {
	case s.FilteredOut > 0:
		return caseFiltered
	case s.TotalDependencies == 0:
		return caseNoDependencies
	case s.NotExamined >= s.TotalDependencies:
		return caseNothingExamined
	default:
		return caseGenuinelyClean
	}
}

// examinedCount is how many dependencies the scan actually inspected.
func examinedCount(s types.ScanSummary) int {
	n := s.TotalDependencies - s.NotExamined
	if n < 0 {
		return 0
	}
	return n
}

// unexaminedAdvice is the next step for dependencies nothing reached, worded
// for what the user has already done.
//
// A tool that answers "run --deep" to someone who ran --deep has given them a
// dead end. The two states need different sentences because they need different
// actions.
func unexaminedAdvice(s types.ScanSummary) string {
	if s.DeepAttempted {
		return "source analysis could not read them; see the warnings printed during the scan"
	}
	return "not in the crypto database (use --deep to analyze them)"
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
		if p == nil {
			continue
		}

		// Withheld findings are a property of the SCAN, not of an empty report,
		// so this is asked before and independently of the no-findings
		// classification. Routing it through classifyNoFindings, which by
		// contract only speaks about scans that produced nothing, meant a
		// partially filtered scan said nothing at all: 28 findings withheld
		// beside 38 reported, and neither SARIF nor CBOM mentioned it, because
		// one finding had survived.
		if p.Summary.FilteredOut > 0 {
			notes = append(notes, coverageNote{
				Manifest: p.Manifest,
				Case:     caseFiltered,
				Summary:  p.Summary,
			})
		}

		// Incomplete coverage is a property of the SCAN too, for the same
		// reason: a project can have findings AND dependencies nothing read.
		// Asking it only of empty reports meant a CBOM listed two of three
		// libraries, and a SARIF run reported executionSuccessful with no
		// notification, for a scan whose stderr had said it could not read the
		// third. The human formats said so; the machine ones did not.
		if p.Summary.NotExamined > 0 && p.Summary.NotExamined < p.Summary.TotalDependencies {
			notes = append(notes, coverageNote{
				Manifest: p.Manifest,
				Case:     casePartialCoverage,
				Summary:  p.Summary,
			})
		}

		if hasAnyCrypto(p.Dependencies) {
			continue
		}
		c := classifyNoFindings(p.Summary)
		// caseFiltered and casePartialCoverage are already handled above, and
		// caseGenuinelyClean needs no explanation: an empty result set is
		// exactly what it means.
		if c == caseGenuinelyClean || c == caseFiltered {
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
	case casePartialCoverage:
		return fmt.Sprintf("%d of the %d dependencies could not be examined: %s. The findings "+
			"below describe the %d that were examined, and say nothing about the rest.",
			n.Summary.NotExamined, n.Summary.TotalDependencies, unexaminedAdvice(n.Summary),
			examinedCount(n.Summary))
	case caseNothingExamined:
		if n.Summary.DeepAttempted {
			return fmt.Sprintf("None of the %d dependencies could be examined: they are absent from the "+
				"crypto database, and source analysis could not read any of them. An empty result set "+
				"here means nothing was examined, not that nothing was found.", n.Summary.TotalDependencies)
		}
		return fmt.Sprintf("None of the %d dependencies are present in the crypto database and source "+
			"analysis was not run, so no conclusion about cryptographic usage was drawn. An empty "+
			"result set here means nothing was examined, not that nothing was found.",
			n.Summary.TotalDependencies)
	default:
		return ""
	}
}

// Level maps a note to a SARIF notification level.
//
// Only a scan that failed to establish something warns. A filtered report and a
// manifest that declared no dependencies are both complete and correct states
// that merely need explaining, so they are notes. Warning on every one of them
// buried the signal: a healthy npm workspace produced three warnings saying
// "this package.json has no dependencies" and none saying findings were
// withheld.
func (n coverageNote) Level() string {
	switch n.Case {
	case caseFiltered, caseNoDependencies:
		return "note"
	default:
		return "warning"
	}
}
