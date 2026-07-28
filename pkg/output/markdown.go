// Copyright 2025-2026 CyberSecurity NonProfit (CSNP)
// SPDX-License-Identifier: Apache-2.0

package output

import (
	"errors"
	"fmt"
	"io"
	"sort"

	"github.com/csnp/qramm-cryptodeps/pkg/types"
)

// MarkdownFormatter formats scan results as Markdown.
type MarkdownFormatter struct {
	Options FormatterOptions
}

// Format writes the scan result as Markdown.
func (f *MarkdownFormatter) Format(result *types.ScanResult, w io.Writer) error {
	return f.formatProject(result, "", w)
}

// formatProject renders one project. root is the scan root when this render is
// part of a workspace report and empty when it stands alone, so that a manifest
// is named the same way here as in the project list above it. Threaded as an
// argument rather than held on the formatter, which is what cbom.go does, so the
// formatter stays stateless.
func (f *MarkdownFormatter) formatProject(result *types.ScanResult, root string, w io.Writer) error {
	if result == nil {
		return errors.New("result cannot be nil")
	}
	if w == nil {
		return errors.New("writer cannot be nil")
	}
	// Title
	fmt.Fprintf(w, "# CryptoDeps Scan Report\n\n")

	// Summary
	fmt.Fprintf(w, "## Summary\n\n")
	fmt.Fprintf(w, "| Metric | Value |\n")
	fmt.Fprintf(w, "|--------|-------|\n")
	fmt.Fprintf(w, "| **Manifest** | `%s` |\n", markdownCell(manifestForReport(root, result.Manifest)))
	fmt.Fprintf(w, "| **Ecosystem** | %s |\n", result.Ecosystem)
	fmt.Fprintf(w, "| **Total Dependencies** | %d |\n", result.Summary.TotalDependencies)
	fmt.Fprintf(w, "| **Using Crypto** | %d |\n", result.Summary.WithCrypto)
	fmt.Fprintf(w, "| **Quantum Vulnerable** | %d |\n", result.Summary.QuantumVulnerable)
	fmt.Fprintf(w, "| **Quantum Partial** | %d |\n", result.Summary.QuantumPartial)
	fmt.Fprintf(w, "| **Not in Database** | %d |\n", result.Summary.NotInDatabase)
	// Not the same number once --deep is in play, and the difference is the
	// part a reader needs in order to know how much of the tree this report
	// actually covers.
	fmt.Fprintf(w, "| **Not Examined** | %d |\n", result.Summary.NotExamined)
	fmt.Fprintf(w, "\n")

	if !hasAnyCrypto(result.Dependencies) {
		writeMarkdownNoFindingsVerdict(w, result.Summary)
		return nil
	}

	// A filtered report describes only what survived the filter, so say so next
	// to the numbers rather than letting the table above read as complete.
	if result.Summary.FilteredOut > 0 {
		fmt.Fprintf(w, "> %d further finding(s) were excluded by `--risk` or `--min-severity`.\n\n",
			result.Summary.FilteredOut)
	}

	// Findings by risk level
	fmt.Fprintf(w, "## Findings\n\n")

	// Collect remediation for detailed section
	remediationMap := make(map[string]string) // algorithm -> remediation

	// Vulnerable
	fmt.Fprintf(w, "### Quantum Vulnerable\n\n")
	hasVulnerable := false
	for _, dep := range result.Dependencies {
		if dep.Analysis == nil {
			continue
		}
		for _, crypto := range dep.Analysis.Crypto {
			if crypto.QuantumRisk == types.RiskVulnerable {
				if !hasVulnerable {
					fmt.Fprintf(w, "| Dependency | Algorithm | Type | Severity |\n")
					fmt.Fprintf(w, "|------------|-----------|------|----------|\n")
					hasVulnerable = true
				}
				// The name and the version come from the manifest being
				// scanned, so they are attacker-controlled in exactly the way a
				// path is, and they need no exotic filesystem to deliver: a
				// dependency entry in a pull request is enough. A version of
				// "1.3.1\n\n## Scan result: CLEAN" put that heading in this
				// report, in a table row, seven times.
				fmt.Fprintf(w, "| `%s` | %s | %s | %s |\n",
					markdownCell(dependencyLabel(dep.Dependency.Name, dep.Dependency.Version)),
					crypto.Algorithm,
					crypto.Type,
					crypto.Severity,
				)
				if crypto.Remediation != "" {
					remediationMap[crypto.Algorithm] = crypto.Remediation
				}
			}
		}
	}
	if !hasVulnerable {
		fmt.Fprintf(w, "No quantum-vulnerable algorithms found.\n")
	}
	fmt.Fprintf(w, "\n")

	// Partial
	fmt.Fprintf(w, "### Quantum Partial Risk\n\n")
	hasPartial := false
	for _, dep := range result.Dependencies {
		if dep.Analysis == nil {
			continue
		}
		for _, crypto := range dep.Analysis.Crypto {
			if crypto.QuantumRisk == types.RiskPartial {
				if !hasPartial {
					fmt.Fprintf(w, "| Dependency | Algorithm | Type | Severity |\n")
					fmt.Fprintf(w, "|------------|-----------|------|----------|\n")
					hasPartial = true
				}
				// The name and the version come from the manifest being
				// scanned, so they are attacker-controlled in exactly the way a
				// path is, and they need no exotic filesystem to deliver: a
				// dependency entry in a pull request is enough. A version of
				// "1.3.1\n\n## Scan result: CLEAN" put that heading in this
				// report, in a table row, seven times.
				fmt.Fprintf(w, "| `%s` | %s | %s | %s |\n",
					markdownCell(dependencyLabel(dep.Dependency.Name, dep.Dependency.Version)),
					crypto.Algorithm,
					crypto.Type,
					crypto.Severity,
				)
				if crypto.Remediation != "" {
					remediationMap[crypto.Algorithm] = crypto.Remediation
				}
			}
		}
	}
	if !hasPartial {
		fmt.Fprintf(w, "No partial-risk algorithms found.\n")
	}
	fmt.Fprintf(w, "\n")

	// Remediation Guidance
	if f.Options.ShowRemediation && len(remediationMap) > 0 {
		fmt.Fprintf(w, "## Remediation Guidance\n\n")
		fmt.Fprintf(w, "| Algorithm | Recommended Action |\n")
		fmt.Fprintf(w, "|-----------|--------------------|\n")
		// Sorted, not ranged: Go randomises map iteration, so this table was the
		// one part of the report that still shuffled between runs of the same
		// scan after the other four formats were made deterministic.
		algos := make([]string, 0, len(remediationMap))
		for algo := range remediationMap {
			algos = append(algos, algo)
		}
		sort.Strings(algos)
		for _, algo := range algos {
			fmt.Fprintf(w, "| **%s** | %s |\n", algo, remediationMap[algo])
		}
		fmt.Fprintf(w, "\n")
	}

	// NIST PQC Standards Reference
	fmt.Fprintf(w, "## NIST Post-Quantum Cryptography Standards\n\n")
	fmt.Fprintf(w, "| Standard | Algorithm | Use Case |\n")
	fmt.Fprintf(w, "|----------|-----------|----------|\n")
	fmt.Fprintf(w, "| [FIPS 203](https://csrc.nist.gov/pubs/fips/203/final) | ML-KEM (Kyber) | Key Encapsulation |\n")
	fmt.Fprintf(w, "| [FIPS 204](https://csrc.nist.gov/pubs/fips/204/final) | ML-DSA (Dilithium) | Digital Signatures |\n")
	fmt.Fprintf(w, "| [FIPS 205](https://csrc.nist.gov/pubs/fips/205/final) | SLH-DSA (SPHINCS+) | Stateless Hash Signatures |\n")
	fmt.Fprintf(w, "\n")

	// Notes section for packages nothing examined. Keyed on NotExamined rather
	// than NotInDatabase: a package the database does not carry and source
	// analysis read is covered, and telling the reader to run --deep for it
	// repeats a step they have already taken.
	if result.Summary.NotExamined > 0 {
		fmt.Fprintf(w, "## Notes\n\n")
		pct := float64(result.Summary.NotExamined) / float64(result.Summary.TotalDependencies) * 100
		fmt.Fprintf(w, "> **%d packages (%.0f%%) were not examined.**\n", result.Summary.NotExamined, pct)
		if result.Summary.DeepAttempted {
			fmt.Fprintf(w, "> Source analysis could not read them; see the warnings printed during the scan.\n\n")
		} else {
			fmt.Fprintf(w, "> Run with `--deep` flag to analyze these packages via source code inspection.\n\n")
		}
	}

	// Footer
	fmt.Fprintf(w, "---\n\n")
	fmt.Fprintf(w, "*Generated by [CryptoDeps](https://github.com/csnp/qramm-cryptodeps) - Part of the [QRAMM Toolkit](https://qramm.org)*\n")

	return nil
}

// writeMarkdownNoFindingsVerdict states what a findings-free scan established.
// It renders the shared classification in markdown prose; the wording differs
// from the table's, the meaning must not.
func writeMarkdownNoFindingsVerdict(w io.Writer, s types.ScanSummary) {
	switch classifyNoFindings(s) {
	case caseFiltered:
		fmt.Fprintf(w, "**No findings matched the active filter.** %d finding(s) were detected and "+
			"excluded by `--risk` or `--min-severity`. This is not a clean result. "+
			"Re-run without the filter to see them.\n", s.FilteredOut)

	case caseNoDependencies:
		fmt.Fprintf(w, "**No dependencies found in this manifest.** Nothing to analyze.\n")

	case caseNothingExamined:
		if s.DeepAttempted {
			fmt.Fprintf(w, "**Not analyzed.** None of the %d dependencies could be examined: they are absent "+
				"from the crypto database, and source analysis could not read any of them. "+
				"See the warnings printed during the scan.\n", s.TotalDependencies)
		} else {
			fmt.Fprintf(w, "**Not analyzed.** All %d dependencies are absent from the crypto database, "+
				"so no conclusion about cryptographic usage can be drawn from this scan. "+
				"Run with `--deep` to analyze package source code directly.\n", s.TotalDependencies)
		}

	default:
		fmt.Fprintf(w, "No cryptographic usage detected in the %d of %d dependencies that were examined.\n",
			examinedCount(s), s.TotalDependencies)
		if s.NotExamined > 0 {
			fmt.Fprintf(w, "\n%d could not be examined: %s.\n", s.NotExamined, unexaminedAdvice(s))
		}
	}
}

// FormatMulti writes multi-project scan results as Markdown.
func (f *MarkdownFormatter) FormatMulti(result *types.MultiProjectResult, w io.Writer) error {
	if result == nil {
		return errors.New("result cannot be nil")
	}
	if w == nil {
		return errors.New("writer cannot be nil")
	}

	// Title
	fmt.Fprintf(w, "# CryptoDeps Multi-Project Scan Report\n\n")

	// Manifests that were found but not read change how every number below
	// should be read, so they are stated before the overview rather than in a
	// footnote.
	// Split by kind, for the same reason the table does: counting an unreadable
	// manifest and an unsupported ecosystem together produced a number that
	// disagreed with the CBOM for the same run, and asserted that a healthy
	// Cargo.toml "could not be read".
	var unread, unsupported []types.SkippedManifest
	for _, s := range result.Skipped {
		if s.Unsupported {
			unsupported = append(unsupported, s)
		} else {
			unread = append(unread, s)
		}
	}
	if len(unread) > 0 {
		fmt.Fprintf(w, "## Not analyzed\n\n")
		fmt.Fprintf(w, "%d manifest file(s) were found but could not be read. "+
			"The dependencies they declare are missing from this report.\n\n", len(unread))
		fmt.Fprintf(w, "| Manifest | Reason |\n")
		fmt.Fprintf(w, "|----------|--------|\n")
		for _, s := range unread {
			// The reason is a code span too: it is an error string that quotes the
			// path back, so it carries the same untrusted bytes as the cell beside it.
			fmt.Fprintf(w, "| `%s` | `%s` |\n", markdownCell(getRelativePath(result.RootPath, s.Path)), markdownCell(s.Reason))
		}
		fmt.Fprintf(w, "\n")
	}
	if len(unsupported) > 0 {
		fmt.Fprintf(w, "## Unsupported ecosystems\n\n")
		fmt.Fprintf(w, "%d manifest file(s) belong to ecosystems cryptodeps does not parse. "+
			"Their dependencies were not analyzed, and this does not affect the exit code.\n\n",
			len(unsupported))
		for _, s := range unsupported {
			fmt.Fprintf(w, "- `%s`\n", markdownCode(getRelativePath(result.RootPath, s.Path)))
		}
		fmt.Fprintf(w, "\n")
	}

	// Overview
	fmt.Fprintf(w, "## Overview\n\n")
	fmt.Fprintf(w, "| Metric | Value |\n")
	fmt.Fprintf(w, "|--------|-------|\n")
	fmt.Fprintf(w, "| **Root Path** | `%s` |\n", markdownCell(scanRootDir(result.RootPath)))
	fmt.Fprintf(w, "| **Projects Scanned** | %d |\n", len(result.Projects))
	fmt.Fprintf(w, "| **Total Dependencies** | %d |\n", result.TotalSummary.TotalDependencies)
	fmt.Fprintf(w, "| **Using Crypto** | %d |\n", result.TotalSummary.WithCrypto)
	fmt.Fprintf(w, "| **Quantum Vulnerable** | %d |\n", result.TotalSummary.QuantumVulnerable)
	fmt.Fprintf(w, "| **Quantum Partial** | %d |\n", result.TotalSummary.QuantumPartial)
	if result.TotalSummary.FilteredOut > 0 {
		fmt.Fprintf(w, "| **Withheld by filter** | %d |\n", result.TotalSummary.FilteredOut)
	}
	fmt.Fprintf(w, "\n")
	if result.TotalSummary.FilteredOut > 0 {
		fmt.Fprintf(w, "> Every number above describes only the findings that survived "+
			"`--risk` or `--min-severity`. %d were withheld.\n\n", result.TotalSummary.FilteredOut)
	}

	// Project list
	fmt.Fprintf(w, "### Projects\n\n")
	for _, project := range result.Projects {
		fmt.Fprintf(w, "- `%s` (%s)\n", markdownCode(getRelativePath(result.RootPath, project.Manifest)), project.Ecosystem)
	}
	fmt.Fprintf(w, "\n")

	// Individual project reports
	for _, project := range result.Projects {
		fmt.Fprintf(w, "---\n\n")
		// In a code span, like every other path in this document. A bare heading
		// renders whatever the name contains, and a directory can be named
		// "**CLEAN**" or "[no findings](https://...)".
		fmt.Fprintf(w, "## `%s`\n\n", markdownCode(getRelativePath(result.RootPath, project.Manifest)))

		// Use the single-project formatter for detailed output
		if err := f.formatProject(project, result.RootPath, w); err != nil {
			return err
		}
	}

	return nil
}
