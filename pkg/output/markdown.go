// Copyright 2025-2026 CyberSecurity NonProfit (CSNP)
// SPDX-License-Identifier: Apache-2.0

package output

import (
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/csnp/qramm-cryptodeps/pkg/types"
	"github.com/csnp/qramm-cryptodeps/pkg/version"
)

// MarkdownFormatter formats scan results as Markdown.
type MarkdownFormatter struct {
	Options FormatterOptions
}

// Format writes the scan result as Markdown.
func (f *MarkdownFormatter) Format(result *types.ScanResult, w io.Writer) error {
	if result == nil {
		return errors.New("result cannot be nil")
	}
	if w == nil {
		return errors.New("writer cannot be nil")
	}
	fmt.Fprintf(w, "# CryptoDeps Scan Report\n\n")
	f.writeProject(w, result, projectLayout{depth: 2, totals: true, nist: true})
	writeMarkdownFooter(w)
	return nil
}

// projectLayout says how one project is rendered: as the whole report, or as a
// section of a workspace report under the project's own heading. A workspace
// report used to render each project as a complete report, with its own H1
// title and footer, so a scan of 11 projects carried 12 H1 headings.
type projectLayout struct {
	// root is the scan root when the project is part of a workspace report and
	// empty when it stands alone, so that a manifest is named the same way here
	// as in the project list above it.
	root string
	// depth is the heading level of the project's top sections: 2 when it is
	// the whole report, 3 under the project heading of a workspace report.
	depth int
	// totals is whether the Summary carries the dependency and finding counts.
	// A workspace report of one project leaves them to its Overview, which
	// states the same numbers.
	totals bool
	// nist is whether the NIST reference table follows the guidance. A
	// workspace report prints it once, after the projects.
	nist bool
}

// writeProject renders one project. The root is threaded through the layout
// rather than held on the formatter, which is what cbom.go does, so the
// formatter stays stateless.
func (f *MarkdownFormatter) writeProject(w io.Writer, result *types.ScanResult, layout projectLayout) {
	section := strings.Repeat("#", layout.depth)
	subsection := section + "#"
	root := layout.root

	// Summary
	fmt.Fprintf(w, "%s Summary\n\n", section)
	fmt.Fprintf(w, "| Metric | Value |\n")
	fmt.Fprintf(w, "|--------|-------|\n")
	writeMarkdownSourceRows(w, result.Source)
	fmt.Fprintf(w, "| **Manifest** | `%s` |\n", markdownCell(manifestForReport(root, result.Manifest)))
	fmt.Fprintf(w, "| **Ecosystem** | %s |\n", result.Ecosystem)
	if layout.totals {
		fmt.Fprintf(w, "| **Total Dependencies** | %d |\n", result.Summary.TotalDependencies)
		fmt.Fprintf(w, "| **Using Crypto** | %d |\n", result.Summary.WithCrypto)
		fmt.Fprintf(w, "| **Quantum Vulnerable** | %d |\n", result.Summary.QuantumVulnerable)
		fmt.Fprintf(w, "| **Quantum Partial** | %d |\n", result.Summary.QuantumPartial)
		writeMarkdownSafeRows(w, result.Summary)
	}
	fmt.Fprintf(w, "| **Not in Database** | %d |\n", result.Summary.NotInDatabase)
	// Not the same number once --deep is in play, and the difference is the
	// part a reader needs in order to know how much of the tree this report
	// actually covers.
	fmt.Fprintf(w, "| **Not Examined** | %d |\n", result.Summary.NotExamined)
	fmt.Fprintf(w, "\n")

	if len(result.UnreadLines) > 0 {
		fmt.Fprintf(w, "> **%d manifest line(s) declare dependencies this scan did not read.** "+
			"Those dependencies are missing from this report.\n>\n", len(result.UnreadLines))
		for _, u := range result.UnreadLines {
			if u.Name != "" {
				fmt.Fprintf(w, "> - line %d: `%s`: %s\n", u.Line, markdownCell(u.Name), u.Reason)
			} else {
				fmt.Fprintf(w, "> - line %d: %s\n", u.Line, u.Reason)
			}
		}
		fmt.Fprintf(w, "\n")
	}

	if !hasAnyCrypto(result.Dependencies) {
		writeMarkdownNoFindingsVerdict(w, result.Summary)
		fmt.Fprintf(w, "\n")
		return
	}

	// A filtered report describes only what survived the filter, so say so next
	// to the numbers rather than letting the table above read as complete.
	if result.Summary.FilteredOut > 0 {
		fmt.Fprintf(w, "> %d further finding(s) were excluded by `--risk` or `--min-severity`.\n\n",
			result.Summary.FilteredOut)
	}

	// Findings by risk level
	fmt.Fprintf(w, "%s Findings\n\n", section)

	// Collect remediation for detailed section
	remediationMap := make(map[string]string) // algorithm -> remediation

	// Counted over the rows this report lists, which are the vulnerable and
	// partial ones, so the note states a fraction of what the reader can see.
	listed, inferred := 0, 0

	// Vulnerable
	fmt.Fprintf(w, "%s Quantum Vulnerable\n\n", subsection)
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
				fmt.Fprintf(w, "| `%s` | %s | %s | %s%s |\n",
					markdownCell(dependencyLabel(dep.Dependency.Name, dep.Dependency.Version)),
					crypto.Algorithm,
					crypto.Type,
					crypto.Severity,
					inferredMark(crypto.Inferred()),
				)
				listed++
				if crypto.Inferred() {
					inferred++
				}
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
	fmt.Fprintf(w, "%s Quantum Partial Risk\n\n", subsection)
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
				fmt.Fprintf(w, "| `%s` | %s | %s | %s%s |\n",
					markdownCell(dependencyLabel(dep.Dependency.Name, dep.Dependency.Version)),
					crypto.Algorithm,
					crypto.Type,
					crypto.Severity,
					inferredMark(crypto.Inferred()),
				)
				listed++
				if crypto.Inferred() {
					inferred++
				}
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

	if note := inferredNote(inferred, listed); note != "" {
		fmt.Fprintf(w, "> %s\n\n", note)
	}

	// Remediation Guidance
	if f.Options.ShowRemediation && len(remediationMap) > 0 {
		fmt.Fprintf(w, "%s Remediation Guidance\n\n", section)
		fmt.Fprintf(w, "| Algorithm | Recommended Action | Where | Verify |\n")
		fmt.Fprintf(w, "|-----------|--------------------|-------|--------|\n")
		// Sorted, not ranged: Go randomises map iteration, so this table was the
		// one part of the report that still shuffled between runs of the same
		// scan after the other four formats were made deterministic.
		algos := make([]string, 0, len(remediationMap))
		for algo := range remediationMap {
			algos = append(algos, algo)
		}
		sort.Strings(algos)
		// The declarations are named as the summary table above names the
		// manifest, so the Verify command runs from the directory that path
		// is relative to. Every piece comes from the tree under scan and goes
		// into a cell, so each is rendered as a cell code span.
		manifest := manifestForReport(root, result.Manifest)
		for _, algo := range algos {
			where, verify := "", ""
			if manifest != "" {
				providers := declarationsOf(result.Dependencies, algo)
				refs := make([]string, 0, len(providers))
				for _, d := range providers {
					label := d.Name
					if d.Version != "" {
						label += " " + d.Version
					}
					refs = append(refs, "`"+markdownCell(declarationRef(manifest, d.Line))+"` `"+markdownCell(label)+"`")
				}
				where = strings.Join(refs, "<br>")
				if command := verifyDeclarationCommand(result.Ecosystem, manifest, providers); command != "" {
					verify = "`" + markdownCell(command) + "`"
				}
			}
			fmt.Fprintf(w, "| **%s** | %s | %s | %s |\n", algo, remediationMap[algo], where, verify)
		}
		fmt.Fprintf(w, "\n")
	}

	if layout.nist {
		writeMarkdownNISTReference(w, section)
	}

	// Notes section for packages nothing examined. Keyed on NotExamined rather
	// than NotInDatabase: a package the database does not carry and source
	// analysis read is covered, and telling the reader to run --deep for it
	// repeats a step they have already taken.
	// A package read in part is counted as examined, so it is absent from
	// NotExamined and needs its own note. The heading belongs to either state
	// rather than to the first one that happened to be written.
	if result.Summary.NotExamined > 0 || result.Summary.SourceFilesUnreadable > 0 {
		fmt.Fprintf(w, "%s Notes\n\n", section)
	}
	if result.Summary.NotExamined > 0 {
		pct := float64(result.Summary.NotExamined) / float64(result.Summary.TotalDependencies) * 100
		// Worded to read the same for one package as for several, which
		// "1 packages (17%) were not examined" did not.
		fmt.Fprintf(w, "> **Packages that were not examined: %d of %d (%.0f%%).**\n",
			result.Summary.NotExamined, result.Summary.TotalDependencies, pct)
		if result.Summary.DeepAttempted {
			fmt.Fprintf(w, "> Source analysis could not read them; see the warnings printed during the scan.\n\n")
		} else if result.Summary.DeepSkippedOffline {
			fmt.Fprintf(w, "> %s.\n\n", deepSkippedOffline)
		} else {
			fmt.Fprintf(w, "> Run with `--deep` flag to analyze them via source code inspection.\n\n")
		}
	}
	if result.Summary.SourceFilesUnreadable > 0 {
		fmt.Fprintf(w, "> **%s could not be read** in packages that were examined, so "+
			"their cryptography may be under-reported.\n",
			countOf(result.Summary.SourceFilesUnreadable, "source file", "source files"))
		fmt.Fprintf(w, "> The scan names them in the warnings it printed.\n\n")
	}
}

// writeMarkdownNISTReference writes the table of NIST post-quantum standards
// under a heading at the level of section.
func writeMarkdownNISTReference(w io.Writer, section string) {
	fmt.Fprintf(w, "%s NIST Post-Quantum Cryptography Standards\n\n", section)
	fmt.Fprintf(w, "| Standard | Algorithm | Use Case |\n")
	fmt.Fprintf(w, "|----------|-----------|----------|\n")
	fmt.Fprintf(w, "| [FIPS 203](https://csrc.nist.gov/pubs/fips/203/final) | ML-KEM (Kyber) | Key Encapsulation |\n")
	fmt.Fprintf(w, "| [FIPS 204](https://csrc.nist.gov/pubs/fips/204/final) | ML-DSA (Dilithium) | Digital Signatures |\n")
	fmt.Fprintf(w, "| [FIPS 205](https://csrc.nist.gov/pubs/fips/205/final) | SLH-DSA (SPHINCS+) | Stateless Hash Signatures |\n")
	fmt.Fprintf(w, "\n")
}

// writeMarkdownFooter ends a report, once, with the tool and the version that
// wrote it. The footer named no version, and the link named the repository by
// the name it had before it was renamed.
func writeMarkdownFooter(w io.Writer) {
	fmt.Fprintf(w, "---\n\n")
	fmt.Fprintf(w, "*Generated by [CryptoDeps](%s) version `%s` - Part of the [QRAMM Toolkit](https://qramm.org)*\n",
		version.InformationURI, markdownCode(version.Version()))
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
		} else if s.DeepSkippedOffline {
			fmt.Fprintf(w, "**Not analyzed.** All %d dependencies are absent from the crypto database, "+
				"so no conclusion about cryptographic usage can be drawn from this scan. "+
				"%s.\n", s.TotalDependencies, deepSkippedOffline)
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
		// A dependency read in part is counted as read, so it is absent from
		// NotExamined and this verdict claimed a complete reading of it.
		if s.SourceFilesUnreadable > 0 {
			fmt.Fprintf(w, "\n%d source file(s) in those dependencies could not be read, so this is not a "+
				"complete reading of them. See the warnings printed during the scan.\n", s.SourceFilesUnreadable)
		}
	}
}

// writeMarkdownSourceRows names a fetched repository in a summary table, and
// writes nothing for a local scan. In code spans, like every path in these
// reports, because the values come from the command line and the GitHub API.
// writeMarkdownSafeRows writes the counts of the findings that are neither
// vulnerable nor partial, so the risk rows sum to the findings listed.
func writeMarkdownSafeRows(w io.Writer, s types.ScanSummary) {
	fmt.Fprintf(w, "| **Quantum Safe** | %d |\n", s.QuantumSafe)
	if s.QuantumUnknown > 0 {
		fmt.Fprintf(w, "| **Unknown Risk** | %d |\n", s.QuantumUnknown)
	}
}

func writeMarkdownSourceRows(w io.Writer, s *types.ScanSource) {
	if s == nil {
		return
	}
	fmt.Fprintf(w, "| **Repository** | `%s` |\n", markdownCell(s.Repository))
	fmt.Fprintf(w, "| **Branch** | `%s` |\n", markdownCell(s.Branch))
	if s.Path != "" {
		fmt.Fprintf(w, "| **Repository Path** | `%s` |\n", markdownCell(s.Path))
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
	writeMarkdownSourceRows(w, result.Source)
	fmt.Fprintf(w, "| **Root Path** | `%s` |\n", markdownCell(scanRootDir(result.RootPath)))
	fmt.Fprintf(w, "| **Projects Scanned** | %d |\n", len(result.Projects))
	fmt.Fprintf(w, "| **Total Dependencies** | %d |\n", result.TotalSummary.TotalDependencies)
	fmt.Fprintf(w, "| **Using Crypto** | %d |\n", result.TotalSummary.WithCrypto)
	fmt.Fprintf(w, "| **Quantum Vulnerable** | %d |\n", result.TotalSummary.QuantumVulnerable)
	fmt.Fprintf(w, "| **Quantum Partial** | %d |\n", result.TotalSummary.QuantumPartial)
	writeMarkdownSafeRows(w, result.TotalSummary)
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

	// Individual project reports, each a section under its own heading rather
	// than a complete report with a title and footer of its own.
	layout := projectLayout{root: result.RootPath, depth: 3, totals: len(result.Projects) > 1}
	anyFindings := false
	for _, project := range result.Projects {
		fmt.Fprintf(w, "---\n\n")
		// In a code span, like every other path in this document. A bare heading
		// renders whatever the name contains, and a directory can be named
		// "**CLEAN**" or "[no findings](https://...)".
		fmt.Fprintf(w, "## `%s`\n\n", markdownCode(getRelativePath(result.RootPath, project.Manifest)))
		f.writeProject(w, project, layout)
		anyFindings = anyFindings || hasAnyCrypto(project.Dependencies)
	}

	// Once, after the projects, where each project with findings used to print
	// its own copy.
	if anyFindings {
		fmt.Fprintf(w, "---\n\n")
		writeMarkdownNISTReference(w, "##")
	}
	writeMarkdownFooter(w)

	return nil
}
