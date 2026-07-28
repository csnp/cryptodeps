// Copyright 2025-2026 CyberSecurity NonProfit (CSNP)
// SPDX-License-Identifier: Apache-2.0

package output

import (
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/csnp/qramm-cryptodeps/pkg/crypto"
	"github.com/csnp/qramm-cryptodeps/pkg/types"
)

// TableFormatter formats scan results as a human-readable table.
type TableFormatter struct {
	Options FormatterOptions
}

// cryptoDetail holds info for detailed crypto breakdown.
type cryptoDetail struct {
	algorithm    string
	risk         types.QuantumRisk
	reachability types.Reachability
	dependency   string
	traces       []types.CallTrace
	ecosystem    types.Ecosystem
}

// Format writes the scan result as a table.
func (f *TableFormatter) Format(result *types.ScanResult, w io.Writer) error {
	if result == nil {
		return errors.New("result cannot be nil")
	}
	if w == nil {
		return errors.New("writer cannot be nil")
	}
	// Header
	fmt.Fprintf(w, "\n[*] Scanning %s... found %d dependencies\n\n", reportSafe(result.Manifest), result.Summary.TotalDependencies)

	// Check if there are any crypto findings
	hasCrypto := false
	for _, dep := range result.Dependencies {
		if dep.Analysis != nil && len(dep.Analysis.Crypto) > 0 {
			hasCrypto = true
			break
		}
	}

	if !hasCrypto {
		f.printNoFindingsVerdict(w, result)
		return nil
	}

	hasReachability := result.Summary.ReachabilityAnalyzed

	// Collect all crypto details for breakdown
	var allCrypto []cryptoDetail

	for _, dep := range result.Dependencies {
		if dep.Analysis == nil || len(dep.Analysis.Crypto) == 0 {
			continue
		}

		depName := dep.Dependency.Name
		if dep.Dependency.Version != "" {
			depName = fmt.Sprintf("%s@%s", dep.Dependency.Name, dep.Dependency.Version)
		}

		for _, c := range dep.Analysis.Crypto {
			allCrypto = append(allCrypto, cryptoDetail{
				algorithm:    c.Algorithm,
				risk:         c.QuantumRisk,
				reachability: c.Reachability,
				dependency:   depName,
				traces:       c.Traces,
				ecosystem:    result.Ecosystem,
			})
		}
	}

	// Print detailed crypto breakdown grouped by reachability
	if hasReachability {
		f.printReachabilityBreakdown(w, allCrypto)
	} else {
		f.printSimpleBreakdown(w, allCrypto)
	}

	// Summary
	fmt.Fprintln(w, strings.Repeat("═", 90))
	if hasReachability {
		fmt.Fprintf(w, "SUMMARY: %d deps | %d with crypto | %d vulnerable | %d partial\n",
			result.Summary.TotalDependencies,
			result.Summary.WithCrypto,
			result.Summary.QuantumVulnerable,
			result.Summary.QuantumPartial,
		)
		fmt.Fprintf(w, "REACHABILITY: %d confirmed | %d reachable | %d available-only\n\n",
			result.Summary.ConfirmedCrypto,
			result.Summary.ReachableCrypto,
			result.Summary.AvailableCrypto,
		)
	} else {
		fmt.Fprintf(w, "SUMMARY: %d deps | %d with crypto | %d vulnerable | %d partial\n",
			result.Summary.TotalDependencies,
			result.Summary.WithCrypto,
			result.Summary.QuantumVulnerable,
			result.Summary.QuantumPartial,
		)
		fmt.Fprintln(w)
	}

	// A filtered report is a partial view, and every number above describes only
	// what survived the filter. Say so, next to the numbers.
	if result.Summary.FilteredOut > 0 {
		fmt.Fprintf(w, "FILTERED: %d further finding(s) excluded by --risk or --min-severity.\n\n",
			result.Summary.FilteredOut)
	}

	// Display detailed remediation for vulnerable findings
	// For reachability-analyzed projects: show CONFIRMED first, then PLANNING
	// For other projects: show all vulnerable/partial algorithms
	if hasReachability {
		if f.Options.ShowRemediation {
			f.printDetailedRemediation(w, allCrypto, result.Ecosystem)
		}
	} else {
		// Always show remediation for non-reachability projects (Python, npm, Java, etc.)
		f.printSimpleRemediation(w, allCrypto, result.Ecosystem)
	}

	// Count deep-analyzed packages
	deepAnalyzed := 0
	notAnalyzed := 0
	for _, dep := range result.Dependencies {
		if dep.DeepAnalyzed {
			deepAnalyzed++
		} else if !dep.InDatabase && dep.Analysis == nil {
			notAnalyzed++
		}
	}

	// Info for deep-analyzed packages
	if deepAnalyzed > 0 {
		fmt.Fprintf(w, "[*] %d packages analyzed via AST (--deep)\n", deepAnalyzed)
	}

	// Warning for packages not analyzed
	if notAnalyzed > 0 {
		fmt.Fprintf(w, "[!] %d packages not in database (use --deep to analyze)\n", notAnalyzed)
	}

	f.printHints(w, result)

	if deepAnalyzed > 0 || notAnalyzed > 0 || len(result.Hints) > 0 {
		fmt.Fprintln(w)
	}

	return nil
}

// printNoFindingsVerdict states what a scan with no crypto findings actually
// established.
//
// "No cryptographic usage detected" is only true if something was examined. When
// every dependency is unknown to the database, nothing was examined, and
// reporting a clean result is a false negative on the tool's core question. The
// three cases below are genuinely different and are worded differently.
func (f *TableFormatter) printNoFindingsVerdict(w io.Writer, result *types.ScanResult) {
	total := result.Summary.TotalDependencies
	unknown := result.Summary.NotInDatabase

	switch classifyNoFindings(result.Summary) {
	case caseFiltered:
		fmt.Fprintf(w, "[?] No findings matched the active filter. %d finding(s) were detected and\n",
			result.Summary.FilteredOut)
		fmt.Fprintln(w, "    excluded by --risk or --min-severity. This is not a clean result.")
		fmt.Fprintln(w, "    Re-run without the filter to see them.")

	case caseNoDependencies:
		fmt.Fprintln(w, "[?] No dependencies found in this manifest. Nothing to analyze.")

	case caseNothingExamined:
		fmt.Fprintf(w, "[?] Not analyzed. All %d dependencies are absent from the crypto database,\n", total)
		fmt.Fprintln(w, "    so no conclusion about cryptographic usage can be drawn from this scan.")
		fmt.Fprintln(w, "    Run with --deep to analyze package source code directly.")
		// The hints for this case say the same thing in other words. Printing
		// both reads as three separate problems.

	default:
		fmt.Fprintf(w, "[OK] No cryptographic usage detected in the %d of %d dependencies that were analyzed.\n",
			total-unknown, total)
		if unknown > 0 {
			fmt.Fprintf(w, "[!] %d not in database, so they were not examined (use --deep to analyze).\n", unknown)
		}
		f.printHints(w, result)
	}

	fmt.Fprintln(w)
}

// printHints prints the analyzer's suggestions. They were generated on every
// scan but never reached the terminal.
func (f *TableFormatter) printHints(w io.Writer, result *types.ScanResult) {
	for _, hint := range result.Hints {
		fmt.Fprintf(w, "    %s\n", hint)
	}
}

// PrintSkipped reports manifests that were found but not analyzed. It is
// deliberately loud: a silently skipped manifest is how a scanner reports a
// clean tree it never read.
func PrintSkipped(w io.Writer, skipped []types.SkippedManifest) {
	if len(skipped) == 0 {
		return
	}
	// Split by kind. Counting them together made this report say "2 manifest
	// file(s) found but NOT analyzed" about a corrupt package.json and a
	// Cargo.toml in the same breath, while the CBOM for the same run said one.
	// Only the first is a gap in the scan; the second is a limit of the tool.
	var unread, unsupported []types.SkippedManifest
	for _, s := range skipped {
		if s.Unsupported {
			unsupported = append(unsupported, s)
		} else {
			unread = append(unread, s)
		}
	}

	if len(unread) > 0 {
		fmt.Fprintf(w, "[!] %d manifest file(s) found but NOT analyzed:\n", len(unread))
		for _, s := range unread {
			fmt.Fprintf(w, "    %s\n", reportSafe(s.Path))
			fmt.Fprintf(w, "      reason: %s\n", reportSafe(s.Reason))
		}
		fmt.Fprintln(w, "    These dependencies are missing from the results below.")
		fmt.Fprintln(w)
	}

	if len(unsupported) > 0 {
		fmt.Fprintf(w, "[?] %d manifest file(s) found for ecosystems cryptodeps does not support:\n",
			len(unsupported))
		for _, s := range unsupported {
			fmt.Fprintf(w, "    %s\n", reportSafe(s.Path))
		}
		fmt.Fprintln(w, "    Their dependencies were not analyzed. This does not affect the exit code.")
		fmt.Fprintln(w)
	}
}

// printReachabilityBreakdown prints crypto grouped by reachability status.
func (f *TableFormatter) printReachabilityBreakdown(w io.Writer, allCrypto []cryptoDetail) {
	// Group by reachability
	confirmed := filterByReachability(allCrypto, types.ReachabilityConfirmed)
	reachable := filterByReachability(allCrypto, types.ReachabilityReachable)
	available := filterByReachability(allCrypto, types.ReachabilityAvailable)

	// Sort each group by risk (vulnerable first)
	sortByRisk(confirmed)
	sortByRisk(reachable)
	sortByRisk(available)

	// Print CONFIRMED section (most important) - with call traces
	if len(confirmed) > 0 {
		fmt.Fprintln(w, "[!] CONFIRMED - Actually used by your code (requires action):")
		fmt.Fprintln(w, strings.Repeat("─", 90))
		for _, c := range confirmed {
			icon := riskIcon(c.risk)
			timeline := formatTimelineShort(getTimeline(c.algorithm))
			effort := formatEffortShort(getEffort(c.algorithm))
			fmt.Fprintf(w, "  %-4s %-14s %-12s  %-12s  %s\n",
				icon, c.algorithm, formatRisk(c.risk), timeline, effort)
			fmt.Fprintf(w, "     └─ %s\n", c.dependency)

			// Show call traces (where in user code)
			if len(c.traces) > 0 {
				for _, trace := range c.traces {
					if len(trace.Path) > 0 {
						// Show entry point (user's function)
						entryFunc := shortenFuncName(trace.EntryPoint)
						fmt.Fprintf(w, "        > Called from: %s\n", entryFunc)
					}
				}
			}
		}
		fmt.Fprintln(w)
	}

	// Print REACHABLE section
	if len(reachable) > 0 {
		fmt.Fprintln(w, "REACHABLE - In call graph from your code:")
		fmt.Fprintln(w, strings.Repeat("─", 90))
		for _, c := range reachable {
			icon := riskIcon(c.risk)
			fmt.Fprintf(w, "  %-4s %-14s %-12s  %s\n", icon, c.algorithm, formatRisk(c.risk), c.dependency)
		}
		fmt.Fprintln(w)
	}

	// Print AVAILABLE section (lower priority) - condensed
	if len(available) > 0 {
		fmt.Fprintln(w, "[.] AVAILABLE - In dependencies but not called (lower priority):")
		fmt.Fprintln(w, strings.Repeat("─", 90))

		// Group available by dependency for cleaner output. Iterate the names in
		// sorted order rather than ranging over the map, whose order Go
		// randomises.
		byDep := make(map[string][]cryptoDetail)
		for _, c := range available {
			byDep[c.dependency] = append(byDep[c.dependency], c)
		}
		depNames := make([]string, 0, len(byDep))
		for dep := range byDep {
			depNames = append(depNames, dep)
		}
		sort.Strings(depNames)

		for _, dep := range depNames {
			var algoStrs []string
			for _, a := range byDep[dep] {
				algoStrs = append(algoStrs, fmt.Sprintf("%s %s", riskIcon(a.risk), a.algorithm))
			}
			fmt.Fprintf(w, "  %s\n", dep)
			fmt.Fprintf(w, "     └─ %s\n", strings.Join(algoStrs, ", "))
		}
		fmt.Fprintln(w)
	}
}

// printSimpleBreakdown prints crypto without reachability grouping.
func (f *TableFormatter) printSimpleBreakdown(w io.Writer, allCrypto []cryptoDetail) {
	sortByRisk(allCrypto)

	// Group by risk level for cleaner output
	vulnerable := filterByRisk(allCrypto, types.RiskVulnerable)
	partial := filterByRisk(allCrypto, types.RiskPartial)
	safe := filterByRisk(allCrypto, types.RiskSafe)

	if len(vulnerable) > 0 {
		fmt.Fprintln(w, "[!] VULNERABLE - Quantum computers will break these:")
		fmt.Fprintln(w, strings.Repeat("─", 90))
		for _, c := range vulnerable {
			timeline := formatTimelineShort(getTimeline(c.algorithm))
			effort := formatEffortShort(getEffort(c.algorithm))
			fmt.Fprintf(w, "  %-4s %-14s %-12s  %-12s  %s\n", riskIcon(c.risk), c.algorithm, timeline, effort, c.dependency)
		}
		fmt.Fprintln(w)
	}

	if len(partial) > 0 {
		fmt.Fprintln(w, "[~] PARTIAL RISK - Weakened but usable:")
		fmt.Fprintln(w, strings.Repeat("─", 90))
		for _, c := range partial {
			timeline := formatTimelineShort(getTimeline(c.algorithm))
			effort := formatEffortShort(getEffort(c.algorithm))
			fmt.Fprintf(w, "  %-4s %-14s %-12s  %-12s  %s\n", riskIcon(c.risk), c.algorithm, timeline, effort, c.dependency)
		}
		fmt.Fprintln(w)
	}

	if len(safe) > 0 {
		fmt.Fprintln(w, "[OK] QUANTUM SAFE:")
		fmt.Fprintln(w, strings.Repeat("─", 90))
		for _, c := range safe {
			fmt.Fprintf(w, "  %-4s %-14s %s\n", riskIcon(c.risk), c.algorithm, c.dependency)
		}
		fmt.Fprintln(w)
	}

	// Handle unknown risk (not in any of the above categories)
	unknown := filterByRisk(allCrypto, types.RiskUnknown)
	if len(unknown) > 0 {
		fmt.Fprintln(w, "[?] UNKNOWN RISK:")
		fmt.Fprintln(w, strings.Repeat("─", 90))
		for _, c := range unknown {
			fmt.Fprintf(w, "  %-4s %-14s %s\n", riskIcon(c.risk), c.algorithm, c.dependency)
		}
		fmt.Fprintln(w)
	}
}

// printSimpleRemediation prints remediation for non-reachability projects.
func (f *TableFormatter) printSimpleRemediation(w io.Writer, allCrypto []cryptoDetail, ecosystem types.Ecosystem) {
	seen := make(map[string]bool)
	var toRemediate []cryptoDetail

	// Collect all vulnerable and partial algorithms (deduplicated)
	for _, c := range allCrypto {
		if seen[c.algorithm] {
			continue
		}
		if c.risk == types.RiskVulnerable || c.risk == types.RiskPartial {
			toRemediate = append(toRemediate, c)
			seen[c.algorithm] = true
		}
	}

	if len(toRemediate) == 0 {
		return
	}

	// Sort by risk priority
	sort.Slice(toRemediate, func(i, j int) bool {
		return riskPriority(toRemediate[i].risk) > riskPriority(toRemediate[j].risk)
	})

	fmt.Fprintln(w, "REMEDIATION GUIDANCE:")
	fmt.Fprintln(w, strings.Repeat("═", 90))

	for _, c := range toRemediate {
		f.printRemediationItem(w, c, ecosystem)
	}
	fmt.Fprintln(w)
}

// printDetailedRemediation prints actionable remediation guidance.
// Shows remediation for CONFIRMED findings first, then PLANNING for available vulnerable algorithms.
func (f *TableFormatter) printDetailedRemediation(w io.Writer, allCrypto []cryptoDetail, ecosystem types.Ecosystem) {
	seen := make(map[string]bool)
	var confirmed []cryptoDetail
	var planning []cryptoDetail

	// First pass: CONFIRMED vulnerable/partial (requires action)
	for _, c := range allCrypto {
		if seen[c.algorithm] {
			continue
		}
		if c.reachability == types.ReachabilityConfirmed &&
			(c.risk == types.RiskVulnerable || c.risk == types.RiskPartial) {
			confirmed = append(confirmed, c)
			seen[c.algorithm] = true
		}
	}

	// Second pass: AVAILABLE vulnerable (for future planning)
	for _, c := range allCrypto {
		if seen[c.algorithm] {
			continue
		}
		if c.reachability == types.ReachabilityAvailable && c.risk == types.RiskVulnerable {
			planning = append(planning, c)
			seen[c.algorithm] = true
		}
	}

	// Sort both by risk
	sort.Slice(confirmed, func(i, j int) bool {
		return riskPriority(confirmed[i].risk) > riskPriority(confirmed[j].risk)
	})
	sort.Slice(planning, func(i, j int) bool {
		return riskPriority(planning[i].risk) > riskPriority(planning[j].risk)
	})

	// Print CONFIRMED remediation (requires action)
	if len(confirmed) > 0 {
		fmt.Fprintln(w, "REMEDIATION GUIDANCE:")
		fmt.Fprintln(w, strings.Repeat("═", 90))

		for _, c := range confirmed {
			f.printRemediationItem(w, c, ecosystem)
		}
		fmt.Fprintln(w)
	}

	// Print PLANNING section (available but not used - for future reference)
	if len(planning) > 0 {
		fmt.Fprintln(w, "PLANNING - Available in Dependencies (not currently used):")
		fmt.Fprintln(w, strings.Repeat("─", 90))
		fmt.Fprintln(w, "These algorithms exist in your dependencies but aren't called by your code.")
		fmt.Fprintln(w, "Review if you plan to use these features in the future.")
		fmt.Fprintln(w)

		for _, c := range planning {
			f.printRemediationItem(w, c, ecosystem)
		}
		fmt.Fprintln(w)
	}
}

// printRemediationItem prints a single remediation entry.
func (f *TableFormatter) printRemediationItem(w io.Writer, c cryptoDetail, ecosystem types.Ecosystem) {
	r := crypto.GetDetailedRemediation(c.algorithm, "", ecosystem)
	if r == nil {
		return
	}

	// Show priority marker for confirmed findings
	priorityMarker := ""
	if c.reachability == types.ReachabilityConfirmed {
		priorityMarker = " [PRIORITY]"
	}

	fmt.Fprintf(w, "\n%s %s%s\n", riskIcon(c.risk), c.algorithm, priorityMarker)
	fmt.Fprintln(w, strings.Repeat("─", 50))

	// Summary and replacement
	fmt.Fprintf(w, "  Action:       %s\n", r.Summary)
	if r.Replacement != "" && r.Replacement != "No change needed" {
		fmt.Fprintf(w, "  Replace with: %s\n", r.Replacement)
	}

	// NIST Standard
	if r.NISTStandard != "" {
		fmt.Fprintf(w, "  NIST:         %s\n", r.NISTStandard)
	}

	// Timeline and effort
	fmt.Fprintf(w, "  Timeline:     %s\n", formatTimeline(r.Timeline))
	fmt.Fprintf(w, "  Effort:       %s\n", formatEffort(r.Effort))

	// Libraries for the ecosystem
	if r.Libraries != nil {
		if libs, ok := r.Libraries[ecosystem]; ok && len(libs) > 0 {
			fmt.Fprintf(w, "  Libraries:    %s\n", strings.Join(libs, ", "))
		}
	}

	// Notes
	if r.Notes != "" {
		fmt.Fprintf(w, "  Note:         %s\n", r.Notes)
	}
}

// Helper functions

func filterByReachability(crypto []cryptoDetail, reach types.Reachability) []cryptoDetail {
	var result []cryptoDetail
	for _, c := range crypto {
		if c.reachability == reach {
			result = append(result, c)
		}
	}
	return result
}

func filterByRisk(crypto []cryptoDetail, risk types.QuantumRisk) []cryptoDetail {
	var result []cryptoDetail
	for _, c := range crypto {
		if c.risk == risk {
			result = append(result, c)
		}
	}
	return result
}

// sortByRisk orders findings highest risk first.
//
// The comparison has to be total. Ordering on risk alone left every same-risk
// finding in an arbitrary relative position, and since sort.Slice is not stable
// the same scan printed its rows in a different order between runs.
func sortByRisk(crypto []cryptoDetail) {
	sort.Slice(crypto, func(i, j int) bool {
		a, b := crypto[i], crypto[j]
		if pa, pb := riskPriority(a.risk), riskPriority(b.risk); pa != pb {
			return pa > pb
		}
		if a.algorithm != b.algorithm {
			return a.algorithm < b.algorithm
		}
		return a.dependency < b.dependency
	})
}

// riskIcon maps a risk level to the marker shown beside a finding. It is the
// single place that decision is made.
//
// These are the same ASCII tokens the section headers already use, so a reader
// never needs a legend to connect a row to its section. They also survive a pipe
// into a file, a screen reader, a terminal without an emoji font, and a
// fixed-width column, none of which was true of the coloured circles that used
// to be here. CSNP output carries no emoji.
func riskIcon(risk types.QuantumRisk) string {
	switch risk {
	case types.RiskVulnerable:
		return "[!]"
	case types.RiskPartial:
		return "[~]"
	case types.RiskSafe:
		return "[OK]"
	default:
		return "[?]"
	}
}

func riskPriority(risk types.QuantumRisk) int {
	switch risk {
	case types.RiskVulnerable:
		return 3
	case types.RiskPartial:
		return 2
	case types.RiskSafe:
		return 1
	default:
		return 0
	}
}

func formatRisk(risk types.QuantumRisk) string {
	switch risk {
	case types.RiskVulnerable:
		return "VULNERABLE"
	case types.RiskPartial:
		return "PARTIAL"
	case types.RiskSafe:
		return "SAFE"
	default:
		return "UNKNOWN"
	}
}

func getTimeline(algorithm string) string {
	r := crypto.GetDetailedRemediation(algorithm, "", types.EcosystemGo)
	if r != nil {
		return r.Timeline
	}
	return "unknown"
}

func getEffort(algorithm string) string {
	r := crypto.GetDetailedRemediation(algorithm, "", types.EcosystemGo)
	if r != nil {
		return r.Effort
	}
	return "unknown"
}

func formatTimeline(timeline string) string {
	switch timeline {
	case "immediate":
		return "Immediate"
	case "short-term":
		return "Short-term (1-2 years)"
	case "medium-term":
		return "Medium-term (2-5 years)"
	case "none":
		return "No action needed"
	default:
		return timeline
	}
}

func formatTimelineShort(timeline string) string {
	switch timeline {
	case "immediate":
		return "NOW"
	case "short-term":
		return "1-2yr"
	case "medium-term":
		return "2-5yr"
	case "none":
		return "-"
	default:
		return timeline
	}
}

func formatEffort(effort string) string {
	switch effort {
	case "low":
		return "Low (simple change)"
	case "medium":
		return "Medium (API changes)"
	case "high":
		return "High (architectural)"
	case "none":
		return "None"
	default:
		return effort
	}
}

func formatEffortShort(effort string) string {
	switch effort {
	case "low":
		return "low"
	case "medium":
		return "med"
	case "high":
		return "high"
	case "none":
		return "-"
	default:
		return effort
	}
}

func shortenFuncName(fullName string) string {
	// "github.com/foo/bar/pkg.Handler.ServeHTTP" -> "pkg.Handler.ServeHTTP"
	parts := strings.Split(fullName, "/")
	if len(parts) > 0 {
		return parts[len(parts)-1]
	}
	return fullName
}

// FormatMulti writes multi-project scan results as a table.
func (f *TableFormatter) FormatMulti(result *types.MultiProjectResult, w io.Writer) error {
	if result == nil {
		return errors.New("result cannot be nil")
	}
	if w == nil {
		return errors.New("writer cannot be nil")
	}

	// Report unread manifests first. They change how every number below should
	// be read, so they cannot go in a footer.
	PrintSkipped(w, result.Skipped)

	// If there's only one project, just format it normally
	if len(result.Projects) == 1 {
		return f.Format(result.Projects[0], w)
	}

	// Header showing discovered projects
	fmt.Fprintf(w, "\nScanning %s...\n", reportSafe(result.RootPath))
	fmt.Fprintf(w, "Found %d projects:\n", len(result.Projects))
	for _, p := range result.Projects {
		relPath := getRelativePath(result.RootPath, p.Manifest)
		fmt.Fprintf(w, "  - %s (%s)\n", reportSafe(relPath), p.Ecosystem)
	}
	fmt.Fprintln(w)

	// Format each project
	for i, project := range result.Projects {
		relPath := getRelativePath(result.RootPath, project.Manifest)
		fmt.Fprintf(w, "=== %s (%s) ===\n", reportSafe(relPath), project.Ecosystem)

		// Use the single-project formatter for each project
		if err := f.Format(project, w); err != nil {
			return err
		}

		// Add separator between projects (but not after the last one)
		if i < len(result.Projects)-1 {
			fmt.Fprintln(w)
		}
	}

	// Total summary across all projects
	fmt.Fprintln(w, strings.Repeat("═", 90))
	fmt.Fprintf(w, "TOTAL: %d projects | %d deps | %d with crypto | %d vulnerable | %d partial\n",
		len(result.Projects),
		result.TotalSummary.TotalDependencies,
		result.TotalSummary.WithCrypto,
		result.TotalSummary.QuantumVulnerable,
		result.TotalSummary.QuantumPartial,
	)
	// The aggregate is the line a reader takes away, so it carries the filter
	// annotation too. Printing it only under each project left the TOTAL row
	// describing a filtered scan as though it were complete.
	if result.TotalSummary.FilteredOut > 0 {
		fmt.Fprintf(w, "FILTERED: %d further finding(s) excluded by --risk or --min-severity.\n",
			result.TotalSummary.FilteredOut)
	}
	if result.TotalSummary.ReachabilityAnalyzed {
		fmt.Fprintf(w, "REACHABILITY: %d confirmed | %d reachable | %d available-only\n",
			result.TotalSummary.ConfirmedCrypto,
			result.TotalSummary.ReachableCrypto,
			result.TotalSummary.AvailableCrypto,
		)
	}
	fmt.Fprintln(w)

	return nil
}

// getRelativePath returns a relative path from root to target.
func getRelativePath(root, target string) string {
	// Simple approach: remove root prefix if present
	if strings.HasPrefix(target, root) {
		rel := strings.TrimPrefix(target, root)
		rel = strings.TrimPrefix(rel, "/")
		if rel == "" {
			return "."
		}
		return "./" + rel
	}
	return target
}
