// Copyright 2024-2025 CSNP (csnp.org)
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
	fmt.Fprintf(w, "\n[*] Scanning %s... found %d dependencies\n\n", result.Manifest, result.Summary.TotalDependencies)

	// Check if there are any crypto findings
	hasCrypto := false
	for _, dep := range result.Dependencies {
		if dep.Analysis != nil && len(dep.Analysis.Crypto) > 0 {
			hasCrypto = true
			break
		}
	}

	if !hasCrypto {
		fmt.Fprintln(w, "[OK] No cryptographic usage detected in dependencies.")
		fmt.Fprintln(w)
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
		fmt.Fprintf(w, "SUMMARY: %d deps | %d with crypto | %d vulnerable | %d partial\n\n",
			result.Summary.TotalDependencies,
			result.Summary.WithCrypto,
			result.Summary.QuantumVulnerable,
			result.Summary.QuantumPartial,
		)
	}

	// Display detailed remediation for confirmed/vulnerable findings
	if f.Options.ShowRemediation {
		f.printDetailedRemediation(w, allCrypto, result.Ecosystem)
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

	if deepAnalyzed > 0 || notAnalyzed > 0 {
		fmt.Fprintln(w)
	}

	return nil
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
			fmt.Fprintf(w, "  %s %-14s %-12s  %-12s  %s\n",
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
			fmt.Fprintf(w, "  %s %-14s %-12s  %s\n", icon, c.algorithm, formatRisk(c.risk), c.dependency)
		}
		fmt.Fprintln(w)
	}

	// Print AVAILABLE section (lower priority) - condensed
	if len(available) > 0 {
		fmt.Fprintln(w, "[.] AVAILABLE - In dependencies but not called (lower priority):")
		fmt.Fprintln(w, strings.Repeat("─", 90))

		// Group available by dependency for cleaner output
		byDep := make(map[string][]cryptoDetail)
		for _, c := range available {
			byDep[c.dependency] = append(byDep[c.dependency], c)
		}

		for dep, algos := range byDep {
			var algoStrs []string
			for _, a := range algos {
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

	fmt.Fprintln(w, "CRYPTO ALGORITHMS FOUND:")
	fmt.Fprintln(w, strings.Repeat("─", 90))
	fmt.Fprintf(w, "  %-14s %-12s %-12s %s\n", "ALGORITHM", "RISK", "TIMELINE", "DEPENDENCY")
	for _, c := range allCrypto {
		icon := riskIcon(c.risk)
		timeline := getTimeline(c.algorithm)
		fmt.Fprintf(w, "  %s %-12s %-12s %-12s %s\n", icon, c.algorithm, formatRisk(c.risk), timeline, c.dependency)
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

func sortByRisk(crypto []cryptoDetail) {
	sort.Slice(crypto, func(i, j int) bool {
		return riskPriority(crypto[i].risk) > riskPriority(crypto[j].risk)
	})
}

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

	// If there's only one project, just format it normally
	if len(result.Projects) == 1 {
		return f.Format(result.Projects[0], w)
	}

	// Header showing discovered projects
	fmt.Fprintf(w, "\nScanning %s...\n", result.RootPath)
	fmt.Fprintf(w, "Found %d projects:\n", len(result.Projects))
	for _, p := range result.Projects {
		relPath := getRelativePath(result.RootPath, p.Manifest)
		fmt.Fprintf(w, "  - %s (%s)\n", relPath, p.Ecosystem)
	}
	fmt.Fprintln(w)

	// Format each project
	for i, project := range result.Projects {
		relPath := getRelativePath(result.RootPath, project.Manifest)
		fmt.Fprintf(w, "=== %s (%s) ===\n", relPath, project.Ecosystem)

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
