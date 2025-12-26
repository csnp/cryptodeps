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
	fmt.Fprintf(w, "\n🔍 Scanning %s... found %d dependencies\n\n", result.Manifest, result.Summary.TotalDependencies)

	// Check if there are any crypto findings
	hasCrypto := false
	for _, dep := range result.Dependencies {
		if dep.Analysis != nil && len(dep.Analysis.Crypto) > 0 {
			hasCrypto = true
			break
		}
	}

	if !hasCrypto {
		fmt.Fprintln(w, "✅ No cryptographic usage detected in dependencies.")
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
		fmt.Fprintf(w, "📊 SUMMARY: %d deps | %d with crypto | %d vulnerable | %d partial\n",
			result.Summary.TotalDependencies,
			result.Summary.WithCrypto,
			result.Summary.QuantumVulnerable,
			result.Summary.QuantumPartial,
		)
		fmt.Fprintf(w, "🎯 REACHABILITY: %d confirmed | %d reachable | %d available-only\n\n",
			result.Summary.ConfirmedCrypto,
			result.Summary.ReachableCrypto,
			result.Summary.AvailableCrypto,
		)
	} else {
		fmt.Fprintf(w, "📊 SUMMARY: %d deps | %d with crypto | %d vulnerable | %d partial\n\n",
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
		fmt.Fprintf(w, "✓ %d packages analyzed via AST (--deep)\n", deepAnalyzed)
	}

	// Warning for packages not analyzed
	if notAnalyzed > 0 {
		fmt.Fprintf(w, "⚠ %d packages not in database (use --deep to analyze)\n", notAnalyzed)
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
		fmt.Fprintln(w, "🚨 CONFIRMED - Actually used by your code (requires action):")
		fmt.Fprintln(w, strings.Repeat("─", 90))
		for _, c := range confirmed {
			icon := riskIcon(c.risk)
			timeline := getTimeline(c.algorithm)
			effort := getEffort(c.algorithm)
			fmt.Fprintf(w, "  %s %-14s %-12s  ⏱ %-12s  💪 %s\n",
				icon, c.algorithm, formatRisk(c.risk), timeline, effort)
			fmt.Fprintf(w, "     └─ %s\n", c.dependency)

			// Show call traces (where in user code)
			if len(c.traces) > 0 {
				for _, trace := range c.traces {
					if len(trace.Path) > 0 {
						// Show entry point (user's function)
						entryFunc := shortenFuncName(trace.EntryPoint)
						fmt.Fprintf(w, "        📍 Called from: %s\n", entryFunc)
					}
				}
			}
		}
		fmt.Fprintln(w)
	}

	// Print REACHABLE section
	if len(reachable) > 0 {
		fmt.Fprintln(w, "⚡ REACHABLE - In call graph from your code:")
		fmt.Fprintln(w, strings.Repeat("─", 90))
		for _, c := range reachable {
			icon := riskIcon(c.risk)
			fmt.Fprintf(w, "  %s %-14s %-12s  %s\n", icon, c.algorithm, formatRisk(c.risk), c.dependency)
		}
		fmt.Fprintln(w)
	}

	// Print AVAILABLE section (lower priority) - condensed
	if len(available) > 0 {
		fmt.Fprintln(w, "📦 AVAILABLE - In dependencies but not called (lower priority):")
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

	fmt.Fprintln(w, "🔐 CRYPTO ALGORITHMS FOUND:")
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
func (f *TableFormatter) printDetailedRemediation(w io.Writer, allCrypto []cryptoDetail, ecosystem types.Ecosystem) {
	// Only show remediation for vulnerable/partial algorithms, prioritizing confirmed
	seen := make(map[string]bool)
	var toShow []cryptoDetail

	// First pass: confirmed vulnerable/partial
	for _, c := range allCrypto {
		if seen[c.algorithm] {
			continue
		}
		if c.reachability == types.ReachabilityConfirmed &&
			(c.risk == types.RiskVulnerable || c.risk == types.RiskPartial) {
			toShow = append(toShow, c)
			seen[c.algorithm] = true
		}
	}

	// Second pass: other vulnerable (not confirmed but still important)
	for _, c := range allCrypto {
		if seen[c.algorithm] {
			continue
		}
		if c.risk == types.RiskVulnerable {
			toShow = append(toShow, c)
			seen[c.algorithm] = true
		}
	}

	if len(toShow) == 0 {
		return
	}

	// Sort: confirmed first, then by risk
	sort.Slice(toShow, func(i, j int) bool {
		if toShow[i].reachability == types.ReachabilityConfirmed && toShow[j].reachability != types.ReachabilityConfirmed {
			return true
		}
		if toShow[i].reachability != types.ReachabilityConfirmed && toShow[j].reachability == types.ReachabilityConfirmed {
			return false
		}
		return riskPriority(toShow[i].risk) > riskPriority(toShow[j].risk)
	})

	fmt.Fprintln(w, "🛠️  REMEDIATION GUIDANCE:")
	fmt.Fprintln(w, strings.Repeat("═", 90))

	for _, c := range toShow {
		r := crypto.GetDetailedRemediation(c.algorithm, "", ecosystem)
		if r == nil {
			continue
		}

		priorityTag := ""
		if c.reachability == types.ReachabilityConfirmed {
			priorityTag = " 🎯 PRIORITY"
		}

		fmt.Fprintf(w, "\n%s %s%s\n", riskIcon(c.risk), c.algorithm, priorityTag)
		fmt.Fprintln(w, strings.Repeat("─", 50))

		// Summary and replacement
		fmt.Fprintf(w, "  📋 Action:      %s\n", r.Summary)
		if r.Replacement != "" && r.Replacement != "No change needed" {
			fmt.Fprintf(w, "  🔄 Replace with: %s\n", r.Replacement)
		}

		// NIST Standard
		if r.NISTStandard != "" {
			fmt.Fprintf(w, "  📜 NIST:         %s\n", r.NISTStandard)
		}

		// Timeline and effort
		fmt.Fprintf(w, "  ⏱️  Timeline:     %s\n", formatTimeline(r.Timeline))
		fmt.Fprintf(w, "  💪 Effort:       %s\n", formatEffort(r.Effort))

		// Libraries for the ecosystem
		if r.Libraries != nil {
			if libs, ok := r.Libraries[ecosystem]; ok && len(libs) > 0 {
				fmt.Fprintf(w, "  📦 Libraries:    %s\n", strings.Join(libs, ", "))
			}
		}

		// Notes
		if r.Notes != "" {
			fmt.Fprintf(w, "  💡 Note:         %s\n", r.Notes)
		}
	}

	fmt.Fprintln(w)
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
		return "🔴"
	case types.RiskPartial:
		return "🟡"
	case types.RiskSafe:
		return "🟢"
	default:
		return "⚪"
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
		return "🔴 Immediate"
	case "short-term":
		return "🟠 Short-term (1-2 years)"
	case "medium-term":
		return "🟡 Medium-term (2-5 years)"
	case "none":
		return "🟢 No action needed"
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

func shortenFuncName(fullName string) string {
	// "github.com/foo/bar/pkg.Handler.ServeHTTP" -> "pkg.Handler.ServeHTTP"
	parts := strings.Split(fullName, "/")
	if len(parts) > 0 {
		return parts[len(parts)-1]
	}
	return fullName
}
