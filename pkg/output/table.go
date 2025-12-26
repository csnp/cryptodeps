// Copyright 2024-2025 CSNP (csnp.org)
// SPDX-License-Identifier: Apache-2.0

package output

import (
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/csnp/qramm-cryptodeps/pkg/types"
)

// TableFormatter formats scan results as a human-readable table.
type TableFormatter struct {
	Options FormatterOptions
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
	fmt.Fprintf(w, "\nScanning %s... found %d dependencies\n\n", result.Manifest, result.Summary.TotalDependencies)

	// Check if there are any crypto findings
	hasCrypto := false
	for _, dep := range result.Dependencies {
		if dep.Analysis != nil && len(dep.Analysis.Crypto) > 0 {
			hasCrypto = true
			break
		}
	}

	if !hasCrypto {
		fmt.Fprintln(w, "No cryptographic usage detected in dependencies.")
		fmt.Fprintln(w)
		return nil
	}

	// Table header
	fmt.Fprintf(w, "%-45s %-20s %-12s\n", "DEPENDENCY", "CRYPTO", "RISK")
	fmt.Fprintln(w, strings.Repeat("─", 80))

	// Collect remediation for later display
	type remediationItem struct {
		algorithm   string
		risk        types.QuantumRisk
		remediation string
	}
	remediations := make([]remediationItem, 0)

	// Table rows
	for _, dep := range result.Dependencies {
		if dep.Analysis == nil || len(dep.Analysis.Crypto) == 0 {
			continue
		}

		// Format dependency name with version
		depName := dep.Dependency.Name
		if dep.Dependency.Version != "" {
			depName = fmt.Sprintf("%s %s", dep.Dependency.Name, dep.Dependency.Version)
		}
		// Add indicator for deep-analyzed packages
		if dep.DeepAnalyzed {
			depName = depName + " *"
		}

		// Truncate if too long
		if len(depName) > 44 {
			depName = depName[:41] + "..."
		}

		// Group crypto by algorithm
		algorithms := make([]string, 0)
		highestRisk := types.RiskUnknown
		for _, crypto := range dep.Analysis.Crypto {
			algorithms = append(algorithms, crypto.Algorithm)
			if riskPriority(crypto.QuantumRisk) > riskPriority(highestRisk) {
				highestRisk = crypto.QuantumRisk
			}
			// Collect remediation for vulnerable/partial algorithms
			if f.Options.ShowRemediation && crypto.Remediation != "" &&
				(crypto.QuantumRisk == types.RiskVulnerable || crypto.QuantumRisk == types.RiskPartial) {
				remediations = append(remediations, remediationItem{
					algorithm:   crypto.Algorithm,
					risk:        crypto.QuantumRisk,
					remediation: crypto.Remediation,
				})
			}
		}

		// Format algorithms (truncate if needed)
		algStr := strings.Join(algorithms, ", ")
		if len(algStr) > 19 {
			algStr = algStr[:16] + "..."
		}

		// Format risk with color indicator
		riskStr := formatRisk(highestRisk)

		fmt.Fprintf(w, "%-45s %-20s %-12s\n", depName, algStr, riskStr)
	}

	fmt.Fprintln(w, strings.Repeat("─", 80))

	// Summary
	fmt.Fprintf(w, "SUMMARY: %d deps | %d use crypto | %d vulnerable | %d partial\n\n",
		result.Summary.TotalDependencies,
		result.Summary.WithCrypto,
		result.Summary.QuantumVulnerable,
		result.Summary.QuantumPartial,
	)

	// Display remediation guidance
	if f.Options.ShowRemediation && len(remediations) > 0 {
		// Deduplicate by algorithm
		seen := make(map[string]bool)
		fmt.Fprintln(w, "REMEDIATION GUIDANCE:")
		fmt.Fprintln(w, strings.Repeat("─", 80))
		for _, r := range remediations {
			if seen[r.algorithm] {
				continue
			}
			seen[r.algorithm] = true
			riskIcon := "!"
			if r.risk == types.RiskVulnerable {
				riskIcon = "!!"
			}
			fmt.Fprintf(w, "  [%s] %-12s → %s\n", riskIcon, r.algorithm, r.remediation)
		}
		fmt.Fprintln(w)
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

// riskPriority returns a numeric priority for sorting risks.
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

// formatRisk formats a quantum risk level for display.
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
