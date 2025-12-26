// Copyright 2024 CSNP (csnp.org)
// SPDX-License-Identifier: Apache-2.0

package output

import (
	"fmt"
	"io"
	"strings"

	"github.com/csnp/qramm-cryptodeps/pkg/types"
)

// TableFormatter formats scan results as a human-readable table.
type TableFormatter struct{}

// Format writes the scan result as a table.
func (f *TableFormatter) Format(result *types.ScanResult, w io.Writer) error {
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

	// Warning for packages not in database
	if result.Summary.NotInDatabase > 0 {
		fmt.Fprintf(w, "⚠ %d packages not in database (use --deep to analyze)\n\n", result.Summary.NotInDatabase)
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
