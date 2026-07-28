// Copyright 2025-2026 CyberSecurity NonProfit (CSNP)
// SPDX-License-Identifier: Apache-2.0

// Package analyzer provides the core dependency analysis functionality.
package analyzer

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/csnp/qramm-cryptodeps/internal/analyzer/ondemand"
	"github.com/csnp/qramm-cryptodeps/internal/analyzer/reachability"
	"github.com/csnp/qramm-cryptodeps/internal/database"
	"github.com/csnp/qramm-cryptodeps/internal/manifest"
	"github.com/csnp/qramm-cryptodeps/pkg/types"
)

// Analyzer analyzes dependencies for cryptographic usage.
type Analyzer struct {
	db       *database.Database
	options  Options
	ondemand *ondemand.Analyzer
}

// Options configures the analyzer behavior.
type Options struct {
	Offline      bool   // Only use database, no on-demand analysis
	Deep         bool   // Force on-demand analysis for all packages
	Reachability bool   // Perform reachability analysis to determine actual crypto usage
	RiskFilter   string // Filter by risk level (vulnerable, partial, safe, unknown, all)
	MinSeverity  string // Minimum severity to report (info, low, medium, high, critical)
}

// Risk filter values accepted by --risk.
const (
	RiskFilterAll = "all"
)

// severityRank orders severities so that --min-severity can act as a threshold.
var severityRank = map[types.Severity]int{
	types.SeverityInfo:     0,
	types.SeverityLow:      1,
	types.SeverityMedium:   2,
	types.SeverityHigh:     3,
	types.SeverityCritical: 4,
}

// ValidateRiskFilter checks a --risk value. An unrecognised value used to be
// accepted and then ignored, so a typo produced a full report that the user
// believed was filtered.
func ValidateRiskFilter(s string) error {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", RiskFilterAll,
		strings.ToLower(string(types.RiskVulnerable)),
		strings.ToLower(string(types.RiskPartial)),
		strings.ToLower(string(types.RiskSafe)),
		strings.ToLower(string(types.RiskUnknown)):
		return nil
	default:
		return fmt.Errorf("invalid --risk value %q: expected one of vulnerable, partial, safe, unknown, all", s)
	}
}

// ValidateMinSeverity checks a --min-severity value.
func ValidateMinSeverity(s string) error {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	if _, ok := severityRank[types.Severity(strings.ToUpper(strings.TrimSpace(s)))]; ok {
		return nil
	}
	return fmt.Errorf("invalid --min-severity value %q: expected one of info, low, medium, high, critical", s)
}

// keepCrypto reports whether a finding survives the configured filters.
func (a *Analyzer) keepCrypto(c types.CryptoUsage) bool {
	risk := strings.ToLower(strings.TrimSpace(a.options.RiskFilter))
	if risk != "" && risk != RiskFilterAll {
		if !strings.EqualFold(string(c.QuantumRisk), risk) {
			return false
		}
	}

	min := strings.ToUpper(strings.TrimSpace(a.options.MinSeverity))
	if min != "" {
		threshold, ok := severityRank[types.Severity(min)]
		// A severity this build does not recognise is reported, not withheld.
		// Ranking an unmapped key gave 0, which is INFO, so any threshold above
		// INFO silently dropped it. Database records arrive from a remote feed
		// and are unmarshalled without normalising case, so a record carrying
		// "critical" rather than "CRITICAL" was discarded by the very filter a
		// user reaches for to see critical findings. A finding whose severity
		// cannot be ranked has not been shown to be below the threshold.
		if rank, known := severityRank[normalizeSeverity(c.Severity)]; ok && known && rank < threshold {
			return false
		}
	}

	return true
}

// normalizeSeverity puts a severity into the case severityRank is keyed by.
func normalizeSeverity(s types.Severity) types.Severity {
	return types.Severity(strings.ToUpper(strings.TrimSpace(string(s))))
}

// filtersActive reports whether any reporting filter is set.
func (a *Analyzer) filtersActive() bool {
	risk := strings.ToLower(strings.TrimSpace(a.options.RiskFilter))
	return (risk != "" && risk != RiskFilterAll) || strings.TrimSpace(a.options.MinSeverity) != ""
}

// New creates a new analyzer with the given database and options.
func New(db *database.Database, opts Options) *Analyzer {
	a := &Analyzer{
		db:      db,
		options: opts,
	}

	// Initialize on-demand analyzer if deep mode is enabled
	if opts.Deep && !opts.Offline {
		a.ondemand = ondemand.NewAnalyzer("")
	}

	return a
}

// Analyze analyzes dependencies in a manifest file.
func (a *Analyzer) Analyze(path string) (*types.ScanResult, error) {
	// Parse the manifest
	m, err := manifest.DetectAndParse(path)
	if err != nil {
		return nil, err
	}

	return a.analyzeManifest(m, path)
}

// AnalyzeAll discovers and analyzes all manifests in a directory (including workspaces).
//
// Manifests that could not be read are carried on the result rather than
// dropped, so that the report can say what was not looked at.
func (a *Analyzer) AnalyzeAll(path string) (*types.MultiProjectResult, error) {
	// Discover and parse all manifests
	manifests, skipped, err := manifest.DetectAndParseAll(path)
	if err != nil {
		return nil, err
	}

	var results []*types.ScanResult
	for _, m := range manifests {
		result, err := a.analyzeManifest(m, filepath.Dir(m.Path))
		if err != nil {
			skipped = append(skipped, types.SkippedManifest{Path: m.Path, Reason: err.Error()})
			continue
		}
		results = append(results, result)
	}

	if len(results) == 0 {
		if len(skipped) > 0 {
			return nil, fmt.Errorf("no manifests could be analyzed: %d found, all unreadable", len(skipped))
		}
		return nil, fmt.Errorf("no manifests could be analyzed")
	}

	multi := types.AggregateResults(path, results)
	multi.Skipped = skipped
	return multi, nil
}

// analyzeManifest analyzes a single parsed manifest.
func (a *Analyzer) analyzeManifest(m *manifest.Manifest, projectPath string) (*types.ScanResult, error) {
	result := &types.ScanResult{
		Project:      projectPath,
		Manifest:     m.Path,
		Ecosystem:    m.Ecosystem,
		ScanDate:     time.Now(),
		Dependencies: make([]types.DependencyResult, 0, len(m.Dependencies)),
		Summary:      types.ScanSummary{},
	}

	// Analyze each dependency
	for _, dep := range m.Dependencies {
		depResult := a.analyzeDependency(dep)

		// Apply the reporting filters before the summary is accumulated, so
		// that the counts, the table and the exit code all describe the same
		// set of findings. --risk and --min-severity were previously stored and
		// never read, so every value including a misspelt one produced the full
		// report.
		if a.filtersActive() && depResult.Analysis != nil {
			kept := make([]types.CryptoUsage, 0, len(depResult.Analysis.Crypto))
			for _, c := range depResult.Analysis.Crypto {
				if a.keepCrypto(c) {
					kept = append(kept, c)
				} else {
					result.Summary.FilteredOut++
				}
			}
			// Copy before mutating: Analysis points into the shared database,
			// so writing through it would corrupt the entry for every other
			// dependency that resolves to the same package.
			filtered := *depResult.Analysis
			filtered.Crypto = kept
			depResult.Analysis = &filtered
		}

		result.Dependencies = append(result.Dependencies, depResult)

		// Update summary
		result.Summary.TotalDependencies++
		if dep.Direct {
			result.Summary.DirectDependencies++
		}
		if depResult.Analysis != nil && len(depResult.Analysis.Crypto) > 0 {
			result.Summary.WithCrypto++
			// Check quantum risk
			for _, crypto := range depResult.Analysis.Crypto {
				switch crypto.QuantumRisk {
				case types.RiskVulnerable:
					result.Summary.QuantumVulnerable++
				case types.RiskPartial:
					result.Summary.QuantumPartial++
				}
			}
		}
		if !depResult.InDatabase {
			result.Summary.NotInDatabase++
		}
	}

	// Perform reachability analysis if enabled and ecosystem supports it
	if a.options.Reachability && m.Ecosystem == types.EcosystemGo {
		a.performReachabilityAnalysis(result, projectPath)
	}

	// Generate hints based on results
	result.Hints = a.generateHints(result)

	return result, nil
}

// performReachabilityAnalysis analyzes the user's source code to determine
// which crypto functions are actually reachable from their code.
func (a *Analyzer) performReachabilityAnalysis(result *types.ScanResult, projectPath string) {
	// Get the project directory (parent of manifest)
	projectDir := filepath.Dir(result.Manifest)
	if projectDir == "" || projectDir == "." {
		projectDir = projectPath
	}

	// Create reachability analyzer
	reachAnalyzer := reachability.NewAnalyzer(projectDir)

	// Perform analysis
	traces, err := reachAnalyzer.Analyze()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Warning: reachability analysis failed: %v\n", err)
		return
	}

	// Mark that reachability was analyzed
	result.Summary.ReachabilityAnalyzed = true

	// Classify all crypto findings by reachability
	for i := range result.Dependencies {
		dep := &result.Dependencies[i]
		if dep.Analysis == nil || len(dep.Analysis.Crypto) == 0 {
			continue
		}

		// Classify each crypto usage
		dep.Analysis.Crypto = reachability.ClassifyFindings(dep.Analysis.Crypto, traces)

		// Update summary stats
		for _, crypto := range dep.Analysis.Crypto {
			switch crypto.Reachability {
			case types.ReachabilityConfirmed:
				result.Summary.ConfirmedCrypto++
			case types.ReachabilityReachable:
				result.Summary.ReachableCrypto++
			case types.ReachabilityAvailable:
				result.Summary.AvailableCrypto++
			}
		}
	}
}

// generateHints creates actionable suggestions based on scan results.
func (a *Analyzer) generateHints(result *types.ScanResult) []string {
	hints := make([]string, 0)

	// Hint: suggest --deep when many packages not in database
	if result.Summary.NotInDatabase > 0 && !a.options.Deep {
		pct := float64(result.Summary.NotInDatabase) / float64(result.Summary.TotalDependencies) * 100
		if pct >= 50 || (result.Summary.WithCrypto == 0 && result.Summary.NotInDatabase > 5) {
			hints = append(hints, fmt.Sprintf(
				"%d packages (%.0f%%) not in database. Run with --deep for source code analysis.",
				result.Summary.NotInDatabase, pct))
		}
	}

	// Hint: no crypto found but packages exist
	if result.Summary.WithCrypto == 0 && result.Summary.TotalDependencies > 0 {
		if result.Summary.NotInDatabase == result.Summary.TotalDependencies {
			hints = append(hints, "No crypto findings. All packages are unknown - try --deep to analyze source code.")
		}
	}

	return hints
}

// analyzeDependency analyzes a single dependency.
func (a *Analyzer) analyzeDependency(dep types.Dependency) types.DependencyResult {
	result := types.DependencyResult{
		Dependency: dep,
		InDatabase: false,
	}

	// Look up in database
	analysis, found := a.db.Lookup(dep.Ecosystem, dep.Name, dep.Version)
	if found {
		result.Analysis = analysis
		result.InDatabase = true
		return result
	}

	// If offline mode or not deep, just return without analysis
	if a.options.Offline || !a.options.Deep {
		return result
	}

	// On-demand analysis
	if a.ondemand != nil {
		analysis, err := a.ondemand.Analyze(dep)
		if err != nil {
			// Log the error but continue
			fmt.Fprintf(os.Stderr, "Warning: on-demand analysis failed for %s: %v\n", dep.Name, err)
			return result
		}
		result.Analysis = analysis
		result.DeepAnalyzed = true
	}

	return result
}
