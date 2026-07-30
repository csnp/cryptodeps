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

// ValidateFailOn checks a --fail-on value.
//
// This is the one enum flag of the three that did not validate, and it is the
// one that decides an exit code. An unrecognised value fell through to the
// default policy, so `--fail-on partail` turned a build that the operator had
// asked to fail on partial risk into a build that passed, with nothing on
// either stream: exit 3 became exit 0 on the same project. A CI gate that
// silently loosens on a typo is worse than one that refuses to run.
func ValidateFailOn(s string) error {
	// An empty value is refused for the same reason a padded one is honoured:
	// whatever this accepts, the exit code must act on. "" matched no policy and
	// fell through to the vulnerable-only default, so a project with partial-risk
	// findings exited 3 for "partial" and 0 for "", silently, and an unset
	// workflow input is precisely how a CI gate arrives here empty. Unlike --risk
	// and --min-severity, where empty means "do not filter" and is a real state,
	// this flag already has a default and cannot express one by being blank.
	switch CanonicalFailOn(s) {
	case "none", "any", "partial", "vulnerable":
		return nil
	default:
		return fmt.Errorf("invalid --fail-on value %q: expected one of vulnerable, partial, any, none", s)
	}
}

// CanonicalFailOn is the one reading of a --fail-on value.
//
// It exists because there were two. The validator trimmed and lowercased before
// deciding, and the code that turns the value into an exit code only lowercased,
// so " partial " was accepted as valid and then matched no policy: the gate
// reverted to vulnerable-only and a project with partial-risk findings exited 0
// where "partial" exited 3, on either stream in silence. Whitespace around a
// value is the ordinary result of a YAML block scalar or an expression in a
// workflow file, which is exactly where this flag is used.
//
// Every reader of the flag must go through this, so that accepting a value and
// acting on it cannot disagree.
func CanonicalFailOn(s string) string {
	return strings.ToLower(strings.TrimSpace(s))
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
					// Remember what was withheld, by the risk the gate asks about,
					// so that hiding a finding from the report cannot also hide it
					// from --fail-on. These counters are not serialized.
					switch c.QuantumRisk {
					case types.RiskVulnerable:
						result.Summary.WithheldVulnerable++
					case types.RiskPartial:
						result.Summary.WithheldPartial++
					}
				}
			}
			if len(kept) == 0 && len(depResult.Analysis.Crypto) > 0 {
				// The dependency HAS cryptography; the filter removed all of it.
				// Without this, --fail-on any reports a project with crypto as
				// having none, because WithCrypto is counted from survivors.
				result.Summary.WithheldWithCrypto++
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
		// Counted here, where the means of examination are known, rather than
		// re-derived from NotInDatabase by each report that needs it.
		if !depResult.Examined() {
			result.Summary.NotExamined++
		}
		// The same, for the dependencies that were examined incompletely. These
		// are absent from NotExamined by definition, which is why a partial
		// reading was reported as a complete one.
		if depResult.Analysis != nil {
			result.Summary.SourceFilesUnreadable += depResult.Analysis.Analysis.FilesUnreadable
		}
	}

	// Whether source analysis ran at all, which is a property of the scan and
	// not of any one dependency. a.ondemand is the thing that governs it:
	// --deep with --offline sets the option without giving the analyzer any way
	// to fetch, so the option alone would overstate what was attempted.
	result.Summary.DeepAttempted = a.ondemand != nil

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

	// Hint: no crypto found but packages exist.
	//
	// Guarded on source analysis not having run, which the hint above it was
	// already guarded on and this one was not. Without the guard a --deep scan
	// that read every package and found no cryptography ended with advice to
	// run --deep.
	if result.Summary.WithCrypto == 0 && result.Summary.TotalDependencies > 0 && !result.Summary.DeepAttempted {
		if result.Summary.NotExamined == result.Summary.TotalDependencies {
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
			result.Error = fmt.Sprintf("source analysis could not fetch %s: %v", dep.Name, err)
			return result
		}
		// Examination is claimed from what an analyzer parsed, not from a call
		// that returned no error. The two differ whenever an archive arrives
		// carrying nothing this tool can read: a Maven artifact with no sources
		// JAR falls back to the compiled main JAR, the Java walker accepts only
		// .java, .kt and .kts, and it then returns no usages and no error. That
		// was reported as "no cryptographic usage detected in the 1 of 1
		// dependencies that were examined" for a scan that read zero files, so
		// the absence of an error was standing in for evidence and saying the
		// opposite of the truth.
		if !analysis.SourceWasRead() {
			fmt.Fprintf(os.Stderr,
				"Warning: source analysis of %s read no files it can parse, so it is "+
					"reported as not examined rather than as clean\n", dep.Name)
			result.Error = fmt.Sprintf(
				"source analysis read no files it can parse in the fetched archive for %s", dep.Name)
			return result
		}
		// Partly read is not read. A package can hold a file this analyzer
		// parsed and another it refused, and the refusal left no trace outside
		// the walk that recorded it: the count stopped at the AST layer, so a
		// dependency whose only cryptography sat in the refused file was
		// reported as examined and clean on every stream and in every format.
		// The exception belongs beside the claim, not inside the walk.
		if analysis.Analysis.FilesUnreadable > 0 {
			fmt.Fprintf(os.Stderr,
				"Warning: source analysis of %s read %d file(s) and could not read %d more, so its "+
					"cryptography may be under-reported\n",
				dep.Name, analysis.Analysis.FilesAnalyzed, analysis.Analysis.FilesUnreadable)
			// Named, not just counted. A reader told that one file went unread and
			// not which one has been handed a dead end, and the reason differs in
			// what they should do about it.
			for _, reason := range analysis.Analysis.UnreadableFiles {
				fmt.Fprintf(os.Stderr, "  not read: %s\n", reason)
			}
			if n := analysis.Analysis.FilesUnreadable - len(analysis.Analysis.UnreadableFiles); n > 0 {
				fmt.Fprintf(os.Stderr, "  and %d more not named here\n", n)
			}
		}
		result.Analysis = analysis
		result.DeepAnalyzed = true
	}

	return result
}
