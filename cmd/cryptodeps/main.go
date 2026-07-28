// Copyright 2025-2026 CyberSecurity NonProfit (CSNP)
// SPDX-License-Identifier: Apache-2.0

// CryptoDeps analyzes software dependencies for cryptographic usage and quantum vulnerability.
package main

import (
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"github.com/csnp/qramm-cryptodeps/internal/analyzer"
	"github.com/csnp/qramm-cryptodeps/internal/database"
	"github.com/csnp/qramm-cryptodeps/pkg/output"
	"github.com/csnp/qramm-cryptodeps/pkg/types"
	buildinfo "github.com/csnp/qramm-cryptodeps/pkg/version"
)

// Exit codes for CI/CD integration
const (
	ExitSuccess    = 0 // No issues found
	ExitVulnerable = 1 // Quantum-vulnerable findings detected
	ExitError      = 2 // Analysis error occurred
	ExitPartial    = 3 // Partial-risk findings detected (when --fail-on=partial)
)

// Build identity. GoReleaser injects these via -X main.version and friends, so
// they have to live here under these exact names. They are handed straight to
// pkg/version, which is what the rest of the tool reads. Keep them var, not
// const: -X is silently ignored on a const and the build still succeeds.
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

func init() {
	buildinfo.Set(version, commit, date)
}

// CLI flags
var (
	formatFlag       string
	offlineFlag      bool
	deepFlag         bool
	reachabilityFlag bool
	noWorkspacesFlag bool
	riskFilter       string
	minSeverity      string
	updateURL        string
	verboseFlag      bool
	failOn           string // CI/CD: fail on vulnerable, partial, or any
	exitCode         int    // Tracks exit code for CI/CD
)

func main() {
	// Cobra has already written the error to stderr, and for a flag mistake it
	// writes the message before the usage block, which is the order a reader
	// needs. Printing it again here would duplicate every message.
	if err := rootCmd.Execute(); err != nil {
		os.Exit(ExitError)
	}
	// Exit with appropriate code for CI/CD
	os.Exit(exitCode)
}

var rootCmd = &cobra.Command{
	Use:   "cryptodeps",
	Short: "Analyze dependencies for cryptographic usage and quantum vulnerability",
	Long: `CryptoDeps scans your project dependencies to identify cryptographic algorithms
and assess their quantum computing vulnerability.

It provides:
  - Full dependency tree analysis
  - Crypto algorithm detection with call graphs
  - Quantum risk classification (VULNERABLE, PARTIAL, SAFE)
  - Multiple output formats (table, JSON, CBOM, SARIF)

Examples:
  cryptodeps analyze .
  cryptodeps analyze ./go.mod --format json
  cryptodeps update`,
}

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print version information",
	Run: func(cmd *cobra.Command, args []string) {
		// Read through pkg/version rather than the locals, so that this command
		// and every machine-readable emitter provably agree.
		fmt.Printf("%s %s\n", buildinfo.Name, buildinfo.Version())
		fmt.Printf("  commit: %s\n", buildinfo.Commit())
		fmt.Printf("  built:  %s\n", buildinfo.Date())
	},
}

var analyzeCmd = &cobra.Command{
	Use:   "analyze [path|url]",
	Short: "Analyze dependencies for cryptographic usage",
	Long: `Analyze a project's dependencies to identify cryptographic algorithms
and assess their quantum computing vulnerability.

The path can be:
  - A directory containing a manifest file (go.mod, package.json, etc.)
  - A specific manifest file
  - "." for the current directory
  - A GitHub URL (https://github.com/owner/repo)
  - A GitHub shorthand (owner/repo)

Exit codes (for CI/CD):
  0 - No quantum-vulnerable findings
  1 - Quantum-vulnerable findings detected
  2 - Analysis error, including any manifest that was found but could not be read
  3 - Partial-risk findings detected (with --fail-on=partial)

--risk and --min-severity filter the report. The summary and the exit code are
computed from what the filters leave, so that every number in the output
describes the same set of findings.

Examples:
  cryptodeps analyze .
  cryptodeps analyze ./go.mod
  cryptodeps analyze /path/to/project --format json
  cryptodeps analyze https://github.com/golang-jwt/jwt
  cryptodeps analyze golang-jwt/jwt
  cryptodeps analyze . --fail-on vulnerable --format sarif`,
	Args: cobra.MaximumNArgs(1),
	RunE: runAnalyze,
}

var updateCmd = &cobra.Command{
	Use:   "update",
	Short: "Update the crypto knowledge database",
	Long: `Download the latest crypto knowledge database from CSNP.

This fetches the newest package data, algorithm classifications, and
remediation guidance from GitHub releases.

The database is cached locally at ~/.cryptodeps/crypto-database.json`,
	RunE: runUpdate,
}

var statusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show database status",
	Long:  `Display information about the crypto knowledge database.`,
	RunE:  runStatus,
}

func init() {
	// Analyze command flags
	analyzeCmd.Flags().StringVarP(&formatFlag, "format", "f", "table", "Output format (table, json, cbom, sarif, markdown)")
	analyzeCmd.Flags().BoolVar(&offlineFlag, "offline", false, "Only use local database, no downloads")
	analyzeCmd.Flags().BoolVar(&deepFlag, "deep", false, "Force on-demand analysis for unknown packages")
	analyzeCmd.Flags().BoolVar(&reachabilityFlag, "reachability", true, "Analyze call graph to find actually-used crypto (Go only, use --reachability=false to disable)")
	analyzeCmd.Flags().BoolVar(&noWorkspacesFlag, "no-workspaces", false, "Disable workspace/monorepo discovery (scan single manifest only)")
	analyzeCmd.Flags().StringVar(&riskFilter, "risk", "", "Report only this risk level (vulnerable, partial, safe, unknown, all)")
	analyzeCmd.Flags().StringVar(&minSeverity, "min-severity", "", "Report only findings at or above this severity (info, low, medium, high, critical)")
	analyzeCmd.Flags().StringVar(&failOn, "fail-on", "vulnerable", "Exit non-zero when risk found (vulnerable, partial, any, none)")

	// Update command flags
	updateCmd.Flags().StringVar(&updateURL, "url", "", "Custom database URL (default: CSNP GitHub)")
	updateCmd.Flags().BoolVarP(&verboseFlag, "verbose", "v", false, "Verbose output")

	// Add commands
	rootCmd.AddCommand(versionCmd)
	rootCmd.AddCommand(analyzeCmd)
	rootCmd.AddCommand(updateCmd)
	rootCmd.AddCommand(statusCmd)
}

func runAnalyze(cmd *cobra.Command, args []string) error {
	// From here on, a failure is a runtime failure rather than a usage mistake,
	// so do not follow it with the whole flag list. Setting this inside RunE
	// rather than on the command keeps usage where it helps: an unknown flag is
	// rejected during parsing, before this line runs.
	cmd.SilenceUsage = true

	// Default to current directory
	path := "."
	if len(args) > 0 {
		path = args[0]
	}

	// Check if path is a GitHub URL
	var tempDir string
	if analyzer.IsGitHubURL(path) {
		repo, err := analyzer.ParseGitHubURL(path)
		if err != nil {
			return err
		}

		fmt.Fprintf(os.Stderr, "Fetching %s/%s from GitHub...\n", repo.Owner, repo.Repo)
		tempDir, err = analyzer.FetchGitHubManifests(repo)
		if err != nil {
			return fmt.Errorf("failed to fetch from GitHub: %w", err)
		}
		defer analyzer.CleanupTempDir(tempDir)
		path = tempDir
	}

	// Reject unknown filter values before doing any work. Silently ignoring
	// them produced an unfiltered report that the user believed was filtered.
	if err := analyzer.ValidateRiskFilter(riskFilter); err != nil {
		return err
	}
	if err := analyzer.ValidateMinSeverity(minSeverity); err != nil {
		return err
	}

	// Parse output format
	format, err := output.ParseFormat(formatFlag)
	if err != nil {
		return err
	}

	// Initialize database with embedded + cached data
	// Auto-update if not in offline mode (silently fetches if cache > 7 days old)
	db := database.NewWithAutoUpdate(!offlineFlag)

	// Create analyzer
	a := analyzer.New(db, analyzer.Options{
		Offline:      offlineFlag,
		Deep:         deepFlag,
		Reachability: reachabilityFlag,
		RiskFilter:   riskFilter,
		MinSeverity:  minSeverity,
	})

	// Get formatter
	formatter, err := output.GetFormatter(format)
	if err != nil {
		return err
	}

	// Run analysis - use workspace discovery by default
	if noWorkspacesFlag {
		// Single manifest analysis (legacy behavior)
		result, err := a.Analyze(path)
		if err != nil {
			return fmt.Errorf("analysis failed: %w", err)
		}

		if err := formatter.Format(result, os.Stdout); err != nil {
			return err
		}

		exitCode = determineExitCode(result, failOn)
	} else {
		// Multi-project workspace discovery (default)
		multiResult, err := a.AnalyzeAll(path)
		if err != nil {
			return fmt.Errorf("analysis failed: %w", err)
		}

		if err := formatter.FormatMulti(multiResult, os.Stdout); err != nil {
			return err
		}

		exitCode = determineExitCodeMulti(multiResult, failOn)

		// An unread manifest means the scan is incomplete, whatever the
		// findings say. That is an analysis error, so it takes precedence over
		// the finding-based codes and over --fail-on none: a build must not go
		// green on a report that silently omits a dependency file.
		//
		// A manifest for an ecosystem cryptodeps has no parser for is reported
		// but does not count. It is not a failure to read something; it is a
		// declared limit of the tool, and treating it as an error made every
		// repository holding a Cargo.toml or a build.gradle exit 2.
		if types.IncompleteScan(multiResult.Skipped) {
			exitCode = ExitError
		}
	}

	return nil
}

// determineExitCode calculates the appropriate exit code based on scan results
// and the --fail-on threshold. This enables CI/CD pipelines to fail builds
// when quantum-vulnerable crypto is detected.
func determineExitCode(result *types.ScanResult, threshold string) int {
	threshold = strings.ToLower(threshold)

	switch threshold {
	case "none":
		// Never fail based on findings
		return ExitSuccess

	case "any":
		// Fail if any crypto usage is detected
		if result.Summary.WithCrypto > 0 {
			if result.Summary.QuantumVulnerable > 0 {
				return ExitVulnerable
			}
			if result.Summary.QuantumPartial > 0 {
				return ExitPartial
			}
			// Has crypto but all safe - still exit non-zero for "any" mode
			return ExitPartial
		}
		return ExitSuccess

	case "partial":
		// Fail on partial or vulnerable
		if result.Summary.QuantumVulnerable > 0 {
			return ExitVulnerable
		}
		if result.Summary.QuantumPartial > 0 {
			return ExitPartial
		}
		return ExitSuccess

	case "vulnerable":
		fallthrough
	default:
		// Fail only on vulnerable (default)
		if result.Summary.QuantumVulnerable > 0 {
			return ExitVulnerable
		}
		return ExitSuccess
	}
}

// determineExitCodeMulti calculates exit code for multi-project results.
func determineExitCodeMulti(result *types.MultiProjectResult, threshold string) int {
	threshold = strings.ToLower(threshold)

	switch threshold {
	case "none":
		return ExitSuccess

	case "any":
		if result.TotalSummary.WithCrypto > 0 {
			if result.TotalSummary.QuantumVulnerable > 0 {
				return ExitVulnerable
			}
			if result.TotalSummary.QuantumPartial > 0 {
				return ExitPartial
			}
			return ExitPartial
		}
		return ExitSuccess

	case "partial":
		if result.TotalSummary.QuantumVulnerable > 0 {
			return ExitVulnerable
		}
		if result.TotalSummary.QuantumPartial > 0 {
			return ExitPartial
		}
		return ExitSuccess

	case "vulnerable":
		fallthrough
	default:
		if result.TotalSummary.QuantumVulnerable > 0 {
			return ExitVulnerable
		}
		return ExitSuccess
	}
}

func runStatus(cmd *cobra.Command, args []string) error {
	db := database.NewWithCachedData()
	stats := db.Stats()

	fmt.Println("CryptoDeps Database")
	fmt.Println("===================")
	fmt.Printf("Total packages: %d\n", stats.TotalPackages)
	fmt.Println()
	fmt.Println("By ecosystem:")
	// Sorted. Ranging over the map printed the ecosystems in a different order
	// on almost every run, which is the same nondeterminism the five output
	// formats were fixed for: it defeats diffing two runs and any golden file.
	ecosystems := make([]string, 0, len(stats.ByEcosystem))
	for ecosystem := range stats.ByEcosystem {
		ecosystems = append(ecosystems, string(ecosystem))
	}
	sort.Strings(ecosystems)
	for _, ecosystem := range ecosystems {
		fmt.Printf("  %-8s %d packages\n", ecosystem+":", stats.ByEcosystem[types.Ecosystem(ecosystem)])
	}
	fmt.Println()

	// Check for cached database
	updater := database.NewUpdater(nil)
	cacheInfo, err := updater.GetCacheInfo()
	if err == nil && cacheInfo != nil {
		fmt.Println("Local cache:")
		fmt.Printf("  Version:  %s\n", cacheInfo.Version)
		fmt.Printf("  Updated:  %s\n", cacheInfo.ModifiedAt.Format("2006-01-02 15:04:05"))
		fmt.Printf("  Path:     %s\n", cacheInfo.Path)
	} else {
		fmt.Println("Local cache: not downloaded")
		fmt.Println("  Run 'cryptodeps update' to download the latest database")
	}

	return nil
}

func runUpdate(cmd *cobra.Command, args []string) error {
	fmt.Println("Updating database...")

	// Configure updater
	config := database.DefaultUpdateConfig()
	if updateURL != "" {
		config.URL = updateURL
	}
	config.Verbose = verboseFlag

	// Create updater and run update
	updater := database.NewUpdater(config)
	result, err := updater.Update()
	if err != nil {
		return fmt.Errorf("update failed: %w", err)
	}

	fmt.Printf("Done! %d packages downloaded.\n", result.TotalPackages)

	return nil
}
