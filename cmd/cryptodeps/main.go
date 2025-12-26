// Copyright 2024-2025 CSNP (csnp.org)
// SPDX-License-Identifier: Apache-2.0

// CryptoDeps analyzes software dependencies for cryptographic usage and quantum vulnerability.
package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/csnp/qramm-cryptodeps/internal/analyzer"
	"github.com/csnp/qramm-cryptodeps/internal/database"
	"github.com/csnp/qramm-cryptodeps/pkg/output"
	"github.com/csnp/qramm-cryptodeps/pkg/types"
)

// Exit codes for CI/CD integration
const (
	ExitSuccess         = 0 // No issues found
	ExitVulnerable      = 1 // Quantum-vulnerable findings detected
	ExitError           = 2 // Analysis error occurred
	ExitPartial         = 3 // Partial-risk findings detected (when --fail-on=partial)
)

var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

// CLI flags
var (
	formatFlag     string
	offlineFlag    bool
	deepFlag       bool
	riskFilter     string
	minSeverity    string
	updateURL      string
	verboseFlag    bool
	failOn         string // CI/CD: fail on vulnerable, partial, or any
	exitCode       int    // Tracks exit code for CI/CD
)

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
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
		fmt.Printf("cryptodeps %s\n", version)
		fmt.Printf("  commit: %s\n", commit)
		fmt.Printf("  built:  %s\n", date)
	},
}

var analyzeCmd = &cobra.Command{
	Use:   "analyze [path]",
	Short: "Analyze dependencies for cryptographic usage",
	Long: `Analyze a project's dependencies to identify cryptographic algorithms
and assess their quantum computing vulnerability.

The path can be:
  - A directory containing a manifest file (go.mod, package.json, etc.)
  - A specific manifest file
  - "." for the current directory

Exit codes (for CI/CD):
  0 - No quantum-vulnerable findings
  1 - Quantum-vulnerable findings detected
  2 - Analysis error
  3 - Partial-risk findings detected (with --fail-on=partial)

Examples:
  cryptodeps analyze .
  cryptodeps analyze ./go.mod
  cryptodeps analyze /path/to/project --format json
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
	analyzeCmd.Flags().StringVar(&riskFilter, "risk", "", "Filter by risk level (vulnerable, partial, all)")
	analyzeCmd.Flags().StringVar(&minSeverity, "min-severity", "", "Minimum severity to report")
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
	// Default to current directory
	path := "."
	if len(args) > 0 {
		path = args[0]
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
		Offline:     offlineFlag,
		Deep:        deepFlag,
		RiskFilter:  riskFilter,
		MinSeverity: minSeverity,
	})

	// Run analysis
	result, err := a.Analyze(path)
	if err != nil {
		return fmt.Errorf("analysis failed: %w", err)
	}

	// Get formatter and output
	formatter, err := output.GetFormatter(format)
	if err != nil {
		return err
	}

	if err := formatter.Format(result, os.Stdout); err != nil {
		return err
	}

	// Set exit code based on findings and --fail-on flag
	exitCode = determineExitCode(result, failOn)
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

func runStatus(cmd *cobra.Command, args []string) error {
	db := database.NewWithCachedData()
	stats := db.Stats()

	fmt.Println("CryptoDeps Database")
	fmt.Println("===================")
	fmt.Printf("Total packages: %d\n", stats.TotalPackages)
	fmt.Println()
	fmt.Println("By ecosystem:")
	for ecosystem, count := range stats.ByEcosystem {
		fmt.Printf("  %-8s %d packages\n", ecosystem+":", count)
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
