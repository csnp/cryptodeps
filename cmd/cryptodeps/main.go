// Copyright 2024 CSNP (csnp.org)
// SPDX-License-Identifier: Apache-2.0

// CryptoDeps analyzes software dependencies for cryptographic usage and quantum vulnerability.
package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/csnp/qramm-cryptodeps/internal/analyzer"
	"github.com/csnp/qramm-cryptodeps/internal/database"
	"github.com/csnp/qramm-cryptodeps/pkg/output"
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
)

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
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
  cryptodeps analyze ./go.mod
  cryptodeps analyze ./package.json --format json
  cryptodeps analyze . --risk vulnerable
  cryptodeps db stats`,
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

Examples:
  cryptodeps analyze .
  cryptodeps analyze ./go.mod
  cryptodeps analyze /path/to/project --format json
  cryptodeps analyze . --risk vulnerable --format sarif`,
	Args: cobra.MaximumNArgs(1),
	RunE: runAnalyze,
}

var dbCmd = &cobra.Command{
	Use:   "db",
	Short: "Database management commands",
	Long:  `Commands for managing the crypto knowledge database.`,
}

var dbStatsCmd = &cobra.Command{
	Use:   "stats",
	Short: "Show database statistics",
	Long:  `Display statistics about the crypto knowledge database.`,
	RunE:  runDBStats,
}

var dbUpdateCmd = &cobra.Command{
	Use:   "update",
	Short: "Update the database",
	Long:  `Pull the latest crypto knowledge database from the remote repository.`,
	RunE:  runDBUpdate,
}

func init() {
	// Analyze command flags
	analyzeCmd.Flags().StringVarP(&formatFlag, "format", "f", "table", "Output format (table, json, cbom, sarif, markdown)")
	analyzeCmd.Flags().BoolVar(&offlineFlag, "offline", false, "Only use local database, no downloads")
	analyzeCmd.Flags().BoolVar(&deepFlag, "deep", false, "Force on-demand analysis for unknown packages")
	analyzeCmd.Flags().StringVar(&riskFilter, "risk", "", "Filter by risk level (vulnerable, partial, all)")
	analyzeCmd.Flags().StringVar(&minSeverity, "min-severity", "", "Minimum severity to report")

	// Add commands
	rootCmd.AddCommand(versionCmd)
	rootCmd.AddCommand(analyzeCmd)
	rootCmd.AddCommand(dbCmd)
	dbCmd.AddCommand(dbStatsCmd)
	dbCmd.AddCommand(dbUpdateCmd)
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

	// Initialize database with embedded data
	db := database.NewEmbedded()

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

	return formatter.Format(result, os.Stdout)
}

func runDBStats(cmd *cobra.Command, args []string) error {
	db := database.NewEmbedded()
	stats := db.Stats()

	fmt.Println("CryptoDeps Database Statistics")
	fmt.Println("==============================")
	fmt.Printf("Total packages: %d\n", stats.TotalPackages)
	fmt.Println()
	fmt.Println("By ecosystem:")
	for ecosystem, count := range stats.ByEcosystem {
		fmt.Printf("  %s: %d\n", ecosystem, count)
	}
	fmt.Println()
	fmt.Println("Database type: embedded (built-in seed data)")
	fmt.Println("To use a custom database, set CRYPTODEPS_DB_PATH")

	return nil
}

func runDBUpdate(cmd *cobra.Command, args []string) error {
	fmt.Println("Database update not yet implemented.")
	fmt.Println("Currently using embedded database with seed data.")
	fmt.Println()
	fmt.Println("In a future version, this will pull from:")
	fmt.Println("  https://github.com/csnp/qramm-cryptodeps-db")
	return nil
}
