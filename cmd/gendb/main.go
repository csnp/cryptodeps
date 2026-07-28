// Copyright 2025-2026 CyberSecurity NonProfit (CSNP)
// SPDX-License-Identifier: Apache-2.0

// Command gendb generates a JSON database file from the embedded database
// and optionally fetches additional packages from package registries.
//
// Usage:
//
//	go run cmd/gendb/main.go > data/crypto-database.json           # curated only
//	go run cmd/gendb/main.go --fetch > data/crypto-database.json   # curated + registry
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"sort"
	"time"

	"github.com/csnp/qramm-cryptodeps/internal/database"
	"github.com/csnp/qramm-cryptodeps/internal/registry"
	"github.com/csnp/qramm-cryptodeps/pkg/types"
)

// DatabaseExport is the format for the exported database.
type DatabaseExport struct {
	Version   string                  `json:"version"`
	UpdatedAt string                  `json:"updatedAt"`
	Stats     DatabaseStats           `json:"stats"`
	Packages  []types.PackageAnalysis `json:"packages"`
}

// DatabaseStats contains statistics about the database.
type DatabaseStats struct {
	TotalPackages    int                       `json:"totalPackages"`
	VerifiedPackages int                       `json:"verifiedPackages"`
	InferredPackages int                       `json:"inferredPackages"`
	ByEcosystem      map[types.Ecosystem]int   `json:"byEcosystem"`
	ByConfidence     map[types.Confidence]int  `json:"byConfidence"`
}

var (
	fetchFlag   = flag.Bool("fetch", false, "Fetch additional packages from registries")
	timeoutFlag = flag.Duration("timeout", 2*time.Minute, "Timeout for registry fetches")
)

func main() {
	flag.Parse()

	var packages []types.PackageAnalysis
	var stats DatabaseStats

	if *fetchFlag {
		// Fetch from registries and merge with curated data
		packages, stats = fetchAndMerge()
	} else {
		// Curated only
		packages, stats = curatedOnly()
	}

	// Sort by ecosystem then package name for consistent output
	sort.Slice(packages, func(i, j int) bool {
		if packages[i].Ecosystem != packages[j].Ecosystem {
			return packages[i].Ecosystem < packages[j].Ecosystem
		}
		return packages[i].Package < packages[j].Package
	})

	export := DatabaseExport{
		Version:   "1.1.0",
		UpdatedAt: time.Now().UTC().Format(time.RFC3339),
		Stats:     stats,
		Packages:  packages,
	}

	// Stats to stderr
	fmt.Fprintf(os.Stderr, "CryptoDeps Database Export:\n")
	fmt.Fprintf(os.Stderr, "  Total packages: %d\n", stats.TotalPackages)
	fmt.Fprintf(os.Stderr, "  Verified: %d\n", stats.VerifiedPackages)
	fmt.Fprintf(os.Stderr, "  Inferred: %d\n", stats.InferredPackages)
	fmt.Fprintf(os.Stderr, "  By ecosystem:\n")
	for eco, count := range stats.ByEcosystem {
		fmt.Fprintf(os.Stderr, "    %s: %d\n", eco, count)
	}

	// Marshal and output to stdout
	output, err := json.MarshalIndent(export, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	fmt.Println(string(output))
}

func curatedOnly() ([]types.PackageAnalysis, DatabaseStats) {
	db := database.NewEmbedded()
	packages := db.ExportAll()

	// Mark all as verified
	for i := range packages {
		for j := range packages[i].Crypto {
			packages[i].Crypto[j].Confidence = types.ConfidenceVerified
		}
	}

	stats := DatabaseStats{
		TotalPackages:    len(packages),
		VerifiedPackages: len(packages),
		InferredPackages: 0,
		ByEcosystem:      make(map[types.Ecosystem]int),
		ByConfidence:     make(map[types.Confidence]int),
	}

	for _, pkg := range packages {
		stats.ByEcosystem[pkg.Ecosystem]++
	}
	stats.ByConfidence[types.ConfidenceVerified] = len(packages)

	return packages, stats
}

func fetchAndMerge() ([]types.PackageAnalysis, DatabaseStats) {
	ctx, cancel := context.WithTimeout(context.Background(), *timeoutFlag)
	defer cancel()

	fmt.Fprintf(os.Stderr, "Fetching packages from registries (timeout: %s)...\n", *timeoutFlag)

	merger := registry.NewMerger()
	result, err := merger.Merge(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Warning: merge error: %v\n", err)
	}

	// Log any registry errors
	for _, e := range result.Errors {
		fmt.Fprintf(os.Stderr, "Warning: %v\n", e)
	}

	stats := DatabaseStats{
		TotalPackages:    result.Stats.TotalPackages,
		VerifiedPackages: result.Stats.CuratedPackages,
		InferredPackages: result.Stats.InferredPackages,
		ByEcosystem:      make(map[types.Ecosystem]int),
		ByConfidence:     make(map[types.Confidence]int),
	}

	// Count by ecosystem
	for eco, count := range result.Stats.ByEcosystem {
		stats.ByEcosystem[eco] = count
	}

	// Count by confidence
	for _, pkg := range result.Packages {
		for _, crypto := range pkg.Crypto {
			stats.ByConfidence[crypto.Confidence]++
		}
	}

	fmt.Fprintf(os.Stderr, "Fetched %d new packages from registries\n", result.Stats.NewPackages)

	return result.Packages, stats
}
