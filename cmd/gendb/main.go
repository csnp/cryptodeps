// Copyright 2024-2025 CSNP (csnp.org)
// SPDX-License-Identifier: Apache-2.0

// Command gendb generates a JSON database file from the embedded database.
// This is used to create the remote database that users can download.
//
// Usage: go run cmd/gendb/main.go > data/crypto-database.json
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"time"

	"github.com/csnp/qramm-cryptodeps/internal/database"
	"github.com/csnp/qramm-cryptodeps/pkg/types"
)

// DatabaseExport is the format for the exported database.
type DatabaseExport struct {
	Version   string                  `json:"version"`
	UpdatedAt string                  `json:"updatedAt"`
	Packages  []types.PackageAnalysis `json:"packages"`
}

func main() {
	// Load the embedded database
	db := database.NewEmbedded()

	// Export all packages
	packages := db.ExportAll()

	// Sort by ecosystem then package name for consistent output
	sort.Slice(packages, func(i, j int) bool {
		if packages[i].Ecosystem != packages[j].Ecosystem {
			return packages[i].Ecosystem < packages[j].Ecosystem
		}
		return packages[i].Package < packages[j].Package
	})

	export := DatabaseExport{
		Version:   "1.0.0",
		UpdatedAt: time.Now().UTC().Format(time.RFC3339),
		Packages:  packages,
	}

	// Stats to stderr
	stats := db.Stats()
	fmt.Fprintf(os.Stderr, "Exporting CryptoDeps database:\n")
	fmt.Fprintf(os.Stderr, "  Total packages: %d\n", stats.TotalPackages)
	for ecosystem, count := range stats.ByEcosystem {
		fmt.Fprintf(os.Stderr, "    %s: %d\n", ecosystem, count)
	}

	// Marshal and output to stdout
	output, err := json.MarshalIndent(export, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	fmt.Println(string(output))
}
