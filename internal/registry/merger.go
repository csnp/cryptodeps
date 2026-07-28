// Copyright 2025-2026 CyberSecurity NonProfit (CSNP)
// SPDX-License-Identifier: Apache-2.0

package registry

import (
	"context"
	"time"

	"github.com/csnp/qramm-cryptodeps/internal/database"
	"github.com/csnp/qramm-cryptodeps/pkg/types"
)

// MergeResult contains the merged database and statistics.
type MergeResult struct {
	Packages []types.PackageAnalysis
	Stats    MergeStats
	Errors   []error
}

// MergeStats contains statistics about the merge.
type MergeStats struct {
	CuratedPackages  int
	InferredPackages int
	TotalPackages    int
	NewPackages      int // packages not in curated database
	ByEcosystem      map[types.Ecosystem]int
}

// Merger combines curated and inferred package data.
type Merger struct {
	fetcher *Fetcher
}

// NewMerger creates a new data merger.
func NewMerger() *Merger {
	return &Merger{
		fetcher: NewFetcher(),
	}
}

// Merge combines curated database with dynamically fetched packages.
// Curated data always takes priority over inferred data.
func (m *Merger) Merge(ctx context.Context) (*MergeResult, error) {
	result := &MergeResult{
		Stats: MergeStats{
			ByEcosystem: make(map[types.Ecosystem]int),
		},
	}

	// Load curated database
	curatedDB := database.NewEmbedded()
	curatedPackages := curatedDB.ExportAll()

	// Mark curated packages as verified
	for i := range curatedPackages {
		for j := range curatedPackages[i].Crypto {
			curatedPackages[i].Crypto[j].Confidence = types.ConfidenceVerified
		}
		curatedPackages[i].Analysis.Method = "verified"
	}

	result.Stats.CuratedPackages = len(curatedPackages)

	// Build index of curated packages for quick lookup
	curatedIndex := make(map[string]bool)
	for _, pkg := range curatedPackages {
		key := string(pkg.Ecosystem) + ":" + pkg.Package
		curatedIndex[key] = true
	}

	// Fetch from registries
	registryPackages, errors := m.fetcher.FetchAll(ctx)
	result.Errors = errors

	// Infer algorithms and convert to PackageAnalysis
	var inferredPackages []types.PackageAnalysis
	for _, pkg := range registryPackages {
		key := string(pkg.Ecosystem) + ":" + pkg.Name

		// Skip if already in curated database
		if curatedIndex[key] {
			continue
		}

		// Infer algorithms
		algorithms := InferAlgorithms(pkg)
		if len(algorithms) == 0 {
			continue // No algorithms inferred, skip
		}

		// Convert to PackageAnalysis
		analysis := ToPackageAnalysis(pkg, algorithms)
		analysis.Analysis.Date = time.Now().UTC()
		inferredPackages = append(inferredPackages, analysis)
		result.Stats.NewPackages++
	}

	result.Stats.InferredPackages = len(inferredPackages)

	// Merge: curated first, then inferred
	result.Packages = append(result.Packages, curatedPackages...)
	result.Packages = append(result.Packages, inferredPackages...)

	result.Stats.TotalPackages = len(result.Packages)

	// Calculate ecosystem stats
	for _, pkg := range result.Packages {
		result.Stats.ByEcosystem[pkg.Ecosystem]++
	}

	return result, nil
}

// FetchOnly fetches from registries without merging with curated data.
// Useful for seeing what new packages are available.
func (m *Merger) FetchOnly(ctx context.Context) ([]types.PackageAnalysis, []error) {
	registryPackages, errors := m.fetcher.FetchAll(ctx)

	var packages []types.PackageAnalysis
	for _, pkg := range registryPackages {
		algorithms := InferAlgorithms(pkg)
		if len(algorithms) == 0 {
			continue
		}

		analysis := ToPackageAnalysis(pkg, algorithms)
		analysis.Analysis.Date = time.Now().UTC()
		packages = append(packages, analysis)
	}

	return packages, errors
}
