// Copyright 2024-2025 CSNP (csnp.org)
// SPDX-License-Identifier: Apache-2.0

// Package analyzer provides the core dependency analysis functionality.
package analyzer

import (
	"fmt"
	"os"
	"time"

	"github.com/csnp/qramm-cryptodeps/internal/analyzer/ondemand"
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
	Offline     bool   // Only use database, no on-demand analysis
	Deep        bool   // Force on-demand analysis for all packages
	RiskFilter  string // Filter by risk level (vulnerable, partial, all)
	MinSeverity string // Minimum severity to report
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

	result := &types.ScanResult{
		Project:      path,
		Manifest:     m.Path,
		Ecosystem:    m.Ecosystem,
		ScanDate:     time.Now(),
		Dependencies: make([]types.DependencyResult, 0, len(m.Dependencies)),
		Summary:      types.ScanSummary{},
	}

	// Analyze each dependency
	for _, dep := range m.Dependencies {
		depResult := a.analyzeDependency(dep)
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

	return result, nil
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
