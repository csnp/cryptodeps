// Copyright 2024 CSNP (csnp.org)
// SPDX-License-Identifier: Apache-2.0

// Package ondemand provides on-demand cryptographic analysis of packages.
package ondemand

import (
	"fmt"

	"github.com/csnp/qramm-cryptodeps/internal/analyzer/ast"
	"github.com/csnp/qramm-cryptodeps/internal/analyzer/source"
	"github.com/csnp/qramm-cryptodeps/pkg/crypto"
	"github.com/csnp/qramm-cryptodeps/pkg/types"
)

// Analyzer performs on-demand analysis of package source code.
type Analyzer struct {
	fetcher *source.Fetcher
}

// NewAnalyzer creates a new on-demand analyzer.
func NewAnalyzer(cacheDir string) *Analyzer {
	return &Analyzer{
		fetcher: source.NewFetcher(cacheDir),
	}
}

// Analyze downloads and analyzes a package for cryptographic usage.
func (a *Analyzer) Analyze(dep types.Dependency) (*types.PackageAnalysis, error) {
	// Fetch the source code
	sourceDir, err := a.fetcher.Fetch(dep)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch source: %w", err)
	}

	// Analyze based on ecosystem
	var usages []types.CryptoUsage
	switch dep.Ecosystem {
	case types.EcosystemGo:
		usages, err = a.analyzeGo(sourceDir)
	case types.EcosystemNPM:
		usages, err = a.analyzeJavaScript(sourceDir)
	case types.EcosystemPyPI:
		usages, err = a.analyzePython(sourceDir)
	case types.EcosystemMaven:
		usages, err = a.analyzeJava(sourceDir)
	default:
		return nil, fmt.Errorf("unsupported ecosystem: %s", dep.Ecosystem)
	}

	if err != nil {
		return nil, err
	}

	// Build the analysis result
	analysis := &types.PackageAnalysis{
		Package:   dep.Name,
		Version:   dep.Version,
		Ecosystem: dep.Ecosystem,
		Crypto:    usages,
	}

	// Deduplicate and classify algorithms
	analysis.Crypto = a.deduplicateUsages(usages)

	return analysis, nil
}

// analyzeGo analyzes Go source code.
func (a *Analyzer) analyzeGo(sourceDir string) ([]types.CryptoUsage, error) {
	analyzer := ast.NewGoAnalyzer()
	return analyzer.AnalyzeDirectory(sourceDir)
}

// analyzeJavaScript analyzes JavaScript source code.
func (a *Analyzer) analyzeJavaScript(sourceDir string) ([]types.CryptoUsage, error) {
	analyzer := ast.NewJavaScriptAnalyzer()
	return analyzer.AnalyzeDirectory(sourceDir)
}

// analyzePython analyzes Python source code.
func (a *Analyzer) analyzePython(sourceDir string) ([]types.CryptoUsage, error) {
	analyzer := ast.NewPythonAnalyzer()
	return analyzer.AnalyzeDirectory(sourceDir)
}

// analyzeJava analyzes Java source code.
func (a *Analyzer) analyzeJava(sourceDir string) ([]types.CryptoUsage, error) {
	// TODO: Implement Java AST analysis using tree-sitter
	// For now, return empty - we'll add this in Phase 3
	return nil, nil
}

// deduplicateUsages removes duplicate crypto usages and ensures consistent classification.
func (a *Analyzer) deduplicateUsages(usages []types.CryptoUsage) []types.CryptoUsage {
	seen := make(map[string]types.CryptoUsage)

	for _, usage := range usages {
		key := fmt.Sprintf("%s:%s:%d", usage.Algorithm, usage.Location.File, usage.Location.Line)

		if existing, ok := seen[key]; ok {
			// Keep the one with more detail
			if len(usage.CallPath) > len(existing.CallPath) {
				seen[key] = usage
			}
		} else {
			// Ensure proper classification
			if info, found := crypto.ClassifyAlgorithm(usage.Algorithm); found {
				usage.Type = info.Type
				usage.QuantumRisk = info.QuantumRisk
				usage.Severity = info.Severity
			}
			seen[key] = usage
		}
	}

	result := make([]types.CryptoUsage, 0, len(seen))
	for _, usage := range seen {
		result = append(result, usage)
	}

	return result
}
