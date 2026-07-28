// Copyright 2025-2026 CyberSecurity NonProfit (CSNP)
// SPDX-License-Identifier: Apache-2.0

package output

import (
	"bytes"
	"testing"

	"github.com/csnp/qramm-cryptodeps/pkg/types"
)

// resultWithCrypto builds a scan result whose findings are supplied in the given
// order, all at the same risk level.
func resultWithCrypto(algorithms []string, risk types.QuantumRisk) *types.ScanResult {
	crypto := make([]types.CryptoUsage, 0, len(algorithms))
	for _, a := range algorithms {
		crypto = append(crypto, types.CryptoUsage{
			Algorithm:   a,
			QuantumRisk: risk,
			Severity:    types.SeverityHigh,
		})
	}
	return &types.ScanResult{
		Manifest:  "package.json",
		Ecosystem: types.EcosystemNPM,
		Dependencies: []types.DependencyResult{{
			Dependency: types.Dependency{Name: "node-forge", Version: "1.3.1"},
			InDatabase: true,
			Analysis:   &types.PackageAnalysis{Package: "node-forge", Crypto: crypto},
		}},
		Summary: types.ScanSummary{
			TotalDependencies: 1, WithCrypto: 1, QuantumVulnerable: len(algorithms),
		},
	}
}

// TestTableOrderDoesNotDependOnInputOrder is the regression test for a sort that
// was not total.
//
// Findings were ordered on risk alone, and sort.Slice is not stable, so every
// same-risk finding sat in an arbitrary relative position. Two scans that found
// the same things in a different order printed different reports, which makes
// the text report's numbering meaningless and breaks any diff-based CI check.
func TestTableOrderDoesNotDependOnInputOrder(t *testing.T) {
	forward := []string{"RSA", "DES", "3DES", "MD5", "SHA-1", "DSA", "ECDSA"}
	reversed := make([]string, len(forward))
	for i, a := range forward {
		reversed[len(forward)-1-i] = a
	}

	render := func(order []string) string {
		var buf bytes.Buffer
		result := resultWithCrypto(order, types.RiskVulnerable)
		if err := (&TableFormatter{Options: DefaultOptions()}).Format(result, &buf); err != nil {
			t.Fatalf("format: %v", err)
		}
		return buf.String()
	}

	first := render(forward)
	if first == "" {
		t.Fatal("fixture rendered nothing")
	}
	if got := render(reversed); got != first {
		t.Errorf("report depends on the order findings arrived in.\n--- forward ---\n%s\n--- reversed ---\n%s",
			first, got)
	}

	// Rendering the same input repeatedly must also be stable.
	for i := 0; i < 10; i++ {
		if got := render(forward); got != first {
			t.Fatalf("repeated render of identical input differs on iteration %d", i)
		}
	}
}
