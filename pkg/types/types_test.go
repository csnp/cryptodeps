// Copyright 2024-2025 CSNP (csnp.org)
// SPDX-License-Identifier: Apache-2.0

package types

import "testing"

func TestHighestRisk(t *testing.T) {
	tests := []struct {
		name     string
		usages   []CryptoUsage
		expected QuantumRisk
	}{
		{
			name:     "empty usages returns unknown",
			usages:   []CryptoUsage{},
			expected: RiskUnknown,
		},
		{
			name: "single vulnerable",
			usages: []CryptoUsage{
				{Algorithm: "RSA", QuantumRisk: RiskVulnerable},
			},
			expected: RiskVulnerable,
		},
		{
			name: "single safe",
			usages: []CryptoUsage{
				{Algorithm: "AES-256", QuantumRisk: RiskSafe},
			},
			expected: RiskSafe,
		},
		{
			name: "single partial",
			usages: []CryptoUsage{
				{Algorithm: "SHA-256", QuantumRisk: RiskPartial},
			},
			expected: RiskPartial,
		},
		{
			name: "single unknown",
			usages: []CryptoUsage{
				{Algorithm: "CUSTOM", QuantumRisk: RiskUnknown},
			},
			expected: RiskUnknown,
		},
		{
			name: "vulnerable takes precedence over safe",
			usages: []CryptoUsage{
				{Algorithm: "AES-256", QuantumRisk: RiskSafe},
				{Algorithm: "RSA", QuantumRisk: RiskVulnerable},
			},
			expected: RiskVulnerable,
		},
		{
			name: "vulnerable takes precedence over partial",
			usages: []CryptoUsage{
				{Algorithm: "SHA-256", QuantumRisk: RiskPartial},
				{Algorithm: "RSA", QuantumRisk: RiskVulnerable},
			},
			expected: RiskVulnerable,
		},
		{
			name: "partial takes precedence over safe",
			usages: []CryptoUsage{
				{Algorithm: "AES-256", QuantumRisk: RiskSafe},
				{Algorithm: "SHA-256", QuantumRisk: RiskPartial},
			},
			expected: RiskPartial,
		},
		{
			name: "mixed all risks - vulnerable wins",
			usages: []CryptoUsage{
				{Algorithm: "AES-256", QuantumRisk: RiskSafe},
				{Algorithm: "SHA-256", QuantumRisk: RiskPartial},
				{Algorithm: "RSA", QuantumRisk: RiskVulnerable},
				{Algorithm: "CUSTOM", QuantumRisk: RiskUnknown},
			},
			expected: RiskVulnerable,
		},
		{
			name: "safe and unknown - safe wins",
			usages: []CryptoUsage{
				{Algorithm: "AES-256", QuantumRisk: RiskSafe},
				{Algorithm: "CUSTOM", QuantumRisk: RiskUnknown},
			},
			expected: RiskSafe,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := HighestRisk(tt.usages)
			if result != tt.expected {
				t.Errorf("HighestRisk() = %v, expected %v", result, tt.expected)
			}
		})
	}
}

func TestQuantumRiskString(t *testing.T) {
	tests := []struct {
		risk     QuantumRisk
		expected string
	}{
		{RiskUnknown, "UNKNOWN"},
		{RiskSafe, "SAFE"},
		{RiskPartial, "PARTIAL"},
		{RiskVulnerable, "VULNERABLE"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			if string(tt.risk) != tt.expected {
				t.Errorf("QuantumRisk string = %s, expected %s", string(tt.risk), tt.expected)
			}
		})
	}
}

func TestEcosystemString(t *testing.T) {
	tests := []struct {
		eco      Ecosystem
		expected string
	}{
		{EcosystemGo, "go"},
		{EcosystemNPM, "npm"},
		{EcosystemPyPI, "pypi"},
		{EcosystemMaven, "maven"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			if string(tt.eco) != tt.expected {
				t.Errorf("Ecosystem string = %s, expected %s", string(tt.eco), tt.expected)
			}
		})
	}
}

func TestCryptoUsageFields(t *testing.T) {
	usage := CryptoUsage{
		Algorithm:   "RSA-2048",
		Type:        "encryption",
		Location:    Location{File: "main.go", Line: 10, Column: 5},
		Function:    "generateKey",
		CallPath:    []string{"main", "encrypt", "generateKey"},
		QuantumRisk: RiskVulnerable,
		Severity:    SeverityCritical,
		InExported:  true,
		Remediation: "Migrate to ML-KEM",
	}

	if usage.Algorithm != "RSA-2048" {
		t.Error("Algorithm field not set correctly")
	}
	if usage.Type != "encryption" {
		t.Error("Type field not set correctly")
	}
	if usage.Location.File != "main.go" {
		t.Error("Location.File not set correctly")
	}
	if usage.Location.Line != 10 {
		t.Error("Location.Line not set correctly")
	}
	if usage.Location.Column != 5 {
		t.Error("Location.Column not set correctly")
	}
	if len(usage.CallPath) != 3 {
		t.Error("CallPath not set correctly")
	}
	if usage.QuantumRisk != RiskVulnerable {
		t.Error("QuantumRisk not set correctly")
	}
	if usage.Severity != SeverityCritical {
		t.Error("Severity field not set correctly")
	}
	if !usage.InExported {
		t.Error("InExported field not set correctly")
	}
	if usage.Remediation != "Migrate to ML-KEM" {
		t.Error("Remediation field not set correctly")
	}
}

func TestDependencyFields(t *testing.T) {
	dep := Dependency{
		Name:      "github.com/example/crypto",
		Version:   "v1.2.3",
		Ecosystem: EcosystemGo,
		Direct:    true,
	}

	if dep.Name != "github.com/example/crypto" {
		t.Error("Name field not set correctly")
	}
	if dep.Version != "v1.2.3" {
		t.Error("Version field not set correctly")
	}
	if dep.Ecosystem != EcosystemGo {
		t.Error("Ecosystem field not set correctly")
	}
	if !dep.Direct {
		t.Error("Direct field not set correctly")
	}
}

func TestScanResultFields(t *testing.T) {
	result := ScanResult{
		Project:   "/path/to/project",
		Manifest:  "go.mod",
		Ecosystem: EcosystemGo,
		Dependencies: []DependencyResult{
			{
				Dependency: Dependency{
					Name:      "crypto/sha256",
					Version:   "go1.21",
					Ecosystem: EcosystemGo,
					Direct:    true,
				},
				InDatabase: true,
			},
		},
		Summary: ScanSummary{
			TotalDependencies:  10,
			DirectDependencies: 5,
			WithCrypto:         3,
			QuantumVulnerable:  1,
			QuantumPartial:     1,
			NotInDatabase:      2,
		},
	}

	if result.Project != "/path/to/project" {
		t.Error("Project field not set correctly")
	}
	if result.Manifest != "go.mod" {
		t.Error("Manifest field not set correctly")
	}
	if len(result.Dependencies) != 1 {
		t.Error("Dependencies field not set correctly")
	}
	if result.Summary.TotalDependencies != 10 {
		t.Error("Summary.TotalDependencies not set correctly")
	}
	if result.Summary.QuantumVulnerable != 1 {
		t.Error("Summary.QuantumVulnerable not set correctly")
	}
}

func TestDependencyResultFields(t *testing.T) {
	depResult := DependencyResult{
		Dependency: Dependency{
			Name:      "example-lib",
			Version:   "1.0.0",
			Ecosystem: EcosystemNPM,
			Direct:    true,
		},
		Analysis: &PackageAnalysis{
			Package:   "example-lib",
			Version:   "1.0.0",
			Ecosystem: EcosystemNPM,
			Crypto: []CryptoUsage{
				{Algorithm: "AES-256", QuantumRisk: RiskSafe},
			},
		},
		InDatabase:   true,
		DeepAnalyzed: true,
	}

	if depResult.Dependency.Name != "example-lib" {
		t.Error("Dependency.Name not set correctly")
	}
	if !depResult.InDatabase {
		t.Error("InDatabase field not set correctly")
	}
	if !depResult.DeepAnalyzed {
		t.Error("DeepAnalyzed field not set correctly")
	}
	if depResult.Analysis == nil {
		t.Error("Analysis should not be nil")
	}
	if len(depResult.Analysis.Crypto) != 1 {
		t.Error("Analysis.Crypto not set correctly")
	}
}

func TestPackageAnalysisFields(t *testing.T) {
	analysis := PackageAnalysis{
		Package:   "my-crypto-lib",
		Version:   "2.0.0",
		Ecosystem: EcosystemPyPI,
		License:   "MIT",
		Crypto: []CryptoUsage{
			{Algorithm: "RSA", QuantumRisk: RiskVulnerable},
			{Algorithm: "AES-256", QuantumRisk: RiskSafe},
		},
		QuantumSummary: QuantumSummary{
			Vulnerable: 1,
			Safe:       1,
		},
	}

	if analysis.Package != "my-crypto-lib" {
		t.Error("Package field not set correctly")
	}
	if analysis.License != "MIT" {
		t.Error("License field not set correctly")
	}
	if len(analysis.Crypto) != 2 {
		t.Error("Crypto field not set correctly")
	}
	if analysis.QuantumSummary.Vulnerable != 1 {
		t.Error("QuantumSummary.Vulnerable not set correctly")
	}
}

func TestSeverityConstants(t *testing.T) {
	tests := []struct {
		sev      Severity
		expected string
	}{
		{SeverityCritical, "CRITICAL"},
		{SeverityHigh, "HIGH"},
		{SeverityMedium, "MEDIUM"},
		{SeverityLow, "LOW"},
		{SeverityInfo, "INFO"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			if string(tt.sev) != tt.expected {
				t.Errorf("Severity string = %s, expected %s", string(tt.sev), tt.expected)
			}
		})
	}
}
