// Copyright 2024 CSNP (csnp.org)
// SPDX-License-Identifier: Apache-2.0

// Package types defines the core data structures used throughout CryptoDeps.
package types

import "time"

// Ecosystem represents a package ecosystem (npm, go, pypi, maven).
type Ecosystem string

const (
	EcosystemGo     Ecosystem = "go"
	EcosystemNPM    Ecosystem = "npm"
	EcosystemPyPI   Ecosystem = "pypi"
	EcosystemMaven  Ecosystem = "maven"
	EcosystemUnknown Ecosystem = "unknown"
)

// QuantumRisk represents the quantum computing threat level.
type QuantumRisk string

const (
	// RiskVulnerable means the algorithm is broken by quantum computers (Shor's algorithm).
	RiskVulnerable QuantumRisk = "VULNERABLE"
	// RiskPartial means security is reduced by quantum (Grover's algorithm halves key strength).
	RiskPartial QuantumRisk = "PARTIAL"
	// RiskSafe means the algorithm is quantum-resistant.
	RiskSafe QuantumRisk = "SAFE"
	// RiskUnknown means the risk cannot be determined.
	RiskUnknown QuantumRisk = "UNKNOWN"
)

// Severity represents the severity level of a finding.
type Severity string

const (
	SeverityCritical Severity = "CRITICAL"
	SeverityHigh     Severity = "HIGH"
	SeverityMedium   Severity = "MEDIUM"
	SeverityLow      Severity = "LOW"
	SeverityInfo     Severity = "INFO"
)

// Dependency represents a software package dependency.
type Dependency struct {
	Name      string    `json:"name" yaml:"name"`
	Version   string    `json:"version" yaml:"version"`
	Ecosystem Ecosystem `json:"ecosystem" yaml:"ecosystem"`
	Direct    bool      `json:"direct" yaml:"direct"`       // true if direct dependency, false if transitive
	Parent    string    `json:"parent,omitempty" yaml:"parent,omitempty"` // parent dependency (for transitive)
}

// Location represents a source code location.
type Location struct {
	File   string `json:"file" yaml:"file"`
	Line   int    `json:"line" yaml:"line"`
	Column int    `json:"column,omitempty" yaml:"column,omitempty"`
}

// CryptoUsage represents a single cryptographic algorithm usage in a package.
type CryptoUsage struct {
	Algorithm   string      `json:"algorithm" yaml:"algorithm"`
	Type        string      `json:"type" yaml:"type"` // encryption, signature, hash, key-exchange
	QuantumRisk QuantumRisk `json:"quantumRisk" yaml:"quantumRisk"`
	Severity    Severity    `json:"severity" yaml:"severity"`
	Location    Location    `json:"location" yaml:"location"`
	CallPath    []string    `json:"callPath,omitempty" yaml:"callPath,omitempty"` // trace from public API to crypto
}

// AnalysisMetadata contains information about how the analysis was performed.
type AnalysisMetadata struct {
	Date        time.Time `json:"date" yaml:"date"`
	Method      string    `json:"method" yaml:"method"` // "database", "ast", "signature"
	Tool        string    `json:"tool" yaml:"tool"`
	ToolVersion string    `json:"toolVersion" yaml:"toolVersion"`
	Contributor string    `json:"contributor,omitempty" yaml:"contributor,omitempty"`
	SourceHash  string    `json:"sourceHash,omitempty" yaml:"sourceHash,omitempty"`
}

// QuantumSummary summarizes the quantum risk of a package.
type QuantumSummary struct {
	Vulnerable int `json:"vulnerable" yaml:"vulnerable"`
	Partial    int `json:"partial" yaml:"partial"`
	Safe       int `json:"safe" yaml:"safe"`
	Unknown    int `json:"unknown" yaml:"unknown"`
}

// PackageAnalysis represents the complete analysis of a single package.
type PackageAnalysis struct {
	Package        string           `json:"package" yaml:"package"`
	Version        string           `json:"version" yaml:"version"`
	Ecosystem      Ecosystem        `json:"ecosystem" yaml:"ecosystem"`
	License        string           `json:"license,omitempty" yaml:"license,omitempty"`
	Analysis       AnalysisMetadata `json:"analysis" yaml:"analysis"`
	Crypto         []CryptoUsage    `json:"crypto" yaml:"crypto"`
	QuantumSummary QuantumSummary   `json:"quantumSummary" yaml:"quantumSummary"`
}

// DependencyResult represents the analysis result for a dependency.
type DependencyResult struct {
	Dependency  Dependency      `json:"dependency" yaml:"dependency"`
	Analysis    *PackageAnalysis `json:"analysis,omitempty" yaml:"analysis,omitempty"`
	InDatabase  bool            `json:"inDatabase" yaml:"inDatabase"`
	Error       string          `json:"error,omitempty" yaml:"error,omitempty"`
}

// ScanResult represents the complete result of scanning a project.
type ScanResult struct {
	Project      string             `json:"project" yaml:"project"`
	Manifest     string             `json:"manifest" yaml:"manifest"`
	Ecosystem    Ecosystem          `json:"ecosystem" yaml:"ecosystem"`
	ScanDate     time.Time          `json:"scanDate" yaml:"scanDate"`
	Dependencies []DependencyResult `json:"dependencies" yaml:"dependencies"`
	Summary      ScanSummary        `json:"summary" yaml:"summary"`
}

// ScanSummary provides aggregate statistics for a scan.
type ScanSummary struct {
	TotalDependencies    int `json:"totalDependencies" yaml:"totalDependencies"`
	DirectDependencies   int `json:"directDependencies" yaml:"directDependencies"`
	WithCrypto           int `json:"withCrypto" yaml:"withCrypto"`
	QuantumVulnerable    int `json:"quantumVulnerable" yaml:"quantumVulnerable"`
	QuantumPartial       int `json:"quantumPartial" yaml:"quantumPartial"`
	NotInDatabase        int `json:"notInDatabase" yaml:"notInDatabase"`
}

// HighestRisk returns the highest quantum risk from a list of crypto usages.
func HighestRisk(usages []CryptoUsage) QuantumRisk {
	if len(usages) == 0 {
		return RiskUnknown
	}

	hasVulnerable := false
	hasPartial := false
	hasSafe := false

	for _, u := range usages {
		switch u.QuantumRisk {
		case RiskVulnerable:
			hasVulnerable = true
		case RiskPartial:
			hasPartial = true
		case RiskSafe:
			hasSafe = true
		}
	}

	if hasVulnerable {
		return RiskVulnerable
	}
	if hasPartial {
		return RiskPartial
	}
	if hasSafe {
		return RiskSafe
	}
	return RiskUnknown
}
