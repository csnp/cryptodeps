// Copyright 2025-2026 CyberSecurity NonProfit (CSNP)
// SPDX-License-Identifier: Apache-2.0

// Package types defines the core data structures used throughout CryptoDeps.
package types

import "time"

// Ecosystem represents a package ecosystem (npm, go, pypi, maven).
type Ecosystem string

const (
	EcosystemGo      Ecosystem = "go"
	EcosystemNPM     Ecosystem = "npm"
	EcosystemPyPI    Ecosystem = "pypi"
	EcosystemMaven   Ecosystem = "maven"
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
	Direct    bool      `json:"direct" yaml:"direct"`                     // true if direct dependency, false if transitive
	Parent    string    `json:"parent,omitempty" yaml:"parent,omitempty"` // parent dependency (for transitive)
}

// Location represents a source code location.
type Location struct {
	File   string `json:"file" yaml:"file"`
	Line   int    `json:"line" yaml:"line"`
	Column int    `json:"column,omitempty" yaml:"column,omitempty"`
}

// Confidence represents how confident we are in the analysis.
type Confidence string

const (
	// ConfidenceVerified means manually verified by a human.
	ConfidenceVerified Confidence = "verified"
	// ConfidenceHigh means inferred with high confidence from patterns.
	ConfidenceHigh Confidence = "high"
	// ConfidenceMedium means inferred with medium confidence.
	ConfidenceMedium Confidence = "medium"
	// ConfidenceLow means inferred with low confidence, may be inaccurate.
	ConfidenceLow Confidence = "low"
)

// Reachability indicates whether crypto is actually used by the project.
type Reachability string

const (
	// ReachabilityConfirmed means direct call from user code to crypto function.
	ReachabilityConfirmed Reachability = "CONFIRMED"
	// ReachabilityReachable means crypto is in the call graph from user code.
	ReachabilityReachable Reachability = "REACHABLE"
	// ReachabilityAvailable means crypto exists in dependency but no path from user code.
	ReachabilityAvailable Reachability = "AVAILABLE"
	// ReachabilityUnknown means reachability could not be determined.
	ReachabilityUnknown Reachability = "UNKNOWN"
)

// CallTrace represents a path from user code to crypto usage.
type CallTrace struct {
	EntryPoint string   `json:"entryPoint" yaml:"entryPoint"` // User's function (e.g., "main.handleLogin")
	Path       []string `json:"path" yaml:"path"`             // Call chain to crypto
	TargetFunc string   `json:"targetFunc" yaml:"targetFunc"` // Crypto function called
	TargetPkg  string   `json:"targetPkg" yaml:"targetPkg"`   // Package containing crypto
}

// CryptoUsage represents a single cryptographic algorithm usage in a package.
type CryptoUsage struct {
	Algorithm    string       `json:"algorithm" yaml:"algorithm"`
	Type         string       `json:"type" yaml:"type"` // encryption, signature, hash, key-exchange
	QuantumRisk  QuantumRisk  `json:"quantumRisk" yaml:"quantumRisk"`
	Severity     Severity     `json:"severity" yaml:"severity"`
	Location     Location     `json:"location" yaml:"location"`
	CallPath     []string     `json:"callPath,omitempty" yaml:"callPath,omitempty"`         // trace from public API to crypto
	InExported   bool         `json:"inExported,omitempty" yaml:"inExported,omitempty"`     // whether in exported/public function
	Function     string       `json:"function,omitempty" yaml:"function,omitempty"`         // containing function name
	Remediation  string       `json:"remediation,omitempty" yaml:"remediation,omitempty"`   // migration guidance
	Confidence   Confidence   `json:"confidence,omitempty" yaml:"confidence,omitempty"`     // verified, high, medium, low
	Reachability Reachability `json:"reachability,omitempty" yaml:"reachability,omitempty"` // CONFIRMED, REACHABLE, AVAILABLE
	Traces       []CallTrace  `json:"traces,omitempty" yaml:"traces,omitempty"`             // paths from user code to this crypto
}

// AnalysisMetadata contains information about how the analysis was performed.
type AnalysisMetadata struct {
	Date        time.Time `json:"date" yaml:"date"`
	Method      string    `json:"method" yaml:"method"` // "database", "ast", "signature"
	Tool        string    `json:"tool" yaml:"tool"`
	ToolVersion string    `json:"toolVersion" yaml:"toolVersion"`
	Contributor string    `json:"contributor,omitempty" yaml:"contributor,omitempty"`
	SourceHash  string    `json:"sourceHash,omitempty" yaml:"sourceHash,omitempty"`
	// FilesAnalyzed is how many source files an analyzer actually parsed. It is
	// the evidence behind every claim this tool makes about having examined a
	// package by reading it, and it is reported so that the claim can be
	// audited rather than taken on trust. Zero for a database record, which was
	// not produced by reading this package here.
	FilesAnalyzed int `json:"filesAnalyzed,omitempty" yaml:"filesAnalyzed,omitempty"`
	// FilesUnreadable is how many files carried one of this analyzer's own
	// extensions and could not be parsed.
	//
	// It is reported for the same reason FilesAnalyzed is. A package that was
	// partly read is not the same as one that was read, and the difference was
	// invisible: the count existed inside the walk and stopped there, so a
	// dependency whose only cryptography sat in a file the analyzer refused was
	// reported as examined and clean, with nothing on any stream saying a file
	// had been skipped. Examination is a claim, and a claim needs its exceptions
	// stated as well as its evidence.
	FilesUnreadable int `json:"filesUnreadable,omitempty" yaml:"filesUnreadable,omitempty"`
}

// SourceWasRead reports whether source analysis parsed at least one file.
//
// This is the question "was this package examined by reading it", and it has to
// be asked of the files that were read rather than of an error that was not
// returned. A fetch can succeed and yield nothing an analyzer can parse: a
// Maven artifact whose sources JAR does not exist falls back to the main JAR,
// which holds compiled classes only, so the walker sees no .java file and
// returns no usages and no error. Reading that as a completed examination
// produced "no cryptographic usage detected in the 1 of 1 dependencies that
// were examined" for a scan that had read nothing at all, which is the
// false-clean class this release exists to close.
func (p *PackageAnalysis) SourceWasRead() bool {
	return p != nil && p.Analysis.FilesAnalyzed > 0
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
	Dependency Dependency       `json:"dependency" yaml:"dependency"`
	Analysis   *PackageAnalysis `json:"analysis,omitempty" yaml:"analysis,omitempty"`
	InDatabase bool             `json:"inDatabase" yaml:"inDatabase"`
	// DeepAnalyzed records that source analysis read this package. It must be
	// set from what an analyzer parsed, never from an on-demand call that
	// merely returned no error: see PackageAnalysis.SourceWasRead.
	DeepAnalyzed bool `json:"deepAnalyzed,omitempty" yaml:"deepAnalyzed,omitempty"`
	// Error says why a dependency was not examined, for the consumers that read
	// this document rather than the warnings printed during the scan. A machine
	// reading JSON or SARIF could previously see only that a package was absent
	// from the results, with no way to tell an unreachable download from an
	// archive that carried nothing to read.
	Error string `json:"error,omitempty" yaml:"error,omitempty"`
}

// Examined reports whether this dependency was inspected by any means.
//
// There are two, and reports that asked only about the first were wrong about
// the second. A database lookup answers "do we already know what this package
// contains"; source analysis answers the same question by reading the package.
// A scan that ran source analysis over every dependency and found nothing was
// still described as having examined nothing, because the only question being
// asked was the database one. The distinction belongs here rather than in each
// caller's own condition, so that a third means of examination added later has
// one place to declare itself.
func (d DependencyResult) Examined() bool {
	return d.InDatabase || d.DeepAnalyzed
}

// ScanResult represents the complete result of scanning a project.
type ScanResult struct {
	Project      string             `json:"project" yaml:"project"`
	Manifest     string             `json:"manifest" yaml:"manifest"`
	Ecosystem    Ecosystem          `json:"ecosystem" yaml:"ecosystem"`
	ScanDate     time.Time          `json:"scanDate" yaml:"scanDate"`
	Dependencies []DependencyResult `json:"dependencies" yaml:"dependencies"`
	Summary      ScanSummary        `json:"summary" yaml:"summary"`
	Hints        []string           `json:"hints,omitempty" yaml:"hints,omitempty"`
}

// ScanSummary provides aggregate statistics for a scan.
type ScanSummary struct {
	TotalDependencies  int `json:"totalDependencies" yaml:"totalDependencies"`
	DirectDependencies int `json:"directDependencies" yaml:"directDependencies"`
	WithCrypto         int `json:"withCrypto" yaml:"withCrypto"`
	QuantumVulnerable  int `json:"quantumVulnerable" yaml:"quantumVulnerable"`
	QuantumPartial     int `json:"quantumPartial" yaml:"quantumPartial"`
	NotInDatabase      int `json:"notInDatabase" yaml:"notInDatabase"`
	// NotExamined counts dependencies that no means of examination reached:
	// absent from the crypto database, and not read by source analysis either.
	//
	// NotInDatabase is not a substitute for it. Using the database count to
	// answer "was anything examined" was correct only while the database was
	// the only way to examine a package, and --deep is a second way. A scan
	// that deep-analyzed every dependency reported that none had been examined,
	// and told the user to run the flag they had just run.
	NotExamined int `json:"notExamined" yaml:"notExamined"`
	// DeepAttempted records whether source analysis ran for the packages the
	// database did not cover. Without it a report cannot tell "not examined
	// because you did not ask for source analysis", where the next step is
	// --deep, from "not examined because source analysis could not fetch the
	// package", where suggesting --deep is a dead end.
	DeepAttempted bool `json:"deepAttempted,omitempty" yaml:"deepAttempted,omitempty"`
	// FilteredOut counts findings that were detected and then withheld by
	// --risk or --min-severity. Without it, a filter that matches nothing is
	// indistinguishable from a project with no cryptography, and the report
	// would state the second while the first is true.
	FilteredOut int `json:"filteredOut,omitempty" yaml:"filteredOut,omitempty"`
	// SourceFilesUnreadable counts source files that source analysis could not
	// parse across the dependencies it did examine.
	//
	// NotExamined cannot carry this: a dependency with one readable file and one
	// unreadable one WAS examined, so it is absent from that count, and the
	// report then described a partial reading as a complete one. This is the
	// partial state of the same question, and the coverage note has to be asked
	// of it rather than only of the empty one.
	SourceFilesUnreadable int `json:"sourceFilesUnreadable,omitempty" yaml:"sourceFilesUnreadable,omitempty"`
	// Reachability stats (only populated when reachability analysis is enabled)
	ReachabilityAnalyzed bool `json:"reachabilityAnalyzed,omitempty" yaml:"reachabilityAnalyzed,omitempty"`
	ConfirmedCrypto      int  `json:"confirmedCrypto,omitempty" yaml:"confirmedCrypto,omitempty"` // Direct calls from user code
	ReachableCrypto      int  `json:"reachableCrypto,omitempty" yaml:"reachableCrypto,omitempty"` // In call graph
	AvailableCrypto      int  `json:"availableCrypto,omitempty" yaml:"availableCrypto,omitempty"` // In deps but not called
}

// SkippedManifest records a file that was recognised as a manifest but could not
// be analyzed, and why.
//
// A scanner may skip input. It must never skip it silently: a manifest broken by
// a bad merge would otherwise vanish from the report while the summary still
// reads clean and CI still goes green.
type SkippedManifest struct {
	Path   string `json:"path" yaml:"path"`
	Reason string `json:"reason" yaml:"reason"`
	// Unsupported separates "cryptodeps has no parser for this ecosystem" from
	// "this file should have been readable and was not".
	//
	// Both are reported, because a file that looks like a manifest and was not
	// read is something the user is entitled to know either way. Only the second
	// means the scan is incomplete, so only the second forces exit 2. Collapsing
	// the two made every polyglot repository an analysis error, and then
	// dropping the unsupported ones from discovery to fix that made them
	// invisible instead, which is the failure this type exists to prevent.
	Unsupported bool `json:"unsupported,omitempty" yaml:"unsupported,omitempty"`
}

// IncompleteScan reports whether any skip means the scan failed to cover input
// it should have covered. An unsupported ecosystem is not such a case.
func IncompleteScan(skipped []SkippedManifest) bool {
	for _, s := range skipped {
		if !s.Unsupported {
			return true
		}
	}
	return false
}

// MultiProjectResult represents the result of scanning multiple projects/manifests.
type MultiProjectResult struct {
	RootPath string        `json:"rootPath" yaml:"rootPath"`
	ScanDate time.Time     `json:"scanDate" yaml:"scanDate"`
	Projects []*ScanResult `json:"projects" yaml:"projects"`
	// Skipped lists manifests that were found but could not be analyzed. An
	// empty scan with a non-empty Skipped is an incomplete scan, not a clean one.
	Skipped      []SkippedManifest `json:"skipped,omitempty" yaml:"skipped,omitempty"`
	TotalSummary ScanSummary       `json:"totalSummary" yaml:"totalSummary"`
}

// AggregateResults combines multiple scan results into a single multi-project result.
func AggregateResults(rootPath string, results []*ScanResult) *MultiProjectResult {
	multi := &MultiProjectResult{
		RootPath: rootPath,
		ScanDate: time.Now(),
		Projects: results,
	}

	// Aggregate summaries
	for _, r := range results {
		multi.TotalSummary.TotalDependencies += r.Summary.TotalDependencies
		multi.TotalSummary.DirectDependencies += r.Summary.DirectDependencies
		multi.TotalSummary.WithCrypto += r.Summary.WithCrypto
		multi.TotalSummary.QuantumVulnerable += r.Summary.QuantumVulnerable
		multi.TotalSummary.QuantumPartial += r.Summary.QuantumPartial
		multi.TotalSummary.NotInDatabase += r.Summary.NotInDatabase
		// The aggregate answers the same coverage question as each project's
		// own summary and must not answer it from a different field.
		multi.TotalSummary.NotExamined += r.Summary.NotExamined
		if r.Summary.DeepAttempted {
			multi.TotalSummary.DeepAttempted = true
		}
		// Without this the aggregate reported zero withheld findings while the
		// per-project summaries reported dozens, so the totals a reader
		// actually looks at described a filtered scan as a complete one.
		multi.TotalSummary.FilteredOut += r.Summary.FilteredOut
		multi.TotalSummary.ConfirmedCrypto += r.Summary.ConfirmedCrypto
		multi.TotalSummary.ReachableCrypto += r.Summary.ReachableCrypto
		multi.TotalSummary.AvailableCrypto += r.Summary.AvailableCrypto
		if r.Summary.ReachabilityAnalyzed {
			multi.TotalSummary.ReachabilityAnalyzed = true
		}
	}

	return multi
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
