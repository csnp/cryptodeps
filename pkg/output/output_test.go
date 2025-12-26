// Copyright 2024-2025 CSNP (csnp.org)
// SPDX-License-Identifier: Apache-2.0

package output

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/csnp/qramm-cryptodeps/pkg/types"
)

// testScanResult creates a sample scan result for testing
func testScanResult() *types.ScanResult {
	return &types.ScanResult{
		Project:   "/test/project",
		Manifest:  "go.mod",
		Ecosystem: types.EcosystemGo,
		ScanDate:  time.Now(),
		Dependencies: []types.DependencyResult{
			{
				Dependency: types.Dependency{
					Name:      "github.com/test/crypto",
					Version:   "1.0.0",
					Ecosystem: types.EcosystemGo,
					Direct:    true,
				},
				InDatabase: true,
				Analysis: &types.PackageAnalysis{
					Package:   "github.com/test/crypto",
					Ecosystem: types.EcosystemGo,
					Crypto: []types.CryptoUsage{
						{
							Algorithm:    "RSA",
							Type:         "encryption",
							QuantumRisk:  types.RiskVulnerable,
							Severity:     types.SeverityHigh,
							Remediation:  "Migrate to ML-KEM",
							Reachability: types.ReachabilityConfirmed,
						},
						{
							Algorithm:   "AES-256",
							Type:        "encryption",
							QuantumRisk: types.RiskSafe,
							Severity:    types.SeverityInfo,
							Remediation: "No action needed",
						},
					},
				},
			},
			{
				Dependency: types.Dependency{
					Name:      "github.com/test/utils",
					Version:   "2.0.0",
					Ecosystem: types.EcosystemGo,
					Direct:    false,
				},
				InDatabase: false,
			},
		},
		Summary: types.ScanSummary{
			TotalDependencies:  2,
			DirectDependencies: 1,
			WithCrypto:         1,
			QuantumVulnerable:  1,
			QuantumPartial:     0,
			NotInDatabase:      1,
		},
	}
}

func TestParseFormat(t *testing.T) {
	tests := []struct {
		input   string
		want    Format
		wantErr bool
	}{
		{"table", FormatTable, false},
		{"", FormatTable, false}, // Default
		{"json", FormatJSON, false},
		{"cbom", FormatCBOM, false},
		{"sarif", FormatSARIF, false},
		{"markdown", FormatMarkdown, false},
		{"md", FormatMarkdown, false},
		{"invalid", "", true},
		{"TABLE", "", true}, // Case sensitive
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got, err := ParseFormat(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseFormat(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
			}
			if got != tt.want {
				t.Errorf("ParseFormat(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestGetFormatter(t *testing.T) {
	formats := []Format{FormatTable, FormatJSON, FormatCBOM, FormatSARIF, FormatMarkdown}

	for _, format := range formats {
		t.Run(string(format), func(t *testing.T) {
			f, err := GetFormatter(format)
			if err != nil {
				t.Errorf("GetFormatter(%q) error = %v", format, err)
			}
			if f == nil {
				t.Errorf("GetFormatter(%q) returned nil", format)
			}
		})
	}
}

func TestGetFormatterInvalid(t *testing.T) {
	_, err := GetFormatter("invalid")
	if err == nil {
		t.Error("GetFormatter(invalid) should return error")
	}
}

func TestGetFormatterWithOptions(t *testing.T) {
	opts := FormatterOptions{
		ShowRemediation: true,
		Verbose:         true,
	}

	f, err := GetFormatterWithOptions(FormatTable, opts)
	if err != nil {
		t.Fatalf("GetFormatterWithOptions error: %v", err)
	}
	if f == nil {
		t.Fatal("GetFormatterWithOptions returned nil")
	}
}

func TestDefaultOptions(t *testing.T) {
	opts := DefaultOptions()
	if !opts.ShowRemediation {
		t.Error("ShowRemediation should be true by default")
	}
	if opts.Verbose {
		t.Error("Verbose should be false by default")
	}
}

func TestTableFormatter(t *testing.T) {
	f := &TableFormatter{Options: DefaultOptions()}
	result := testScanResult()

	var buf bytes.Buffer
	err := f.Format(result, &buf)
	if err != nil {
		t.Fatalf("Format error: %v", err)
	}

	output := buf.String()

	// Should contain dependency info
	if !strings.Contains(output, "github.com/test/crypto") {
		t.Error("Output should contain dependency name")
	}
	if !strings.Contains(output, "RSA") {
		t.Error("Output should contain algorithm")
	}
	if !strings.Contains(output, "VULNERABLE") {
		t.Error("Output should contain risk level")
	}
	if !strings.Contains(output, "SUMMARY") {
		t.Error("Output should contain summary")
	}
}

func TestTableFormatterWithRemediation(t *testing.T) {
	f := &TableFormatter{Options: FormatterOptions{ShowRemediation: true}}
	result := testScanResult()

	var buf bytes.Buffer
	err := f.Format(result, &buf)
	if err != nil {
		t.Fatalf("Format error: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "REMEDIATION") {
		t.Error("Output should contain remediation section")
	}
}

func TestJSONFormatter(t *testing.T) {
	f := &JSONFormatter{Indent: true}
	result := testScanResult()

	var buf bytes.Buffer
	err := f.Format(result, &buf)
	if err != nil {
		t.Fatalf("Format error: %v", err)
	}

	// Verify it's valid JSON
	var parsed types.ScanResult
	if err := json.Unmarshal(buf.Bytes(), &parsed); err != nil {
		t.Errorf("Output is not valid JSON: %v", err)
	}

	// Check key fields
	if parsed.Manifest != "go.mod" {
		t.Errorf("Manifest = %q, want go.mod", parsed.Manifest)
	}
}

func TestCBOMFormatter(t *testing.T) {
	f := &CBOMFormatter{}
	result := testScanResult()

	var buf bytes.Buffer
	err := f.Format(result, &buf)
	if err != nil {
		t.Fatalf("Format error: %v", err)
	}

	output := buf.String()

	// Should be valid JSON and have CycloneDX structure
	if !strings.Contains(output, "bomFormat") {
		t.Error("CBOM output should contain bomFormat")
	}
	if !strings.Contains(output, "CycloneDX") {
		t.Error("CBOM output should contain CycloneDX")
	}
}

func TestSARIFFormatter(t *testing.T) {
	f := &SARIFFormatter{Options: DefaultOptions()}
	result := testScanResult()

	var buf bytes.Buffer
	err := f.Format(result, &buf)
	if err != nil {
		t.Fatalf("Format error: %v", err)
	}

	output := buf.String()

	// Should have SARIF structure
	if !strings.Contains(output, "$schema") {
		t.Error("SARIF output should contain $schema")
	}
	if !strings.Contains(output, "sarif") {
		t.Error("SARIF output should contain sarif")
	}
	if !strings.Contains(output, "results") {
		t.Error("SARIF output should contain results")
	}
}

func TestMarkdownFormatter(t *testing.T) {
	f := &MarkdownFormatter{Options: DefaultOptions()}
	result := testScanResult()

	var buf bytes.Buffer
	err := f.Format(result, &buf)
	if err != nil {
		t.Fatalf("Format error: %v", err)
	}

	output := buf.String()

	// Should have markdown structure
	if !strings.Contains(output, "# CryptoDeps") {
		t.Error("Markdown output should contain header")
	}
	if !strings.Contains(output, "| Dependency |") || !strings.Contains(output, "| Algorithm |") {
		t.Error("Markdown output should contain table headers")
	}
}

func TestEmptyScanResult(t *testing.T) {
	formats := []Format{FormatTable, FormatJSON, FormatCBOM, FormatSARIF, FormatMarkdown}
	result := &types.ScanResult{
		Project:      "/empty",
		Manifest:     "go.mod",
		Ecosystem:    types.EcosystemGo,
		Dependencies: []types.DependencyResult{},
		Summary:      types.ScanSummary{},
	}

	for _, format := range formats {
		t.Run(string(format), func(t *testing.T) {
			f, _ := GetFormatter(format)
			var buf bytes.Buffer
			err := f.Format(result, &buf)
			if err != nil {
				t.Errorf("Format(%q) error with empty result: %v", format, err)
			}
		})
	}
}

func TestNilWriter(t *testing.T) {
	f := &JSONFormatter{}
	result := testScanResult()

	// Should handle nil writer gracefully
	err := f.Format(result, nil)
	if err == nil {
		t.Error("Format with nil writer should error")
	}
}

func TestNilResult(t *testing.T) {
	f := &JSONFormatter{}
	var buf bytes.Buffer

	// Should handle nil result gracefully
	err := f.Format(nil, &buf)
	if err == nil {
		t.Error("Format with nil result should error")
	}
}

// testScanResultAllRisks creates a sample scan result with all risk types
func testScanResultAllRisks() *types.ScanResult {
	return &types.ScanResult{
		Project:   "/test/project",
		Manifest:  "go.mod",
		Ecosystem: types.EcosystemGo,
		ScanDate:  time.Now(),
		Dependencies: []types.DependencyResult{
			{
				Dependency: types.Dependency{
					Name:      "github.com/test/vulnerable",
					Version:   "1.0.0",
					Ecosystem: types.EcosystemGo,
					Direct:    true,
				},
				InDatabase: true,
				Analysis: &types.PackageAnalysis{
					Package:   "github.com/test/vulnerable",
					Ecosystem: types.EcosystemGo,
					Crypto: []types.CryptoUsage{
						{
							Algorithm:   "RSA",
							Type:        "encryption",
							QuantumRisk: types.RiskVulnerable,
							Severity:    types.SeverityCritical,
						},
					},
				},
			},
			{
				Dependency: types.Dependency{
					Name:      "github.com/test/partial",
					Version:   "1.0.0",
					Ecosystem: types.EcosystemGo,
					Direct:    true,
				},
				InDatabase: true,
				Analysis: &types.PackageAnalysis{
					Package:   "github.com/test/partial",
					Ecosystem: types.EcosystemGo,
					Crypto: []types.CryptoUsage{
						{
							Algorithm:   "SHA-256",
							Type:        "hash",
							QuantumRisk: types.RiskPartial,
							Severity:    types.SeverityMedium,
						},
					},
				},
			},
			{
				Dependency: types.Dependency{
					Name:      "github.com/test/safe",
					Version:   "1.0.0",
					Ecosystem: types.EcosystemGo,
					Direct:    true,
				},
				InDatabase: true,
				Analysis: &types.PackageAnalysis{
					Package:   "github.com/test/safe",
					Ecosystem: types.EcosystemGo,
					Crypto: []types.CryptoUsage{
						{
							Algorithm:   "AES-256",
							Type:        "encryption",
							QuantumRisk: types.RiskSafe,
							Severity:    types.SeverityInfo,
						},
					},
				},
			},
			{
				Dependency: types.Dependency{
					Name:      "github.com/test/unknown",
					Version:   "1.0.0",
					Ecosystem: types.EcosystemGo,
					Direct:    true,
				},
				InDatabase: true,
				Analysis: &types.PackageAnalysis{
					Package:   "github.com/test/unknown",
					Ecosystem: types.EcosystemGo,
					Crypto: []types.CryptoUsage{
						{
							Algorithm:   "CUSTOM",
							Type:        "encryption",
							QuantumRisk: types.RiskUnknown,
							Severity:    types.SeverityLow,
						},
					},
				},
			},
		},
		Summary: types.ScanSummary{
			TotalDependencies:  4,
			DirectDependencies: 4,
			WithCrypto:         4,
			QuantumVulnerable:  1,
			QuantumPartial:     1,
			NotInDatabase:      0,
		},
	}
}

func TestTableFormatterAllRisks(t *testing.T) {
	f := &TableFormatter{Options: DefaultOptions()}
	result := testScanResultAllRisks()

	var buf bytes.Buffer
	err := f.Format(result, &buf)
	if err != nil {
		t.Fatalf("Format error: %v", err)
	}

	output := buf.String()

	// Should contain all risk levels
	if !strings.Contains(output, "VULNERABLE") {
		t.Error("Output should contain VULNERABLE risk")
	}
	if !strings.Contains(output, "PARTIAL") {
		t.Error("Output should contain PARTIAL risk")
	}
	if !strings.Contains(output, "SAFE") {
		t.Error("Output should contain SAFE risk")
	}
	if !strings.Contains(output, "UNKNOWN") {
		t.Error("Output should contain UNKNOWN risk")
	}
}

func TestSARIFFormatterAllSeverities(t *testing.T) {
	f := &SARIFFormatter{Options: DefaultOptions()}
	result := testScanResultAllRisks()

	var buf bytes.Buffer
	err := f.Format(result, &buf)
	if err != nil {
		t.Fatalf("Format error: %v", err)
	}

	output := buf.String()

	// Should contain SARIF severity levels
	if !strings.Contains(output, "error") && !strings.Contains(output, "warning") && !strings.Contains(output, "note") {
		t.Error("SARIF output should contain severity levels")
	}
}

func TestMarkdownFormatterAllRisks(t *testing.T) {
	f := &MarkdownFormatter{Options: DefaultOptions()}
	result := testScanResultAllRisks()

	var buf bytes.Buffer
	err := f.Format(result, &buf)
	if err != nil {
		t.Fatalf("Format error: %v", err)
	}

	output := buf.String()

	// Should contain all dependencies
	if !strings.Contains(output, "github.com/test/vulnerable") {
		t.Error("Output should contain vulnerable dependency")
	}
	if !strings.Contains(output, "github.com/test/partial") {
		t.Error("Output should contain partial dependency")
	}
}
