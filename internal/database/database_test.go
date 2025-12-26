// Copyright 2024-2025 CSNP (csnp.org)
// SPDX-License-Identifier: Apache-2.0

package database

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/csnp/qramm-cryptodeps/pkg/types"
)

func TestNewEmbedded(t *testing.T) {
	db := NewEmbedded()
	if db == nil {
		t.Fatal("NewEmbedded returned nil")
	}

	stats := db.Stats()
	if stats.TotalPackages == 0 {
		t.Error("NewEmbedded should have embedded packages")
	}
}

func TestNew(t *testing.T) {
	db := New("/tmp/test-db")
	if db == nil {
		t.Fatal("New returned nil")
	}
	if db.path != "/tmp/test-db" {
		t.Errorf("path = %q, want /tmp/test-db", db.path)
	}
}

func TestLookup(t *testing.T) {
	db := NewEmbedded()

	tests := []struct {
		name      string
		ecosystem types.Ecosystem
		pkg       string
		version   string
		wantFound bool
	}{
		// Go packages
		{"x/crypto found", types.EcosystemGo, "golang.org/x/crypto", "", true},
		{"jwt-go found", types.EcosystemGo, "github.com/golang-jwt/jwt/v5", "", true},
		{"unknown go pkg", types.EcosystemGo, "github.com/unknown/pkg", "", false},

		// npm packages
		{"jsonwebtoken found", types.EcosystemNPM, "jsonwebtoken", "", true},
		{"bcrypt found", types.EcosystemNPM, "bcrypt", "", true},
		{"crypto-js found", types.EcosystemNPM, "crypto-js", "", true},
		{"unknown npm pkg", types.EcosystemNPM, "unknown-package", "", false},

		// Python packages
		{"cryptography found", types.EcosystemPyPI, "cryptography", "", true},
		{"PyJWT found", types.EcosystemPyPI, "PyJWT", "", true},
		{"unknown python pkg", types.EcosystemPyPI, "unknown-package", "", false},

		// Maven packages
		{"bouncycastle found", types.EcosystemMaven, "org.bouncycastle:bcprov-jdk18on", "", true},
		{"unknown maven pkg", types.EcosystemMaven, "com.unknown:pkg", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			analysis, found := db.Lookup(tt.ecosystem, tt.pkg, tt.version)
			if found != tt.wantFound {
				t.Errorf("Lookup(%q, %q, %q) found = %v, want %v",
					tt.ecosystem, tt.pkg, tt.version, found, tt.wantFound)
			}
			if found && analysis == nil {
				t.Error("Lookup returned found=true but nil analysis")
			}
		})
	}
}

func TestLookupCaseInsensitive(t *testing.T) {
	db := NewEmbedded()

	// Lookup should be case-insensitive
	tests := []struct {
		pkg       string
		ecosystem types.Ecosystem
	}{
		{"GOLANG.ORG/X/CRYPTO", types.EcosystemGo},
		{"GoLang.Org/X/Crypto", types.EcosystemGo},
		{"JSONWEBTOKEN", types.EcosystemNPM},
		{"JsonWebToken", types.EcosystemNPM},
	}

	for _, tt := range tests {
		t.Run(tt.pkg, func(t *testing.T) {
			analysis, found := db.Lookup(tt.ecosystem, tt.pkg, "")
			if !found {
				t.Errorf("Lookup(%q) should find package (case-insensitive)", tt.pkg)
			}
			if analysis == nil {
				t.Error("Lookup returned nil analysis")
			}
		})
	}
}

func TestLookupEnrichesRemediation(t *testing.T) {
	db := NewEmbedded()

	// Lookup should enrich results with remediation
	analysis, found := db.Lookup(types.EcosystemGo, "golang.org/x/crypto", "")
	if !found {
		t.Fatal("Expected to find golang.org/x/crypto")
	}

	for _, crypto := range analysis.Crypto {
		if crypto.QuantumRisk == types.RiskVulnerable && crypto.Remediation == "" {
			t.Errorf("Crypto %q is vulnerable but has no remediation", crypto.Algorithm)
		}
	}
}

func TestStats(t *testing.T) {
	db := NewEmbedded()
	stats := db.Stats()

	if stats.TotalPackages == 0 {
		t.Error("TotalPackages should be > 0")
	}

	// Should have packages for all ecosystems
	ecosystems := []types.Ecosystem{
		types.EcosystemGo,
		types.EcosystemNPM,
		types.EcosystemPyPI,
		types.EcosystemMaven,
	}

	for _, eco := range ecosystems {
		if stats.ByEcosystem[eco] == 0 {
			t.Errorf("Expected packages for ecosystem %q", eco)
		}
	}
}

func TestExportAll(t *testing.T) {
	db := NewEmbedded()
	packages := db.ExportAll()

	if len(packages) == 0 {
		t.Error("ExportAll returned empty slice")
	}

	// Verify no duplicates
	seen := make(map[string]bool)
	for _, pkg := range packages {
		key := string(pkg.Ecosystem) + ":" + pkg.Package
		if seen[key] {
			t.Errorf("Duplicate package: %s", key)
		}
		seen[key] = true
	}
}

func TestMakeKey(t *testing.T) {
	tests := []struct {
		name    string
		version string
		want    string
	}{
		{"package", "", "package"},
		{"Package", "", "package"},
		{"PACKAGE", "", "package"},
		{"package", "1.0.0", "package@1.0.0"},
		{"Package", "1.0.0", "package@1.0.0"},
	}

	for _, tt := range tests {
		t.Run(tt.name+"@"+tt.version, func(t *testing.T) {
			got := makeKey(tt.name, tt.version)
			if got != tt.want {
				t.Errorf("makeKey(%q, %q) = %q, want %q", tt.name, tt.version, got, tt.want)
			}
		})
	}
}

func TestLoadFromDisk(t *testing.T) {
	// Create a temporary database directory
	tmpDir, err := os.MkdirTemp("", "cryptodeps-test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	// Create a test YAML file
	testYAML := `
package: test-package
version: "1.0.0"
ecosystem: go
analysis:
  date: 2024-01-01T00:00:00Z
  method: test
  tool: test
crypto:
  - algorithm: RSA
    type: encryption
    quantumRisk: vulnerable
    severity: high
`
	err = os.WriteFile(filepath.Join(tmpDir, "test.yaml"), []byte(testYAML), 0644)
	if err != nil {
		t.Fatal(err)
	}

	// Load the database
	db := New(tmpDir)
	err = db.Load()
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	// Verify the package was loaded
	analysis, found := db.Lookup(types.EcosystemGo, "test-package", "1.0.0")
	if !found {
		t.Error("Expected to find test-package")
	}
	if analysis == nil {
		t.Fatal("analysis is nil")
	}
	if len(analysis.Crypto) != 1 {
		t.Errorf("Expected 1 crypto usage, got %d", len(analysis.Crypto))
	}
	if analysis.Crypto[0].Algorithm != "RSA" {
		t.Errorf("Expected RSA algorithm, got %q", analysis.Crypto[0].Algorithm)
	}
}

func TestLoadEmptyPath(t *testing.T) {
	db := New("")
	err := db.Load()
	if err != nil {
		t.Errorf("Load with empty path should not error: %v", err)
	}
}

func TestLoadNonExistentPath(t *testing.T) {
	db := New("/nonexistent/path/that/does/not/exist")
	err := db.Load()
	if err == nil {
		t.Error("Load with nonexistent path should error")
	}
}

func TestEnrichWithRemediation(t *testing.T) {
	analysis := &types.PackageAnalysis{
		Package:   "test",
		Ecosystem: types.EcosystemGo,
		Crypto: []types.CryptoUsage{
			{Algorithm: "RSA", Type: "encryption", QuantumRisk: types.RiskVulnerable},
			{Algorithm: "AES-256", Type: "encryption", QuantumRisk: types.RiskSafe},
		},
	}

	enriched := enrichWithRemediation(analysis, types.EcosystemGo)

	// Should not modify original
	if analysis.Crypto[0].Remediation != "" {
		t.Error("Original analysis was modified")
	}

	// Enriched should have remediation
	for _, crypto := range enriched.Crypto {
		if crypto.Remediation == "" {
			t.Errorf("Crypto %q should have remediation", crypto.Algorithm)
		}
	}
}

func TestAddToIndex(t *testing.T) {
	db := New("")

	analysis := &types.PackageAnalysis{
		Package:   "test-pkg",
		Version:   "2.0.0",
		Ecosystem: types.EcosystemNPM,
	}

	db.addToIndex(analysis)

	// Should be findable by name+version
	_, found := db.Lookup(types.EcosystemNPM, "test-pkg", "2.0.0")
	if !found {
		t.Error("Should find package by name+version")
	}

	// Should also be findable by name only
	_, found = db.Lookup(types.EcosystemNPM, "test-pkg", "")
	if !found {
		t.Error("Should find package by name only")
	}
}

func TestEmbeddedDataQuality(t *testing.T) {
	db := NewEmbedded()

	// Check that all embedded packages have required fields
	for eco, pkgs := range db.index {
		for key, pkg := range pkgs {
			t.Run(string(eco)+"/"+key, func(t *testing.T) {
				if pkg.Package == "" {
					t.Error("Package name is empty")
				}
				if pkg.Ecosystem == "" {
					t.Error("Ecosystem is empty")
				}
				// Crypto can be empty for some packages
			})
		}
	}
}

func TestLookupUnknownEcosystem(t *testing.T) {
	db := NewEmbedded()

	// Test lookup with unknown ecosystem - should return not found
	_, found := db.Lookup(types.Ecosystem("rust"), "some-package", "1.0.0")
	if found {
		t.Error("Should not find package in unknown ecosystem")
	}
}

func TestLookupWithExactVersion(t *testing.T) {
	db := New("")

	// Add a package with specific version
	analysis := &types.PackageAnalysis{
		Package:   "versioned-pkg",
		Version:   "3.0.0",
		Ecosystem: types.EcosystemGo,
		Crypto: []types.CryptoUsage{
			{Algorithm: "RSA", QuantumRisk: types.RiskVulnerable},
		},
	}
	db.addToIndex(analysis)

	// Lookup with exact version should succeed
	result, found := db.Lookup(types.EcosystemGo, "versioned-pkg", "3.0.0")
	if !found {
		t.Fatal("Should find package with exact version")
	}
	if result.Version != "3.0.0" {
		t.Errorf("Expected version 3.0.0, got %s", result.Version)
	}

	// Lookup with different version should still find it (via fallback)
	_, found = db.Lookup(types.EcosystemGo, "versioned-pkg", "2.0.0")
	if !found {
		t.Error("Should find package with fallback to no-version key")
	}
}
