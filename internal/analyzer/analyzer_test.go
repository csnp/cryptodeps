// Copyright 2024-2025 CSNP (csnp.org)
// SPDX-License-Identifier: Apache-2.0

package analyzer

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/csnp/qramm-cryptodeps/internal/database"
	"github.com/csnp/qramm-cryptodeps/pkg/types"
)

func TestNew(t *testing.T) {
	db := database.NewEmbedded()

	// Test with default options
	a := New(db, Options{})
	if a == nil {
		t.Fatal("New returned nil")
	}
	if a.db != db {
		t.Error("Database not set")
	}
	if a.ondemand != nil {
		t.Error("ondemand should be nil when Deep is false")
	}

	// Test with Deep mode
	a = New(db, Options{Deep: true})
	if a.ondemand == nil {
		t.Error("ondemand should be initialized when Deep is true")
	}

	// Test with Offline mode (should not initialize ondemand even with Deep)
	a = New(db, Options{Deep: true, Offline: true})
	if a.ondemand != nil {
		t.Error("ondemand should be nil when Offline is true")
	}
}

func TestAnalyze(t *testing.T) {
	// Create temp directory with go.mod
	tmpDir, err := os.MkdirTemp("", "analyzer-test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	gomod := `module test

require (
	golang.org/x/crypto v0.17.0
	github.com/pkg/errors v0.9.1
)
`
	gomodPath := filepath.Join(tmpDir, "go.mod")
	if err := os.WriteFile(gomodPath, []byte(gomod), 0644); err != nil {
		t.Fatal(err)
	}

	db := database.NewEmbedded()
	analyzer := New(db, Options{})

	result, err := analyzer.Analyze(tmpDir)
	if err != nil {
		t.Fatalf("Analyze error: %v", err)
	}

	if result == nil {
		t.Fatal("Analyze returned nil result")
	}

	if result.Ecosystem != types.EcosystemGo {
		t.Errorf("Ecosystem = %q, want %q", result.Ecosystem, types.EcosystemGo)
	}

	if result.Summary.TotalDependencies != 2 {
		t.Errorf("TotalDependencies = %d, want 2", result.Summary.TotalDependencies)
	}

	// Check that x/crypto was found in database (it's a known crypto package)
	foundCrypto := false
	for _, dep := range result.Dependencies {
		if dep.Dependency.Name == "golang.org/x/crypto" {
			foundCrypto = true
			if !dep.InDatabase {
				t.Error("x/crypto should be in database")
			}
			if dep.Analysis == nil {
				t.Error("x/crypto should have analysis")
			}
		}
	}

	if !foundCrypto {
		t.Error("x/crypto not found in results")
	}
}

func TestAnalyzeWithCryptoPackages(t *testing.T) {
	tmpDir, _ := os.MkdirTemp("", "analyzer-test")
	defer os.RemoveAll(tmpDir)

	gomod := `module test

require (
	golang.org/x/crypto v0.17.0
	github.com/golang-jwt/jwt/v5 v5.0.0
)
`
	gomodPath := filepath.Join(tmpDir, "go.mod")
	os.WriteFile(gomodPath, []byte(gomod), 0644)

	db := database.NewEmbedded()
	analyzer := New(db, Options{})

	result, err := analyzer.Analyze(tmpDir)
	if err != nil {
		t.Fatalf("Analyze error: %v", err)
	}

	// Should find crypto usage
	if result.Summary.WithCrypto == 0 {
		t.Error("Expected to find crypto usage")
	}
}

func TestAnalyzeInvalidPath(t *testing.T) {
	db := database.NewEmbedded()
	analyzer := New(db, Options{})

	_, err := analyzer.Analyze("/nonexistent/path")
	if err == nil {
		t.Error("Expected error for nonexistent path")
	}
}

func TestAnalyzeEmptyDirectory(t *testing.T) {
	tmpDir, _ := os.MkdirTemp("", "analyzer-test")
	defer os.RemoveAll(tmpDir)

	db := database.NewEmbedded()
	analyzer := New(db, Options{})

	_, err := analyzer.Analyze(tmpDir)
	if err == nil {
		t.Error("Expected error for empty directory")
	}
}

func TestAnalyzeDependencyNotInDatabase(t *testing.T) {
	tmpDir, _ := os.MkdirTemp("", "analyzer-test")
	defer os.RemoveAll(tmpDir)

	gomod := `module test

require github.com/unknown/package v1.0.0
`
	gomodPath := filepath.Join(tmpDir, "go.mod")
	os.WriteFile(gomodPath, []byte(gomod), 0644)

	db := database.NewEmbedded()
	analyzer := New(db, Options{})

	result, err := analyzer.Analyze(tmpDir)
	if err != nil {
		t.Fatalf("Analyze error: %v", err)
	}

	// Should count as not in database
	if result.Summary.NotInDatabase != 1 {
		t.Errorf("NotInDatabase = %d, want 1", result.Summary.NotInDatabase)
	}

	for _, dep := range result.Dependencies {
		if dep.Dependency.Name == "github.com/unknown/package" {
			if dep.InDatabase {
				t.Error("Unknown package should not be in database")
			}
			if dep.Analysis != nil {
				t.Error("Unknown package should not have analysis in offline mode")
			}
		}
	}
}

func TestAnalyzeDirectDependencies(t *testing.T) {
	tmpDir, _ := os.MkdirTemp("", "analyzer-test")
	defer os.RemoveAll(tmpDir)

	gomod := `module test

require (
	golang.org/x/crypto v0.17.0
	github.com/pkg/errors v0.9.1 // indirect
)
`
	gomodPath := filepath.Join(tmpDir, "go.mod")
	os.WriteFile(gomodPath, []byte(gomod), 0644)

	db := database.NewEmbedded()
	analyzer := New(db, Options{})

	result, err := analyzer.Analyze(tmpDir)
	if err != nil {
		t.Fatalf("Analyze error: %v", err)
	}

	if result.Summary.DirectDependencies != 1 {
		t.Errorf("DirectDependencies = %d, want 1", result.Summary.DirectDependencies)
	}
}

func TestAnalyzeQuantumRiskCounting(t *testing.T) {
	tmpDir, _ := os.MkdirTemp("", "analyzer-test")
	defer os.RemoveAll(tmpDir)

	// Use packages known to have vulnerable crypto
	gomod := `module test

require golang.org/x/crypto v0.17.0
`
	gomodPath := filepath.Join(tmpDir, "go.mod")
	os.WriteFile(gomodPath, []byte(gomod), 0644)

	db := database.NewEmbedded()
	analyzer := New(db, Options{})

	result, err := analyzer.Analyze(tmpDir)
	if err != nil {
		t.Fatalf("Analyze error: %v", err)
	}

	// x/crypto should have vulnerable algorithms
	if result.Summary.QuantumVulnerable == 0 {
		t.Error("Expected quantum vulnerable algorithms in x/crypto")
	}
}

func TestOptions(t *testing.T) {
	opts := Options{
		Offline:     true,
		Deep:        true,
		RiskFilter:  "vulnerable",
		MinSeverity: "high",
	}

	if !opts.Offline {
		t.Error("Offline should be true")
	}
	if !opts.Deep {
		t.Error("Deep should be true")
	}
	if opts.RiskFilter != "vulnerable" {
		t.Error("RiskFilter should be vulnerable")
	}
	if opts.MinSeverity != "high" {
		t.Error("MinSeverity should be high")
	}
}

func TestAnalyzeNPM(t *testing.T) {
	tmpDir, _ := os.MkdirTemp("", "analyzer-test")
	defer os.RemoveAll(tmpDir)

	packageJSON := `{
  "name": "test",
  "dependencies": {
    "jsonwebtoken": "^9.0.0",
    "bcrypt": "^5.1.0"
  }
}`
	pkgPath := filepath.Join(tmpDir, "package.json")
	os.WriteFile(pkgPath, []byte(packageJSON), 0644)

	db := database.NewEmbedded()
	analyzer := New(db, Options{})

	result, err := analyzer.Analyze(tmpDir)
	if err != nil {
		t.Fatalf("Analyze error: %v", err)
	}

	if result.Ecosystem != types.EcosystemNPM {
		t.Errorf("Ecosystem = %q, want %q", result.Ecosystem, types.EcosystemNPM)
	}

	if result.Summary.TotalDependencies != 2 {
		t.Errorf("TotalDependencies = %d, want 2", result.Summary.TotalDependencies)
	}
}

func TestAnalyzePython(t *testing.T) {
	tmpDir, _ := os.MkdirTemp("", "analyzer-test")
	defer os.RemoveAll(tmpDir)

	requirements := `cryptography==41.0.0
PyJWT==2.8.0
`
	reqPath := filepath.Join(tmpDir, "requirements.txt")
	os.WriteFile(reqPath, []byte(requirements), 0644)

	db := database.NewEmbedded()
	analyzer := New(db, Options{})

	result, err := analyzer.Analyze(tmpDir)
	if err != nil {
		t.Fatalf("Analyze error: %v", err)
	}

	if result.Ecosystem != types.EcosystemPyPI {
		t.Errorf("Ecosystem = %q, want %q", result.Ecosystem, types.EcosystemPyPI)
	}
}

func TestAnalyzeMaven(t *testing.T) {
	tmpDir, _ := os.MkdirTemp("", "analyzer-test")
	defer os.RemoveAll(tmpDir)

	pomXML := `<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
    <groupId>com.example</groupId>
    <artifactId>test</artifactId>
    <version>1.0.0</version>
    <dependencies>
        <dependency>
            <groupId>org.bouncycastle</groupId>
            <artifactId>bcprov-jdk18on</artifactId>
            <version>1.77</version>
        </dependency>
    </dependencies>
</project>`
	pomPath := filepath.Join(tmpDir, "pom.xml")
	os.WriteFile(pomPath, []byte(pomXML), 0644)

	db := database.NewEmbedded()
	analyzer := New(db, Options{})

	result, err := analyzer.Analyze(tmpDir)
	if err != nil {
		t.Fatalf("Analyze error: %v", err)
	}

	if result.Ecosystem != types.EcosystemMaven {
		t.Errorf("Ecosystem = %q, want %q", result.Ecosystem, types.EcosystemMaven)
	}
}

func TestAnalyzeWithDirectFile(t *testing.T) {
	tmpDir, _ := os.MkdirTemp("", "analyzer-test")
	defer os.RemoveAll(tmpDir)

	gomod := `module test
require golang.org/x/crypto v0.17.0
`
	gomodPath := filepath.Join(tmpDir, "go.mod")
	os.WriteFile(gomodPath, []byte(gomod), 0644)

	db := database.NewEmbedded()
	analyzer := New(db, Options{})

	// Analyze with file path directly
	result, err := analyzer.Analyze(gomodPath)
	if err != nil {
		t.Fatalf("Analyze error: %v", err)
	}

	if result.Manifest != gomodPath {
		t.Errorf("Manifest = %q, want %q", result.Manifest, gomodPath)
	}
}
