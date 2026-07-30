// Copyright 2025-2026 CyberSecurity NonProfit (CSNP)
// SPDX-License-Identifier: Apache-2.0

package analyzer

import (
	"os"
	"path/filepath"
	"strings"
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

// TestSummaryCoverageMatchesDependencies pins the summary to the dependency
// list it describes.
//
// The coverage fields are what every format's verdict is computed from, and
// they are accumulated in a different loop from the one that decides whether a
// dependency was examined. If the two ever disagree, the reports are wrong in a
// way no formatter test can see, because the formatters would be faithfully
// rendering a summary that does not describe the scan.
func TestSummaryCoverageMatchesDependencies(t *testing.T) {
	tmpDir := t.TempDir()

	// One dependency the embedded database carries, one it does not.
	gomod := `module test

require (
	golang.org/x/crypto v0.31.0
	github.com/unknown/package v1.0.0
)
`
	if err := os.WriteFile(filepath.Join(tmpDir, "go.mod"), []byte(gomod), 0644); err != nil {
		t.Fatalf("write go.mod: %v", err)
	}

	result, err := New(database.NewEmbedded(), Options{}).Analyze(tmpDir)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}

	// Guard the fixture: it has to contain both kinds of dependency, or the
	// invariant below holds for a reason that has nothing to do with the code.
	var examined, unexamined int
	for _, dep := range result.Dependencies {
		if dep.Examined() {
			examined++
		} else {
			unexamined++
		}
	}
	if examined == 0 || unexamined == 0 {
		t.Fatalf("fixture does not mix examined and unexamined dependencies: %d/%d",
			examined, unexamined)
	}

	if result.Summary.NotExamined != unexamined {
		t.Errorf("Summary.NotExamined = %d, want %d; the summary does not describe the "+
			"dependency list it was built from", result.Summary.NotExamined, unexamined)
	}
	if result.Summary.TotalDependencies-result.Summary.NotExamined != examined {
		t.Errorf("summary reports %d examined, want %d",
			result.Summary.TotalDependencies-result.Summary.NotExamined, examined)
	}
	if result.Summary.DeepAttempted {
		t.Error("DeepAttempted is set on a scan that did not request source analysis")
	}
}

// TestDeepAttemptedReflectsWhatCouldRun separates the flag the user passed from
// the analysis that was actually possible.
//
// --deep with --offline sets the option and gives the analyzer no way to fetch
// anything, so a report keyed on the option alone would tell the user that
// source analysis had been tried.
func TestDeepAttemptedReflectsWhatCouldRun(t *testing.T) {
	tmpDir := t.TempDir()
	gomod := "module test\n\nrequire github.com/unknown/package v1.0.0\n"
	if err := os.WriteFile(filepath.Join(tmpDir, "go.mod"), []byte(gomod), 0644); err != nil {
		t.Fatalf("write go.mod: %v", err)
	}

	for _, tc := range []struct {
		name string
		opts Options
		want bool
	}{
		{"neither flag", Options{}, false},
		{"offline", Options{Offline: true}, false},
		{"deep and offline", Options{Deep: true, Offline: true}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			result, err := New(database.NewEmbedded(), tc.opts).Analyze(tmpDir)
			if err != nil {
				t.Fatalf("Analyze: %v", err)
			}
			if result.Summary.DeepAttempted != tc.want {
				t.Errorf("DeepAttempted = %v, want %v", result.Summary.DeepAttempted, tc.want)
			}
		})
	}
}

// TestUnexaminedHintIsNotPrintedAfterDeep guards the hint that had no guard.
//
// The hint above it in generateHints was already conditioned on source analysis
// not having run; this one was not, so a --deep scan that read every package
// ended with "try --deep to analyze source code".
func TestUnexaminedHintIsNotPrintedAfterDeep(t *testing.T) {
	// Source analysis ran and could not read any of them. This is the fixture
	// that reaches the branch: NotExamined equals TotalDependencies, which is
	// the condition the hint is generated under. A fixture where the packages
	// were successfully read never reaches it, so it would pass whether the
	// guard were present or not.
	deepRan := &types.ScanResult{
		Summary: types.ScanSummary{
			TotalDependencies: 3, NotInDatabase: 3, NotExamined: 3, DeepAttempted: true,
		},
	}
	if deepRan.Summary.NotExamined != deepRan.Summary.TotalDependencies {
		t.Fatalf("fixture does not reach the hint's condition: %+v", deepRan.Summary)
	}
	a := New(database.NewEmbedded(), Options{Deep: true})
	for _, hint := range a.generateHints(deepRan) {
		if strings.Contains(hint, "--deep") {
			t.Errorf("hint sends a user who ran --deep back to --deep: %q", hint)
		}
	}

	// And the same hint must still appear when it is the right advice.
	deepNotRun := &types.ScanResult{
		Summary: types.ScanSummary{TotalDependencies: 3, NotInDatabase: 3, NotExamined: 3},
	}
	var found bool
	for _, hint := range New(database.NewEmbedded(), Options{}).generateHints(deepNotRun) {
		if strings.Contains(hint, "--deep") {
			found = true
		}
	}
	if !found {
		t.Error("the --deep hint no longer appears for a scan that never ran source analysis")
	}
}
