// Copyright 2025-2026 CyberSecurity NonProfit (CSNP)
// SPDX-License-Identifier: Apache-2.0

package ondemand

import (
	"os"
	"testing"

	"github.com/csnp/qramm-cryptodeps/pkg/types"
)

func TestDeduplicateUsages(t *testing.T) {
	analyzer := NewAnalyzer("")

	usages := []types.CryptoUsage{
		{
			Algorithm: "sha256",
			Location:  types.Location{File: "test.go", Line: 10},
			Function:  "",
		},
		{
			Algorithm: "SHA-256", // Same algorithm, different case
			Location:  types.Location{File: "test.go", Line: 10},
			Function:  "HashData", // More context
		},
		{
			Algorithm: "aes",
			Location:  types.Location{File: "test.go", Line: 20},
		},
		{
			Algorithm: "AES-GCM", // Different algorithm variant
			Location:  types.Location{File: "test.go", Line: 30},
		},
	}

	result := analyzer.deduplicateUsages(usages)

	// Should have 3 unique entries (sha256/SHA-256 merged, aes, AES-GCM)
	if len(result) != 3 {
		t.Errorf("Expected 3 deduplicated usages, got %d", len(result))
	}

	// Check that SHA-256 was normalized and the one with function context was kept
	foundSHA256 := false
	for _, u := range result {
		if u.Algorithm == "SHA-256" {
			foundSHA256 = true
			if u.Function != "HashData" {
				t.Error("Should have kept the SHA-256 usage with function context")
			}
		}
	}
	if !foundSHA256 {
		t.Error("SHA-256 should be normalized from sha256")
	}
}

func TestDeduplicateUsages_PreservesCallPath(t *testing.T) {
	analyzer := NewAnalyzer("")

	usages := []types.CryptoUsage{
		{
			Algorithm: "RSA",
			Location:  types.Location{File: "crypto.go", Line: 50},
			CallPath:  []string{"main"},
		},
		{
			Algorithm: "rsa",
			Location:  types.Location{File: "crypto.go", Line: 50},
			CallPath:  []string{"main", "encryptData", "generateKey"},
		},
	}

	result := analyzer.deduplicateUsages(usages)

	if len(result) != 1 {
		t.Errorf("Expected 1 deduplicated usage, got %d", len(result))
	}

	// Should keep the one with longer call path
	if len(result[0].CallPath) != 3 {
		t.Errorf("Should have kept the usage with longer call path (3), got %d", len(result[0].CallPath))
	}
}

func TestDeduplicateUsages_ClassifiesAlgorithms(t *testing.T) {
	analyzer := NewAnalyzer("")

	usages := []types.CryptoUsage{
		{
			Algorithm: "rsa",
			Location:  types.Location{File: "test.go", Line: 10},
		},
		{
			Algorithm: "AES-256",
			Location:  types.Location{File: "test.go", Line: 20},
		},
	}

	result := analyzer.deduplicateUsages(usages)

	for _, u := range result {
		switch u.Algorithm {
		case "RSA":
			if u.QuantumRisk != types.RiskVulnerable {
				t.Error("RSA should be classified as VULNERABLE")
			}
			if u.Type != "encryption" {
				t.Errorf("RSA should be type 'encryption', got '%s'", u.Type)
			}
		case "AES-256":
			if u.QuantumRisk != types.RiskSafe {
				t.Error("AES-256 should be classified as SAFE")
			}
		}
	}
}

func TestDeduplicateUsages_DifferentLocationsNotMerged(t *testing.T) {
	analyzer := NewAnalyzer("")

	usages := []types.CryptoUsage{
		{
			Algorithm: "SHA-256",
			Location:  types.Location{File: "file1.go", Line: 10},
		},
		{
			Algorithm: "SHA-256",
			Location:  types.Location{File: "file2.go", Line: 10},
		},
		{
			Algorithm: "SHA-256",
			Location:  types.Location{File: "file1.go", Line: 20},
		},
	}

	result := analyzer.deduplicateUsages(usages)

	// All three should be kept (different files or lines)
	if len(result) != 3 {
		t.Errorf("Expected 3 usages (different locations), got %d", len(result))
	}
}

func TestNewAnalyzer(t *testing.T) {
	tmpDir := t.TempDir()
	analyzer := NewAnalyzer(tmpDir)

	if analyzer == nil {
		t.Fatal("NewAnalyzer returned nil")
	}
	if analyzer.fetcher == nil {
		t.Error("Analyzer fetcher should not be nil")
	}
}

func TestAnalyzer_AnalyzeGo(t *testing.T) {
	tmpDir := t.TempDir()

	// Create a Go file with crypto usage
	testFile := tmpDir + "/main.go"
	content := `package main

import "crypto/sha256"

func hashData(data []byte) []byte {
	h := sha256.New()
	h.Write(data)
	return h.Sum(nil)
}
`
	if err := writeFile(testFile, content); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	analyzer := NewAnalyzer(t.TempDir())
	usages, err := analyzer.analyzeGo(tmpDir)
	if err != nil {
		t.Fatalf("analyzeGo failed: %v", err)
	}

	if len(usages) == 0 {
		t.Error("Expected to find crypto usages in Go file")
	}
}

func TestAnalyzer_AnalyzeJavaScript(t *testing.T) {
	tmpDir := t.TempDir()

	// Create a JavaScript file with crypto usage
	testFile := tmpDir + "/index.js"
	content := `const crypto = require('crypto');

function hashData(data) {
	return crypto.createHash('sha256').update(data).digest('hex');
}

module.exports = { hashData };
`
	if err := writeFile(testFile, content); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	analyzer := NewAnalyzer(t.TempDir())
	usages, err := analyzer.analyzeJavaScript(tmpDir)
	if err != nil {
		t.Fatalf("analyzeJavaScript failed: %v", err)
	}

	if len(usages) == 0 {
		t.Error("Expected to find crypto usages in JavaScript file")
	}
}

func TestAnalyzer_AnalyzePython(t *testing.T) {
	tmpDir := t.TempDir()

	// Create a Python file with crypto usage
	testFile := tmpDir + "/main.py"
	content := `import hashlib

def hash_data(data):
    return hashlib.sha256(data.encode()).hexdigest()
`
	if err := writeFile(testFile, content); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	analyzer := NewAnalyzer(t.TempDir())
	usages, err := analyzer.analyzePython(tmpDir)
	if err != nil {
		t.Fatalf("analyzePython failed: %v", err)
	}

	if len(usages) == 0 {
		t.Error("Expected to find crypto usages in Python file")
	}
}

func TestAnalyzer_AnalyzeJava(t *testing.T) {
	tmpDir := t.TempDir()

	// Create a Java file with crypto usage
	testFile := tmpDir + "/Main.java"
	content := `import java.security.MessageDigest;

public class Main {
    public static byte[] hashData(byte[] data) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        return md.digest(data);
    }
}
`
	if err := writeFile(testFile, content); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	analyzer := NewAnalyzer(t.TempDir())
	usages, err := analyzer.analyzeJava(tmpDir)
	if err != nil {
		t.Fatalf("analyzeJava failed: %v", err)
	}

	if len(usages) == 0 {
		t.Error("Expected to find crypto usages in Java file")
	}
}

func TestAnalyzer_EmptyDirectory(t *testing.T) {
	tmpDir := t.TempDir()
	analyzer := NewAnalyzer(t.TempDir())

	// Test with empty directories - should return empty slice, no error
	usages, err := analyzer.analyzeGo(tmpDir)
	if err != nil {
		t.Fatalf("analyzeGo on empty dir failed: %v", err)
	}
	if len(usages) != 0 {
		t.Errorf("Expected 0 usages for empty dir, got %d", len(usages))
	}

	usages, err = analyzer.analyzeJavaScript(tmpDir)
	if err != nil {
		t.Fatalf("analyzeJavaScript on empty dir failed: %v", err)
	}
	if len(usages) != 0 {
		t.Errorf("Expected 0 usages for empty dir, got %d", len(usages))
	}

	usages, err = analyzer.analyzePython(tmpDir)
	if err != nil {
		t.Fatalf("analyzePython on empty dir failed: %v", err)
	}
	if len(usages) != 0 {
		t.Errorf("Expected 0 usages for empty dir, got %d", len(usages))
	}

	usages, err = analyzer.analyzeJava(tmpDir)
	if err != nil {
		t.Fatalf("analyzeJava on empty dir failed: %v", err)
	}
	if len(usages) != 0 {
		t.Errorf("Expected 0 usages for empty dir, got %d", len(usages))
	}
}

func TestDeduplicateUsages_Empty(t *testing.T) {
	analyzer := NewAnalyzer("")
	result := analyzer.deduplicateUsages([]types.CryptoUsage{})

	if len(result) != 0 {
		t.Errorf("Expected 0 usages for empty input, got %d", len(result))
	}
}

// Helper function to write file content
func writeFile(path, content string) error {
	return writeFileBytes(path, []byte(content))
}

func writeFileBytes(path string, content []byte) error {
	return os.WriteFile(path, content, 0644)
}

// Tests for Analyze function using pre-cached packages (no network required)

func TestAnalyze_GoWithCachedSource(t *testing.T) {
	// Create temp dir structure simulating a cached Go module
	tmpDir := t.TempDir()
	cacheDir := tmpDir + "/cache"

	// Create a mock "go module" directory with crypto code
	goModDir := tmpDir + "/gomod/test-pkg"
	os.MkdirAll(goModDir, 0755)

	// Write a Go file with RSA crypto
	goCode := `package testpkg

import "crypto/rsa"

func GenerateKey() (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(nil, 2048)
}
`
	if err := writeFile(goModDir+"/main.go", goCode); err != nil {
		t.Fatalf("Failed to write test Go file: %v", err)
	}

	// We can't easily mock go mod download, so test the internal methods directly
	analyzer := NewAnalyzer(cacheDir)
	usages, err := analyzer.analyzeGo(goModDir)
	if err != nil {
		t.Fatalf("analyzeGo failed: %v", err)
	}

	// Verify RSA was detected
	foundRSA := false
	for _, u := range usages {
		if u.Algorithm == "RSA" || u.Algorithm == "rsa" {
			foundRSA = true
			break
		}
	}
	if !foundRSA {
		t.Error("Expected to find RSA usage in Go code")
	}
}

func TestAnalyze_NPMWithCachedSource(t *testing.T) {
	tmpDir := t.TempDir()
	cacheDir := tmpDir + "/cache"

	// Create a pre-cached npm package structure
	npmPkgDir := cacheDir + "/npm/test-crypto-pkg/1.0.0"
	os.MkdirAll(npmPkgDir, 0755)

	// Write a JavaScript file with crypto
	jsCode := `const crypto = require('crypto');

function encrypt(data, key) {
    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
    return cipher.update(data, 'utf8', 'hex');
}

module.exports = { encrypt };
`
	if err := writeFile(npmPkgDir+"/index.js", jsCode); err != nil {
		t.Fatalf("Failed to write test JS file: %v", err)
	}

	analyzer := NewAnalyzer(cacheDir)

	// This will use the cached directory
	result, err := analyzer.Analyze(types.Dependency{
		Name:      "test-crypto-pkg",
		Version:   "1.0.0",
		Ecosystem: types.EcosystemNPM,
	})

	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}

	if result == nil {
		t.Fatal("Expected non-nil result")
	}

	if result.Package != "test-crypto-pkg" {
		t.Errorf("Expected package name 'test-crypto-pkg', got '%s'", result.Package)
	}

	if len(result.Crypto) == 0 {
		t.Error("Expected to find crypto usages")
	}
}

func TestAnalyze_PyPIWithCachedSource(t *testing.T) {
	tmpDir := t.TempDir()
	cacheDir := tmpDir + "/cache"

	// Create a pre-cached PyPI package structure
	pyPkgDir := cacheDir + "/pypi/test-crypto-lib/2.0.0"
	os.MkdirAll(pyPkgDir, 0755)

	// Write a Python file with crypto
	pyCode := `from cryptography.hazmat.primitives.asymmetric import rsa

def generate_key():
    return rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
`
	if err := writeFile(pyPkgDir+"/crypto_utils.py", pyCode); err != nil {
		t.Fatalf("Failed to write test Python file: %v", err)
	}

	analyzer := NewAnalyzer(cacheDir)

	result, err := analyzer.Analyze(types.Dependency{
		Name:      "test-crypto-lib",
		Version:   "2.0.0",
		Ecosystem: types.EcosystemPyPI,
	})

	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}

	if result == nil {
		t.Fatal("Expected non-nil result")
	}

	if result.Ecosystem != types.EcosystemPyPI {
		t.Errorf("Expected ecosystem 'pypi', got '%s'", result.Ecosystem)
	}
}

func TestAnalyze_MavenWithCachedSource(t *testing.T) {
	tmpDir := t.TempDir()
	cacheDir := tmpDir + "/cache"

	// Create a pre-cached Maven artifact structure
	// Maven uses extracted subdirectory
	mavenPkgDir := cacheDir + "/maven/com.example_crypto/1.0.0/extracted"
	os.MkdirAll(mavenPkgDir, 0755)

	// Write a Java file with crypto
	javaCode := `package com.example.crypto;

import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;

public class CryptoUtils {
    public static void generateRSAKey() throws NoSuchAlgorithmException {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
    }
}
`
	if err := writeFile(mavenPkgDir+"/CryptoUtils.java", javaCode); err != nil {
		t.Fatalf("Failed to write test Java file: %v", err)
	}

	analyzer := NewAnalyzer(cacheDir)

	result, err := analyzer.Analyze(types.Dependency{
		Name:      "com.example:crypto",
		Version:   "1.0.0",
		Ecosystem: types.EcosystemMaven,
	})

	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}

	if result == nil {
		t.Fatal("Expected non-nil result")
	}

	if result.Version != "1.0.0" {
		t.Errorf("Expected version '1.0.0', got '%s'", result.Version)
	}
}

func TestAnalyze_UnsupportedEcosystem(t *testing.T) {
	analyzer := NewAnalyzer(t.TempDir())

	_, err := analyzer.Analyze(types.Dependency{
		Name:      "some-package",
		Version:   "1.0.0",
		Ecosystem: types.Ecosystem("unsupported"),
	})

	if err == nil {
		t.Error("Expected error for unsupported ecosystem")
	}
}

func TestAnalyze_NoCryptoFound(t *testing.T) {
	tmpDir := t.TempDir()
	cacheDir := tmpDir + "/cache"

	// Create a cached package with no crypto code
	npmPkgDir := cacheDir + "/npm/no-crypto-pkg/1.0.0"
	os.MkdirAll(npmPkgDir, 0755)

	// Write a JavaScript file WITHOUT crypto
	jsCode := `function add(a, b) {
    return a + b;
}

module.exports = { add };
`
	if err := writeFile(npmPkgDir+"/index.js", jsCode); err != nil {
		t.Fatalf("Failed to write test JS file: %v", err)
	}

	analyzer := NewAnalyzer(cacheDir)

	result, err := analyzer.Analyze(types.Dependency{
		Name:      "no-crypto-pkg",
		Version:   "1.0.0",
		Ecosystem: types.EcosystemNPM,
	})

	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}

	if result == nil {
		t.Fatal("Expected non-nil result even with no crypto")
	}

	// Result should have empty crypto slice
	if len(result.Crypto) != 0 {
		t.Errorf("Expected 0 crypto usages, got %d", len(result.Crypto))
	}
}

func TestAnalyze_MultipleCryptoAlgorithms(t *testing.T) {
	tmpDir := t.TempDir()
	cacheDir := tmpDir + "/cache"

	// Create a cached package with multiple crypto algorithms
	npmPkgDir := cacheDir + "/npm/multi-crypto/1.0.0"
	os.MkdirAll(npmPkgDir, 0755)

	jsCode := `const crypto = require('crypto');

function hashMD5(data) {
    return crypto.createHash('md5').update(data).digest('hex');
}

function hashSHA256(data) {
    return crypto.createHash('sha256').update(data).digest('hex');
}

function encryptAES(data, key, iv) {
    const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
    return cipher.update(data, 'utf8', 'hex');
}

module.exports = { hashMD5, hashSHA256, encryptAES };
`
	if err := writeFile(npmPkgDir+"/crypto.js", jsCode); err != nil {
		t.Fatalf("Failed to write test JS file: %v", err)
	}

	analyzer := NewAnalyzer(cacheDir)

	result, err := analyzer.Analyze(types.Dependency{
		Name:      "multi-crypto",
		Version:   "1.0.0",
		Ecosystem: types.EcosystemNPM,
	})

	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}

	// Should find multiple algorithms
	if len(result.Crypto) < 2 {
		t.Errorf("Expected at least 2 crypto usages, got %d", len(result.Crypto))
	}

	// Check that deduplication worked and algorithms are classified
	for _, c := range result.Crypto {
		if c.Algorithm == "" {
			t.Error("Algorithm should not be empty after deduplication")
		}
	}
}
