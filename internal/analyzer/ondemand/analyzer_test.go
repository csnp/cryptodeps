// Copyright 2024-2025 CSNP (csnp.org)
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
