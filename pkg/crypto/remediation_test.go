// Copyright 2024-2025 CSNP (csnp.org)
// SPDX-License-Identifier: Apache-2.0

package crypto

import (
	"strings"
	"testing"

	"github.com/csnp/qramm-cryptodeps/pkg/types"
)

func TestGetDetailedRemediation(t *testing.T) {
	tests := []struct {
		name        string
		algorithm   string
		cryptoType  string
		ecosystem   types.Ecosystem
		wantSummary string
		wantNIST    string
	}{
		// Key exchange algorithms
		{"RSA", "RSA", "encryption", types.EcosystemGo, "ML-KEM", "FIPS 203"},
		{"ECDH", "ECDH", "key-exchange", types.EcosystemGo, "ML-KEM", "FIPS 203"},
		{"DH", "DH", "key-exchange", types.EcosystemGo, "ML-KEM", "FIPS 203"},
		{"X25519", "X25519", "key-exchange", types.EcosystemGo, "ML-KEM", "FIPS 203"},

		// Signature algorithms
		{"ECDSA", "ECDSA", "signature", types.EcosystemGo, "ML-DSA", "FIPS 204"},
		{"Ed25519", "Ed25519", "signature", types.EcosystemGo, "ML-DSA", "FIPS 204"},
		{"DSA", "DSA", "signature", types.EcosystemGo, "ML-DSA", "FIPS 204"},

		// JWT algorithms - RS/ES migrate to ML-DSA
		{"RS256", "RS256", "signature", types.EcosystemNPM, "ML-DSA", ""},
		{"ES256", "ES256", "signature", types.EcosystemNPM, "ML-DSA", ""},
		{"HS256", "HS256", "signature", types.EcosystemNPM, "HS512", ""},

		// Hash algorithms
		{"SHA-256", "SHA-256", "hash", types.EcosystemPyPI, "SHA-384", ""},
		{"MD5", "MD5", "hash", types.EcosystemPyPI, "SHA-256", ""},
		{"SHA-1", "SHA-1", "hash", types.EcosystemPyPI, "SHA-256", ""},

		// Symmetric encryption
		{"AES-128", "AES-128", "encryption", types.EcosystemMaven, "AES-256", ""},
		{"AES-256", "AES-256", "encryption", types.EcosystemMaven, "quantum", ""},
		{"ChaCha20", "ChaCha20", "encryption", types.EcosystemGo, "quantum", ""},

		// Broken algorithms
		{"DES", "DES", "encryption", types.EcosystemGo, "AES-256", ""},
		{"3DES", "3DES", "encryption", types.EcosystemGo, "AES-256", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := GetDetailedRemediation(tt.algorithm, tt.cryptoType, tt.ecosystem)
			if r == nil {
				t.Fatal("GetDetailedRemediation returned nil")
			}

			if !strings.Contains(r.Summary, tt.wantSummary) {
				t.Errorf("Summary = %q, want to contain %q", r.Summary, tt.wantSummary)
			}

			if tt.wantNIST != "" && r.NISTStandard != tt.wantNIST {
				t.Errorf("NISTStandard = %q, want %q", r.NISTStandard, tt.wantNIST)
			}
		})
	}
}

func TestGetDetailedRemediationUnknownAlgorithm(t *testing.T) {
	r := GetDetailedRemediation("UNKNOWN_ALGO_XYZ", "encryption", types.EcosystemGo)
	if r == nil {
		t.Fatal("GetDetailedRemediation returned nil for unknown algorithm")
	}

	// Should return default remediation
	if r.Summary == "" {
		t.Error("Expected non-empty summary for unknown algorithm")
	}
	if r.Timeline != "unknown" {
		t.Errorf("Expected timeline 'unknown' for unknown algorithm, got %q", r.Timeline)
	}
}

func TestGetDetailedRemediationFields(t *testing.T) {
	// Test that required fields are populated for known algorithms
	algorithms := []string{"RSA", "ECDSA", "Ed25519", "AES-128", "SHA-256"}

	for _, algo := range algorithms {
		t.Run(algo, func(t *testing.T) {
			r := GetDetailedRemediation(algo, "", types.EcosystemGo)
			if r == nil {
				t.Fatal("GetDetailedRemediation returned nil")
			}

			if r.Summary == "" {
				t.Error("Summary is empty")
			}
			if r.Replacement == "" {
				t.Error("Replacement is empty")
			}
			if r.Timeline == "" {
				t.Error("Timeline is empty")
			}
			if r.Effort == "" {
				t.Error("Effort is empty")
			}
		})
	}
}

func TestGetDetailedRemediationLibraries(t *testing.T) {
	// Test that libraries are populated for key algorithms
	tests := []struct {
		algorithm string
		ecosystem types.Ecosystem
		wantLib   string
	}{
		{"RSA", types.EcosystemGo, "circl"},
		{"RSA", types.EcosystemNPM, "noble"},
		{"RSA", types.EcosystemPyPI, "pqcrypto"},
		{"RSA", types.EcosystemMaven, "bouncycastle"},
		{"ECDSA", types.EcosystemGo, "circl"},
		{"Ed25519", types.EcosystemGo, "circl"},
	}

	for _, tt := range tests {
		t.Run(tt.algorithm+"_"+string(tt.ecosystem), func(t *testing.T) {
			r := GetDetailedRemediation(tt.algorithm, "", tt.ecosystem)
			if r == nil {
				t.Fatal("GetDetailedRemediation returned nil")
			}

			if r.Libraries == nil {
				t.Skip("No libraries defined for this algorithm")
			}

			libs := r.Libraries[tt.ecosystem]
			if len(libs) == 0 {
				t.Errorf("No libraries for ecosystem %q", tt.ecosystem)
				return
			}

			found := false
			for _, lib := range libs {
				if strings.Contains(strings.ToLower(lib), tt.wantLib) {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("Libraries %v don't contain %q", libs, tt.wantLib)
			}
		})
	}
}

func TestGetRemediationSummary(t *testing.T) {
	tests := []struct {
		algorithm   string
		cryptoType  string
		ecosystem   types.Ecosystem
		wantContain string
	}{
		{"RSA", "encryption", types.EcosystemGo, "ML-KEM"},
		{"ECDSA", "signature", types.EcosystemGo, "ML-DSA"},
		{"Ed25519", "signature", types.EcosystemGo, "ML-DSA"},
		{"AES-128", "encryption", types.EcosystemGo, "AES-256"},
		{"SHA-256", "hash", types.EcosystemGo, "SHA"},
	}

	for _, tt := range tests {
		t.Run(tt.algorithm, func(t *testing.T) {
			got := GetRemediationSummary(tt.algorithm, tt.cryptoType, tt.ecosystem)
			if got == "" {
				t.Error("GetRemediationSummary returned empty string")
			}
			if !strings.Contains(got, tt.wantContain) {
				t.Errorf("GetRemediationSummary(%q) = %q, want to contain %q", tt.algorithm, got, tt.wantContain)
			}
		})
	}
}

func TestGetRemediationSummaryFallback(t *testing.T) {
	// Test that it falls back to GetRemediation for algorithms not in detailed DB
	// but present in the simple algorithm database
	summary := GetRemediationSummary("rsa", "encryption", types.EcosystemGo)
	if summary == "" {
		t.Error("GetRemediationSummary returned empty for lowercase 'rsa'")
	}
}

func TestGetLibraryRecommendations(t *testing.T) {
	tests := []struct {
		algorithm string
		ecosystem types.Ecosystem
		wantLen   int // Minimum expected libraries
	}{
		{"RSA", types.EcosystemGo, 1},
		{"RSA", types.EcosystemNPM, 1},
		{"RSA", types.EcosystemPyPI, 1},
		{"ECDSA", types.EcosystemGo, 1},
		{"Ed25519", types.EcosystemGo, 1},
	}

	for _, tt := range tests {
		t.Run(tt.algorithm+"_"+string(tt.ecosystem), func(t *testing.T) {
			libs := GetLibraryRecommendations(tt.algorithm, tt.ecosystem)
			if len(libs) < tt.wantLen {
				t.Errorf("GetLibraryRecommendations(%q, %q) = %v, want at least %d libraries",
					tt.algorithm, tt.ecosystem, libs, tt.wantLen)
			}
		})
	}
}

func TestGetLibraryRecommendationsUnknown(t *testing.T) {
	libs := GetLibraryRecommendations("UNKNOWN_ALGO", types.EcosystemGo)
	// Should return nil or empty for unknown algorithms
	if len(libs) > 0 {
		t.Errorf("GetLibraryRecommendations(unknown) = %v, want nil/empty", libs)
	}
}

func TestRemediationDBConsistency(t *testing.T) {
	// Verify all entries in remediationDB have required fields
	for key, r := range remediationDB {
		t.Run(key, func(t *testing.T) {
			if r.Summary == "" {
				t.Error("Summary is empty")
			}
			if r.Replacement == "" {
				t.Error("Replacement is empty")
			}
			if r.Timeline == "" {
				t.Error("Timeline is empty")
			}
			if r.Effort == "" {
				t.Error("Effort is empty")
			}

			// Validate timeline values
			validTimelines := map[string]bool{
				"immediate":   true,
				"short-term":  true,
				"medium-term": true,
				"none":        true,
			}
			if !validTimelines[r.Timeline] {
				t.Errorf("Invalid timeline: %q", r.Timeline)
			}

			// Validate effort values
			validEfforts := map[string]bool{
				"low":    true,
				"medium": true,
				"high":   true,
				"none":   true,
			}
			if !validEfforts[r.Effort] {
				t.Errorf("Invalid effort: %q", r.Effort)
			}
		})
	}
}

func TestNISTStandardsPresent(t *testing.T) {
	// Key algorithms should reference NIST PQC standards
	keyAlgorithms := map[string]string{
		"RSA":     "FIPS 203",
		"ECDH":    "FIPS 203",
		"DH":      "FIPS 203",
		"X25519":  "FIPS 203",
		"ECDSA":   "FIPS 204",
		"Ed25519": "FIPS 204",
		"DSA":     "FIPS 204",
	}

	for algo, wantNIST := range keyAlgorithms {
		t.Run(algo, func(t *testing.T) {
			r, ok := remediationDB[algo]
			if !ok {
				t.Fatalf("Algorithm %q not in remediationDB", algo)
			}
			if r.NISTStandard != wantNIST {
				t.Errorf("NISTStandard = %q, want %q", r.NISTStandard, wantNIST)
			}
		})
	}
}
