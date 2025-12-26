// Copyright 2024-2025 CSNP (csnp.org)
// SPDX-License-Identifier: Apache-2.0

package crypto

import (
	"testing"

	"github.com/csnp/qramm-cryptodeps/pkg/types"
)

func TestClassifyAlgorithm(t *testing.T) {
	tests := []struct {
		name      string
		algorithm string
		wantFound bool
		wantName  string
		wantRisk  types.QuantumRisk
	}{
		// Vulnerable asymmetric algorithms
		{"RSA lowercase", "rsa", true, "RSA", types.RiskVulnerable},
		{"RSA uppercase", "RSA", true, "RSA", types.RiskVulnerable},
		{"RSA-2048", "rsa-2048", true, "RSA-2048", types.RiskVulnerable},
		{"ECDSA", "ecdsa", true, "ECDSA", types.RiskVulnerable},
		{"Ed25519", "ed25519", true, "Ed25519", types.RiskVulnerable},
		{"X25519", "x25519", true, "X25519", types.RiskVulnerable},
		{"ECDH", "ecdh", true, "ECDH", types.RiskVulnerable},
		{"DSA", "dsa", true, "DSA", types.RiskVulnerable},
		{"DH", "dh", true, "DH", types.RiskVulnerable},

		// JWT algorithms - vulnerable
		{"RS256", "rs256", true, "RS256", types.RiskVulnerable},
		{"ES256", "es256", true, "ES256", types.RiskVulnerable},
		{"PS256", "ps256", true, "PS256", types.RiskVulnerable},

		// JWT algorithms - partial
		{"HS256", "hs256", true, "HS256", types.RiskPartial},
		{"HS384", "hs384", true, "HS384", types.RiskPartial},

		// JWT algorithms - safe
		{"HS512", "hs512", true, "HS512", types.RiskSafe},

		// Symmetric - partial risk
		{"AES generic", "aes", true, "AES", types.RiskPartial},
		{"AES-128", "aes-128", true, "AES-128", types.RiskPartial},
		{"AES-GCM", "aes-gcm", true, "AES-GCM", types.RiskPartial},

		// Symmetric - safe
		{"AES-256", "aes-256", true, "AES-256", types.RiskSafe},
		{"ChaCha20", "chacha20", true, "ChaCha20", types.RiskSafe},
		{"XChaCha20", "xchacha20", true, "XChaCha20", types.RiskSafe},

		// Hash functions
		{"MD5", "md5", true, "MD5", types.RiskVulnerable},
		{"SHA-1", "sha-1", true, "SHA-1", types.RiskVulnerable},
		{"SHA1 variant", "sha1", true, "SHA-1", types.RiskVulnerable},
		{"SHA-256", "sha-256", true, "SHA-256", types.RiskPartial},
		{"SHA256 variant", "sha256", true, "SHA-256", types.RiskPartial},
		{"SHA-384", "sha-384", true, "SHA-384", types.RiskSafe},
		{"SHA-512", "sha-512", true, "SHA-512", types.RiskSafe},
		{"BLAKE2", "blake2", true, "BLAKE2", types.RiskSafe},
		{"BLAKE3", "blake3", true, "BLAKE3", types.RiskSafe},

		// Broken algorithms
		{"DES", "des", true, "DES", types.RiskVulnerable},
		{"3DES", "3des", true, "3DES", types.RiskVulnerable},
		{"RC4", "rc4", true, "RC4", types.RiskVulnerable},

		// Post-quantum safe
		{"ML-KEM", "ml-kem", true, "ML-KEM", types.RiskSafe},
		{"ML-DSA", "ml-dsa", true, "ML-DSA", types.RiskSafe},
		{"SLH-DSA", "slh-dsa", true, "SLH-DSA", types.RiskSafe},
		{"Kyber", "kyber", true, "Kyber", types.RiskSafe},
		{"Dilithium", "dilithium", true, "Dilithium", types.RiskSafe},

		// Unknown algorithm
		{"Unknown", "unknown-algo", false, "", types.RiskUnknown},
		{"Empty", "", false, "", types.RiskUnknown},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			info, found := ClassifyAlgorithm(tt.algorithm)
			if found != tt.wantFound {
				t.Errorf("ClassifyAlgorithm(%q) found = %v, want %v", tt.algorithm, found, tt.wantFound)
			}
			if found {
				if info.Name != tt.wantName {
					t.Errorf("ClassifyAlgorithm(%q) name = %q, want %q", tt.algorithm, info.Name, tt.wantName)
				}
				if info.QuantumRisk != tt.wantRisk {
					t.Errorf("ClassifyAlgorithm(%q) risk = %v, want %v", tt.algorithm, info.QuantumRisk, tt.wantRisk)
				}
			}
		})
	}
}

func TestClassifyAlgorithmUnderscoreNormalization(t *testing.T) {
	// Test that underscores are normalized to hyphens
	info, found := ClassifyAlgorithm("aes_256")
	if !found {
		t.Error("ClassifyAlgorithm should find aes_256 (normalized to aes-256)")
	}
	if info.Name != "AES-256" {
		t.Errorf("ClassifyAlgorithm(aes_256) name = %q, want AES-256", info.Name)
	}
}

func TestGetQuantumRisk(t *testing.T) {
	tests := []struct {
		algorithm string
		want      types.QuantumRisk
	}{
		{"rsa", types.RiskVulnerable},
		{"aes-256", types.RiskSafe},
		{"sha-256", types.RiskPartial},
		{"unknown", types.RiskUnknown},
	}

	for _, tt := range tests {
		t.Run(tt.algorithm, func(t *testing.T) {
			got := GetQuantumRisk(tt.algorithm)
			if got != tt.want {
				t.Errorf("GetQuantumRisk(%q) = %v, want %v", tt.algorithm, got, tt.want)
			}
		})
	}
}

func TestGetSeverity(t *testing.T) {
	tests := []struct {
		algorithm string
		want      types.Severity
	}{
		{"rsa", types.SeverityHigh},
		{"md5", types.SeverityCritical},
		{"sha-1", types.SeverityCritical},
		{"aes-128", types.SeverityLow},
		{"aes-256", types.SeverityInfo},
		{"unknown", types.SeverityInfo}, // Default for unknown
	}

	for _, tt := range tests {
		t.Run(tt.algorithm, func(t *testing.T) {
			got := GetSeverity(tt.algorithm)
			if got != tt.want {
				t.Errorf("GetSeverity(%q) = %v, want %v", tt.algorithm, got, tt.want)
			}
		})
	}
}

func TestIsVulnerable(t *testing.T) {
	vulnerable := []string{"rsa", "ecdsa", "ed25519", "dsa", "md5", "sha1", "des", "rc4"}
	notVulnerable := []string{"aes-256", "chacha20", "sha-512", "ml-kem", "dilithium"}

	for _, alg := range vulnerable {
		t.Run(alg+"_vulnerable", func(t *testing.T) {
			if !IsVulnerable(alg) {
				t.Errorf("IsVulnerable(%q) = false, want true", alg)
			}
		})
	}

	for _, alg := range notVulnerable {
		t.Run(alg+"_not_vulnerable", func(t *testing.T) {
			if IsVulnerable(alg) {
				t.Errorf("IsVulnerable(%q) = true, want false", alg)
			}
		})
	}
}

func TestNormalizeAlgorithmName(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"rsa", "RSA"},
		{"RSA", "RSA"},
		{"sha256", "SHA-256"},
		{"sha-256", "SHA-256"},
		{"aes_gcm", "AES-GCM"},
		{"ml-kem", "ML-KEM"},
		{"unknown-algo", "unknown-algo"}, // Returns original if not found
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := NormalizeAlgorithmName(tt.input)
			if got != tt.want {
				t.Errorf("NormalizeAlgorithmName(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestGetRemediation(t *testing.T) {
	tests := []struct {
		algorithm   string
		wantContain string
		wantEmpty   bool
	}{
		{"rsa", "ML-KEM", false},
		{"ecdsa", "ML-DSA", false},
		{"ed25519", "ML-DSA", false},
		{"aes-128", "AES-256", false},
		{"md5", "SHA-256", false},
		{"aes-256", "quantum safe", false},
		{"unknown", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.algorithm, func(t *testing.T) {
			got := GetRemediation(tt.algorithm)
			if tt.wantEmpty && got != "" {
				t.Errorf("GetRemediation(%q) = %q, want empty", tt.algorithm, got)
			}
			if !tt.wantEmpty && got == "" {
				t.Errorf("GetRemediation(%q) = empty, want non-empty", tt.algorithm)
			}
			if tt.wantContain != "" && !containsIgnoreCase(got, tt.wantContain) {
				t.Errorf("GetRemediation(%q) = %q, want to contain %q", tt.algorithm, got, tt.wantContain)
			}
		})
	}
}

func TestAlgorithmInfoFields(t *testing.T) {
	// Test that all algorithms have required fields
	for key, info := range algorithmDatabase {
		t.Run(key, func(t *testing.T) {
			if info.Name == "" {
				t.Errorf("Algorithm %q has empty Name", key)
			}
			if info.Type == "" {
				t.Errorf("Algorithm %q has empty Type", key)
			}
			if info.Description == "" {
				t.Errorf("Algorithm %q has empty Description", key)
			}
			// Remediation can be empty for unknown risk
			if info.QuantumRisk != types.RiskUnknown && info.Remediation == "" {
				t.Errorf("Algorithm %q has empty Remediation", key)
			}
		})
	}
}

func TestAlgorithmTypes(t *testing.T) {
	validTypes := map[string]bool{
		"encryption":   true,
		"signature":    true,
		"hash":         true,
		"key-exchange": true,
		"mac":          true,
	}

	for key, info := range algorithmDatabase {
		t.Run(key, func(t *testing.T) {
			if !validTypes[info.Type] {
				t.Errorf("Algorithm %q has invalid type %q", key, info.Type)
			}
		})
	}
}

// Helper function
func containsIgnoreCase(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) == 0 ||
		(len(s) > 0 && containsIgnoreCaseImpl(s, substr)))
}

func containsIgnoreCaseImpl(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if equalIgnoreCase(s[i:i+len(substr)], substr) {
			return true
		}
	}
	return false
}

func equalIgnoreCase(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		ca, cb := a[i], b[i]
		if ca >= 'A' && ca <= 'Z' {
			ca += 'a' - 'A'
		}
		if cb >= 'A' && cb <= 'Z' {
			cb += 'a' - 'A'
		}
		if ca != cb {
			return false
		}
	}
	return true
}
