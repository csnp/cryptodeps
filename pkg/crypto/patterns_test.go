// Copyright 2024-2025 CSNP (csnp.org)
// SPDX-License-Identifier: Apache-2.0

package crypto

import (
	"testing"

	"github.com/csnp/qramm-cryptodeps/pkg/types"
)

func TestGetPatternsForEcosystem(t *testing.T) {
	ecosystems := []types.Ecosystem{
		types.EcosystemGo,
		types.EcosystemNPM,
		types.EcosystemPyPI,
		types.EcosystemMaven,
	}

	for _, eco := range ecosystems {
		t.Run(string(eco), func(t *testing.T) {
			patterns := GetPatternsForEcosystem(eco)
			if len(patterns) == 0 {
				t.Errorf("GetPatternsForEcosystem(%q) returned empty slice", eco)
			}

			// Verify all patterns have required fields
			for _, p := range patterns {
				if p.Pattern == "" {
					t.Error("Pattern has empty Pattern field")
				}
				if p.Ecosystem != eco {
					t.Errorf("Pattern ecosystem = %q, want %q", p.Ecosystem, eco)
				}
				if p.Description == "" {
					t.Error("Pattern has empty Description field")
				}
			}
		})
	}
}

func TestGetPatternsForUnknownEcosystem(t *testing.T) {
	patterns := GetPatternsForEcosystem("unknown")
	if len(patterns) > 0 {
		t.Errorf("GetPatternsForEcosystem(unknown) = %v, want empty/nil", patterns)
	}
}

func TestIsCryptoImport_Go(t *testing.T) {
	tests := []struct {
		name       string
		importPath string
		wantMatch  bool
	}{
		// Standard library exact matches
		{"crypto/aes", "crypto/aes", true},
		{"crypto/rsa", "crypto/rsa", true},
		{"crypto/ecdsa", "crypto/ecdsa", true},
		{"crypto/ed25519", "crypto/ed25519", true},
		{"crypto/sha256", "crypto/sha256", true},
		{"crypto/md5", "crypto/md5", true},
		{"crypto/tls", "crypto/tls", true},

		// Extended library
		{"x/crypto base", "golang.org/x/crypto", true},
		{"x/crypto/chacha20", "golang.org/x/crypto/chacha20", true},
		{"x/crypto/ed25519", "golang.org/x/crypto/ed25519", true},
		{"x/crypto/argon2", "golang.org/x/crypto/argon2", true},

		// Third-party
		{"jwt-go new", "github.com/golang-jwt/jwt", true},
		{"jwt-go deprecated", "github.com/dgrijalva/jwt-go", true},

		// Subpackage matches
		{"jwt subpackage", "github.com/golang-jwt/jwt/v5", true},
		{"x/crypto subpkg", "golang.org/x/crypto/nacl/box", true},

		// Non-crypto imports
		{"fmt", "fmt", false},
		{"net/http", "net/http", false},
		{"encoding/json", "encoding/json", false},
		{"github.com/other/pkg", "github.com/other/pkg", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, found := IsCryptoImport(tt.importPath, types.EcosystemGo)
			if found != tt.wantMatch {
				t.Errorf("IsCryptoImport(%q, Go) found = %v, want %v", tt.importPath, found, tt.wantMatch)
			}
		})
	}
}

func TestIsCryptoImport_NPM(t *testing.T) {
	tests := []struct {
		importPath string
		wantMatch  bool
	}{
		{"crypto", true},
		{"node:crypto", true},
		{"bcrypt", true},
		{"crypto-js", true},
		{"jsonwebtoken", true},
		{"jose", true},
		{"tweetnacl", true},
		{"argon2", true},

		// Non-crypto
		{"express", false},
		{"lodash", false},
		{"react", false},
	}

	for _, tt := range tests {
		t.Run(tt.importPath, func(t *testing.T) {
			_, found := IsCryptoImport(tt.importPath, types.EcosystemNPM)
			if found != tt.wantMatch {
				t.Errorf("IsCryptoImport(%q, NPM) = %v, want %v", tt.importPath, found, tt.wantMatch)
			}
		})
	}
}

func TestIsCryptoImport_PyPI(t *testing.T) {
	tests := []struct {
		importPath string
		wantMatch  bool
	}{
		{"hashlib", true},
		{"hmac", true},
		{"ssl", true},
		{"cryptography", true},
		{"pycryptodome", true},
		{"nacl", true},
		{"bcrypt", true},
		{"PyJWT", true},
		{"paramiko", true},

		// Non-crypto
		{"requests", false},
		{"numpy", false},
		{"django", false},
	}

	for _, tt := range tests {
		t.Run(tt.importPath, func(t *testing.T) {
			_, found := IsCryptoImport(tt.importPath, types.EcosystemPyPI)
			if found != tt.wantMatch {
				t.Errorf("IsCryptoImport(%q, PyPI) = %v, want %v", tt.importPath, found, tt.wantMatch)
			}
		})
	}
}

func TestIsCryptoImport_Maven(t *testing.T) {
	tests := []struct {
		importPath string
		wantMatch  bool
	}{
		{"javax.crypto", true},
		{"java.security", true},
		{"org.bouncycastle", true},
		{"io.jsonwebtoken", true},
		{"com.google.crypto.tink", true},

		// Non-crypto
		{"java.util", false},
		{"org.springframework.web", false},
		{"com.fasterxml.jackson", false},
	}

	for _, tt := range tests {
		t.Run(tt.importPath, func(t *testing.T) {
			_, found := IsCryptoImport(tt.importPath, types.EcosystemMaven)
			if found != tt.wantMatch {
				t.Errorf("IsCryptoImport(%q, Maven) = %v, want %v", tt.importPath, found, tt.wantMatch)
			}
		})
	}
}

func TestIsCryptoImportAlgorithms(t *testing.T) {
	// Test that patterns have associated algorithms
	// Note: Some patterns match prefix (e.g., "crypto" matches "crypto/aes")
	// so we test patterns that have specific algorithm lists
	tests := []struct {
		importPath string
		ecosystem  types.Ecosystem
		wantAlgos  []string
	}{
		{"bcrypt", types.EcosystemNPM, []string{"bcrypt"}},
		{"jsonwebtoken", types.EcosystemNPM, []string{"RS256", "ES256", "HS256"}},
		{"github.com/golang-jwt/jwt", types.EcosystemGo, []string{"RS256", "ES256", "HS256"}},
	}

	for _, tt := range tests {
		t.Run(tt.importPath, func(t *testing.T) {
			pattern, found := IsCryptoImport(tt.importPath, tt.ecosystem)
			if !found {
				t.Fatalf("IsCryptoImport(%q, %q) not found", tt.importPath, tt.ecosystem)
			}

			for _, wantAlgo := range tt.wantAlgos {
				found := false
				for _, algo := range pattern.Algorithms {
					if algo == wantAlgo {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("Pattern %q missing algorithm %q, has %v", tt.importPath, wantAlgo, pattern.Algorithms)
				}
			}
		})
	}
}

func TestMatchesPrefix(t *testing.T) {
	tests := []struct {
		importPath string
		pattern    string
		want       bool
	}{
		// Exact match is not prefix match
		{"crypto/aes", "crypto/aes", false},

		// Subpackage matches (uses / separator)
		{"golang.org/x/crypto/nacl/box", "golang.org/x/crypto", true},
		{"github.com/golang-jwt/jwt/v5", "github.com/golang-jwt/jwt", true},

		// Not a prefix (different path)
		{"crypto/aes", "crypto/rsa", false},
		{"cryptography", "crypto", false}, // Not a subpackage

		// Partial word match should fail
		{"crypto-js", "crypto", false}, // Different separator

		// Java packages use . separator, not matched by matchesPrefix
		// which only checks for / separator
		{"org.bouncycastle.jce.provider", "org.bouncycastle", false},
	}

	for _, tt := range tests {
		t.Run(tt.importPath+"_"+tt.pattern, func(t *testing.T) {
			got := matchesPrefix(tt.importPath, tt.pattern)
			if got != tt.want {
				t.Errorf("matchesPrefix(%q, %q) = %v, want %v", tt.importPath, tt.pattern, got, tt.want)
			}
		})
	}
}

func TestAllPatternsHaveEcosystem(t *testing.T) {
	for eco, patterns := range CryptoImportPatterns {
		for _, p := range patterns {
			if p.Ecosystem != eco {
				t.Errorf("Pattern %q has ecosystem %q but is in %q map", p.Pattern, p.Ecosystem, eco)
			}
		}
	}
}
