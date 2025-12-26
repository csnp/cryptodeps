// Copyright 2024-2025 CSNP (csnp.org)
// SPDX-License-Identifier: Apache-2.0

// Package database provides the crypto knowledge base lookup functionality.
package database

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/csnp/qramm-cryptodeps/pkg/crypto"
	"github.com/csnp/qramm-cryptodeps/pkg/types"
)

// Database represents the crypto knowledge base.
type Database struct {
	path  string
	index map[types.Ecosystem]map[string]*types.PackageAnalysis
}

// New creates a new database instance.
func New(path string) *Database {
	return &Database{
		path:  path,
		index: make(map[types.Ecosystem]map[string]*types.PackageAnalysis),
	}
}

// NewEmbedded creates a database with embedded seed data.
func NewEmbedded() *Database {
	db := &Database{
		path:  "",
		index: make(map[types.Ecosystem]map[string]*types.PackageAnalysis),
	}
	db.loadEmbeddedData()
	return db
}

// Load loads the database from disk.
func (db *Database) Load() error {
	if db.path == "" {
		return nil // Embedded-only database
	}

	// Walk the database directory
	return filepath.Walk(db.path, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Skip non-YAML files
		if info.IsDir() || !strings.HasSuffix(path, ".yaml") {
			return nil
		}

		// Read and parse the file
		data, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("failed to read %s: %w", path, err)
		}

		var analysis types.PackageAnalysis
		if err := yaml.Unmarshal(data, &analysis); err != nil {
			return fmt.Errorf("failed to parse %s: %w", path, err)
		}

		// Add to index
		db.addToIndex(&analysis)

		return nil
	})
}

// Lookup looks up a package in the database.
// It enriches results with remediation guidance for each crypto usage.
func (db *Database) Lookup(ecosystem types.Ecosystem, name, version string) (*types.PackageAnalysis, bool) {
	ecosystemIndex, ok := db.index[ecosystem]
	if !ok {
		return nil, false
	}

	// Try exact version match first
	key := makeKey(name, version)
	if analysis, ok := ecosystemIndex[key]; ok {
		return enrichWithRemediation(analysis, ecosystem), true
	}

	// Try without version (latest/any)
	key = makeKey(name, "")
	if analysis, ok := ecosystemIndex[key]; ok {
		return enrichWithRemediation(analysis, ecosystem), true
	}

	return nil, false
}

// enrichWithRemediation adds remediation guidance to each CryptoUsage in the analysis.
func enrichWithRemediation(analysis *types.PackageAnalysis, ecosystem types.Ecosystem) *types.PackageAnalysis {
	// Create a copy to avoid modifying the cached data
	result := *analysis
	result.Crypto = make([]types.CryptoUsage, len(analysis.Crypto))
	copy(result.Crypto, analysis.Crypto)

	// Enrich each crypto usage with remediation
	for i := range result.Crypto {
		if result.Crypto[i].Remediation == "" {
			result.Crypto[i].Remediation = crypto.GetRemediationSummary(
				result.Crypto[i].Algorithm,
				result.Crypto[i].Type,
				ecosystem,
			)
		}
	}

	return &result
}

// Stats returns statistics about the database.
func (db *Database) Stats() DatabaseStats {
	stats := DatabaseStats{
		ByEcosystem: make(map[types.Ecosystem]int),
	}

	for ecosystem, pkgs := range db.index {
		stats.ByEcosystem[ecosystem] = len(pkgs)
		stats.TotalPackages += len(pkgs)
	}

	return stats
}

// DatabaseStats contains statistics about the database.
type DatabaseStats struct {
	TotalPackages int
	ByEcosystem   map[types.Ecosystem]int
}

// addToIndex adds a package analysis to the index.
func (db *Database) addToIndex(analysis *types.PackageAnalysis) {
	if _, ok := db.index[analysis.Ecosystem]; !ok {
		db.index[analysis.Ecosystem] = make(map[string]*types.PackageAnalysis)
	}

	// Index by name+version and name-only
	key := makeKey(analysis.Package, analysis.Version)
	db.index[analysis.Ecosystem][key] = analysis

	keyNoVersion := makeKey(analysis.Package, "")
	db.index[analysis.Ecosystem][keyNoVersion] = analysis
}

// makeKey creates a lookup key from package name and version.
func makeKey(name, version string) string {
	if version == "" {
		return strings.ToLower(name)
	}
	return strings.ToLower(name) + "@" + version
}

// ExportAll returns all packages in the database for serialization.
func (db *Database) ExportAll() []types.PackageAnalysis {
	seen := make(map[string]bool)
	result := make([]types.PackageAnalysis, 0)

	for _, ecosystemPkgs := range db.index {
		for key, pkg := range ecosystemPkgs {
			// Skip version-specific duplicates
			if strings.Contains(key, "@") {
				continue
			}
			pkgKey := string(pkg.Ecosystem) + ":" + pkg.Package
			if seen[pkgKey] {
				continue
			}
			seen[pkgKey] = true
			result = append(result, *pkg)
		}
	}

	return result
}

// loadEmbeddedData loads the built-in seed data for common crypto packages.
func (db *Database) loadEmbeddedData() {
	// Seed data for common crypto-using packages
	seedData := []types.PackageAnalysis{
		// Go packages
		{
			Package:   "golang.org/x/crypto",
			Version:   "",
			Ecosystem: types.EcosystemGo,
			Analysis: types.AnalysisMetadata{
				Date:        time.Now(),
				Method:      "embedded",
				Tool:        "cryptodeps",
				ToolVersion: "1.0.0",
			},
			Crypto: []types.CryptoUsage{
				{Algorithm: "Ed25519", Type: "signature", QuantumRisk: types.RiskVulnerable, Severity: types.SeverityHigh, Remediation: "Migrate to ML-DSA (FIPS 204) for signatures"},
				{Algorithm: "ChaCha20-Poly1305", Type: "encryption", QuantumRisk: types.RiskSafe, Severity: types.SeverityInfo, Remediation: "No action needed - quantum safe"},
				{Algorithm: "bcrypt", Type: "hash", QuantumRisk: types.RiskSafe, Severity: types.SeverityInfo, Remediation: "No action needed - quantum safe"},
				{Algorithm: "X25519", Type: "key-exchange", QuantumRisk: types.RiskVulnerable, Severity: types.SeverityHigh, Remediation: "Migrate to ML-KEM (FIPS 203) for key exchange"},
				{Algorithm: "Argon2", Type: "hash", QuantumRisk: types.RiskSafe, Severity: types.SeverityInfo, Remediation: "No action needed - quantum safe"},
			},
			QuantumSummary: types.QuantumSummary{Vulnerable: 2, Partial: 0, Safe: 3},
		},
		{
			Package:   "github.com/golang-jwt/jwt/v5",
			Version:   "",
			Ecosystem: types.EcosystemGo,
			Analysis: types.AnalysisMetadata{
				Date:   time.Now(),
				Method: "embedded",
				Tool:   "cryptodeps",
			},
			Crypto: []types.CryptoUsage{
				{Algorithm: "RS256", Type: "signature", QuantumRisk: types.RiskVulnerable, Severity: types.SeverityHigh, Remediation: "Use HS256/HS512 for symmetric signing, or wait for PQ-JWT standards"},
				{Algorithm: "RS384", Type: "signature", QuantumRisk: types.RiskVulnerable, Severity: types.SeverityHigh, Remediation: "Use HS384/HS512 for symmetric signing, or wait for PQ-JWT standards"},
				{Algorithm: "RS512", Type: "signature", QuantumRisk: types.RiskVulnerable, Severity: types.SeverityHigh, Remediation: "Use HS512 for symmetric signing, or wait for PQ-JWT standards"},
				{Algorithm: "ES256", Type: "signature", QuantumRisk: types.RiskVulnerable, Severity: types.SeverityHigh, Remediation: "Use HS256/HS512 for symmetric signing, or wait for PQ-JWT standards"},
				{Algorithm: "ES384", Type: "signature", QuantumRisk: types.RiskVulnerable, Severity: types.SeverityHigh, Remediation: "Use HS384/HS512 for symmetric signing, or wait for PQ-JWT standards"},
				{Algorithm: "ES512", Type: "signature", QuantumRisk: types.RiskVulnerable, Severity: types.SeverityHigh, Remediation: "Use HS512 for symmetric signing, or wait for PQ-JWT standards"},
				{Algorithm: "HS256", Type: "signature", QuantumRisk: types.RiskPartial, Severity: types.SeverityInfo, Remediation: "Consider HS512 for stronger post-quantum security"},
				{Algorithm: "HS384", Type: "signature", QuantumRisk: types.RiskPartial, Severity: types.SeverityInfo, Remediation: "Consider HS512 for stronger post-quantum security"},
				{Algorithm: "HS512", Type: "signature", QuantumRisk: types.RiskSafe, Severity: types.SeverityInfo, Remediation: "No action needed - quantum safe"},
			},
			QuantumSummary: types.QuantumSummary{Vulnerable: 6, Partial: 2, Safe: 1},
		},
		// npm packages
		{
			Package:   "jsonwebtoken",
			Version:   "",
			Ecosystem: types.EcosystemNPM,
			Analysis: types.AnalysisMetadata{
				Date:   time.Now(),
				Method: "embedded",
				Tool:   "cryptodeps",
			},
			Crypto: []types.CryptoUsage{
				{Algorithm: "RS256", Type: "signature", QuantumRisk: types.RiskVulnerable, Severity: types.SeverityHigh, Remediation: "Use HS256/HS512 for symmetric signing, or wait for PQ-JWT standards"},
				{Algorithm: "ES256", Type: "signature", QuantumRisk: types.RiskVulnerable, Severity: types.SeverityHigh, Remediation: "Use HS256/HS512 for symmetric signing, or wait for PQ-JWT standards"},
				{Algorithm: "HS256", Type: "signature", QuantumRisk: types.RiskPartial, Severity: types.SeverityInfo, Remediation: "Consider HS512 for stronger post-quantum security"},
			},
			QuantumSummary: types.QuantumSummary{Vulnerable: 2, Partial: 1, Safe: 0},
		},
		{
			Package:   "bcrypt",
			Version:   "",
			Ecosystem: types.EcosystemNPM,
			Analysis: types.AnalysisMetadata{
				Date:   time.Now(),
				Method: "embedded",
				Tool:   "cryptodeps",
			},
			Crypto: []types.CryptoUsage{
				{Algorithm: "bcrypt", Type: "hash", QuantumRisk: types.RiskSafe, Severity: types.SeverityInfo, Remediation: "No action needed - quantum safe"},
			},
			QuantumSummary: types.QuantumSummary{Vulnerable: 0, Partial: 0, Safe: 1},
		},
		{
			Package:   "crypto-js",
			Version:   "",
			Ecosystem: types.EcosystemNPM,
			Analysis: types.AnalysisMetadata{
				Date:   time.Now(),
				Method: "embedded",
				Tool:   "cryptodeps",
			},
			Crypto: []types.CryptoUsage{
				{Algorithm: "AES", Type: "encryption", QuantumRisk: types.RiskPartial, Severity: types.SeverityInfo, Remediation: "Use AES-256 for 128-bit post-quantum security"},
				{Algorithm: "DES", Type: "encryption", QuantumRisk: types.RiskVulnerable, Severity: types.SeverityCritical, Remediation: "Replace immediately with AES-256"},
				{Algorithm: "3DES", Type: "encryption", QuantumRisk: types.RiskVulnerable, Severity: types.SeverityHigh, Remediation: "Replace with AES-256"},
				{Algorithm: "MD5", Type: "hash", QuantumRisk: types.RiskVulnerable, Severity: types.SeverityCritical, Remediation: "Replace immediately with SHA-256 or SHA-3"},
				{Algorithm: "SHA-1", Type: "hash", QuantumRisk: types.RiskVulnerable, Severity: types.SeverityCritical, Remediation: "Replace immediately with SHA-256 or SHA-3"},
				{Algorithm: "SHA-256", Type: "hash", QuantumRisk: types.RiskPartial, Severity: types.SeverityInfo, Remediation: "Consider SHA-384/SHA-512 for stronger post-quantum security"},
			},
			QuantumSummary: types.QuantumSummary{Vulnerable: 4, Partial: 2, Safe: 0},
		},
		// Python packages
		{
			Package:   "cryptography",
			Version:   "",
			Ecosystem: types.EcosystemPyPI,
			Analysis: types.AnalysisMetadata{
				Date:   time.Now(),
				Method: "embedded",
				Tool:   "cryptodeps",
			},
			Crypto: []types.CryptoUsage{
				{Algorithm: "RSA", Type: "encryption", QuantumRisk: types.RiskVulnerable, Severity: types.SeverityHigh, Remediation: "Migrate to ML-KEM (FIPS 203) for encryption or ML-DSA (FIPS 204) for signatures"},
				{Algorithm: "ECDSA", Type: "signature", QuantumRisk: types.RiskVulnerable, Severity: types.SeverityHigh, Remediation: "Migrate to ML-DSA (FIPS 204) for signatures"},
				{Algorithm: "Ed25519", Type: "signature", QuantumRisk: types.RiskVulnerable, Severity: types.SeverityHigh, Remediation: "Migrate to ML-DSA (FIPS 204) for signatures"},
				{Algorithm: "AES", Type: "encryption", QuantumRisk: types.RiskPartial, Severity: types.SeverityInfo, Remediation: "Use AES-256 for 128-bit post-quantum security"},
				{Algorithm: "ChaCha20", Type: "encryption", QuantumRisk: types.RiskSafe, Severity: types.SeverityInfo, Remediation: "No action needed - quantum safe"},
			},
			QuantumSummary: types.QuantumSummary{Vulnerable: 3, Partial: 1, Safe: 1},
		},
		{
			Package:   "PyJWT",
			Version:   "",
			Ecosystem: types.EcosystemPyPI,
			Analysis: types.AnalysisMetadata{
				Date:   time.Now(),
				Method: "embedded",
				Tool:   "cryptodeps",
			},
			Crypto: []types.CryptoUsage{
				{Algorithm: "RS256", Type: "signature", QuantumRisk: types.RiskVulnerable, Severity: types.SeverityHigh, Remediation: "Use HS256/HS512 for symmetric signing, or wait for PQ-JWT standards"},
				{Algorithm: "ES256", Type: "signature", QuantumRisk: types.RiskVulnerable, Severity: types.SeverityHigh, Remediation: "Use HS256/HS512 for symmetric signing, or wait for PQ-JWT standards"},
				{Algorithm: "HS256", Type: "signature", QuantumRisk: types.RiskPartial, Severity: types.SeverityInfo, Remediation: "Consider HS512 for stronger post-quantum security"},
			},
			QuantumSummary: types.QuantumSummary{Vulnerable: 2, Partial: 1, Safe: 0},
		},
		// Java/Maven packages
		{
			Package:   "org.bouncycastle:bcprov-jdk18on",
			Version:   "",
			Ecosystem: types.EcosystemMaven,
			Analysis: types.AnalysisMetadata{
				Date:   time.Now(),
				Method: "embedded",
				Tool:   "cryptodeps",
			},
			Crypto: []types.CryptoUsage{
				{Algorithm: "RSA", Type: "encryption", QuantumRisk: types.RiskVulnerable, Severity: types.SeverityHigh, Remediation: "Migrate to ML-KEM (FIPS 203) for encryption or ML-DSA (FIPS 204) for signatures"},
				{Algorithm: "ECDSA", Type: "signature", QuantumRisk: types.RiskVulnerable, Severity: types.SeverityHigh, Remediation: "Migrate to ML-DSA (FIPS 204) for signatures"},
				{Algorithm: "Ed25519", Type: "signature", QuantumRisk: types.RiskVulnerable, Severity: types.SeverityHigh, Remediation: "Migrate to ML-DSA (FIPS 204) for signatures"},
				{Algorithm: "AES", Type: "encryption", QuantumRisk: types.RiskPartial, Severity: types.SeverityInfo, Remediation: "Use AES-256 for 128-bit post-quantum security"},
				{Algorithm: "ChaCha20", Type: "encryption", QuantumRisk: types.RiskSafe, Severity: types.SeverityInfo, Remediation: "No action needed - quantum safe"},
				{Algorithm: "ML-KEM", Type: "key-exchange", QuantumRisk: types.RiskSafe, Severity: types.SeverityInfo, Remediation: "No action needed - quantum safe"},
				{Algorithm: "ML-DSA", Type: "signature", QuantumRisk: types.RiskSafe, Severity: types.SeverityInfo, Remediation: "No action needed - quantum safe"},
			},
			QuantumSummary: types.QuantumSummary{Vulnerable: 3, Partial: 1, Safe: 3},
		},
		{
			Package:   "io.jsonwebtoken:jjwt-api",
			Version:   "",
			Ecosystem: types.EcosystemMaven,
			Analysis: types.AnalysisMetadata{
				Date:   time.Now(),
				Method: "embedded",
				Tool:   "cryptodeps",
			},
			Crypto: []types.CryptoUsage{
				{Algorithm: "RS256", Type: "signature", QuantumRisk: types.RiskVulnerable, Severity: types.SeverityHigh, Remediation: "Use HS256/HS512 for symmetric signing, or wait for PQ-JWT standards"},
				{Algorithm: "RS384", Type: "signature", QuantumRisk: types.RiskVulnerable, Severity: types.SeverityHigh, Remediation: "Use HS384/HS512 for symmetric signing, or wait for PQ-JWT standards"},
				{Algorithm: "RS512", Type: "signature", QuantumRisk: types.RiskVulnerable, Severity: types.SeverityHigh, Remediation: "Use HS512 for symmetric signing, or wait for PQ-JWT standards"},
				{Algorithm: "ES256", Type: "signature", QuantumRisk: types.RiskVulnerable, Severity: types.SeverityHigh, Remediation: "Use HS256/HS512 for symmetric signing, or wait for PQ-JWT standards"},
				{Algorithm: "ES384", Type: "signature", QuantumRisk: types.RiskVulnerable, Severity: types.SeverityHigh, Remediation: "Use HS384/HS512 for symmetric signing, or wait for PQ-JWT standards"},
				{Algorithm: "HS256", Type: "signature", QuantumRisk: types.RiskPartial, Severity: types.SeverityInfo, Remediation: "Consider HS512 for stronger post-quantum security"},
				{Algorithm: "HS512", Type: "signature", QuantumRisk: types.RiskSafe, Severity: types.SeverityInfo, Remediation: "No action needed - quantum safe"},
			},
			QuantumSummary: types.QuantumSummary{Vulnerable: 5, Partial: 1, Safe: 1},
		},
		{
			Package:   "com.google.crypto.tink:tink",
			Version:   "",
			Ecosystem: types.EcosystemMaven,
			Analysis: types.AnalysisMetadata{
				Date:   time.Now(),
				Method: "embedded",
				Tool:   "cryptodeps",
			},
			Crypto: []types.CryptoUsage{
				{Algorithm: "AES-GCM", Type: "encryption", QuantumRisk: types.RiskPartial, Severity: types.SeverityInfo, Remediation: "Use AES-256-GCM for post-quantum security"},
				{Algorithm: "ChaCha20-Poly1305", Type: "encryption", QuantumRisk: types.RiskSafe, Severity: types.SeverityInfo, Remediation: "No action needed - quantum safe"},
				{Algorithm: "ECDSA", Type: "signature", QuantumRisk: types.RiskVulnerable, Severity: types.SeverityHigh, Remediation: "Migrate to ML-DSA (FIPS 204) for signatures"},
				{Algorithm: "Ed25519", Type: "signature", QuantumRisk: types.RiskVulnerable, Severity: types.SeverityHigh, Remediation: "Migrate to ML-DSA (FIPS 204) for signatures"},
				{Algorithm: "ECDH", Type: "key-exchange", QuantumRisk: types.RiskVulnerable, Severity: types.SeverityHigh, Remediation: "Migrate to ML-KEM (FIPS 203) for key exchange"},
				{Algorithm: "RSA", Type: "encryption", QuantumRisk: types.RiskVulnerable, Severity: types.SeverityHigh, Remediation: "Migrate to ML-KEM (FIPS 203) for encryption"},
			},
			QuantumSummary: types.QuantumSummary{Vulnerable: 4, Partial: 1, Safe: 1},
		},
		{
			Package:   "org.springframework.security:spring-security-crypto",
			Version:   "",
			Ecosystem: types.EcosystemMaven,
			Analysis: types.AnalysisMetadata{
				Date:   time.Now(),
				Method: "embedded",
				Tool:   "cryptodeps",
			},
			Crypto: []types.CryptoUsage{
				{Algorithm: "bcrypt", Type: "hash", QuantumRisk: types.RiskSafe, Severity: types.SeverityInfo, Remediation: "No action needed - quantum safe"},
				{Algorithm: "Argon2", Type: "hash", QuantumRisk: types.RiskSafe, Severity: types.SeverityInfo, Remediation: "No action needed - quantum safe"},
				{Algorithm: "scrypt", Type: "hash", QuantumRisk: types.RiskSafe, Severity: types.SeverityInfo, Remediation: "No action needed - quantum safe"},
				{Algorithm: "PBKDF2", Type: "hash", QuantumRisk: types.RiskPartial, Severity: types.SeverityInfo, Remediation: "Consider Argon2 for stronger security"},
			},
			QuantumSummary: types.QuantumSummary{Vulnerable: 0, Partial: 1, Safe: 3},
		},
		// Additional Go packages
		{
			Package:   "github.com/go-jose/go-jose/v3",
			Version:   "",
			Ecosystem: types.EcosystemGo,
			Analysis: types.AnalysisMetadata{
				Date:   time.Now(),
				Method: "embedded",
				Tool:   "cryptodeps",
			},
			Crypto: []types.CryptoUsage{
				{Algorithm: "RS256", Type: "signature", QuantumRisk: types.RiskVulnerable, Severity: types.SeverityHigh, Remediation: "Use HS256/HS512 for symmetric signing, or wait for PQ-JWT standards"},
				{Algorithm: "ES256", Type: "signature", QuantumRisk: types.RiskVulnerable, Severity: types.SeverityHigh, Remediation: "Use HS256/HS512 for symmetric signing, or wait for PQ-JWT standards"},
				{Algorithm: "A256GCM", Type: "encryption", QuantumRisk: types.RiskSafe, Severity: types.SeverityInfo, Remediation: "No action needed - quantum safe"},
				{Algorithm: "ECDH-ES", Type: "key-exchange", QuantumRisk: types.RiskVulnerable, Severity: types.SeverityHigh, Remediation: "Migrate to ML-KEM (FIPS 203) for key exchange"},
			},
			QuantumSummary: types.QuantumSummary{Vulnerable: 3, Partial: 0, Safe: 1},
		},
		{
			Package:   "github.com/hashicorp/vault/api",
			Version:   "",
			Ecosystem: types.EcosystemGo,
			Analysis: types.AnalysisMetadata{
				Date:   time.Now(),
				Method: "embedded",
				Tool:   "cryptodeps",
			},
			Crypto: []types.CryptoUsage{
				{Algorithm: "AES-GCM", Type: "encryption", QuantumRisk: types.RiskPartial, Severity: types.SeverityInfo, Remediation: "Use AES-256-GCM for post-quantum security"},
				{Algorithm: "RSA", Type: "encryption", QuantumRisk: types.RiskVulnerable, Severity: types.SeverityHigh, Remediation: "Migrate to ML-KEM (FIPS 203) for encryption"},
				{Algorithm: "ECDSA", Type: "signature", QuantumRisk: types.RiskVulnerable, Severity: types.SeverityHigh, Remediation: "Migrate to ML-DSA (FIPS 204) for signatures"},
				{Algorithm: "Ed25519", Type: "signature", QuantumRisk: types.RiskVulnerable, Severity: types.SeverityHigh, Remediation: "Migrate to ML-DSA (FIPS 204) for signatures"},
			},
			QuantumSummary: types.QuantumSummary{Vulnerable: 3, Partial: 1, Safe: 0},
		},
		{
			Package:   "filippo.io/age",
			Version:   "",
			Ecosystem: types.EcosystemGo,
			Analysis: types.AnalysisMetadata{
				Date:   time.Now(),
				Method: "embedded",
				Tool:   "cryptodeps",
			},
			Crypto: []types.CryptoUsage{
				{Algorithm: "X25519", Type: "key-exchange", QuantumRisk: types.RiskVulnerable, Severity: types.SeverityHigh, Remediation: "Migrate to ML-KEM (FIPS 203) for key exchange"},
				{Algorithm: "ChaCha20-Poly1305", Type: "encryption", QuantumRisk: types.RiskSafe, Severity: types.SeverityInfo, Remediation: "No action needed - quantum safe"},
				{Algorithm: "scrypt", Type: "hash", QuantumRisk: types.RiskSafe, Severity: types.SeverityInfo, Remediation: "No action needed - quantum safe"},
			},
			QuantumSummary: types.QuantumSummary{Vulnerable: 1, Partial: 0, Safe: 2},
		},
		// Additional npm packages
		{
			Package:   "node-forge",
			Version:   "",
			Ecosystem: types.EcosystemNPM,
			Analysis: types.AnalysisMetadata{
				Date:   time.Now(),
				Method: "embedded",
				Tool:   "cryptodeps",
			},
			Crypto: []types.CryptoUsage{
				{Algorithm: "RSA", Type: "encryption", QuantumRisk: types.RiskVulnerable, Severity: types.SeverityHigh, Remediation: "Migrate to ML-KEM (FIPS 203) for encryption or ML-DSA (FIPS 204) for signatures"},
				{Algorithm: "AES", Type: "encryption", QuantumRisk: types.RiskPartial, Severity: types.SeverityInfo, Remediation: "Use AES-256 for 128-bit post-quantum security"},
				{Algorithm: "DES", Type: "encryption", QuantumRisk: types.RiskVulnerable, Severity: types.SeverityCritical, Remediation: "Replace immediately with AES-256"},
				{Algorithm: "3DES", Type: "encryption", QuantumRisk: types.RiskVulnerable, Severity: types.SeverityHigh, Remediation: "Replace with AES-256"},
				{Algorithm: "MD5", Type: "hash", QuantumRisk: types.RiskVulnerable, Severity: types.SeverityCritical, Remediation: "Replace immediately with SHA-256 or SHA-3"},
				{Algorithm: "SHA-1", Type: "hash", QuantumRisk: types.RiskVulnerable, Severity: types.SeverityCritical, Remediation: "Replace immediately with SHA-256 or SHA-3"},
				{Algorithm: "SHA-256", Type: "hash", QuantumRisk: types.RiskPartial, Severity: types.SeverityInfo, Remediation: "Consider SHA-384/SHA-512 for stronger post-quantum security"},
			},
			QuantumSummary: types.QuantumSummary{Vulnerable: 5, Partial: 2, Safe: 0},
		},
		{
			Package:   "tweetnacl",
			Version:   "",
			Ecosystem: types.EcosystemNPM,
			Analysis: types.AnalysisMetadata{
				Date:   time.Now(),
				Method: "embedded",
				Tool:   "cryptodeps",
			},
			Crypto: []types.CryptoUsage{
				{Algorithm: "X25519", Type: "key-exchange", QuantumRisk: types.RiskVulnerable, Severity: types.SeverityHigh, Remediation: "Migrate to ML-KEM (FIPS 203) for key exchange"},
				{Algorithm: "Ed25519", Type: "signature", QuantumRisk: types.RiskVulnerable, Severity: types.SeverityHigh, Remediation: "Migrate to ML-DSA (FIPS 204) for signatures"},
				{Algorithm: "XSalsa20-Poly1305", Type: "encryption", QuantumRisk: types.RiskSafe, Severity: types.SeverityInfo, Remediation: "No action needed - quantum safe"},
			},
			QuantumSummary: types.QuantumSummary{Vulnerable: 2, Partial: 0, Safe: 1},
		},
		{
			Package:   "jose",
			Version:   "",
			Ecosystem: types.EcosystemNPM,
			Analysis: types.AnalysisMetadata{
				Date:   time.Now(),
				Method: "embedded",
				Tool:   "cryptodeps",
			},
			Crypto: []types.CryptoUsage{
				{Algorithm: "RS256", Type: "signature", QuantumRisk: types.RiskVulnerable, Severity: types.SeverityHigh, Remediation: "Use HS256/HS512 for symmetric signing, or wait for PQ-JWT standards"},
				{Algorithm: "ES256", Type: "signature", QuantumRisk: types.RiskVulnerable, Severity: types.SeverityHigh, Remediation: "Use HS256/HS512 for symmetric signing, or wait for PQ-JWT standards"},
				{Algorithm: "PS256", Type: "signature", QuantumRisk: types.RiskVulnerable, Severity: types.SeverityHigh, Remediation: "Use HS256/HS512 for symmetric signing, or wait for PQ-JWT standards"},
				{Algorithm: "A256GCM", Type: "encryption", QuantumRisk: types.RiskSafe, Severity: types.SeverityInfo, Remediation: "No action needed - quantum safe"},
				{Algorithm: "ECDH-ES", Type: "key-exchange", QuantumRisk: types.RiskVulnerable, Severity: types.SeverityHigh, Remediation: "Migrate to ML-KEM (FIPS 203) for key exchange"},
			},
			QuantumSummary: types.QuantumSummary{Vulnerable: 4, Partial: 0, Safe: 1},
		},
		{
			Package:   "argon2",
			Version:   "",
			Ecosystem: types.EcosystemNPM,
			Analysis: types.AnalysisMetadata{
				Date:   time.Now(),
				Method: "embedded",
				Tool:   "cryptodeps",
			},
			Crypto: []types.CryptoUsage{
				{Algorithm: "Argon2", Type: "hash", QuantumRisk: types.RiskSafe, Severity: types.SeverityInfo, Remediation: "No action needed - quantum safe"},
			},
			QuantumSummary: types.QuantumSummary{Vulnerable: 0, Partial: 0, Safe: 1},
		},
		{
			Package:   "sodium-native",
			Version:   "",
			Ecosystem: types.EcosystemNPM,
			Analysis: types.AnalysisMetadata{
				Date:   time.Now(),
				Method: "embedded",
				Tool:   "cryptodeps",
			},
			Crypto: []types.CryptoUsage{
				{Algorithm: "X25519", Type: "key-exchange", QuantumRisk: types.RiskVulnerable, Severity: types.SeverityHigh, Remediation: "Migrate to ML-KEM (FIPS 203) for key exchange"},
				{Algorithm: "Ed25519", Type: "signature", QuantumRisk: types.RiskVulnerable, Severity: types.SeverityHigh, Remediation: "Migrate to ML-DSA (FIPS 204) for signatures"},
				{Algorithm: "ChaCha20-Poly1305", Type: "encryption", QuantumRisk: types.RiskSafe, Severity: types.SeverityInfo, Remediation: "No action needed - quantum safe"},
				{Algorithm: "Argon2", Type: "hash", QuantumRisk: types.RiskSafe, Severity: types.SeverityInfo, Remediation: "No action needed - quantum safe"},
				{Algorithm: "BLAKE2b", Type: "hash", QuantumRisk: types.RiskSafe, Severity: types.SeverityInfo, Remediation: "No action needed - quantum safe"},
			},
			QuantumSummary: types.QuantumSummary{Vulnerable: 2, Partial: 0, Safe: 3},
		},
		// Additional Python packages
		{
			Package:   "pycryptodome",
			Version:   "",
			Ecosystem: types.EcosystemPyPI,
			Analysis: types.AnalysisMetadata{
				Date:   time.Now(),
				Method: "embedded",
				Tool:   "cryptodeps",
			},
			Crypto: []types.CryptoUsage{
				{Algorithm: "RSA", Type: "encryption", QuantumRisk: types.RiskVulnerable, Severity: types.SeverityHigh, Remediation: "Migrate to ML-KEM (FIPS 203) for encryption or ML-DSA (FIPS 204) for signatures"},
				{Algorithm: "ECDSA", Type: "signature", QuantumRisk: types.RiskVulnerable, Severity: types.SeverityHigh, Remediation: "Migrate to ML-DSA (FIPS 204) for signatures"},
				{Algorithm: "AES", Type: "encryption", QuantumRisk: types.RiskPartial, Severity: types.SeverityInfo, Remediation: "Use AES-256 for 128-bit post-quantum security"},
				{Algorithm: "ChaCha20", Type: "encryption", QuantumRisk: types.RiskSafe, Severity: types.SeverityInfo, Remediation: "No action needed - quantum safe"},
				{Algorithm: "DES", Type: "encryption", QuantumRisk: types.RiskVulnerable, Severity: types.SeverityCritical, Remediation: "Replace immediately with AES-256"},
				{Algorithm: "3DES", Type: "encryption", QuantumRisk: types.RiskVulnerable, Severity: types.SeverityHigh, Remediation: "Replace with AES-256"},
				{Algorithm: "MD5", Type: "hash", QuantumRisk: types.RiskVulnerable, Severity: types.SeverityCritical, Remediation: "Replace immediately with SHA-256 or SHA-3"},
				{Algorithm: "SHA-1", Type: "hash", QuantumRisk: types.RiskVulnerable, Severity: types.SeverityCritical, Remediation: "Replace immediately with SHA-256 or SHA-3"},
			},
			QuantumSummary: types.QuantumSummary{Vulnerable: 6, Partial: 1, Safe: 1},
		},
		{
			Package:   "pynacl",
			Version:   "",
			Ecosystem: types.EcosystemPyPI,
			Analysis: types.AnalysisMetadata{
				Date:   time.Now(),
				Method: "embedded",
				Tool:   "cryptodeps",
			},
			Crypto: []types.CryptoUsage{
				{Algorithm: "X25519", Type: "key-exchange", QuantumRisk: types.RiskVulnerable, Severity: types.SeverityHigh, Remediation: "Migrate to ML-KEM (FIPS 203) for key exchange"},
				{Algorithm: "Ed25519", Type: "signature", QuantumRisk: types.RiskVulnerable, Severity: types.SeverityHigh, Remediation: "Migrate to ML-DSA (FIPS 204) for signatures"},
				{Algorithm: "XSalsa20-Poly1305", Type: "encryption", QuantumRisk: types.RiskSafe, Severity: types.SeverityInfo, Remediation: "No action needed - quantum safe"},
				{Algorithm: "BLAKE2b", Type: "hash", QuantumRisk: types.RiskSafe, Severity: types.SeverityInfo, Remediation: "No action needed - quantum safe"},
				{Algorithm: "Argon2", Type: "hash", QuantumRisk: types.RiskSafe, Severity: types.SeverityInfo, Remediation: "No action needed - quantum safe"},
			},
			QuantumSummary: types.QuantumSummary{Vulnerable: 2, Partial: 0, Safe: 3},
		},
		{
			Package:   "paramiko",
			Version:   "",
			Ecosystem: types.EcosystemPyPI,
			Analysis: types.AnalysisMetadata{
				Date:   time.Now(),
				Method: "embedded",
				Tool:   "cryptodeps",
			},
			Crypto: []types.CryptoUsage{
				{Algorithm: "RSA", Type: "encryption", QuantumRisk: types.RiskVulnerable, Severity: types.SeverityHigh, Remediation: "Migrate to ML-KEM (FIPS 203) for encryption or ML-DSA (FIPS 204) for signatures"},
				{Algorithm: "ECDSA", Type: "signature", QuantumRisk: types.RiskVulnerable, Severity: types.SeverityHigh, Remediation: "Migrate to ML-DSA (FIPS 204) for signatures"},
				{Algorithm: "Ed25519", Type: "signature", QuantumRisk: types.RiskVulnerable, Severity: types.SeverityHigh, Remediation: "Migrate to ML-DSA (FIPS 204) for signatures"},
				{Algorithm: "AES", Type: "encryption", QuantumRisk: types.RiskPartial, Severity: types.SeverityInfo, Remediation: "Use AES-256 for 128-bit post-quantum security"},
				{Algorithm: "ChaCha20-Poly1305", Type: "encryption", QuantumRisk: types.RiskSafe, Severity: types.SeverityInfo, Remediation: "No action needed - quantum safe"},
			},
			QuantumSummary: types.QuantumSummary{Vulnerable: 3, Partial: 1, Safe: 1},
		},
		{
			Package:   "passlib",
			Version:   "",
			Ecosystem: types.EcosystemPyPI,
			Analysis: types.AnalysisMetadata{
				Date:   time.Now(),
				Method: "embedded",
				Tool:   "cryptodeps",
			},
			Crypto: []types.CryptoUsage{
				{Algorithm: "bcrypt", Type: "hash", QuantumRisk: types.RiskSafe, Severity: types.SeverityInfo, Remediation: "No action needed - quantum safe"},
				{Algorithm: "Argon2", Type: "hash", QuantumRisk: types.RiskSafe, Severity: types.SeverityInfo, Remediation: "No action needed - quantum safe"},
				{Algorithm: "scrypt", Type: "hash", QuantumRisk: types.RiskSafe, Severity: types.SeverityInfo, Remediation: "No action needed - quantum safe"},
				{Algorithm: "PBKDF2", Type: "hash", QuantumRisk: types.RiskPartial, Severity: types.SeverityInfo, Remediation: "Consider Argon2 for stronger security"},
				{Algorithm: "SHA-512", Type: "hash", QuantumRisk: types.RiskSafe, Severity: types.SeverityInfo, Remediation: "No action needed - quantum safe"},
			},
			QuantumSummary: types.QuantumSummary{Vulnerable: 0, Partial: 1, Safe: 4},
		},
		{
			Package:   "python-jose",
			Version:   "",
			Ecosystem: types.EcosystemPyPI,
			Analysis: types.AnalysisMetadata{
				Date:   time.Now(),
				Method: "embedded",
				Tool:   "cryptodeps",
			},
			Crypto: []types.CryptoUsage{
				{Algorithm: "RS256", Type: "signature", QuantumRisk: types.RiskVulnerable, Severity: types.SeverityHigh, Remediation: "Use HS256/HS512 for symmetric signing, or wait for PQ-JWT standards"},
				{Algorithm: "ES256", Type: "signature", QuantumRisk: types.RiskVulnerable, Severity: types.SeverityHigh, Remediation: "Use HS256/HS512 for symmetric signing, or wait for PQ-JWT standards"},
				{Algorithm: "HS256", Type: "signature", QuantumRisk: types.RiskPartial, Severity: types.SeverityInfo, Remediation: "Consider HS512 for stronger post-quantum security"},
				{Algorithm: "A256GCM", Type: "encryption", QuantumRisk: types.RiskSafe, Severity: types.SeverityInfo, Remediation: "No action needed - quantum safe"},
			},
			QuantumSummary: types.QuantumSummary{Vulnerable: 2, Partial: 1, Safe: 1},
		},
		// More Go packages
		{
			Package:   "github.com/ProtonMail/go-crypto",
			Version:   "",
			Ecosystem: types.EcosystemGo,
			Analysis: types.AnalysisMetadata{
				Date:   time.Now(),
				Method: "embedded",
				Tool:   "cryptodeps",
			},
			Crypto: []types.CryptoUsage{
				{Algorithm: "RSA", Type: "encryption", QuantumRisk: types.RiskVulnerable, Severity: types.SeverityHigh, Remediation: "Migrate to ML-KEM (FIPS 203) for encryption or ML-DSA (FIPS 204) for signatures"},
				{Algorithm: "ECDSA", Type: "signature", QuantumRisk: types.RiskVulnerable, Severity: types.SeverityHigh, Remediation: "Migrate to ML-DSA (FIPS 204) for signatures"},
				{Algorithm: "Ed25519", Type: "signature", QuantumRisk: types.RiskVulnerable, Severity: types.SeverityHigh, Remediation: "Migrate to ML-DSA (FIPS 204) for signatures"},
				{Algorithm: "X25519", Type: "key-exchange", QuantumRisk: types.RiskVulnerable, Severity: types.SeverityHigh, Remediation: "Migrate to ML-KEM (FIPS 203) for key exchange"},
				{Algorithm: "AES", Type: "encryption", QuantumRisk: types.RiskPartial, Severity: types.SeverityInfo, Remediation: "Use AES-256 for 128-bit post-quantum security"},
			},
			QuantumSummary: types.QuantumSummary{Vulnerable: 4, Partial: 1, Safe: 0},
		},
		{
			Package:   "github.com/cloudflare/cfssl",
			Version:   "",
			Ecosystem: types.EcosystemGo,
			Analysis: types.AnalysisMetadata{
				Date:   time.Now(),
				Method: "embedded",
				Tool:   "cryptodeps",
			},
			Crypto: []types.CryptoUsage{
				{Algorithm: "RSA", Type: "encryption", QuantumRisk: types.RiskVulnerable, Severity: types.SeverityHigh, Remediation: "Migrate to ML-KEM (FIPS 203) for encryption or ML-DSA (FIPS 204) for signatures"},
				{Algorithm: "ECDSA", Type: "signature", QuantumRisk: types.RiskVulnerable, Severity: types.SeverityHigh, Remediation: "Migrate to ML-DSA (FIPS 204) for signatures"},
				{Algorithm: "SHA-256", Type: "hash", QuantumRisk: types.RiskPartial, Severity: types.SeverityInfo, Remediation: "Consider SHA-384/SHA-512 for stronger post-quantum security"},
				{Algorithm: "SHA-384", Type: "hash", QuantumRisk: types.RiskSafe, Severity: types.SeverityInfo, Remediation: "No action needed - quantum safe"},
			},
			QuantumSummary: types.QuantumSummary{Vulnerable: 2, Partial: 1, Safe: 1},
		},
		{
			Package:   "github.com/pquerna/otp",
			Version:   "",
			Ecosystem: types.EcosystemGo,
			Analysis: types.AnalysisMetadata{
				Date:   time.Now(),
				Method: "embedded",
				Tool:   "cryptodeps",
			},
			Crypto: []types.CryptoUsage{
				{Algorithm: "HMAC-SHA1", Type: "mac", QuantumRisk: types.RiskPartial, Severity: types.SeverityMedium, Remediation: "Consider HMAC-SHA256 for stronger post-quantum security"},
				{Algorithm: "HMAC-SHA256", Type: "mac", QuantumRisk: types.RiskPartial, Severity: types.SeverityInfo, Remediation: "Consider HMAC-SHA512 for stronger post-quantum security"},
				{Algorithm: "HMAC-SHA512", Type: "mac", QuantumRisk: types.RiskSafe, Severity: types.SeverityInfo, Remediation: "No action needed - quantum safe"},
			},
			QuantumSummary: types.QuantumSummary{Vulnerable: 0, Partial: 2, Safe: 1},
		},
		{
			Package:   "github.com/open-quantum-safe/liboqs-go",
			Version:   "",
			Ecosystem: types.EcosystemGo,
			Analysis: types.AnalysisMetadata{
				Date:   time.Now(),
				Method: "embedded",
				Tool:   "cryptodeps",
			},
			Crypto: []types.CryptoUsage{
				{Algorithm: "ML-KEM", Type: "key-exchange", QuantumRisk: types.RiskSafe, Severity: types.SeverityInfo, Remediation: "No action needed - quantum safe"},
				{Algorithm: "ML-DSA", Type: "signature", QuantumRisk: types.RiskSafe, Severity: types.SeverityInfo, Remediation: "No action needed - quantum safe"},
				{Algorithm: "SLH-DSA", Type: "signature", QuantumRisk: types.RiskSafe, Severity: types.SeverityInfo, Remediation: "No action needed - quantum safe"},
				{Algorithm: "BIKE", Type: "key-exchange", QuantumRisk: types.RiskSafe, Severity: types.SeverityInfo, Remediation: "No action needed - quantum safe"},
				{Algorithm: "HQC", Type: "key-exchange", QuantumRisk: types.RiskSafe, Severity: types.SeverityInfo, Remediation: "No action needed - quantum safe"},
			},
			QuantumSummary: types.QuantumSummary{Vulnerable: 0, Partial: 0, Safe: 5},
		},
		{
			Package:   "github.com/miekg/pkcs11",
			Version:   "",
			Ecosystem: types.EcosystemGo,
			Analysis: types.AnalysisMetadata{
				Date:   time.Now(),
				Method: "embedded",
				Tool:   "cryptodeps",
			},
			Crypto: []types.CryptoUsage{
				{Algorithm: "RSA", Type: "encryption", QuantumRisk: types.RiskVulnerable, Severity: types.SeverityHigh, Remediation: "Migrate to ML-KEM (FIPS 203) for encryption or ML-DSA (FIPS 204) for signatures"},
				{Algorithm: "ECDSA", Type: "signature", QuantumRisk: types.RiskVulnerable, Severity: types.SeverityHigh, Remediation: "Migrate to ML-DSA (FIPS 204) for signatures"},
				{Algorithm: "AES", Type: "encryption", QuantumRisk: types.RiskPartial, Severity: types.SeverityInfo, Remediation: "Use AES-256 for 128-bit post-quantum security"},
				{Algorithm: "DES", Type: "encryption", QuantumRisk: types.RiskVulnerable, Severity: types.SeverityCritical, Remediation: "Replace immediately with AES-256"},
				{Algorithm: "3DES", Type: "encryption", QuantumRisk: types.RiskVulnerable, Severity: types.SeverityHigh, Remediation: "Replace with AES-256"},
			},
			QuantumSummary: types.QuantumSummary{Vulnerable: 4, Partial: 1, Safe: 0},
		},
		{
			Package:   "github.com/cossacklabs/themis/gothemis",
			Version:   "",
			Ecosystem: types.EcosystemGo,
			Analysis: types.AnalysisMetadata{
				Date:   time.Now(),
				Method: "embedded",
				Tool:   "cryptodeps",
			},
			Crypto: []types.CryptoUsage{
				{Algorithm: "AES-GCM", Type: "encryption", QuantumRisk: types.RiskPartial, Severity: types.SeverityInfo, Remediation: "Use AES-256-GCM for post-quantum security"},
				{Algorithm: "ECDH", Type: "key-exchange", QuantumRisk: types.RiskVulnerable, Severity: types.SeverityHigh, Remediation: "Migrate to ML-KEM (FIPS 203) for key exchange"},
				{Algorithm: "ECDSA", Type: "signature", QuantumRisk: types.RiskVulnerable, Severity: types.SeverityHigh, Remediation: "Migrate to ML-DSA (FIPS 204) for signatures"},
			},
			QuantumSummary: types.QuantumSummary{Vulnerable: 2, Partial: 1, Safe: 0},
		},
		{
			Package:   "github.com/secure-io/sio-go",
			Version:   "",
			Ecosystem: types.EcosystemGo,
			Analysis: types.AnalysisMetadata{
				Date:   time.Now(),
				Method: "embedded",
				Tool:   "cryptodeps",
			},
			Crypto: []types.CryptoUsage{
				{Algorithm: "AES-GCM", Type: "encryption", QuantumRisk: types.RiskPartial, Severity: types.SeverityInfo, Remediation: "Use AES-256-GCM for post-quantum security"},
				{Algorithm: "ChaCha20-Poly1305", Type: "encryption", QuantumRisk: types.RiskSafe, Severity: types.SeverityInfo, Remediation: "No action needed - quantum safe"},
			},
			QuantumSummary: types.QuantumSummary{Vulnerable: 0, Partial: 1, Safe: 1},
		},
		{
			Package:   "github.com/tjfoc/gmsm",
			Version:   "",
			Ecosystem: types.EcosystemGo,
			Analysis: types.AnalysisMetadata{
				Date:   time.Now(),
				Method: "embedded",
				Tool:   "cryptodeps",
			},
			Crypto: []types.CryptoUsage{
				{Algorithm: "SM2", Type: "encryption", QuantumRisk: types.RiskVulnerable, Severity: types.SeverityHigh, Remediation: "SM2 is ECDSA-based - migrate to ML-DSA (FIPS 204)"},
				{Algorithm: "SM3", Type: "hash", QuantumRisk: types.RiskPartial, Severity: types.SeverityInfo, Remediation: "Consider SHA-3 for post-quantum security"},
				{Algorithm: "SM4", Type: "encryption", QuantumRisk: types.RiskPartial, Severity: types.SeverityInfo, Remediation: "128-bit key - consider 256-bit alternatives for post-quantum security"},
			},
			QuantumSummary: types.QuantumSummary{Vulnerable: 1, Partial: 2, Safe: 0},
		},
		{
			Package:   "github.com/gtank/cryptopasta",
			Version:   "",
			Ecosystem: types.EcosystemGo,
			Analysis: types.AnalysisMetadata{
				Date:   time.Now(),
				Method: "embedded",
				Tool:   "cryptodeps",
			},
			Crypto: []types.CryptoUsage{
				{Algorithm: "AES-GCM", Type: "encryption", QuantumRisk: types.RiskPartial, Severity: types.SeverityInfo, Remediation: "Use AES-256-GCM for post-quantum security"},
				{Algorithm: "bcrypt", Type: "hash", QuantumRisk: types.RiskSafe, Severity: types.SeverityInfo, Remediation: "No action needed - quantum safe"},
				{Algorithm: "ECDSA", Type: "signature", QuantumRisk: types.RiskVulnerable, Severity: types.SeverityHigh, Remediation: "Migrate to ML-DSA (FIPS 204) for signatures"},
			},
			QuantumSummary: types.QuantumSummary{Vulnerable: 1, Partial: 1, Safe: 1},
		},
		// More npm packages
		{
			Package:   "openpgp",
			Version:   "",
			Ecosystem: types.EcosystemNPM,
			Analysis: types.AnalysisMetadata{
				Date:   time.Now(),
				Method: "embedded",
				Tool:   "cryptodeps",
			},
			Crypto: []types.CryptoUsage{
				{Algorithm: "RSA", Type: "encryption", QuantumRisk: types.RiskVulnerable, Severity: types.SeverityHigh, Remediation: "Migrate to ML-KEM (FIPS 203) for encryption or ML-DSA (FIPS 204) for signatures"},
				{Algorithm: "ECDSA", Type: "signature", QuantumRisk: types.RiskVulnerable, Severity: types.SeverityHigh, Remediation: "Migrate to ML-DSA (FIPS 204) for signatures"},
				{Algorithm: "Ed25519", Type: "signature", QuantumRisk: types.RiskVulnerable, Severity: types.SeverityHigh, Remediation: "Migrate to ML-DSA (FIPS 204) for signatures"},
				{Algorithm: "X25519", Type: "key-exchange", QuantumRisk: types.RiskVulnerable, Severity: types.SeverityHigh, Remediation: "Migrate to ML-KEM (FIPS 203) for key exchange"},
				{Algorithm: "AES", Type: "encryption", QuantumRisk: types.RiskPartial, Severity: types.SeverityInfo, Remediation: "Use AES-256 for 128-bit post-quantum security"},
			},
			QuantumSummary: types.QuantumSummary{Vulnerable: 4, Partial: 1, Safe: 0},
		},
		{
			Package:   "node-rsa",
			Version:   "",
			Ecosystem: types.EcosystemNPM,
			Analysis: types.AnalysisMetadata{
				Date:   time.Now(),
				Method: "embedded",
				Tool:   "cryptodeps",
			},
			Crypto: []types.CryptoUsage{
				{Algorithm: "RSA", Type: "encryption", QuantumRisk: types.RiskVulnerable, Severity: types.SeverityHigh, Remediation: "Migrate to ML-KEM (FIPS 203) for encryption or ML-DSA (FIPS 204) for signatures"},
			},
			QuantumSummary: types.QuantumSummary{Vulnerable: 1, Partial: 0, Safe: 0},
		},
		{
			Package:   "libsodium-wrappers",
			Version:   "",
			Ecosystem: types.EcosystemNPM,
			Analysis: types.AnalysisMetadata{
				Date:   time.Now(),
				Method: "embedded",
				Tool:   "cryptodeps",
			},
			Crypto: []types.CryptoUsage{
				{Algorithm: "X25519", Type: "key-exchange", QuantumRisk: types.RiskVulnerable, Severity: types.SeverityHigh, Remediation: "Migrate to ML-KEM (FIPS 203) for key exchange"},
				{Algorithm: "Ed25519", Type: "signature", QuantumRisk: types.RiskVulnerable, Severity: types.SeverityHigh, Remediation: "Migrate to ML-DSA (FIPS 204) for signatures"},
				{Algorithm: "ChaCha20-Poly1305", Type: "encryption", QuantumRisk: types.RiskSafe, Severity: types.SeverityInfo, Remediation: "No action needed - quantum safe"},
				{Algorithm: "XSalsa20-Poly1305", Type: "encryption", QuantumRisk: types.RiskSafe, Severity: types.SeverityInfo, Remediation: "No action needed - quantum safe"},
				{Algorithm: "Argon2", Type: "hash", QuantumRisk: types.RiskSafe, Severity: types.SeverityInfo, Remediation: "No action needed - quantum safe"},
				{Algorithm: "BLAKE2b", Type: "hash", QuantumRisk: types.RiskSafe, Severity: types.SeverityInfo, Remediation: "No action needed - quantum safe"},
			},
			QuantumSummary: types.QuantumSummary{Vulnerable: 2, Partial: 0, Safe: 4},
		},
		{
			Package:   "elliptic",
			Version:   "",
			Ecosystem: types.EcosystemNPM,
			Analysis: types.AnalysisMetadata{
				Date:   time.Now(),
				Method: "embedded",
				Tool:   "cryptodeps",
			},
			Crypto: []types.CryptoUsage{
				{Algorithm: "ECDSA", Type: "signature", QuantumRisk: types.RiskVulnerable, Severity: types.SeverityHigh, Remediation: "Migrate to ML-DSA (FIPS 204) for signatures"},
				{Algorithm: "ECDH", Type: "key-exchange", QuantumRisk: types.RiskVulnerable, Severity: types.SeverityHigh, Remediation: "Migrate to ML-KEM (FIPS 203) for key exchange"},
				{Algorithm: "secp256k1", Type: "signature", QuantumRisk: types.RiskVulnerable, Severity: types.SeverityHigh, Remediation: "Migrate to ML-DSA (FIPS 204) for signatures"},
			},
			QuantumSummary: types.QuantumSummary{Vulnerable: 3, Partial: 0, Safe: 0},
		},
		{
			Package:   "@noble/curves",
			Version:   "",
			Ecosystem: types.EcosystemNPM,
			Analysis: types.AnalysisMetadata{
				Date:   time.Now(),
				Method: "embedded",
				Tool:   "cryptodeps",
			},
			Crypto: []types.CryptoUsage{
				{Algorithm: "Ed25519", Type: "signature", QuantumRisk: types.RiskVulnerable, Severity: types.SeverityHigh, Remediation: "Migrate to ML-DSA (FIPS 204) for signatures"},
				{Algorithm: "Ed448", Type: "signature", QuantumRisk: types.RiskVulnerable, Severity: types.SeverityHigh, Remediation: "Migrate to ML-DSA (FIPS 204) for signatures"},
				{Algorithm: "secp256k1", Type: "signature", QuantumRisk: types.RiskVulnerable, Severity: types.SeverityHigh, Remediation: "Migrate to ML-DSA (FIPS 204) for signatures"},
				{Algorithm: "P-256", Type: "signature", QuantumRisk: types.RiskVulnerable, Severity: types.SeverityHigh, Remediation: "Migrate to ML-DSA (FIPS 204) for signatures"},
				{Algorithm: "P-384", Type: "signature", QuantumRisk: types.RiskVulnerable, Severity: types.SeverityHigh, Remediation: "Migrate to ML-DSA (FIPS 204) for signatures"},
				{Algorithm: "P-521", Type: "signature", QuantumRisk: types.RiskVulnerable, Severity: types.SeverityHigh, Remediation: "Migrate to ML-DSA (FIPS 204) for signatures"},
			},
			QuantumSummary: types.QuantumSummary{Vulnerable: 6, Partial: 0, Safe: 0},
		},
		{
			Package:   "@noble/hashes",
			Version:   "",
			Ecosystem: types.EcosystemNPM,
			Analysis: types.AnalysisMetadata{
				Date:   time.Now(),
				Method: "embedded",
				Tool:   "cryptodeps",
			},
			Crypto: []types.CryptoUsage{
				{Algorithm: "SHA-256", Type: "hash", QuantumRisk: types.RiskPartial, Severity: types.SeverityInfo, Remediation: "Consider SHA-384/SHA-512 for stronger post-quantum security"},
				{Algorithm: "SHA-384", Type: "hash", QuantumRisk: types.RiskSafe, Severity: types.SeverityInfo, Remediation: "No action needed - quantum safe"},
				{Algorithm: "SHA-512", Type: "hash", QuantumRisk: types.RiskSafe, Severity: types.SeverityInfo, Remediation: "No action needed - quantum safe"},
				{Algorithm: "SHA3-256", Type: "hash", QuantumRisk: types.RiskSafe, Severity: types.SeverityInfo, Remediation: "No action needed - quantum safe"},
				{Algorithm: "BLAKE2b", Type: "hash", QuantumRisk: types.RiskSafe, Severity: types.SeverityInfo, Remediation: "No action needed - quantum safe"},
				{Algorithm: "BLAKE2s", Type: "hash", QuantumRisk: types.RiskSafe, Severity: types.SeverityInfo, Remediation: "No action needed - quantum safe"},
				{Algorithm: "BLAKE3", Type: "hash", QuantumRisk: types.RiskSafe, Severity: types.SeverityInfo, Remediation: "No action needed - quantum safe"},
			},
			QuantumSummary: types.QuantumSummary{Vulnerable: 0, Partial: 1, Safe: 6},
		},
		{
			Package:   "sjcl",
			Version:   "",
			Ecosystem: types.EcosystemNPM,
			Analysis: types.AnalysisMetadata{
				Date:   time.Now(),
				Method: "embedded",
				Tool:   "cryptodeps",
			},
			Crypto: []types.CryptoUsage{
				{Algorithm: "AES", Type: "encryption", QuantumRisk: types.RiskPartial, Severity: types.SeverityInfo, Remediation: "Use AES-256 for 128-bit post-quantum security"},
				{Algorithm: "SHA-256", Type: "hash", QuantumRisk: types.RiskPartial, Severity: types.SeverityInfo, Remediation: "Consider SHA-384/SHA-512 for stronger post-quantum security"},
				{Algorithm: "ECDSA", Type: "signature", QuantumRisk: types.RiskVulnerable, Severity: types.SeverityHigh, Remediation: "Migrate to ML-DSA (FIPS 204) for signatures"},
				{Algorithm: "ECDH", Type: "key-exchange", QuantumRisk: types.RiskVulnerable, Severity: types.SeverityHigh, Remediation: "Migrate to ML-KEM (FIPS 203) for key exchange"},
				{Algorithm: "PBKDF2", Type: "hash", QuantumRisk: types.RiskPartial, Severity: types.SeverityInfo, Remediation: "Consider Argon2 for stronger security"},
			},
			QuantumSummary: types.QuantumSummary{Vulnerable: 2, Partial: 3, Safe: 0},
		},
		{
			Package:   "aes-js",
			Version:   "",
			Ecosystem: types.EcosystemNPM,
			Analysis: types.AnalysisMetadata{
				Date:   time.Now(),
				Method: "embedded",
				Tool:   "cryptodeps",
			},
			Crypto: []types.CryptoUsage{
				{Algorithm: "AES", Type: "encryption", QuantumRisk: types.RiskPartial, Severity: types.SeverityInfo, Remediation: "Use AES-256 for 128-bit post-quantum security"},
			},
			QuantumSummary: types.QuantumSummary{Vulnerable: 0, Partial: 1, Safe: 0},
		},
		{
			Package:   "pbkdf2",
			Version:   "",
			Ecosystem: types.EcosystemNPM,
			Analysis: types.AnalysisMetadata{
				Date:   time.Now(),
				Method: "embedded",
				Tool:   "cryptodeps",
			},
			Crypto: []types.CryptoUsage{
				{Algorithm: "PBKDF2", Type: "hash", QuantumRisk: types.RiskPartial, Severity: types.SeverityInfo, Remediation: "Consider Argon2 for stronger security"},
			},
			QuantumSummary: types.QuantumSummary{Vulnerable: 0, Partial: 1, Safe: 0},
		},
		{
			Package:   "scrypt-js",
			Version:   "",
			Ecosystem: types.EcosystemNPM,
			Analysis: types.AnalysisMetadata{
				Date:   time.Now(),
				Method: "embedded",
				Tool:   "cryptodeps",
			},
			Crypto: []types.CryptoUsage{
				{Algorithm: "scrypt", Type: "hash", QuantumRisk: types.RiskSafe, Severity: types.SeverityInfo, Remediation: "No action needed - quantum safe"},
			},
			QuantumSummary: types.QuantumSummary{Vulnerable: 0, Partial: 0, Safe: 1},
		},
		{
			Package:   "eth-crypto",
			Version:   "",
			Ecosystem: types.EcosystemNPM,
			Analysis: types.AnalysisMetadata{
				Date:   time.Now(),
				Method: "embedded",
				Tool:   "cryptodeps",
			},
			Crypto: []types.CryptoUsage{
				{Algorithm: "secp256k1", Type: "signature", QuantumRisk: types.RiskVulnerable, Severity: types.SeverityHigh, Remediation: "Migrate to ML-DSA (FIPS 204) for signatures"},
				{Algorithm: "ECDH", Type: "key-exchange", QuantumRisk: types.RiskVulnerable, Severity: types.SeverityHigh, Remediation: "Migrate to ML-KEM (FIPS 203) for key exchange"},
				{Algorithm: "AES-GCM", Type: "encryption", QuantumRisk: types.RiskPartial, Severity: types.SeverityInfo, Remediation: "Use AES-256-GCM for post-quantum security"},
			},
			QuantumSummary: types.QuantumSummary{Vulnerable: 2, Partial: 1, Safe: 0},
		},
		{
			Package:   "ethereumjs-wallet",
			Version:   "",
			Ecosystem: types.EcosystemNPM,
			Analysis: types.AnalysisMetadata{
				Date:   time.Now(),
				Method: "embedded",
				Tool:   "cryptodeps",
			},
			Crypto: []types.CryptoUsage{
				{Algorithm: "secp256k1", Type: "signature", QuantumRisk: types.RiskVulnerable, Severity: types.SeverityHigh, Remediation: "Migrate to ML-DSA (FIPS 204) for signatures"},
				{Algorithm: "scrypt", Type: "hash", QuantumRisk: types.RiskSafe, Severity: types.SeverityInfo, Remediation: "No action needed - quantum safe"},
				{Algorithm: "PBKDF2", Type: "hash", QuantumRisk: types.RiskPartial, Severity: types.SeverityInfo, Remediation: "Consider Argon2 for stronger security"},
				{Algorithm: "AES-128-CTR", Type: "encryption", QuantumRisk: types.RiskPartial, Severity: types.SeverityMedium, Remediation: "Use AES-256 for 128-bit post-quantum security"},
			},
			QuantumSummary: types.QuantumSummary{Vulnerable: 1, Partial: 2, Safe: 1},
		},
		{
			Package:   "@aws-crypto/client-node",
			Version:   "",
			Ecosystem: types.EcosystemNPM,
			Analysis: types.AnalysisMetadata{
				Date:   time.Now(),
				Method: "embedded",
				Tool:   "cryptodeps",
			},
			Crypto: []types.CryptoUsage{
				{Algorithm: "AES-GCM", Type: "encryption", QuantumRisk: types.RiskPartial, Severity: types.SeverityInfo, Remediation: "Use AES-256-GCM for post-quantum security"},
				{Algorithm: "RSA-OAEP", Type: "encryption", QuantumRisk: types.RiskVulnerable, Severity: types.SeverityHigh, Remediation: "Migrate to ML-KEM (FIPS 203) for encryption"},
				{Algorithm: "ECDH", Type: "key-exchange", QuantumRisk: types.RiskVulnerable, Severity: types.SeverityHigh, Remediation: "Migrate to ML-KEM (FIPS 203) for key exchange"},
			},
			QuantumSummary: types.QuantumSummary{Vulnerable: 2, Partial: 1, Safe: 0},
		},
		{
			Package:   "passport-jwt",
			Version:   "",
			Ecosystem: types.EcosystemNPM,
			Analysis: types.AnalysisMetadata{
				Date:   time.Now(),
				Method: "embedded",
				Tool:   "cryptodeps",
			},
			Crypto: []types.CryptoUsage{
				{Algorithm: "RS256", Type: "signature", QuantumRisk: types.RiskVulnerable, Severity: types.SeverityHigh, Remediation: "Use HS256/HS512 for symmetric signing, or wait for PQ-JWT standards"},
				{Algorithm: "ES256", Type: "signature", QuantumRisk: types.RiskVulnerable, Severity: types.SeverityHigh, Remediation: "Use HS256/HS512 for symmetric signing, or wait for PQ-JWT standards"},
				{Algorithm: "HS256", Type: "signature", QuantumRisk: types.RiskPartial, Severity: types.SeverityInfo, Remediation: "Consider HS512 for stronger post-quantum security"},
			},
			QuantumSummary: types.QuantumSummary{Vulnerable: 2, Partial: 1, Safe: 0},
		},
		{
			Package:   "express-jwt",
			Version:   "",
			Ecosystem: types.EcosystemNPM,
			Analysis: types.AnalysisMetadata{
				Date:   time.Now(),
				Method: "embedded",
				Tool:   "cryptodeps",
			},
			Crypto: []types.CryptoUsage{
				{Algorithm: "RS256", Type: "signature", QuantumRisk: types.RiskVulnerable, Severity: types.SeverityHigh, Remediation: "Use HS256/HS512 for symmetric signing, or wait for PQ-JWT standards"},
				{Algorithm: "ES256", Type: "signature", QuantumRisk: types.RiskVulnerable, Severity: types.SeverityHigh, Remediation: "Use HS256/HS512 for symmetric signing, or wait for PQ-JWT standards"},
				{Algorithm: "HS256", Type: "signature", QuantumRisk: types.RiskPartial, Severity: types.SeverityInfo, Remediation: "Consider HS512 for stronger post-quantum security"},
			},
			QuantumSummary: types.QuantumSummary{Vulnerable: 2, Partial: 1, Safe: 0},
		},
		// More Python packages
		{
			Package:   "pyOpenSSL",
			Version:   "",
			Ecosystem: types.EcosystemPyPI,
			Analysis: types.AnalysisMetadata{
				Date:   time.Now(),
				Method: "embedded",
				Tool:   "cryptodeps",
			},
			Crypto: []types.CryptoUsage{
				{Algorithm: "RSA", Type: "encryption", QuantumRisk: types.RiskVulnerable, Severity: types.SeverityHigh, Remediation: "Migrate to ML-KEM (FIPS 203) for encryption or ML-DSA (FIPS 204) for signatures"},
				{Algorithm: "ECDSA", Type: "signature", QuantumRisk: types.RiskVulnerable, Severity: types.SeverityHigh, Remediation: "Migrate to ML-DSA (FIPS 204) for signatures"},
				{Algorithm: "AES", Type: "encryption", QuantumRisk: types.RiskPartial, Severity: types.SeverityInfo, Remediation: "Use AES-256 for 128-bit post-quantum security"},
				{Algorithm: "DES", Type: "encryption", QuantumRisk: types.RiskVulnerable, Severity: types.SeverityCritical, Remediation: "Replace immediately with AES-256"},
				{Algorithm: "3DES", Type: "encryption", QuantumRisk: types.RiskVulnerable, Severity: types.SeverityHigh, Remediation: "Replace with AES-256"},
			},
			QuantumSummary: types.QuantumSummary{Vulnerable: 4, Partial: 1, Safe: 0},
		},
		{
			Package:   "M2Crypto",
			Version:   "",
			Ecosystem: types.EcosystemPyPI,
			Analysis: types.AnalysisMetadata{
				Date:   time.Now(),
				Method: "embedded",
				Tool:   "cryptodeps",
			},
			Crypto: []types.CryptoUsage{
				{Algorithm: "RSA", Type: "encryption", QuantumRisk: types.RiskVulnerable, Severity: types.SeverityHigh, Remediation: "Migrate to ML-KEM (FIPS 203) for encryption or ML-DSA (FIPS 204) for signatures"},
				{Algorithm: "DSA", Type: "signature", QuantumRisk: types.RiskVulnerable, Severity: types.SeverityHigh, Remediation: "Migrate to ML-DSA (FIPS 204) for signatures"},
				{Algorithm: "ECDSA", Type: "signature", QuantumRisk: types.RiskVulnerable, Severity: types.SeverityHigh, Remediation: "Migrate to ML-DSA (FIPS 204) for signatures"},
				{Algorithm: "AES", Type: "encryption", QuantumRisk: types.RiskPartial, Severity: types.SeverityInfo, Remediation: "Use AES-256 for 128-bit post-quantum security"},
				{Algorithm: "DES", Type: "encryption", QuantumRisk: types.RiskVulnerable, Severity: types.SeverityCritical, Remediation: "Replace immediately with AES-256"},
				{Algorithm: "Blowfish", Type: "encryption", QuantumRisk: types.RiskVulnerable, Severity: types.SeverityHigh, Remediation: "Replace with AES-256"},
			},
			QuantumSummary: types.QuantumSummary{Vulnerable: 5, Partial: 1, Safe: 0},
		},
		{
			Package:   "ecdsa",
			Version:   "",
			Ecosystem: types.EcosystemPyPI,
			Analysis: types.AnalysisMetadata{
				Date:   time.Now(),
				Method: "embedded",
				Tool:   "cryptodeps",
			},
			Crypto: []types.CryptoUsage{
				{Algorithm: "ECDSA", Type: "signature", QuantumRisk: types.RiskVulnerable, Severity: types.SeverityHigh, Remediation: "Migrate to ML-DSA (FIPS 204) for signatures"},
				{Algorithm: "P-256", Type: "signature", QuantumRisk: types.RiskVulnerable, Severity: types.SeverityHigh, Remediation: "Migrate to ML-DSA (FIPS 204) for signatures"},
				{Algorithm: "P-384", Type: "signature", QuantumRisk: types.RiskVulnerable, Severity: types.SeverityHigh, Remediation: "Migrate to ML-DSA (FIPS 204) for signatures"},
				{Algorithm: "P-521", Type: "signature", QuantumRisk: types.RiskVulnerable, Severity: types.SeverityHigh, Remediation: "Migrate to ML-DSA (FIPS 204) for signatures"},
				{Algorithm: "secp256k1", Type: "signature", QuantumRisk: types.RiskVulnerable, Severity: types.SeverityHigh, Remediation: "Migrate to ML-DSA (FIPS 204) for signatures"},
			},
			QuantumSummary: types.QuantumSummary{Vulnerable: 5, Partial: 0, Safe: 0},
		},
		{
			Package:   "ed25519",
			Version:   "",
			Ecosystem: types.EcosystemPyPI,
			Analysis: types.AnalysisMetadata{
				Date:   time.Now(),
				Method: "embedded",
				Tool:   "cryptodeps",
			},
			Crypto: []types.CryptoUsage{
				{Algorithm: "Ed25519", Type: "signature", QuantumRisk: types.RiskVulnerable, Severity: types.SeverityHigh, Remediation: "Migrate to ML-DSA (FIPS 204) for signatures"},
			},
			QuantumSummary: types.QuantumSummary{Vulnerable: 1, Partial: 0, Safe: 0},
		},
		{
			Package:   "argon2-cffi",
			Version:   "",
			Ecosystem: types.EcosystemPyPI,
			Analysis: types.AnalysisMetadata{
				Date:   time.Now(),
				Method: "embedded",
				Tool:   "cryptodeps",
			},
			Crypto: []types.CryptoUsage{
				{Algorithm: "Argon2", Type: "hash", QuantumRisk: types.RiskSafe, Severity: types.SeverityInfo, Remediation: "No action needed - quantum safe"},
			},
			QuantumSummary: types.QuantumSummary{Vulnerable: 0, Partial: 0, Safe: 1},
		},
		{
			Package:   "bcrypt",
			Version:   "",
			Ecosystem: types.EcosystemPyPI,
			Analysis: types.AnalysisMetadata{
				Date:   time.Now(),
				Method: "embedded",
				Tool:   "cryptodeps",
			},
			Crypto: []types.CryptoUsage{
				{Algorithm: "bcrypt", Type: "hash", QuantumRisk: types.RiskSafe, Severity: types.SeverityInfo, Remediation: "No action needed - quantum safe"},
			},
			QuantumSummary: types.QuantumSummary{Vulnerable: 0, Partial: 0, Safe: 1},
		},
		{
			Package:   "scrypt",
			Version:   "",
			Ecosystem: types.EcosystemPyPI,
			Analysis: types.AnalysisMetadata{
				Date:   time.Now(),
				Method: "embedded",
				Tool:   "cryptodeps",
			},
			Crypto: []types.CryptoUsage{
				{Algorithm: "scrypt", Type: "hash", QuantumRisk: types.RiskSafe, Severity: types.SeverityInfo, Remediation: "No action needed - quantum safe"},
			},
			QuantumSummary: types.QuantumSummary{Vulnerable: 0, Partial: 0, Safe: 1},
		},
		{
			Package:   "itsdangerous",
			Version:   "",
			Ecosystem: types.EcosystemPyPI,
			Analysis: types.AnalysisMetadata{
				Date:   time.Now(),
				Method: "embedded",
				Tool:   "cryptodeps",
			},
			Crypto: []types.CryptoUsage{
				{Algorithm: "HMAC-SHA1", Type: "mac", QuantumRisk: types.RiskPartial, Severity: types.SeverityMedium, Remediation: "Consider HMAC-SHA256 for stronger post-quantum security"},
				{Algorithm: "HMAC-SHA256", Type: "mac", QuantumRisk: types.RiskPartial, Severity: types.SeverityInfo, Remediation: "Consider HMAC-SHA512 for stronger post-quantum security"},
				{Algorithm: "HMAC-SHA512", Type: "mac", QuantumRisk: types.RiskSafe, Severity: types.SeverityInfo, Remediation: "No action needed - quantum safe"},
			},
			QuantumSummary: types.QuantumSummary{Vulnerable: 0, Partial: 2, Safe: 1},
		},
		{
			Package:   "jwcrypto",
			Version:   "",
			Ecosystem: types.EcosystemPyPI,
			Analysis: types.AnalysisMetadata{
				Date:   time.Now(),
				Method: "embedded",
				Tool:   "cryptodeps",
			},
			Crypto: []types.CryptoUsage{
				{Algorithm: "RS256", Type: "signature", QuantumRisk: types.RiskVulnerable, Severity: types.SeverityHigh, Remediation: "Use HS256/HS512 for symmetric signing, or wait for PQ-JWT standards"},
				{Algorithm: "ES256", Type: "signature", QuantumRisk: types.RiskVulnerable, Severity: types.SeverityHigh, Remediation: "Use HS256/HS512 for symmetric signing, or wait for PQ-JWT standards"},
				{Algorithm: "PS256", Type: "signature", QuantumRisk: types.RiskVulnerable, Severity: types.SeverityHigh, Remediation: "Use HS256/HS512 for symmetric signing, or wait for PQ-JWT standards"},
				{Algorithm: "A256GCM", Type: "encryption", QuantumRisk: types.RiskSafe, Severity: types.SeverityInfo, Remediation: "No action needed - quantum safe"},
				{Algorithm: "ECDH-ES", Type: "key-exchange", QuantumRisk: types.RiskVulnerable, Severity: types.SeverityHigh, Remediation: "Migrate to ML-KEM (FIPS 203) for key exchange"},
			},
			QuantumSummary: types.QuantumSummary{Vulnerable: 4, Partial: 0, Safe: 1},
		},
		{
			Package:   "authlib",
			Version:   "",
			Ecosystem: types.EcosystemPyPI,
			Analysis: types.AnalysisMetadata{
				Date:   time.Now(),
				Method: "embedded",
				Tool:   "cryptodeps",
			},
			Crypto: []types.CryptoUsage{
				{Algorithm: "RS256", Type: "signature", QuantumRisk: types.RiskVulnerable, Severity: types.SeverityHigh, Remediation: "Use HS256/HS512 for symmetric signing, or wait for PQ-JWT standards"},
				{Algorithm: "ES256", Type: "signature", QuantumRisk: types.RiskVulnerable, Severity: types.SeverityHigh, Remediation: "Use HS256/HS512 for symmetric signing, or wait for PQ-JWT standards"},
				{Algorithm: "HS256", Type: "signature", QuantumRisk: types.RiskPartial, Severity: types.SeverityInfo, Remediation: "Consider HS512 for stronger post-quantum security"},
			},
			QuantumSummary: types.QuantumSummary{Vulnerable: 2, Partial: 1, Safe: 0},
		},
		{
			Package:   "pgpy",
			Version:   "",
			Ecosystem: types.EcosystemPyPI,
			Analysis: types.AnalysisMetadata{
				Date:   time.Now(),
				Method: "embedded",
				Tool:   "cryptodeps",
			},
			Crypto: []types.CryptoUsage{
				{Algorithm: "RSA", Type: "encryption", QuantumRisk: types.RiskVulnerable, Severity: types.SeverityHigh, Remediation: "Migrate to ML-KEM (FIPS 203) for encryption or ML-DSA (FIPS 204) for signatures"},
				{Algorithm: "ECDSA", Type: "signature", QuantumRisk: types.RiskVulnerable, Severity: types.SeverityHigh, Remediation: "Migrate to ML-DSA (FIPS 204) for signatures"},
				{Algorithm: "Ed25519", Type: "signature", QuantumRisk: types.RiskVulnerable, Severity: types.SeverityHigh, Remediation: "Migrate to ML-DSA (FIPS 204) for signatures"},
				{Algorithm: "X25519", Type: "key-exchange", QuantumRisk: types.RiskVulnerable, Severity: types.SeverityHigh, Remediation: "Migrate to ML-KEM (FIPS 203) for key exchange"},
				{Algorithm: "AES", Type: "encryption", QuantumRisk: types.RiskPartial, Severity: types.SeverityInfo, Remediation: "Use AES-256 for 128-bit post-quantum security"},
			},
			QuantumSummary: types.QuantumSummary{Vulnerable: 4, Partial: 1, Safe: 0},
		},
		{
			Package:   "asn1crypto",
			Version:   "",
			Ecosystem: types.EcosystemPyPI,
			Analysis: types.AnalysisMetadata{
				Date:   time.Now(),
				Method: "embedded",
				Tool:   "cryptodeps",
			},
			Crypto: []types.CryptoUsage{
				{Algorithm: "RSA", Type: "encryption", QuantumRisk: types.RiskVulnerable, Severity: types.SeverityHigh, Remediation: "Migrate to ML-KEM (FIPS 203) for encryption or ML-DSA (FIPS 204) for signatures"},
				{Algorithm: "ECDSA", Type: "signature", QuantumRisk: types.RiskVulnerable, Severity: types.SeverityHigh, Remediation: "Migrate to ML-DSA (FIPS 204) for signatures"},
				{Algorithm: "DSA", Type: "signature", QuantumRisk: types.RiskVulnerable, Severity: types.SeverityHigh, Remediation: "Migrate to ML-DSA (FIPS 204) for signatures"},
			},
			QuantumSummary: types.QuantumSummary{Vulnerable: 3, Partial: 0, Safe: 0},
		},
		{
			Package:   "oscrypto",
			Version:   "",
			Ecosystem: types.EcosystemPyPI,
			Analysis: types.AnalysisMetadata{
				Date:   time.Now(),
				Method: "embedded",
				Tool:   "cryptodeps",
			},
			Crypto: []types.CryptoUsage{
				{Algorithm: "RSA", Type: "encryption", QuantumRisk: types.RiskVulnerable, Severity: types.SeverityHigh, Remediation: "Migrate to ML-KEM (FIPS 203) for encryption or ML-DSA (FIPS 204) for signatures"},
				{Algorithm: "ECDSA", Type: "signature", QuantumRisk: types.RiskVulnerable, Severity: types.SeverityHigh, Remediation: "Migrate to ML-DSA (FIPS 204) for signatures"},
				{Algorithm: "AES", Type: "encryption", QuantumRisk: types.RiskPartial, Severity: types.SeverityInfo, Remediation: "Use AES-256 for 128-bit post-quantum security"},
				{Algorithm: "3DES", Type: "encryption", QuantumRisk: types.RiskVulnerable, Severity: types.SeverityHigh, Remediation: "Replace with AES-256"},
			},
			QuantumSummary: types.QuantumSummary{Vulnerable: 3, Partial: 1, Safe: 0},
		},
		// More Maven packages
		{
			Package:   "com.nimbusds:nimbus-jose-jwt",
			Version:   "",
			Ecosystem: types.EcosystemMaven,
			Analysis: types.AnalysisMetadata{
				Date:   time.Now(),
				Method: "embedded",
				Tool:   "cryptodeps",
			},
			Crypto: []types.CryptoUsage{
				{Algorithm: "RS256", Type: "signature", QuantumRisk: types.RiskVulnerable, Severity: types.SeverityHigh, Remediation: "Use HS256/HS512 for symmetric signing, or wait for PQ-JWT standards"},
				{Algorithm: "RS384", Type: "signature", QuantumRisk: types.RiskVulnerable, Severity: types.SeverityHigh, Remediation: "Use HS384/HS512 for symmetric signing, or wait for PQ-JWT standards"},
				{Algorithm: "RS512", Type: "signature", QuantumRisk: types.RiskVulnerable, Severity: types.SeverityHigh, Remediation: "Use HS512 for symmetric signing, or wait for PQ-JWT standards"},
				{Algorithm: "ES256", Type: "signature", QuantumRisk: types.RiskVulnerable, Severity: types.SeverityHigh, Remediation: "Use HS256/HS512 for symmetric signing, or wait for PQ-JWT standards"},
				{Algorithm: "PS256", Type: "signature", QuantumRisk: types.RiskVulnerable, Severity: types.SeverityHigh, Remediation: "Use HS256/HS512 for symmetric signing, or wait for PQ-JWT standards"},
				{Algorithm: "EdDSA", Type: "signature", QuantumRisk: types.RiskVulnerable, Severity: types.SeverityHigh, Remediation: "Wait for PQ-JWT standards"},
				{Algorithm: "HS256", Type: "signature", QuantumRisk: types.RiskPartial, Severity: types.SeverityInfo, Remediation: "Consider HS512 for stronger post-quantum security"},
				{Algorithm: "HS512", Type: "signature", QuantumRisk: types.RiskSafe, Severity: types.SeverityInfo, Remediation: "No action needed - quantum safe"},
				{Algorithm: "A256GCM", Type: "encryption", QuantumRisk: types.RiskSafe, Severity: types.SeverityInfo, Remediation: "No action needed - quantum safe"},
			},
			QuantumSummary: types.QuantumSummary{Vulnerable: 6, Partial: 1, Safe: 2},
		},
		{
			Package:   "com.auth0:java-jwt",
			Version:   "",
			Ecosystem: types.EcosystemMaven,
			Analysis: types.AnalysisMetadata{
				Date:   time.Now(),
				Method: "embedded",
				Tool:   "cryptodeps",
			},
			Crypto: []types.CryptoUsage{
				{Algorithm: "RS256", Type: "signature", QuantumRisk: types.RiskVulnerable, Severity: types.SeverityHigh, Remediation: "Use HS256/HS512 for symmetric signing, or wait for PQ-JWT standards"},
				{Algorithm: "RS384", Type: "signature", QuantumRisk: types.RiskVulnerable, Severity: types.SeverityHigh, Remediation: "Use HS384/HS512 for symmetric signing, or wait for PQ-JWT standards"},
				{Algorithm: "RS512", Type: "signature", QuantumRisk: types.RiskVulnerable, Severity: types.SeverityHigh, Remediation: "Use HS512 for symmetric signing, or wait for PQ-JWT standards"},
				{Algorithm: "ES256", Type: "signature", QuantumRisk: types.RiskVulnerable, Severity: types.SeverityHigh, Remediation: "Use HS256/HS512 for symmetric signing, or wait for PQ-JWT standards"},
				{Algorithm: "ES384", Type: "signature", QuantumRisk: types.RiskVulnerable, Severity: types.SeverityHigh, Remediation: "Use HS384/HS512 for symmetric signing, or wait for PQ-JWT standards"},
				{Algorithm: "HS256", Type: "signature", QuantumRisk: types.RiskPartial, Severity: types.SeverityInfo, Remediation: "Consider HS512 for stronger post-quantum security"},
				{Algorithm: "HS512", Type: "signature", QuantumRisk: types.RiskSafe, Severity: types.SeverityInfo, Remediation: "No action needed - quantum safe"},
			},
			QuantumSummary: types.QuantumSummary{Vulnerable: 5, Partial: 1, Safe: 1},
		},
		{
			Package:   "org.bitbucket.b_c:jose4j",
			Version:   "",
			Ecosystem: types.EcosystemMaven,
			Analysis: types.AnalysisMetadata{
				Date:   time.Now(),
				Method: "embedded",
				Tool:   "cryptodeps",
			},
			Crypto: []types.CryptoUsage{
				{Algorithm: "RS256", Type: "signature", QuantumRisk: types.RiskVulnerable, Severity: types.SeverityHigh, Remediation: "Use HS256/HS512 for symmetric signing, or wait for PQ-JWT standards"},
				{Algorithm: "ES256", Type: "signature", QuantumRisk: types.RiskVulnerable, Severity: types.SeverityHigh, Remediation: "Use HS256/HS512 for symmetric signing, or wait for PQ-JWT standards"},
				{Algorithm: "PS256", Type: "signature", QuantumRisk: types.RiskVulnerable, Severity: types.SeverityHigh, Remediation: "Use HS256/HS512 for symmetric signing, or wait for PQ-JWT standards"},
				{Algorithm: "HS256", Type: "signature", QuantumRisk: types.RiskPartial, Severity: types.SeverityInfo, Remediation: "Consider HS512 for stronger post-quantum security"},
				{Algorithm: "A256GCM", Type: "encryption", QuantumRisk: types.RiskSafe, Severity: types.SeverityInfo, Remediation: "No action needed - quantum safe"},
				{Algorithm: "ECDH-ES", Type: "key-exchange", QuantumRisk: types.RiskVulnerable, Severity: types.SeverityHigh, Remediation: "Migrate to ML-KEM (FIPS 203) for key exchange"},
			},
			QuantumSummary: types.QuantumSummary{Vulnerable: 4, Partial: 1, Safe: 1},
		},
		{
			Package:   "org.jasypt:jasypt",
			Version:   "",
			Ecosystem: types.EcosystemMaven,
			Analysis: types.AnalysisMetadata{
				Date:   time.Now(),
				Method: "embedded",
				Tool:   "cryptodeps",
			},
			Crypto: []types.CryptoUsage{
				{Algorithm: "AES", Type: "encryption", QuantumRisk: types.RiskPartial, Severity: types.SeverityInfo, Remediation: "Use AES-256 for 128-bit post-quantum security"},
				{Algorithm: "DES", Type: "encryption", QuantumRisk: types.RiskVulnerable, Severity: types.SeverityCritical, Remediation: "Replace immediately with AES-256"},
				{Algorithm: "3DES", Type: "encryption", QuantumRisk: types.RiskVulnerable, Severity: types.SeverityHigh, Remediation: "Replace with AES-256"},
				{Algorithm: "PBE", Type: "encryption", QuantumRisk: types.RiskPartial, Severity: types.SeverityMedium, Remediation: "Ensure strong password and use modern KDF like Argon2"},
				{Algorithm: "SHA-256", Type: "hash", QuantumRisk: types.RiskPartial, Severity: types.SeverityInfo, Remediation: "Consider SHA-384/SHA-512 for stronger post-quantum security"},
			},
			QuantumSummary: types.QuantumSummary{Vulnerable: 2, Partial: 3, Safe: 0},
		},
		{
			Package:   "commons-codec:commons-codec",
			Version:   "",
			Ecosystem: types.EcosystemMaven,
			Analysis: types.AnalysisMetadata{
				Date:   time.Now(),
				Method: "embedded",
				Tool:   "cryptodeps",
			},
			Crypto: []types.CryptoUsage{
				{Algorithm: "MD5", Type: "hash", QuantumRisk: types.RiskVulnerable, Severity: types.SeverityCritical, Remediation: "Replace immediately with SHA-256 or SHA-3"},
				{Algorithm: "SHA-1", Type: "hash", QuantumRisk: types.RiskVulnerable, Severity: types.SeverityCritical, Remediation: "Replace immediately with SHA-256 or SHA-3"},
				{Algorithm: "SHA-256", Type: "hash", QuantumRisk: types.RiskPartial, Severity: types.SeverityInfo, Remediation: "Consider SHA-384/SHA-512 for stronger post-quantum security"},
				{Algorithm: "SHA-384", Type: "hash", QuantumRisk: types.RiskSafe, Severity: types.SeverityInfo, Remediation: "No action needed - quantum safe"},
				{Algorithm: "SHA-512", Type: "hash", QuantumRisk: types.RiskSafe, Severity: types.SeverityInfo, Remediation: "No action needed - quantum safe"},
			},
			QuantumSummary: types.QuantumSummary{Vulnerable: 2, Partial: 1, Safe: 2},
		},
		{
			Package:   "net.i2p.crypto:eddsa",
			Version:   "",
			Ecosystem: types.EcosystemMaven,
			Analysis: types.AnalysisMetadata{
				Date:   time.Now(),
				Method: "embedded",
				Tool:   "cryptodeps",
			},
			Crypto: []types.CryptoUsage{
				{Algorithm: "Ed25519", Type: "signature", QuantumRisk: types.RiskVulnerable, Severity: types.SeverityHigh, Remediation: "Migrate to ML-DSA (FIPS 204) for signatures"},
			},
			QuantumSummary: types.QuantumSummary{Vulnerable: 1, Partial: 0, Safe: 0},
		},
		{
			Package:   "org.conscrypt:conscrypt-openjdk-uber",
			Version:   "",
			Ecosystem: types.EcosystemMaven,
			Analysis: types.AnalysisMetadata{
				Date:   time.Now(),
				Method: "embedded",
				Tool:   "cryptodeps",
			},
			Crypto: []types.CryptoUsage{
				{Algorithm: "RSA", Type: "encryption", QuantumRisk: types.RiskVulnerable, Severity: types.SeverityHigh, Remediation: "Migrate to ML-KEM (FIPS 203) for encryption or ML-DSA (FIPS 204) for signatures"},
				{Algorithm: "ECDSA", Type: "signature", QuantumRisk: types.RiskVulnerable, Severity: types.SeverityHigh, Remediation: "Migrate to ML-DSA (FIPS 204) for signatures"},
				{Algorithm: "ECDH", Type: "key-exchange", QuantumRisk: types.RiskVulnerable, Severity: types.SeverityHigh, Remediation: "Migrate to ML-KEM (FIPS 203) for key exchange"},
				{Algorithm: "AES-GCM", Type: "encryption", QuantumRisk: types.RiskPartial, Severity: types.SeverityInfo, Remediation: "Use AES-256-GCM for post-quantum security"},
				{Algorithm: "ChaCha20-Poly1305", Type: "encryption", QuantumRisk: types.RiskSafe, Severity: types.SeverityInfo, Remediation: "No action needed - quantum safe"},
			},
			QuantumSummary: types.QuantumSummary{Vulnerable: 3, Partial: 1, Safe: 1},
		},
		{
			Package:   "com.amazonaws:aws-encryption-sdk-java",
			Version:   "",
			Ecosystem: types.EcosystemMaven,
			Analysis: types.AnalysisMetadata{
				Date:   time.Now(),
				Method: "embedded",
				Tool:   "cryptodeps",
			},
			Crypto: []types.CryptoUsage{
				{Algorithm: "AES-GCM", Type: "encryption", QuantumRisk: types.RiskPartial, Severity: types.SeverityInfo, Remediation: "Use AES-256-GCM for post-quantum security"},
				{Algorithm: "RSA-OAEP", Type: "encryption", QuantumRisk: types.RiskVulnerable, Severity: types.SeverityHigh, Remediation: "Migrate to ML-KEM (FIPS 203) for encryption"},
				{Algorithm: "ECDH", Type: "key-exchange", QuantumRisk: types.RiskVulnerable, Severity: types.SeverityHigh, Remediation: "Migrate to ML-KEM (FIPS 203) for key exchange"},
			},
			QuantumSummary: types.QuantumSummary{Vulnerable: 2, Partial: 1, Safe: 0},
		},
		{
			Package:   "io.netty:netty-handler",
			Version:   "",
			Ecosystem: types.EcosystemMaven,
			Analysis: types.AnalysisMetadata{
				Date:   time.Now(),
				Method: "embedded",
				Tool:   "cryptodeps",
			},
			Crypto: []types.CryptoUsage{
				{Algorithm: "RSA", Type: "encryption", QuantumRisk: types.RiskVulnerable, Severity: types.SeverityHigh, Remediation: "Migrate to ML-KEM (FIPS 203) for encryption or ML-DSA (FIPS 204) for signatures"},
				{Algorithm: "ECDSA", Type: "signature", QuantumRisk: types.RiskVulnerable, Severity: types.SeverityHigh, Remediation: "Migrate to ML-DSA (FIPS 204) for signatures"},
				{Algorithm: "ECDH", Type: "key-exchange", QuantumRisk: types.RiskVulnerable, Severity: types.SeverityHigh, Remediation: "Migrate to ML-KEM (FIPS 203) for key exchange"},
				{Algorithm: "AES-GCM", Type: "encryption", QuantumRisk: types.RiskPartial, Severity: types.SeverityInfo, Remediation: "Use AES-256-GCM for post-quantum security"},
				{Algorithm: "ChaCha20-Poly1305", Type: "encryption", QuantumRisk: types.RiskSafe, Severity: types.SeverityInfo, Remediation: "No action needed - quantum safe"},
			},
			QuantumSummary: types.QuantumSummary{Vulnerable: 3, Partial: 1, Safe: 1},
		},
		{
			Package:   "org.apache.shiro:shiro-crypto-core",
			Version:   "",
			Ecosystem: types.EcosystemMaven,
			Analysis: types.AnalysisMetadata{
				Date:   time.Now(),
				Method: "embedded",
				Tool:   "cryptodeps",
			},
			Crypto: []types.CryptoUsage{
				{Algorithm: "AES", Type: "encryption", QuantumRisk: types.RiskPartial, Severity: types.SeverityInfo, Remediation: "Use AES-256 for 128-bit post-quantum security"},
				{Algorithm: "Blowfish", Type: "encryption", QuantumRisk: types.RiskVulnerable, Severity: types.SeverityHigh, Remediation: "Replace with AES-256"},
				{Algorithm: "SHA-256", Type: "hash", QuantumRisk: types.RiskPartial, Severity: types.SeverityInfo, Remediation: "Consider SHA-384/SHA-512 for stronger post-quantum security"},
				{Algorithm: "SHA-512", Type: "hash", QuantumRisk: types.RiskSafe, Severity: types.SeverityInfo, Remediation: "No action needed - quantum safe"},
			},
			QuantumSummary: types.QuantumSummary{Vulnerable: 1, Partial: 2, Safe: 1},
		},
		{
			Package:   "io.vertx:vertx-auth-jwt",
			Version:   "",
			Ecosystem: types.EcosystemMaven,
			Analysis: types.AnalysisMetadata{
				Date:   time.Now(),
				Method: "embedded",
				Tool:   "cryptodeps",
			},
			Crypto: []types.CryptoUsage{
				{Algorithm: "RS256", Type: "signature", QuantumRisk: types.RiskVulnerable, Severity: types.SeverityHigh, Remediation: "Use HS256/HS512 for symmetric signing, or wait for PQ-JWT standards"},
				{Algorithm: "ES256", Type: "signature", QuantumRisk: types.RiskVulnerable, Severity: types.SeverityHigh, Remediation: "Use HS256/HS512 for symmetric signing, or wait for PQ-JWT standards"},
				{Algorithm: "HS256", Type: "signature", QuantumRisk: types.RiskPartial, Severity: types.SeverityInfo, Remediation: "Consider HS512 for stronger post-quantum security"},
				{Algorithm: "HS512", Type: "signature", QuantumRisk: types.RiskSafe, Severity: types.SeverityInfo, Remediation: "No action needed - quantum safe"},
			},
			QuantumSummary: types.QuantumSummary{Vulnerable: 2, Partial: 1, Safe: 1},
		},
	}

	for i := range seedData {
		db.addToIndex(&seedData[i])
	}
}
