// Copyright 2024 CSNP (csnp.org)
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
func (db *Database) Lookup(ecosystem types.Ecosystem, name, version string) (*types.PackageAnalysis, bool) {
	ecosystemIndex, ok := db.index[ecosystem]
	if !ok {
		return nil, false
	}

	// Try exact version match first
	key := makeKey(name, version)
	if analysis, ok := ecosystemIndex[key]; ok {
		return analysis, true
	}

	// Try without version (latest/any)
	key = makeKey(name, "")
	if analysis, ok := ecosystemIndex[key]; ok {
		return analysis, true
	}

	return nil, false
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
				{Algorithm: "Ed25519", Type: "signature", QuantumRisk: types.RiskVulnerable, Severity: types.SeverityHigh},
				{Algorithm: "ChaCha20-Poly1305", Type: "encryption", QuantumRisk: types.RiskSafe, Severity: types.SeverityInfo},
				{Algorithm: "bcrypt", Type: "hash", QuantumRisk: types.RiskSafe, Severity: types.SeverityInfo},
				{Algorithm: "X25519", Type: "key-exchange", QuantumRisk: types.RiskVulnerable, Severity: types.SeverityHigh},
				{Algorithm: "Argon2", Type: "hash", QuantumRisk: types.RiskSafe, Severity: types.SeverityInfo},
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
				{Algorithm: "RS256", Type: "signature", QuantumRisk: types.RiskVulnerable, Severity: types.SeverityHigh},
				{Algorithm: "RS384", Type: "signature", QuantumRisk: types.RiskVulnerable, Severity: types.SeverityHigh},
				{Algorithm: "RS512", Type: "signature", QuantumRisk: types.RiskVulnerable, Severity: types.SeverityHigh},
				{Algorithm: "ES256", Type: "signature", QuantumRisk: types.RiskVulnerable, Severity: types.SeverityHigh},
				{Algorithm: "ES384", Type: "signature", QuantumRisk: types.RiskVulnerable, Severity: types.SeverityHigh},
				{Algorithm: "ES512", Type: "signature", QuantumRisk: types.RiskVulnerable, Severity: types.SeverityHigh},
				{Algorithm: "HS256", Type: "signature", QuantumRisk: types.RiskPartial, Severity: types.SeverityInfo},
				{Algorithm: "HS384", Type: "signature", QuantumRisk: types.RiskPartial, Severity: types.SeverityInfo},
				{Algorithm: "HS512", Type: "signature", QuantumRisk: types.RiskSafe, Severity: types.SeverityInfo},
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
				{Algorithm: "RS256", Type: "signature", QuantumRisk: types.RiskVulnerable, Severity: types.SeverityHigh},
				{Algorithm: "ES256", Type: "signature", QuantumRisk: types.RiskVulnerable, Severity: types.SeverityHigh},
				{Algorithm: "HS256", Type: "signature", QuantumRisk: types.RiskPartial, Severity: types.SeverityInfo},
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
				{Algorithm: "bcrypt", Type: "hash", QuantumRisk: types.RiskSafe, Severity: types.SeverityInfo},
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
				{Algorithm: "AES", Type: "encryption", QuantumRisk: types.RiskPartial, Severity: types.SeverityInfo},
				{Algorithm: "DES", Type: "encryption", QuantumRisk: types.RiskVulnerable, Severity: types.SeverityCritical},
				{Algorithm: "3DES", Type: "encryption", QuantumRisk: types.RiskVulnerable, Severity: types.SeverityHigh},
				{Algorithm: "MD5", Type: "hash", QuantumRisk: types.RiskVulnerable, Severity: types.SeverityCritical},
				{Algorithm: "SHA-1", Type: "hash", QuantumRisk: types.RiskVulnerable, Severity: types.SeverityCritical},
				{Algorithm: "SHA-256", Type: "hash", QuantumRisk: types.RiskPartial, Severity: types.SeverityInfo},
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
				{Algorithm: "RSA", Type: "encryption", QuantumRisk: types.RiskVulnerable, Severity: types.SeverityHigh},
				{Algorithm: "ECDSA", Type: "signature", QuantumRisk: types.RiskVulnerable, Severity: types.SeverityHigh},
				{Algorithm: "Ed25519", Type: "signature", QuantumRisk: types.RiskVulnerable, Severity: types.SeverityHigh},
				{Algorithm: "AES", Type: "encryption", QuantumRisk: types.RiskPartial, Severity: types.SeverityInfo},
				{Algorithm: "ChaCha20", Type: "encryption", QuantumRisk: types.RiskSafe, Severity: types.SeverityInfo},
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
				{Algorithm: "RS256", Type: "signature", QuantumRisk: types.RiskVulnerable, Severity: types.SeverityHigh},
				{Algorithm: "ES256", Type: "signature", QuantumRisk: types.RiskVulnerable, Severity: types.SeverityHigh},
				{Algorithm: "HS256", Type: "signature", QuantumRisk: types.RiskPartial, Severity: types.SeverityInfo},
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
				{Algorithm: "RSA", Type: "encryption", QuantumRisk: types.RiskVulnerable, Severity: types.SeverityHigh},
				{Algorithm: "ECDSA", Type: "signature", QuantumRisk: types.RiskVulnerable, Severity: types.SeverityHigh},
				{Algorithm: "Ed25519", Type: "signature", QuantumRisk: types.RiskVulnerable, Severity: types.SeverityHigh},
				{Algorithm: "AES", Type: "encryption", QuantumRisk: types.RiskPartial, Severity: types.SeverityInfo},
				{Algorithm: "ChaCha20", Type: "encryption", QuantumRisk: types.RiskSafe, Severity: types.SeverityInfo},
				{Algorithm: "ML-KEM", Type: "key-exchange", QuantumRisk: types.RiskSafe, Severity: types.SeverityInfo},
				{Algorithm: "ML-DSA", Type: "signature", QuantumRisk: types.RiskSafe, Severity: types.SeverityInfo},
			},
			QuantumSummary: types.QuantumSummary{Vulnerable: 3, Partial: 1, Safe: 3},
		},
	}

	for i := range seedData {
		db.addToIndex(&seedData[i])
	}
}
