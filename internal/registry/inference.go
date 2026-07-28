// Copyright 2025-2026 CyberSecurity NonProfit (CSNP)
// SPDX-License-Identifier: Apache-2.0

package registry

import (
	"strings"

	"github.com/csnp/qramm-cryptodeps/pkg/crypto"
	"github.com/csnp/qramm-cryptodeps/pkg/types"
	"github.com/csnp/qramm-cryptodeps/pkg/version"
)

// InferredAlgorithm represents an algorithm inferred from package metadata.
type InferredAlgorithm struct {
	Algorithm  string
	Type       string           // encryption, signature, hash, key-exchange
	Confidence types.Confidence // verified, high, medium, low
	Reason     string           // why we inferred this
}

// InferAlgorithms infers cryptographic algorithms from package metadata.
func InferAlgorithms(pkg PackageInfo) []InferredAlgorithm {
	var algorithms []InferredAlgorithm

	name := strings.ToLower(pkg.Name)
	desc := strings.ToLower(pkg.Description)
	combined := name + " " + desc + " " + strings.ToLower(strings.Join(pkg.Keywords, " "))

	// Check each inference rule
	for _, rule := range inferenceRules {
		if rule.Matches(combined) {
			algorithms = append(algorithms, rule.Algorithms...)
		}
	}

	// Deduplicate
	seen := make(map[string]bool)
	var unique []InferredAlgorithm
	for _, alg := range algorithms {
		key := alg.Algorithm + alg.Type
		if !seen[key] {
			seen[key] = true
			unique = append(unique, alg)
		}
	}

	return unique
}

// inferenceRule defines a pattern and its associated algorithms.
type inferenceRule struct {
	Patterns   []string
	Algorithms []InferredAlgorithm
}

func (r inferenceRule) Matches(text string) bool {
	for _, pattern := range r.Patterns {
		if strings.Contains(text, pattern) {
			return true
		}
	}
	return false
}

// inferenceRules maps package patterns to likely algorithms.
var inferenceRules = []inferenceRule{
	// JWT/JOSE libraries
	{
		Patterns: []string{"jwt", "jsonwebtoken", "jose", "jws", "jwe"},
		Algorithms: []InferredAlgorithm{
			{Algorithm: "RS256", Type: "signature", Confidence: types.ConfidenceHigh, Reason: "JWT library typically supports RSA signatures"},
			{Algorithm: "RS384", Type: "signature", Confidence: types.ConfidenceMedium, Reason: "JWT library typically supports RSA signatures"},
			{Algorithm: "RS512", Type: "signature", Confidence: types.ConfidenceMedium, Reason: "JWT library typically supports RSA signatures"},
			{Algorithm: "ES256", Type: "signature", Confidence: types.ConfidenceHigh, Reason: "JWT library typically supports ECDSA signatures"},
			{Algorithm: "ES384", Type: "signature", Confidence: types.ConfidenceMedium, Reason: "JWT library typically supports ECDSA signatures"},
			{Algorithm: "ES512", Type: "signature", Confidence: types.ConfidenceMedium, Reason: "JWT library typically supports ECDSA signatures"},
			{Algorithm: "HS256", Type: "signature", Confidence: types.ConfidenceHigh, Reason: "JWT library typically supports HMAC signatures"},
			{Algorithm: "HS384", Type: "signature", Confidence: types.ConfidenceMedium, Reason: "JWT library typically supports HMAC signatures"},
			{Algorithm: "HS512", Type: "signature", Confidence: types.ConfidenceMedium, Reason: "JWT library typically supports HMAC signatures"},
			{Algorithm: "EdDSA", Type: "signature", Confidence: types.ConfidenceMedium, Reason: "Modern JWT libraries support EdDSA"},
		},
	},
	// BCrypt
	{
		Patterns: []string{"bcrypt"},
		Algorithms: []InferredAlgorithm{
			{Algorithm: "bcrypt", Type: "hash", Confidence: types.ConfidenceHigh, Reason: "Package name indicates bcrypt"},
		},
	},
	// Argon2
	{
		Patterns: []string{"argon2"},
		Algorithms: []InferredAlgorithm{
			{Algorithm: "Argon2", Type: "hash", Confidence: types.ConfidenceHigh, Reason: "Package name indicates Argon2"},
		},
	},
	// Scrypt
	{
		Patterns: []string{"scrypt"},
		Algorithms: []InferredAlgorithm{
			{Algorithm: "scrypt", Type: "hash", Confidence: types.ConfidenceHigh, Reason: "Package name indicates scrypt"},
		},
	},
	// NaCl / Sodium / TweetNaCl
	{
		Patterns: []string{"nacl", "sodium", "tweetnacl", "libsodium"},
		Algorithms: []InferredAlgorithm{
			{Algorithm: "X25519", Type: "key-exchange", Confidence: types.ConfidenceHigh, Reason: "NaCl uses X25519 for key exchange"},
			{Algorithm: "Ed25519", Type: "signature", Confidence: types.ConfidenceHigh, Reason: "NaCl uses Ed25519 for signatures"},
			{Algorithm: "XSalsa20", Type: "encryption", Confidence: types.ConfidenceHigh, Reason: "NaCl uses XSalsa20 for encryption"},
			{Algorithm: "Poly1305", Type: "hash", Confidence: types.ConfidenceHigh, Reason: "NaCl uses Poly1305 for authentication"},
		},
	},
	// ChaCha20
	{
		Patterns: []string{"chacha20", "chacha"},
		Algorithms: []InferredAlgorithm{
			{Algorithm: "ChaCha20", Type: "encryption", Confidence: types.ConfidenceHigh, Reason: "Package name indicates ChaCha20"},
			{Algorithm: "ChaCha20-Poly1305", Type: "encryption", Confidence: types.ConfidenceMedium, Reason: "ChaCha often paired with Poly1305"},
		},
	},
	// AES
	{
		Patterns: []string{"aes-", "-aes", "aes256", "aes128", "aes192"},
		Algorithms: []InferredAlgorithm{
			{Algorithm: "AES", Type: "encryption", Confidence: types.ConfidenceHigh, Reason: "Package name indicates AES"},
		},
	},
	// RSA
	{
		Patterns: []string{"-rsa", "rsa-", "node-rsa", "python-rsa"},
		Algorithms: []InferredAlgorithm{
			{Algorithm: "RSA", Type: "encryption", Confidence: types.ConfidenceHigh, Reason: "Package name indicates RSA"},
		},
	},
	// ECDSA / Elliptic Curve
	{
		Patterns: []string{"ecdsa", "elliptic", "secp256", "p256", "p384", "p521"},
		Algorithms: []InferredAlgorithm{
			{Algorithm: "ECDSA", Type: "signature", Confidence: types.ConfidenceHigh, Reason: "Package involves elliptic curve cryptography"},
			{Algorithm: "ECDH", Type: "key-exchange", Confidence: types.ConfidenceMedium, Reason: "Elliptic curve packages often support ECDH"},
		},
	},
	// Ed25519
	{
		Patterns: []string{"ed25519", "edwards25519"},
		Algorithms: []InferredAlgorithm{
			{Algorithm: "Ed25519", Type: "signature", Confidence: types.ConfidenceHigh, Reason: "Package name indicates Ed25519"},
		},
	},
	// X25519 / Curve25519
	{
		Patterns: []string{"x25519", "curve25519"},
		Algorithms: []InferredAlgorithm{
			{Algorithm: "X25519", Type: "key-exchange", Confidence: types.ConfidenceHigh, Reason: "Package name indicates X25519"},
		},
	},
	// PGP/GPG
	{
		Patterns: []string{"pgp", "gpg", "openpgp"},
		Algorithms: []InferredAlgorithm{
			{Algorithm: "RSA", Type: "encryption", Confidence: types.ConfidenceHigh, Reason: "PGP commonly uses RSA"},
			{Algorithm: "AES", Type: "encryption", Confidence: types.ConfidenceHigh, Reason: "PGP commonly uses AES"},
			{Algorithm: "SHA-256", Type: "hash", Confidence: types.ConfidenceHigh, Reason: "PGP commonly uses SHA-256"},
			{Algorithm: "ECDSA", Type: "signature", Confidence: types.ConfidenceMedium, Reason: "Modern PGP supports ECDSA"},
		},
	},
	// TLS/SSL
	{
		Patterns: []string{"tls", "ssl", "https", "certificate", "x509"},
		Algorithms: []InferredAlgorithm{
			{Algorithm: "RSA", Type: "encryption", Confidence: types.ConfidenceMedium, Reason: "TLS commonly uses RSA"},
			{Algorithm: "ECDSA", Type: "signature", Confidence: types.ConfidenceMedium, Reason: "TLS commonly uses ECDSA"},
			{Algorithm: "ECDH", Type: "key-exchange", Confidence: types.ConfidenceMedium, Reason: "TLS commonly uses ECDH"},
			{Algorithm: "AES-GCM", Type: "encryption", Confidence: types.ConfidenceMedium, Reason: "TLS commonly uses AES-GCM"},
			{Algorithm: "ChaCha20-Poly1305", Type: "encryption", Confidence: types.ConfidenceMedium, Reason: "Modern TLS supports ChaCha20"},
		},
	},
	// SSH
	{
		Patterns: []string{"ssh", "openssh", "sshd"},
		Algorithms: []InferredAlgorithm{
			{Algorithm: "RSA", Type: "encryption", Confidence: types.ConfidenceHigh, Reason: "SSH commonly uses RSA"},
			{Algorithm: "Ed25519", Type: "signature", Confidence: types.ConfidenceHigh, Reason: "SSH commonly uses Ed25519"},
			{Algorithm: "ECDSA", Type: "signature", Confidence: types.ConfidenceMedium, Reason: "SSH commonly uses ECDSA"},
			{Algorithm: "AES", Type: "encryption", Confidence: types.ConfidenceHigh, Reason: "SSH commonly uses AES"},
			{Algorithm: "ChaCha20-Poly1305", Type: "encryption", Confidence: types.ConfidenceMedium, Reason: "Modern SSH supports ChaCha20"},
		},
	},
	// SHA hashing
	{
		Patterns: []string{"sha256", "sha-256", "sha2"},
		Algorithms: []InferredAlgorithm{
			{Algorithm: "SHA-256", Type: "hash", Confidence: types.ConfidenceHigh, Reason: "Package name indicates SHA-256"},
		},
	},
	{
		Patterns: []string{"sha512", "sha-512"},
		Algorithms: []InferredAlgorithm{
			{Algorithm: "SHA-512", Type: "hash", Confidence: types.ConfidenceHigh, Reason: "Package name indicates SHA-512"},
		},
	},
	{
		Patterns: []string{"sha384", "sha-384"},
		Algorithms: []InferredAlgorithm{
			{Algorithm: "SHA-384", Type: "hash", Confidence: types.ConfidenceHigh, Reason: "Package name indicates SHA-384"},
		},
	},
	{
		Patterns: []string{"sha1", "sha-1"},
		Algorithms: []InferredAlgorithm{
			{Algorithm: "SHA-1", Type: "hash", Confidence: types.ConfidenceHigh, Reason: "Package name indicates SHA-1"},
		},
	},
	{
		Patterns: []string{"md5"},
		Algorithms: []InferredAlgorithm{
			{Algorithm: "MD5", Type: "hash", Confidence: types.ConfidenceHigh, Reason: "Package name indicates MD5"},
		},
	},
	// HMAC
	{
		Patterns: []string{"hmac"},
		Algorithms: []InferredAlgorithm{
			{Algorithm: "HMAC", Type: "hash", Confidence: types.ConfidenceHigh, Reason: "Package name indicates HMAC"},
		},
	},
	// PBKDF2
	{
		Patterns: []string{"pbkdf2", "pbkdf"},
		Algorithms: []InferredAlgorithm{
			{Algorithm: "PBKDF2", Type: "hash", Confidence: types.ConfidenceHigh, Reason: "Package name indicates PBKDF2"},
		},
	},
	// Post-quantum
	{
		Patterns: []string{"kyber", "ml-kem", "mlkem"},
		Algorithms: []InferredAlgorithm{
			{Algorithm: "ML-KEM", Type: "key-exchange", Confidence: types.ConfidenceHigh, Reason: "Package implements post-quantum key exchange"},
		},
	},
	{
		Patterns: []string{"dilithium", "ml-dsa", "mldsa"},
		Algorithms: []InferredAlgorithm{
			{Algorithm: "ML-DSA", Type: "signature", Confidence: types.ConfidenceHigh, Reason: "Package implements post-quantum signatures"},
		},
	},
	{
		Patterns: []string{"sphincs", "slh-dsa"},
		Algorithms: []InferredAlgorithm{
			{Algorithm: "SLH-DSA", Type: "signature", Confidence: types.ConfidenceHigh, Reason: "Package implements post-quantum signatures"},
		},
	},
	{
		Patterns: []string{"post-quantum", "pqc", "liboqs"},
		Algorithms: []InferredAlgorithm{
			{Algorithm: "ML-KEM", Type: "key-exchange", Confidence: types.ConfidenceMedium, Reason: "Post-quantum library likely supports ML-KEM"},
			{Algorithm: "ML-DSA", Type: "signature", Confidence: types.ConfidenceMedium, Reason: "Post-quantum library likely supports ML-DSA"},
		},
	},
	// General crypto libraries
	{
		Patterns: []string{"crypto-js", "cryptojs"},
		Algorithms: []InferredAlgorithm{
			{Algorithm: "AES", Type: "encryption", Confidence: types.ConfidenceHigh, Reason: "CryptoJS supports AES"},
			{Algorithm: "DES", Type: "encryption", Confidence: types.ConfidenceMedium, Reason: "CryptoJS supports DES"},
			{Algorithm: "3DES", Type: "encryption", Confidence: types.ConfidenceMedium, Reason: "CryptoJS supports 3DES"},
			{Algorithm: "SHA-256", Type: "hash", Confidence: types.ConfidenceHigh, Reason: "CryptoJS supports SHA-256"},
			{Algorithm: "MD5", Type: "hash", Confidence: types.ConfidenceHigh, Reason: "CryptoJS supports MD5"},
			{Algorithm: "HMAC", Type: "hash", Confidence: types.ConfidenceHigh, Reason: "CryptoJS supports HMAC"},
		},
	},
	{
		Patterns: []string{"bouncycastle", "bouncy castle", "bcprov"},
		Algorithms: []InferredAlgorithm{
			{Algorithm: "RSA", Type: "encryption", Confidence: types.ConfidenceHigh, Reason: "BouncyCastle supports RSA"},
			{Algorithm: "ECDSA", Type: "signature", Confidence: types.ConfidenceHigh, Reason: "BouncyCastle supports ECDSA"},
			{Algorithm: "AES", Type: "encryption", Confidence: types.ConfidenceHigh, Reason: "BouncyCastle supports AES"},
			{Algorithm: "SHA-256", Type: "hash", Confidence: types.ConfidenceHigh, Reason: "BouncyCastle supports SHA-256"},
			{Algorithm: "Ed25519", Type: "signature", Confidence: types.ConfidenceMedium, Reason: "BouncyCastle supports Ed25519"},
		},
	},
	{
		Patterns: []string{"pycryptodome", "pycrypto"},
		Algorithms: []InferredAlgorithm{
			{Algorithm: "RSA", Type: "encryption", Confidence: types.ConfidenceHigh, Reason: "PyCryptodome supports RSA"},
			{Algorithm: "AES", Type: "encryption", Confidence: types.ConfidenceHigh, Reason: "PyCryptodome supports AES"},
			{Algorithm: "DES", Type: "encryption", Confidence: types.ConfidenceMedium, Reason: "PyCryptodome supports DES"},
			{Algorithm: "SHA-256", Type: "hash", Confidence: types.ConfidenceHigh, Reason: "PyCryptodome supports SHA-256"},
			{Algorithm: "ECDSA", Type: "signature", Confidence: types.ConfidenceMedium, Reason: "PyCryptodome supports ECDSA"},
		},
	},
	{
		Patterns: []string{"cryptography"},
		Algorithms: []InferredAlgorithm{
			{Algorithm: "RSA", Type: "encryption", Confidence: types.ConfidenceHigh, Reason: "Python cryptography library supports RSA"},
			{Algorithm: "AES", Type: "encryption", Confidence: types.ConfidenceHigh, Reason: "Python cryptography library supports AES"},
			{Algorithm: "ECDSA", Type: "signature", Confidence: types.ConfidenceHigh, Reason: "Python cryptography library supports ECDSA"},
			{Algorithm: "Ed25519", Type: "signature", Confidence: types.ConfidenceHigh, Reason: "Python cryptography library supports Ed25519"},
			{Algorithm: "X25519", Type: "key-exchange", Confidence: types.ConfidenceHigh, Reason: "Python cryptography library supports X25519"},
			{Algorithm: "ChaCha20-Poly1305", Type: "encryption", Confidence: types.ConfidenceHigh, Reason: "Python cryptography library supports ChaCha20"},
		},
	},
	{
		Patterns: []string{"circl"},
		Algorithms: []InferredAlgorithm{
			{Algorithm: "ML-KEM", Type: "key-exchange", Confidence: types.ConfidenceHigh, Reason: "CIRCL supports post-quantum algorithms"},
			{Algorithm: "ML-DSA", Type: "signature", Confidence: types.ConfidenceHigh, Reason: "CIRCL supports post-quantum algorithms"},
			{Algorithm: "X25519", Type: "key-exchange", Confidence: types.ConfidenceHigh, Reason: "CIRCL supports X25519"},
			{Algorithm: "Ed25519", Type: "signature", Confidence: types.ConfidenceHigh, Reason: "CIRCL supports Ed25519"},
			{Algorithm: "P-256", Type: "signature", Confidence: types.ConfidenceHigh, Reason: "CIRCL supports NIST curves"},
		},
	},
}

// ToPackageAnalysis converts inferred algorithms to a PackageAnalysis.
func ToPackageAnalysis(pkg PackageInfo, algorithms []InferredAlgorithm) types.PackageAnalysis {
	var cryptoUsages []types.CryptoUsage

	for _, alg := range algorithms {
		risk := crypto.GetQuantumRisk(alg.Algorithm)
		severity := types.SeverityInfo
		if risk == types.RiskVulnerable {
			severity = types.SeverityHigh
		} else if risk == types.RiskPartial {
			severity = types.SeverityMedium
		}

		remediation := crypto.GetRemediation(alg.Algorithm)

		cryptoUsages = append(cryptoUsages, types.CryptoUsage{
			Algorithm:   alg.Algorithm,
			Type:        alg.Type,
			QuantumRisk: risk,
			Severity:    severity,
			Location:    types.Location{},
			Remediation: remediation,
			Confidence:  alg.Confidence,
		})
	}

	// Calculate summary
	summary := types.QuantumSummary{}
	for _, cu := range cryptoUsages {
		switch cu.QuantumRisk {
		case types.RiskVulnerable:
			summary.Vulnerable++
		case types.RiskPartial:
			summary.Partial++
		case types.RiskSafe:
			summary.Safe++
		default:
			summary.Unknown++
		}
	}

	return types.PackageAnalysis{
		Package:   pkg.Name,
		Version:   pkg.Version,
		Ecosystem: pkg.Ecosystem,
		Analysis: types.AnalysisMetadata{
			Date: pkg.UpdatedAt,
			// This record is produced by the running binary, so it is the one
			// place where the scanner's own version is the honest provenance.
			Method:      "inferred",
			Tool:        version.Name,
			ToolVersion: version.Version(),
		},
		Crypto:         cryptoUsages,
		QuantumSummary: summary,
	}
}
