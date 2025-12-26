// Copyright 2024-2025 CSNP (csnp.org)
// SPDX-License-Identifier: Apache-2.0

// Package crypto provides cryptographic algorithm classification and quantum risk assessment.
package crypto

import (
	"strings"

	"github.com/csnp/qramm-cryptodeps/pkg/types"
)

// AlgorithmInfo contains metadata about a cryptographic algorithm.
type AlgorithmInfo struct {
	Name        string
	Type        string // encryption, signature, hash, key-exchange
	QuantumRisk types.QuantumRisk
	Severity    types.Severity
	Description string
	Remediation string // migration guidance for quantum-vulnerable algorithms
}

// algorithmDatabase maps algorithm identifiers to their info.
var algorithmDatabase = map[string]AlgorithmInfo{
	// Asymmetric - VULNERABLE to Shor's algorithm
	"rsa":       {Name: "RSA", Type: "encryption", QuantumRisk: types.RiskVulnerable, Severity: types.SeverityHigh, Description: "RSA encryption/signatures", Remediation: "Migrate to ML-KEM (FIPS 203) for encryption or ML-DSA (FIPS 204) for signatures"},
	"rsa-2048":  {Name: "RSA-2048", Type: "encryption", QuantumRisk: types.RiskVulnerable, Severity: types.SeverityMedium, Description: "2048-bit RSA", Remediation: "Migrate to ML-KEM (FIPS 203) for encryption or ML-DSA (FIPS 204) for signatures"},
	"rsa-4096":  {Name: "RSA-4096", Type: "encryption", QuantumRisk: types.RiskVulnerable, Severity: types.SeverityMedium, Description: "4096-bit RSA", Remediation: "Migrate to ML-KEM (FIPS 203) for encryption or ML-DSA (FIPS 204) for signatures"},
	"ecdsa":     {Name: "ECDSA", Type: "signature", QuantumRisk: types.RiskVulnerable, Severity: types.SeverityHigh, Description: "Elliptic Curve DSA", Remediation: "Migrate to ML-DSA (FIPS 204) or SLH-DSA (FIPS 205) for signatures"},
	"ecdh":      {Name: "ECDH", Type: "key-exchange", QuantumRisk: types.RiskVulnerable, Severity: types.SeverityHigh, Description: "Elliptic Curve Diffie-Hellman", Remediation: "Migrate to ML-KEM (FIPS 203) for key exchange"},
	"ed25519":   {Name: "Ed25519", Type: "signature", QuantumRisk: types.RiskVulnerable, Severity: types.SeverityHigh, Description: "EdDSA with Curve25519", Remediation: "Migrate to ML-DSA (FIPS 204) or SLH-DSA (FIPS 205) for signatures"},
	"ed448":     {Name: "Ed448", Type: "signature", QuantumRisk: types.RiskVulnerable, Severity: types.SeverityHigh, Description: "EdDSA with Curve448", Remediation: "Migrate to ML-DSA (FIPS 204) or SLH-DSA (FIPS 205) for signatures"},
	"x25519":    {Name: "X25519", Type: "key-exchange", QuantumRisk: types.RiskVulnerable, Severity: types.SeverityHigh, Description: "X25519 key exchange", Remediation: "Migrate to ML-KEM (FIPS 203) for key exchange"},
	"dsa":       {Name: "DSA", Type: "signature", QuantumRisk: types.RiskVulnerable, Severity: types.SeverityHigh, Description: "Digital Signature Algorithm", Remediation: "Migrate to ML-DSA (FIPS 204) for signatures"},
	"dh":        {Name: "DH", Type: "key-exchange", QuantumRisk: types.RiskVulnerable, Severity: types.SeverityHigh, Description: "Diffie-Hellman", Remediation: "Migrate to ML-KEM (FIPS 203) for key exchange"},
	"dhe":       {Name: "DHE", Type: "key-exchange", QuantumRisk: types.RiskVulnerable, Severity: types.SeverityHigh, Description: "Ephemeral Diffie-Hellman", Remediation: "Migrate to ML-KEM (FIPS 203) for key exchange"},
	"p-256":     {Name: "P-256", Type: "key-exchange", QuantumRisk: types.RiskVulnerable, Severity: types.SeverityHigh, Description: "NIST P-256 curve", Remediation: "Migrate to ML-KEM (FIPS 203) for key exchange"},
	"p-384":     {Name: "P-384", Type: "key-exchange", QuantumRisk: types.RiskVulnerable, Severity: types.SeverityHigh, Description: "NIST P-384 curve", Remediation: "Migrate to ML-KEM (FIPS 203) for key exchange"},
	"p-521":     {Name: "P-521", Type: "key-exchange", QuantumRisk: types.RiskVulnerable, Severity: types.SeverityHigh, Description: "NIST P-521 curve", Remediation: "Migrate to ML-KEM (FIPS 203) for key exchange"},
	"secp256k1": {Name: "secp256k1", Type: "key-exchange", QuantumRisk: types.RiskVulnerable, Severity: types.SeverityHigh, Description: "Bitcoin/Ethereum curve", Remediation: "Migrate to ML-KEM (FIPS 203) for key exchange"},

	// JWT/JWS algorithm names
	"rs256": {Name: "RS256", Type: "signature", QuantumRisk: types.RiskVulnerable, Severity: types.SeverityHigh, Description: "RSASSA-PKCS1-v1_5 with SHA-256", Remediation: "Use HS256/HS512 for symmetric signing, or wait for PQ-JWT standards"},
	"rs384": {Name: "RS384", Type: "signature", QuantumRisk: types.RiskVulnerable, Severity: types.SeverityHigh, Description: "RSASSA-PKCS1-v1_5 with SHA-384", Remediation: "Use HS384/HS512 for symmetric signing, or wait for PQ-JWT standards"},
	"rs512": {Name: "RS512", Type: "signature", QuantumRisk: types.RiskVulnerable, Severity: types.SeverityHigh, Description: "RSASSA-PKCS1-v1_5 with SHA-512", Remediation: "Use HS512 for symmetric signing, or wait for PQ-JWT standards"},
	"es256": {Name: "ES256", Type: "signature", QuantumRisk: types.RiskVulnerable, Severity: types.SeverityHigh, Description: "ECDSA with P-256 and SHA-256", Remediation: "Use HS256/HS512 for symmetric signing, or wait for PQ-JWT standards"},
	"es384": {Name: "ES384", Type: "signature", QuantumRisk: types.RiskVulnerable, Severity: types.SeverityHigh, Description: "ECDSA with P-384 and SHA-384", Remediation: "Use HS384/HS512 for symmetric signing, or wait for PQ-JWT standards"},
	"es512": {Name: "ES512", Type: "signature", QuantumRisk: types.RiskVulnerable, Severity: types.SeverityHigh, Description: "ECDSA with P-521 and SHA-512", Remediation: "Use HS512 for symmetric signing, or wait for PQ-JWT standards"},
	"ps256": {Name: "PS256", Type: "signature", QuantumRisk: types.RiskVulnerable, Severity: types.SeverityHigh, Description: "RSASSA-PSS with SHA-256", Remediation: "Use HS256/HS512 for symmetric signing, or wait for PQ-JWT standards"},
	"ps384": {Name: "PS384", Type: "signature", QuantumRisk: types.RiskVulnerable, Severity: types.SeverityHigh, Description: "RSASSA-PSS with SHA-384", Remediation: "Use HS384/HS512 for symmetric signing, or wait for PQ-JWT standards"},
	"ps512": {Name: "PS512", Type: "signature", QuantumRisk: types.RiskVulnerable, Severity: types.SeverityHigh, Description: "RSASSA-PSS with SHA-512", Remediation: "Use HS512 for symmetric signing, or wait for PQ-JWT standards"},

	// Symmetric - PARTIAL (Grover's reduces security by half)
	"aes":         {Name: "AES", Type: "encryption", QuantumRisk: types.RiskPartial, Severity: types.SeverityInfo, Description: "Advanced Encryption Standard", Remediation: "Use AES-256 for 128-bit post-quantum security"},
	"aes-128":     {Name: "AES-128", Type: "encryption", QuantumRisk: types.RiskPartial, Severity: types.SeverityLow, Description: "AES with 128-bit key (64-bit post-quantum)", Remediation: "Upgrade to AES-256 for 128-bit post-quantum security"},
	"aes-192":     {Name: "AES-192", Type: "encryption", QuantumRisk: types.RiskPartial, Severity: types.SeverityInfo, Description: "AES with 192-bit key", Remediation: "Consider upgrading to AES-256"},
	"aes-256":     {Name: "AES-256", Type: "encryption", QuantumRisk: types.RiskSafe, Severity: types.SeverityInfo, Description: "AES with 256-bit key (128-bit post-quantum)", Remediation: "No action needed - quantum safe"},
	"aes-gcm":     {Name: "AES-GCM", Type: "encryption", QuantumRisk: types.RiskPartial, Severity: types.SeverityInfo, Description: "AES Galois/Counter Mode", Remediation: "Use AES-256-GCM for post-quantum security"},
	"aes-cbc":     {Name: "AES-CBC", Type: "encryption", QuantumRisk: types.RiskPartial, Severity: types.SeverityInfo, Description: "AES Cipher Block Chaining", Remediation: "Consider AES-256-GCM for authenticated encryption"},
	"chacha20":    {Name: "ChaCha20", Type: "encryption", QuantumRisk: types.RiskSafe, Severity: types.SeverityInfo, Description: "ChaCha20 stream cipher", Remediation: "No action needed - quantum safe"},
	"xchacha20":   {Name: "XChaCha20", Type: "encryption", QuantumRisk: types.RiskSafe, Severity: types.SeverityInfo, Description: "Extended nonce ChaCha20", Remediation: "No action needed - quantum safe"},
	"poly1305":    {Name: "Poly1305", Type: "hash", QuantumRisk: types.RiskSafe, Severity: types.SeverityInfo, Description: "Poly1305 MAC", Remediation: "No action needed - quantum safe"},

	// HMAC algorithms
	"hs256":       {Name: "HS256", Type: "signature", QuantumRisk: types.RiskPartial, Severity: types.SeverityInfo, Description: "HMAC with SHA-256", Remediation: "Consider HS512 for stronger post-quantum security"},
	"hs384":       {Name: "HS384", Type: "signature", QuantumRisk: types.RiskPartial, Severity: types.SeverityInfo, Description: "HMAC with SHA-384", Remediation: "Consider HS512 for stronger post-quantum security"},
	"hs512":       {Name: "HS512", Type: "signature", QuantumRisk: types.RiskSafe, Severity: types.SeverityInfo, Description: "HMAC with SHA-512", Remediation: "No action needed - quantum safe"},
	"hmac":        {Name: "HMAC", Type: "mac", QuantumRisk: types.RiskPartial, Severity: types.SeverityInfo, Description: "HMAC", Remediation: "Use HMAC-SHA384 or HMAC-SHA512 for post-quantum security"},
	"hmac-md5":    {Name: "HMAC-MD5", Type: "mac", QuantumRisk: types.RiskVulnerable, Severity: types.SeverityCritical, Description: "HMAC with MD5", Remediation: "Replace immediately with HMAC-SHA256 or stronger"},
	"hmac-sha1":   {Name: "HMAC-SHA1", Type: "mac", QuantumRisk: types.RiskPartial, Severity: types.SeverityMedium, Description: "HMAC with SHA-1", Remediation: "Upgrade to HMAC-SHA256 or stronger"},
	"hmac-sha256": {Name: "HMAC-SHA256", Type: "mac", QuantumRisk: types.RiskPartial, Severity: types.SeverityInfo, Description: "HMAC with SHA-256", Remediation: "Consider HMAC-SHA512 for stronger post-quantum security"},
	"hmac-sha384": {Name: "HMAC-SHA384", Type: "mac", QuantumRisk: types.RiskSafe, Severity: types.SeverityInfo, Description: "HMAC with SHA-384", Remediation: "No action needed - quantum safe"},
	"hmac-sha512": {Name: "HMAC-SHA512", Type: "mac", QuantumRisk: types.RiskSafe, Severity: types.SeverityInfo, Description: "HMAC with SHA-512", Remediation: "No action needed - quantum safe"},

	// Hash functions - PARTIAL (Grover's reduces collision resistance)
	"sha-1":   {Name: "SHA-1", Type: "hash", QuantumRisk: types.RiskVulnerable, Severity: types.SeverityCritical, Description: "SHA-1 (broken classically)", Remediation: "Replace immediately with SHA-256 or SHA-3"},
	"sha1":    {Name: "SHA-1", Type: "hash", QuantumRisk: types.RiskVulnerable, Severity: types.SeverityCritical, Description: "SHA-1 (broken classically)", Remediation: "Replace immediately with SHA-256 or SHA-3"},
	"sha-256": {Name: "SHA-256", Type: "hash", QuantumRisk: types.RiskPartial, Severity: types.SeverityInfo, Description: "SHA-256", Remediation: "Consider SHA-384/SHA-512 for stronger post-quantum security"},
	"sha256":  {Name: "SHA-256", Type: "hash", QuantumRisk: types.RiskPartial, Severity: types.SeverityInfo, Description: "SHA-256", Remediation: "Consider SHA-384/SHA-512 for stronger post-quantum security"},
	"sha-384": {Name: "SHA-384", Type: "hash", QuantumRisk: types.RiskSafe, Severity: types.SeverityInfo, Description: "SHA-384", Remediation: "No action needed - quantum safe"},
	"sha384":  {Name: "SHA-384", Type: "hash", QuantumRisk: types.RiskSafe, Severity: types.SeverityInfo, Description: "SHA-384", Remediation: "No action needed - quantum safe"},
	"sha-512": {Name: "SHA-512", Type: "hash", QuantumRisk: types.RiskSafe, Severity: types.SeverityInfo, Description: "SHA-512", Remediation: "No action needed - quantum safe"},
	"sha512":  {Name: "SHA-512", Type: "hash", QuantumRisk: types.RiskSafe, Severity: types.SeverityInfo, Description: "SHA-512", Remediation: "No action needed - quantum safe"},
	"sha3":    {Name: "SHA-3", Type: "hash", QuantumRisk: types.RiskSafe, Severity: types.SeverityInfo, Description: "SHA-3", Remediation: "No action needed - quantum safe"},
	"md5":     {Name: "MD5", Type: "hash", QuantumRisk: types.RiskVulnerable, Severity: types.SeverityCritical, Description: "MD5 (broken classically)", Remediation: "Replace immediately with SHA-256 or SHA-3"},
	"blake2":  {Name: "BLAKE2", Type: "hash", QuantumRisk: types.RiskSafe, Severity: types.SeverityInfo, Description: "BLAKE2 hash", Remediation: "No action needed - quantum safe"},
	"blake3":  {Name: "BLAKE3", Type: "hash", QuantumRisk: types.RiskSafe, Severity: types.SeverityInfo, Description: "BLAKE3 hash", Remediation: "No action needed - quantum safe"},

	// Broken classical algorithms
	"des":    {Name: "DES", Type: "encryption", QuantumRisk: types.RiskVulnerable, Severity: types.SeverityCritical, Description: "DES (56-bit, broken)", Remediation: "Replace immediately with AES-256"},
	"3des":   {Name: "3DES", Type: "encryption", QuantumRisk: types.RiskVulnerable, Severity: types.SeverityHigh, Description: "Triple DES", Remediation: "Replace with AES-256"},
	"rc4":    {Name: "RC4", Type: "encryption", QuantumRisk: types.RiskVulnerable, Severity: types.SeverityCritical, Description: "RC4 (broken)", Remediation: "Replace immediately with AES-256 or ChaCha20"},
	"rc2":    {Name: "RC2", Type: "encryption", QuantumRisk: types.RiskVulnerable, Severity: types.SeverityCritical, Description: "RC2 (weak)", Remediation: "Replace immediately with AES-256"},

	// Post-Quantum - SAFE
	"ml-kem":     {Name: "ML-KEM", Type: "key-exchange", QuantumRisk: types.RiskSafe, Severity: types.SeverityInfo, Description: "NIST FIPS 203 (Kyber)", Remediation: "No action needed - quantum safe"},
	"ml-dsa":     {Name: "ML-DSA", Type: "signature", QuantumRisk: types.RiskSafe, Severity: types.SeverityInfo, Description: "NIST FIPS 204 (Dilithium)", Remediation: "No action needed - quantum safe"},
	"slh-dsa":    {Name: "SLH-DSA", Type: "signature", QuantumRisk: types.RiskSafe, Severity: types.SeverityInfo, Description: "NIST FIPS 205 (SPHINCS+)", Remediation: "No action needed - quantum safe"},
	"kyber":      {Name: "Kyber", Type: "key-exchange", QuantumRisk: types.RiskSafe, Severity: types.SeverityInfo, Description: "Kyber KEM", Remediation: "No action needed - quantum safe"},
	"dilithium":  {Name: "Dilithium", Type: "signature", QuantumRisk: types.RiskSafe, Severity: types.SeverityInfo, Description: "Dilithium signature", Remediation: "No action needed - quantum safe"},
	"sphincs":    {Name: "SPHINCS+", Type: "signature", QuantumRisk: types.RiskSafe, Severity: types.SeverityInfo, Description: "SPHINCS+ signature", Remediation: "No action needed - quantum safe"},
}

// ClassifyAlgorithm returns information about an algorithm.
func ClassifyAlgorithm(algorithm string) (AlgorithmInfo, bool) {
	key := strings.ToLower(strings.ReplaceAll(algorithm, "_", "-"))
	info, found := algorithmDatabase[key]
	return info, found
}

// GetQuantumRisk returns the quantum risk for an algorithm.
func GetQuantumRisk(algorithm string) types.QuantumRisk {
	info, found := ClassifyAlgorithm(algorithm)
	if !found {
		return types.RiskUnknown
	}
	return info.QuantumRisk
}

// GetSeverity returns the severity for an algorithm.
func GetSeverity(algorithm string) types.Severity {
	info, found := ClassifyAlgorithm(algorithm)
	if !found {
		return types.SeverityInfo
	}
	return info.Severity
}

// IsVulnerable returns true if the algorithm is quantum-vulnerable.
func IsVulnerable(algorithm string) bool {
	return GetQuantumRisk(algorithm) == types.RiskVulnerable
}

// NormalizeAlgorithmName returns the canonical name for an algorithm.
// This ensures consistent naming (e.g., "sha256" -> "SHA-256", "aes-gcm" -> "AES-GCM").
func NormalizeAlgorithmName(algorithm string) string {
	info, found := ClassifyAlgorithm(algorithm)
	if found {
		return info.Name
	}
	// Return original if not found in database
	return algorithm
}

// GetRemediation returns the remediation guidance for an algorithm.
func GetRemediation(algorithm string) string {
	info, found := ClassifyAlgorithm(algorithm)
	if !found {
		return ""
	}
	return info.Remediation
}
