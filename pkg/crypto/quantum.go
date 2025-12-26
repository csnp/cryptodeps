// Copyright 2024 CSNP (csnp.org)
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
}

// algorithmDatabase maps algorithm identifiers to their info.
var algorithmDatabase = map[string]AlgorithmInfo{
	// Asymmetric - VULNERABLE to Shor's algorithm
	"rsa":       {Name: "RSA", Type: "encryption", QuantumRisk: types.RiskVulnerable, Severity: types.SeverityHigh, Description: "RSA encryption/signatures"},
	"rsa-2048":  {Name: "RSA-2048", Type: "encryption", QuantumRisk: types.RiskVulnerable, Severity: types.SeverityMedium, Description: "2048-bit RSA"},
	"rsa-4096":  {Name: "RSA-4096", Type: "encryption", QuantumRisk: types.RiskVulnerable, Severity: types.SeverityMedium, Description: "4096-bit RSA"},
	"ecdsa":     {Name: "ECDSA", Type: "signature", QuantumRisk: types.RiskVulnerable, Severity: types.SeverityHigh, Description: "Elliptic Curve DSA"},
	"ecdh":      {Name: "ECDH", Type: "key-exchange", QuantumRisk: types.RiskVulnerable, Severity: types.SeverityHigh, Description: "Elliptic Curve Diffie-Hellman"},
	"ed25519":   {Name: "Ed25519", Type: "signature", QuantumRisk: types.RiskVulnerable, Severity: types.SeverityHigh, Description: "EdDSA with Curve25519"},
	"ed448":     {Name: "Ed448", Type: "signature", QuantumRisk: types.RiskVulnerable, Severity: types.SeverityHigh, Description: "EdDSA with Curve448"},
	"x25519":    {Name: "X25519", Type: "key-exchange", QuantumRisk: types.RiskVulnerable, Severity: types.SeverityHigh, Description: "X25519 key exchange"},
	"dsa":       {Name: "DSA", Type: "signature", QuantumRisk: types.RiskVulnerable, Severity: types.SeverityHigh, Description: "Digital Signature Algorithm"},
	"dh":        {Name: "DH", Type: "key-exchange", QuantumRisk: types.RiskVulnerable, Severity: types.SeverityHigh, Description: "Diffie-Hellman"},
	"dhe":       {Name: "DHE", Type: "key-exchange", QuantumRisk: types.RiskVulnerable, Severity: types.SeverityHigh, Description: "Ephemeral Diffie-Hellman"},
	"p-256":     {Name: "P-256", Type: "key-exchange", QuantumRisk: types.RiskVulnerable, Severity: types.SeverityHigh, Description: "NIST P-256 curve"},
	"p-384":     {Name: "P-384", Type: "key-exchange", QuantumRisk: types.RiskVulnerable, Severity: types.SeverityHigh, Description: "NIST P-384 curve"},
	"p-521":     {Name: "P-521", Type: "key-exchange", QuantumRisk: types.RiskVulnerable, Severity: types.SeverityHigh, Description: "NIST P-521 curve"},
	"secp256k1": {Name: "secp256k1", Type: "key-exchange", QuantumRisk: types.RiskVulnerable, Severity: types.SeverityHigh, Description: "Bitcoin/Ethereum curve"},

	// JWT/JWS algorithm names
	"rs256": {Name: "RS256", Type: "signature", QuantumRisk: types.RiskVulnerable, Severity: types.SeverityHigh, Description: "RSASSA-PKCS1-v1_5 with SHA-256"},
	"rs384": {Name: "RS384", Type: "signature", QuantumRisk: types.RiskVulnerable, Severity: types.SeverityHigh, Description: "RSASSA-PKCS1-v1_5 with SHA-384"},
	"rs512": {Name: "RS512", Type: "signature", QuantumRisk: types.RiskVulnerable, Severity: types.SeverityHigh, Description: "RSASSA-PKCS1-v1_5 with SHA-512"},
	"es256": {Name: "ES256", Type: "signature", QuantumRisk: types.RiskVulnerable, Severity: types.SeverityHigh, Description: "ECDSA with P-256 and SHA-256"},
	"es384": {Name: "ES384", Type: "signature", QuantumRisk: types.RiskVulnerable, Severity: types.SeverityHigh, Description: "ECDSA with P-384 and SHA-384"},
	"es512": {Name: "ES512", Type: "signature", QuantumRisk: types.RiskVulnerable, Severity: types.SeverityHigh, Description: "ECDSA with P-521 and SHA-512"},
	"ps256": {Name: "PS256", Type: "signature", QuantumRisk: types.RiskVulnerable, Severity: types.SeverityHigh, Description: "RSASSA-PSS with SHA-256"},
	"ps384": {Name: "PS384", Type: "signature", QuantumRisk: types.RiskVulnerable, Severity: types.SeverityHigh, Description: "RSASSA-PSS with SHA-384"},
	"ps512": {Name: "PS512", Type: "signature", QuantumRisk: types.RiskVulnerable, Severity: types.SeverityHigh, Description: "RSASSA-PSS with SHA-512"},

	// Symmetric - PARTIAL (Grover's reduces security by half)
	"aes":         {Name: "AES", Type: "encryption", QuantumRisk: types.RiskPartial, Severity: types.SeverityInfo, Description: "Advanced Encryption Standard"},
	"aes-128":     {Name: "AES-128", Type: "encryption", QuantumRisk: types.RiskPartial, Severity: types.SeverityLow, Description: "AES with 128-bit key (64-bit post-quantum)"},
	"aes-192":     {Name: "AES-192", Type: "encryption", QuantumRisk: types.RiskPartial, Severity: types.SeverityInfo, Description: "AES with 192-bit key"},
	"aes-256":     {Name: "AES-256", Type: "encryption", QuantumRisk: types.RiskSafe, Severity: types.SeverityInfo, Description: "AES with 256-bit key (128-bit post-quantum)"},
	"aes-gcm":     {Name: "AES-GCM", Type: "encryption", QuantumRisk: types.RiskPartial, Severity: types.SeverityInfo, Description: "AES Galois/Counter Mode"},
	"aes-cbc":     {Name: "AES-CBC", Type: "encryption", QuantumRisk: types.RiskPartial, Severity: types.SeverityInfo, Description: "AES Cipher Block Chaining"},
	"chacha20":    {Name: "ChaCha20", Type: "encryption", QuantumRisk: types.RiskSafe, Severity: types.SeverityInfo, Description: "ChaCha20 stream cipher"},
	"xchacha20":   {Name: "XChaCha20", Type: "encryption", QuantumRisk: types.RiskSafe, Severity: types.SeverityInfo, Description: "Extended nonce ChaCha20"},
	"poly1305":    {Name: "Poly1305", Type: "hash", QuantumRisk: types.RiskSafe, Severity: types.SeverityInfo, Description: "Poly1305 MAC"},

	// HMAC algorithms
	"hs256":       {Name: "HS256", Type: "signature", QuantumRisk: types.RiskPartial, Severity: types.SeverityInfo, Description: "HMAC with SHA-256"},
	"hs384":       {Name: "HS384", Type: "signature", QuantumRisk: types.RiskPartial, Severity: types.SeverityInfo, Description: "HMAC with SHA-384"},
	"hs512":       {Name: "HS512", Type: "signature", QuantumRisk: types.RiskSafe, Severity: types.SeverityInfo, Description: "HMAC with SHA-512"},
	"hmac":        {Name: "HMAC", Type: "mac", QuantumRisk: types.RiskPartial, Severity: types.SeverityInfo, Description: "HMAC"},
	"hmac-md5":    {Name: "HMAC-MD5", Type: "mac", QuantumRisk: types.RiskVulnerable, Severity: types.SeverityCritical, Description: "HMAC with MD5"},
	"hmac-sha1":   {Name: "HMAC-SHA1", Type: "mac", QuantumRisk: types.RiskPartial, Severity: types.SeverityMedium, Description: "HMAC with SHA-1"},
	"hmac-sha256": {Name: "HMAC-SHA256", Type: "mac", QuantumRisk: types.RiskPartial, Severity: types.SeverityInfo, Description: "HMAC with SHA-256"},
	"hmac-sha384": {Name: "HMAC-SHA384", Type: "mac", QuantumRisk: types.RiskSafe, Severity: types.SeverityInfo, Description: "HMAC with SHA-384"},
	"hmac-sha512": {Name: "HMAC-SHA512", Type: "mac", QuantumRisk: types.RiskSafe, Severity: types.SeverityInfo, Description: "HMAC with SHA-512"},

	// Hash functions - PARTIAL (Grover's reduces collision resistance)
	"sha-1":   {Name: "SHA-1", Type: "hash", QuantumRisk: types.RiskVulnerable, Severity: types.SeverityCritical, Description: "SHA-1 (broken classically)"},
	"sha1":    {Name: "SHA-1", Type: "hash", QuantumRisk: types.RiskVulnerable, Severity: types.SeverityCritical, Description: "SHA-1 (broken classically)"},
	"sha-256": {Name: "SHA-256", Type: "hash", QuantumRisk: types.RiskPartial, Severity: types.SeverityInfo, Description: "SHA-256"},
	"sha256":  {Name: "SHA-256", Type: "hash", QuantumRisk: types.RiskPartial, Severity: types.SeverityInfo, Description: "SHA-256"},
	"sha-384": {Name: "SHA-384", Type: "hash", QuantumRisk: types.RiskSafe, Severity: types.SeverityInfo, Description: "SHA-384"},
	"sha384":  {Name: "SHA-384", Type: "hash", QuantumRisk: types.RiskSafe, Severity: types.SeverityInfo, Description: "SHA-384"},
	"sha-512": {Name: "SHA-512", Type: "hash", QuantumRisk: types.RiskSafe, Severity: types.SeverityInfo, Description: "SHA-512"},
	"sha512":  {Name: "SHA-512", Type: "hash", QuantumRisk: types.RiskSafe, Severity: types.SeverityInfo, Description: "SHA-512"},
	"sha3":    {Name: "SHA-3", Type: "hash", QuantumRisk: types.RiskSafe, Severity: types.SeverityInfo, Description: "SHA-3"},
	"md5":     {Name: "MD5", Type: "hash", QuantumRisk: types.RiskVulnerable, Severity: types.SeverityCritical, Description: "MD5 (broken classically)"},
	"blake2":  {Name: "BLAKE2", Type: "hash", QuantumRisk: types.RiskSafe, Severity: types.SeverityInfo, Description: "BLAKE2 hash"},
	"blake3":  {Name: "BLAKE3", Type: "hash", QuantumRisk: types.RiskSafe, Severity: types.SeverityInfo, Description: "BLAKE3 hash"},

	// Broken classical algorithms
	"des":    {Name: "DES", Type: "encryption", QuantumRisk: types.RiskVulnerable, Severity: types.SeverityCritical, Description: "DES (56-bit, broken)"},
	"3des":   {Name: "3DES", Type: "encryption", QuantumRisk: types.RiskVulnerable, Severity: types.SeverityHigh, Description: "Triple DES"},
	"rc4":    {Name: "RC4", Type: "encryption", QuantumRisk: types.RiskVulnerable, Severity: types.SeverityCritical, Description: "RC4 (broken)"},
	"rc2":    {Name: "RC2", Type: "encryption", QuantumRisk: types.RiskVulnerable, Severity: types.SeverityCritical, Description: "RC2 (weak)"},

	// Post-Quantum - SAFE
	"ml-kem":     {Name: "ML-KEM", Type: "key-exchange", QuantumRisk: types.RiskSafe, Severity: types.SeverityInfo, Description: "NIST FIPS 203 (Kyber)"},
	"ml-dsa":     {Name: "ML-DSA", Type: "signature", QuantumRisk: types.RiskSafe, Severity: types.SeverityInfo, Description: "NIST FIPS 204 (Dilithium)"},
	"slh-dsa":    {Name: "SLH-DSA", Type: "signature", QuantumRisk: types.RiskSafe, Severity: types.SeverityInfo, Description: "NIST FIPS 205 (SPHINCS+)"},
	"kyber":      {Name: "Kyber", Type: "key-exchange", QuantumRisk: types.RiskSafe, Severity: types.SeverityInfo, Description: "Kyber KEM"},
	"dilithium":  {Name: "Dilithium", Type: "signature", QuantumRisk: types.RiskSafe, Severity: types.SeverityInfo, Description: "Dilithium signature"},
	"sphincs":    {Name: "SPHINCS+", Type: "signature", QuantumRisk: types.RiskSafe, Severity: types.SeverityInfo, Description: "SPHINCS+ signature"},
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
