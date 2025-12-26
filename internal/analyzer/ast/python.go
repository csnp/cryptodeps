// Copyright 2024 CSNP (csnp.org)
// SPDX-License-Identifier: Apache-2.0

// Package ast provides AST-based analysis for crypto detection.
package ast

import (
	"bufio"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/csnp/qramm-cryptodeps/pkg/crypto"
	"github.com/csnp/qramm-cryptodeps/pkg/types"
)

// PythonAnalyzer analyzes Python source code for cryptographic usage.
type PythonAnalyzer struct{}

// NewPythonAnalyzer creates a new Python AST analyzer.
func NewPythonAnalyzer() *PythonAnalyzer {
	return &PythonAnalyzer{}
}

// Common patterns for detecting crypto in Python
var (
	// Import patterns
	pyImportPattern     = regexp.MustCompile(`^\s*import\s+([a-zA-Z0-9_., ]+)`)
	pyFromImportPattern = regexp.MustCompile(`^\s*from\s+([a-zA-Z0-9_.]+)\s+import`)

	// Cryptography library patterns
	cryptographyPattern = regexp.MustCompile(`(Fernet|AES|DES|TripleDES|RSA|DSA|ECDSA|Ed25519|X25519|SECP256K1|SECP384R1|SECP521R1|SHA256|SHA384|SHA512|SHA1|MD5|HMAC|PBKDF2|Scrypt|hashes\.(SHA|MD)|padding\.(PKCS|OAEP)|serialization\.)`)

	// PyCryptodome patterns
	pycryptoPattern = regexp.MustCompile(`(Cipher\.AES|Cipher\.DES|Cipher\.DES3|Hash\.SHA256|Hash\.SHA512|Hash\.MD5|PublicKey\.RSA|PublicKey\.DSA|PublicKey\.ECC|Signature\.pkcs1_15|Signature\.pss)`)

	// hashlib patterns
	pyHashlibPattern = regexp.MustCompile(`hashlib\.(sha256|sha384|sha512|sha1|md5|blake2b|blake2s|sha3_256|sha3_512|new)\s*\(`)

	// hmac patterns
	pyHmacPattern = regexp.MustCompile(`hmac\.(new|HMAC|compare_digest)\s*\(`)

	// bcrypt patterns
	pyBcryptPattern = regexp.MustCompile(`bcrypt\.(hashpw|checkpw|gensalt|kdf)\s*\(`)

	// PyJWT patterns
	pyJwtPattern = regexp.MustCompile(`jwt\.(encode|decode|api_jwt|api_jws)\s*\(`)

	// passlib patterns
	passlibPattern = regexp.MustCompile(`passlib\.(hash|context|pwd)\.(bcrypt|argon2|pbkdf2|sha256_crypt|sha512_crypt)`)

	// nacl/libsodium patterns
	naclPattern = regexp.MustCompile(`nacl\.(secret|public|signing|utils|hash)\.(SecretBox|Box|SigningKey|VerifyKey)`)

	// Algorithm detection in strings
	pyAlgPattern = regexp.MustCompile(`['"](RS256|RS384|RS512|ES256|ES384|ES512|PS256|PS384|PS512|HS256|HS384|HS512|EdDSA|aes-\d+-\w+|des|3des|sha256|sha512|md5)['"]`)
)

// Python crypto package mappings
var pythonCryptoPackages = map[string][]string{
	"cryptography":         {"RSA", "ECDSA", "Ed25519", "AES", "3DES", "ChaCha20"},
	"Crypto":               {"RSA", "AES", "DES", "3DES", "SHA-256"},
	"Cryptodome":           {"RSA", "AES", "DES", "3DES", "SHA-256"},
	"pycryptodome":         {"RSA", "AES", "DES", "3DES", "SHA-256"},
	"hashlib":              {"SHA-256", "SHA-512", "MD5", "SHA-1"},
	"hmac":                 {"HMAC"},
	"bcrypt":               {"bcrypt"},
	"argon2":               {"Argon2"},
	"scrypt":               {"scrypt"},
	"nacl":                 {"X25519", "Ed25519", "XSalsa20"},
	"PyNaCl":               {"X25519", "Ed25519", "XSalsa20"},
	"jwt":                  {"RS256", "ES256", "HS256"},
	"jose":                 {"RS256", "ES256", "HS256"},
	"python-jose":          {"RS256", "ES256", "HS256"},
	"passlib":              {"bcrypt", "Argon2", "PBKDF2"},
	"paramiko":             {"RSA", "ECDSA", "Ed25519", "AES"},
	"pyOpenSSL":            {"RSA", "ECDSA", "AES", "3DES"},
	"M2Crypto":             {"RSA", "AES", "DES"},
	"ecdsa":                {"ECDSA"},
	"ed25519":              {"Ed25519"},
	"rsa":                  {"RSA"},
}

// AnalyzeDirectory analyzes all Python files in a directory.
func (a *PythonAnalyzer) AnalyzeDirectory(dir string) ([]types.CryptoUsage, error) {
	var allUsages []types.CryptoUsage

	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Skip directories
		if info.IsDir() {
			// Skip common non-source directories
			base := filepath.Base(path)
			if base == "__pycache__" || base == ".git" || base == "venv" || base == ".venv" ||
				base == "env" || base == ".env" || base == "tests" || base == "test" {
				return filepath.SkipDir
			}
			return nil
		}

		// Only process Python files
		ext := strings.ToLower(filepath.Ext(path))
		if ext != ".py" {
			return nil
		}

		// Skip test files
		base := filepath.Base(path)
		if strings.HasPrefix(base, "test_") || strings.HasSuffix(base, "_test.py") ||
			base == "conftest.py" {
			return nil
		}

		usages, err := a.AnalyzeFile(path)
		if err != nil {
			// Log but continue on parse errors
			return nil
		}

		allUsages = append(allUsages, usages...)
		return nil
	})

	return allUsages, err
}

// AnalyzeFile analyzes a single Python file for cryptographic usage.
func (a *PythonAnalyzer) AnalyzeFile(filename string) ([]types.CryptoUsage, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var usages []types.CryptoUsage
	imports := make(map[string]bool)

	scanner := bufio.NewScanner(file)
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := scanner.Text()

		// Check for crypto imports
		a.checkImports(line, imports)

		// Check for crypto usage
		lineUsages := a.checkCryptoUsage(line, lineNum, filename, imports)
		usages = append(usages, lineUsages...)
	}

	return usages, scanner.Err()
}

// checkImports checks a line for crypto-related imports.
func (a *PythonAnalyzer) checkImports(line string, imports map[string]bool) {
	// Check "import x" pattern
	if matches := pyImportPattern.FindStringSubmatch(line); len(matches) > 1 {
		modules := strings.Split(matches[1], ",")
		for _, mod := range modules {
			mod = strings.TrimSpace(mod)
			// Handle "import x as y"
			if idx := strings.Index(mod, " as "); idx > 0 {
				mod = strings.TrimSpace(mod[:idx])
			}
			if a.isCryptoPackage(mod) {
				imports[mod] = true
			}
		}
	}

	// Check "from x import y" pattern
	if matches := pyFromImportPattern.FindStringSubmatch(line); len(matches) > 1 {
		pkg := matches[1]
		if a.isCryptoPackage(pkg) {
			imports[pkg] = true
		}
	}
}

// isCryptoPackage checks if a package name is crypto-related.
func (a *PythonAnalyzer) isCryptoPackage(pkg string) bool {
	for cryptoPkg := range pythonCryptoPackages {
		if pkg == cryptoPkg || strings.HasPrefix(pkg, cryptoPkg+".") {
			return true
		}
	}

	// Check common crypto module names
	cryptoModules := []string{
		"ssl", "secrets", "crypt", "gnupg", "pgp",
	}
	for _, cm := range cryptoModules {
		if pkg == cm || strings.HasPrefix(pkg, cm+".") {
			return true
		}
	}

	return false
}

// checkCryptoUsage checks a line for crypto function calls.
func (a *PythonAnalyzer) checkCryptoUsage(line string, lineNum int, filename string, imports map[string]bool) []types.CryptoUsage {
	var usages []types.CryptoUsage

	// Check cryptography library usage
	if cryptographyPattern.MatchString(line) {
		alg := a.detectCryptographyAlgorithm(line)
		if alg != "" {
			usages = append(usages, a.createUsage(alg, filename, lineNum, "cryptography"))
		}
	}

	// Check PyCryptodome usage
	if pycryptoPattern.MatchString(line) {
		alg := a.detectPyCryptoAlgorithm(line)
		if alg != "" {
			usages = append(usages, a.createUsage(alg, filename, lineNum, "pycryptodome"))
		}
	}

	// Check hashlib usage
	if pyHashlibPattern.MatchString(line) {
		matches := pyHashlibPattern.FindStringSubmatch(line)
		if len(matches) > 1 {
			alg := a.mapHashlibAlgorithm(matches[1])
			usages = append(usages, a.createUsage(alg, filename, lineNum, "hashlib"))
		}
	}

	// Check hmac usage
	if pyHmacPattern.MatchString(line) {
		alg := a.detectHMACAlgorithm(line)
		usages = append(usages, a.createUsage(alg, filename, lineNum, "hmac"))
	}

	// Check bcrypt usage
	if pyBcryptPattern.MatchString(line) {
		usages = append(usages, a.createUsage("bcrypt", filename, lineNum, "bcrypt"))
	}

	// Check PyJWT usage
	if pyJwtPattern.MatchString(line) {
		alg := a.detectJWTAlgorithm(line)
		usages = append(usages, a.createUsage(alg, filename, lineNum, "jwt"))
	}

	// Check passlib usage
	if passlibPattern.MatchString(line) {
		alg := a.detectPasslibAlgorithm(line)
		usages = append(usages, a.createUsage(alg, filename, lineNum, "passlib"))
	}

	// Check nacl usage
	if naclPattern.MatchString(line) {
		alg := a.detectNaClAlgorithm(line)
		usages = append(usages, a.createUsage(alg, filename, lineNum, "nacl"))
	}

	return usages
}

// detectCryptographyAlgorithm detects algorithm from cryptography library usage.
func (a *PythonAnalyzer) detectCryptographyAlgorithm(line string) string {
	lineLower := strings.ToLower(line)

	algorithms := []struct {
		pattern string
		alg     string
	}{
		{"rsa", "RSA"},
		{"dsa", "DSA"},
		{"ecdsa", "ECDSA"},
		{"ed25519", "Ed25519"},
		{"x25519", "X25519"},
		{"secp256k1", "ECDSA"},
		{"secp384r1", "P-384"},
		{"secp521r1", "P-521"},
		{"aes", "AES"},
		{"tripledes", "3DES"},
		{"des", "DES"},
		{"chacha20", "ChaCha20"},
		{"fernet", "AES-128"}, // Fernet uses AES-128
		{"sha256", "SHA-256"},
		{"sha384", "SHA-384"},
		{"sha512", "SHA-512"},
		{"sha1", "SHA-1"},
		{"md5", "MD5"},
		{"pbkdf2", "PBKDF2"},
		{"scrypt", "scrypt"},
	}

	for _, a := range algorithms {
		if strings.Contains(lineLower, a.pattern) {
			return a.alg
		}
	}

	return ""
}

// detectPyCryptoAlgorithm detects algorithm from PyCryptodome usage.
func (a *PythonAnalyzer) detectPyCryptoAlgorithm(line string) string {
	if strings.Contains(line, "Cipher.AES") {
		return "AES"
	}
	if strings.Contains(line, "Cipher.DES3") {
		return "3DES"
	}
	if strings.Contains(line, "Cipher.DES") {
		return "DES"
	}
	if strings.Contains(line, "Hash.SHA256") {
		return "SHA-256"
	}
	if strings.Contains(line, "Hash.SHA512") {
		return "SHA-512"
	}
	if strings.Contains(line, "Hash.MD5") {
		return "MD5"
	}
	if strings.Contains(line, "PublicKey.RSA") {
		return "RSA"
	}
	if strings.Contains(line, "PublicKey.DSA") {
		return "DSA"
	}
	if strings.Contains(line, "PublicKey.ECC") {
		return "ECDSA"
	}
	return ""
}

// mapHashlibAlgorithm maps hashlib function names to algorithm names.
func (a *PythonAnalyzer) mapHashlibAlgorithm(name string) string {
	switch name {
	case "sha256":
		return "SHA-256"
	case "sha384":
		return "SHA-384"
	case "sha512":
		return "SHA-512"
	case "sha1":
		return "SHA-1"
	case "md5":
		return "MD5"
	case "blake2b":
		return "BLAKE2b"
	case "blake2s":
		return "BLAKE2s"
	case "sha3_256":
		return "SHA3-256"
	case "sha3_512":
		return "SHA3-512"
	default:
		return "SHA-256" // Default for hashlib.new()
	}
}

// detectHMACAlgorithm detects HMAC algorithm from context.
func (a *PythonAnalyzer) detectHMACAlgorithm(line string) string {
	lineLower := strings.ToLower(line)
	if strings.Contains(lineLower, "sha256") {
		return "HMAC-SHA256"
	}
	if strings.Contains(lineLower, "sha512") {
		return "HMAC-SHA512"
	}
	if strings.Contains(lineLower, "sha1") {
		return "HMAC-SHA1"
	}
	if strings.Contains(lineLower, "md5") {
		return "HMAC-MD5"
	}
	return "HMAC"
}

// detectJWTAlgorithm detects JWT algorithm from line.
func (a *PythonAnalyzer) detectJWTAlgorithm(line string) string {
	if matches := pyAlgPattern.FindStringSubmatch(line); len(matches) > 1 {
		return strings.ToUpper(matches[1])
	}

	lineLower := strings.ToLower(line)
	if strings.Contains(lineLower, "rs256") {
		return "RS256"
	}
	if strings.Contains(lineLower, "es256") {
		return "ES256"
	}
	if strings.Contains(lineLower, "hs256") {
		return "HS256"
	}

	return "RS256" // Default
}

// detectPasslibAlgorithm detects passlib algorithm.
func (a *PythonAnalyzer) detectPasslibAlgorithm(line string) string {
	lineLower := strings.ToLower(line)
	if strings.Contains(lineLower, "bcrypt") {
		return "bcrypt"
	}
	if strings.Contains(lineLower, "argon2") {
		return "Argon2"
	}
	if strings.Contains(lineLower, "pbkdf2") {
		return "PBKDF2"
	}
	if strings.Contains(lineLower, "sha256_crypt") {
		return "SHA-256"
	}
	if strings.Contains(lineLower, "sha512_crypt") {
		return "SHA-512"
	}
	return "bcrypt" // Default
}

// detectNaClAlgorithm detects NaCl/libsodium algorithm.
func (a *PythonAnalyzer) detectNaClAlgorithm(line string) string {
	lineLower := strings.ToLower(line)
	if strings.Contains(lineLower, "signingkey") {
		return "Ed25519"
	}
	if strings.Contains(lineLower, "box") {
		return "X25519"
	}
	if strings.Contains(lineLower, "secretbox") {
		return "XSalsa20"
	}
	return "X25519"
}

// createUsage creates a CryptoUsage from detected crypto.
func (a *PythonAnalyzer) createUsage(algorithm, filename string, line int, callPath string) types.CryptoUsage {
	info, found := crypto.ClassifyAlgorithm(algorithm)
	if !found {
		info = crypto.AlgorithmInfo{
			Name:        algorithm,
			Type:        "unknown",
			QuantumRisk: types.RiskUnknown,
			Severity:    types.SeverityInfo,
		}
	}

	return types.CryptoUsage{
		Algorithm:   info.Name,
		Type:        info.Type,
		QuantumRisk: info.QuantumRisk,
		Severity:    info.Severity,
		Location: types.Location{
			File: filename,
			Line: line,
		},
		CallPath: []string{callPath},
	}
}
