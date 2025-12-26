// Copyright 2024-2025 CSNP (csnp.org)
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

// JavaAnalyzer analyzes Java/Kotlin source code for cryptographic usage.
type JavaAnalyzer struct{}

// NewJavaAnalyzer creates a new Java AST analyzer.
func NewJavaAnalyzer() *JavaAnalyzer {
	return &JavaAnalyzer{}
}

// Common patterns for detecting crypto in Java
var (
	// Import patterns
	javaImportPattern = regexp.MustCompile(`^\s*import\s+([a-zA-Z0-9_.]+(?:\.\*)?)\s*;`)

	// JCA/JCE patterns (Java Cryptography Architecture) - with string literals
	cipherPattern      = regexp.MustCompile(`Cipher\.getInstance\s*\(\s*["']([^"']+)["']`)
	messageDigestPattern = regexp.MustCompile(`MessageDigest\.getInstance\s*\(\s*["']([^"']+)["']`)
	keyGeneratorPattern  = regexp.MustCompile(`KeyGenerator\.getInstance\s*\(\s*["']([^"']+)["']`)
	keyPairGenPattern    = regexp.MustCompile(`KeyPairGenerator\.getInstance\s*\(\s*["']([^"']+)["']`)
	signaturePattern     = regexp.MustCompile(`Signature\.getInstance\s*\(\s*["']([^"']+)["']`)
	macPattern           = regexp.MustCompile(`Mac\.getInstance\s*\(\s*["']([^"']+)["']`)
	keyFactoryPattern    = regexp.MustCompile(`KeyFactory\.getInstance\s*\(\s*["']([^"']+)["']`)
	keyAgreementPattern  = regexp.MustCompile(`KeyAgreement\.getInstance\s*\(\s*["']([^"']+)["']`)
	secretKeyFactoryPattern = regexp.MustCompile(`SecretKeyFactory\.getInstance\s*\(\s*["']([^"']+)["']`)

	// JCA/JCE patterns - variable-based (detects crypto API usage without literal)
	cipherVarPattern       = regexp.MustCompile(`(?:javax\.crypto\.)?Cipher\.getInstance\s*\(`)
	messageDigestVarPattern = regexp.MustCompile(`(?:java\.security\.)?MessageDigest\.getInstance\s*\(`)
	keyGenVarPattern       = regexp.MustCompile(`(?:javax\.crypto\.)?KeyGenerator\.getInstance\s*\(`)
	keyPairGenVarPattern   = regexp.MustCompile(`KeyPairGenerator\.getInstance\s*\(`)
	signatureVarPattern    = regexp.MustCompile(`(?:java\.security\.)?Signature\.getInstance\s*\(`)
	macVarPattern          = regexp.MustCompile(`(?:javax\.crypto\.)?Mac\.getInstance\s*\(`)
	secureRandomPattern    = regexp.MustCompile(`SecureRandom\.getInstance\s*\(`)

	// SecretKeySpec usage (indicates symmetric encryption)
	secretKeySpecPattern = regexp.MustCompile(`new\s+SecretKeySpec\s*\(`)

	// Crypto class name patterns (infer algorithm from class names)
	algInClassPattern = regexp.MustCompile(`(?i)(Aes|Des|Rsa|Ecdsa|Dsa|Blowfish|Twofish|Chacha|Salsa|Sha256|Sha512|Md5|Hmac|Pbkdf|Bcrypt|Scrypt|Argon)`)

	// Bouncy Castle patterns
	bouncyCastlePattern = regexp.MustCompile(`new\s+(AES|DES|RSA|ECDSA|Ed25519|SHA256|SHA512|MD5|Blowfish|Twofish|ChaCha20|Salsa20|PBKDF2|Argon2|BCrypt|SCrypt)`)

	// Spring Security patterns
	springCryptoPattern = regexp.MustCompile(`(BCryptPasswordEncoder|Argon2PasswordEncoder|SCryptPasswordEncoder|Pbkdf2PasswordEncoder|StandardPasswordEncoder)`)

	// Java method/class patterns
	javaClassPattern  = regexp.MustCompile(`^\s*(?:public\s+|private\s+|protected\s+)?(?:static\s+)?(?:final\s+)?class\s+(\w+)`)
	javaMethodPattern = regexp.MustCompile(`^\s*(?:public\s+|private\s+|protected\s+)?(?:static\s+)?(?:final\s+)?(?:synchronized\s+)?(?:\w+(?:<[^>]+>)?)\s+(\w+)\s*\(`)
)

// Java crypto algorithm mappings
var javaCryptoAlgorithms = map[string]string{
	// Ciphers
	"AES":                    "AES",
	"AES/CBC/PKCS5Padding":   "AES",
	"AES/GCM/NoPadding":      "AES-GCM",
	"AES/ECB/PKCS5Padding":   "AES-ECB",
	"AES/CTR/NoPadding":      "AES",
	"DES":                    "DES",
	"DES/CBC/PKCS5Padding":   "DES",
	"DESede":                 "3DES",
	"DESede/CBC/PKCS5Padding": "3DES",
	"RSA":                    "RSA",
	"RSA/ECB/PKCS1Padding":   "RSA",
	"RSA/ECB/OAEPWithSHA-256AndMGF1Padding": "RSA-OAEP",
	"Blowfish":               "Blowfish",
	"RC4":                    "RC4",
	"ChaCha20":               "ChaCha20",
	"ChaCha20-Poly1305":      "ChaCha20-Poly1305",

	// Message Digests
	"MD5":         "MD5",
	"SHA-1":       "SHA-1",
	"SHA1":        "SHA-1",
	"SHA-256":     "SHA-256",
	"SHA256":      "SHA-256",
	"SHA-384":     "SHA-384",
	"SHA384":      "SHA-384",
	"SHA-512":     "SHA-512",
	"SHA512":      "SHA-512",
	"SHA3-256":    "SHA3-256",
	"SHA3-512":    "SHA3-512",

	// Signatures
	"SHA256withRSA":     "RSA",
	"SHA384withRSA":     "RSA",
	"SHA512withRSA":     "RSA",
	"SHA256withECDSA":   "ECDSA",
	"SHA384withECDSA":   "ECDSA",
	"SHA512withECDSA":   "ECDSA",
	"SHA256withDSA":     "DSA",
	"Ed25519":           "Ed25519",
	"Ed448":             "Ed448",

	// MACs
	"HmacMD5":    "HMAC-MD5",
	"HmacSHA1":   "HMAC-SHA1",
	"HmacSHA256": "HMAC-SHA256",
	"HmacSHA384": "HMAC-SHA384",
	"HmacSHA512": "HMAC-SHA512",

	// Key Agreement
	"DH":        "DH",
	"ECDH":      "ECDH",
	"X25519":    "X25519",
	"X448":      "X448",
	"XDH":       "X25519",

	// Key Factories
	"EC":        "ECDSA",
	"DSA":       "DSA",

	// Password-based
	"PBKDF2WithHmacSHA256": "PBKDF2",
	"PBKDF2WithHmacSHA512": "PBKDF2",
	"PBEWithMD5AndDES":     "DES",
	"PBEWithSHA1AndDESede": "3DES",
}

// javaFuncContext tracks function context during Java file analysis.
type javaFuncContext struct {
	Name      string
	ClassName string
	IsPublic  bool
	BraceDepth int
}

// AnalyzeDirectory analyzes all Java/Kotlin files in a directory.
func (a *JavaAnalyzer) AnalyzeDirectory(dir string) ([]types.CryptoUsage, error) {
	var allUsages []types.CryptoUsage

	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Skip directories
		if info.IsDir() {
			base := filepath.Base(path)
			if base == ".git" || base == "target" || base == "build" || base == "test" ||
				base == "tests" || base == "node_modules" {
				return filepath.SkipDir
			}
			return nil
		}

		// Only process Java/Kotlin files
		ext := strings.ToLower(filepath.Ext(path))
		if ext != ".java" && ext != ".kt" && ext != ".kts" {
			return nil
		}

		// Skip test files
		base := filepath.Base(path)
		if strings.HasSuffix(base, "Test.java") || strings.HasSuffix(base, "Tests.java") ||
			strings.HasSuffix(base, "Test.kt") || strings.Contains(path, "/test/") {
			return nil
		}

		usages, err := a.AnalyzeFile(path)
		if err != nil {
			return nil
		}

		allUsages = append(allUsages, usages...)
		return nil
	})

	return allUsages, err
}

// AnalyzeFile analyzes a single Java/Kotlin file for cryptographic usage.
func (a *JavaAnalyzer) AnalyzeFile(filename string) ([]types.CryptoUsage, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var usages []types.CryptoUsage
	imports := make(map[string]bool)
	var funcStack []*javaFuncContext
	var currentClass string
	braceDepth := 0

	scanner := bufio.NewScanner(file)
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := scanner.Text()
		trimmedLine := strings.TrimSpace(line)

		// Skip empty lines and comments
		if trimmedLine == "" || strings.HasPrefix(trimmedLine, "//") ||
			strings.HasPrefix(trimmedLine, "*") || strings.HasPrefix(trimmedLine, "/*") {
			continue
		}

		// Track brace depth
		braceChange := strings.Count(line, "{") - strings.Count(line, "}")

		// Check for class declarations
		if matches := javaClassPattern.FindStringSubmatch(line); len(matches) > 1 {
			currentClass = matches[1]
		}

		// Check for method declarations
		if ctx := a.detectMethodDecl(trimmedLine, currentClass, braceDepth); ctx != nil {
			funcStack = append(funcStack, ctx)
		}

		// Update brace depth
		braceDepth += braceChange

		// Pop functions that have ended
		for len(funcStack) > 0 && braceDepth <= funcStack[len(funcStack)-1].BraceDepth {
			funcStack = funcStack[:len(funcStack)-1]
		}

		// Reset class when exiting top level
		if braceDepth == 0 {
			currentClass = ""
		}

		// Check for imports
		a.checkImports(line, imports)

		// Check for crypto usage with context
		var currentFunc *javaFuncContext
		if len(funcStack) > 0 {
			currentFunc = funcStack[len(funcStack)-1]
		}
		lineUsages := a.checkCryptoUsageWithContext(line, lineNum, filename, imports, currentFunc)
		usages = append(usages, lineUsages...)
	}

	return usages, scanner.Err()
}

// detectMethodDecl detects method declarations.
func (a *JavaAnalyzer) detectMethodDecl(line, currentClass string, braceDepth int) *javaFuncContext {
	matches := javaMethodPattern.FindStringSubmatch(line)
	if len(matches) < 2 {
		return nil
	}

	methodName := matches[1]
	// Skip constructors (same name as class) for now, they're still tracked
	isPublic := strings.Contains(line, "public ")

	return &javaFuncContext{
		Name:       methodName,
		ClassName:  currentClass,
		IsPublic:   isPublic,
		BraceDepth: braceDepth,
	}
}

// checkImports checks for crypto-related imports.
func (a *JavaAnalyzer) checkImports(line string, imports map[string]bool) {
	matches := javaImportPattern.FindStringSubmatch(line)
	if len(matches) < 2 {
		return
	}

	pkg := matches[1]
	cryptoPackages := []string{
		"javax.crypto",
		"java.security",
		"org.bouncycastle",
		"org.springframework.security.crypto",
		"com.google.crypto.tink",
		"org.apache.commons.codec",
		"org.apache.shiro.crypto",
	}

	for _, cp := range cryptoPackages {
		if strings.HasPrefix(pkg, cp) {
			imports[pkg] = true
			return
		}
	}
}

// checkCryptoUsageWithContext checks a line for crypto usage with function context.
func (a *JavaAnalyzer) checkCryptoUsageWithContext(line string, lineNum int, filename string, imports map[string]bool, funcCtx *javaFuncContext) []types.CryptoUsage {
	var usages []types.CryptoUsage

	// Check JCA/JCE patterns with string literals
	patterns := []struct {
		pattern  *regexp.Regexp
		cryptoType string
	}{
		{cipherPattern, "encryption"},
		{messageDigestPattern, "hash"},
		{keyGeneratorPattern, "key-generation"},
		{keyPairGenPattern, "key-generation"},
		{signaturePattern, "signature"},
		{macPattern, "mac"},
		{keyFactoryPattern, "key-generation"},
		{keyAgreementPattern, "key-exchange"},
		{secretKeyFactoryPattern, "key-derivation"},
	}

	for _, p := range patterns {
		if matches := p.pattern.FindStringSubmatch(line); len(matches) > 1 {
			algString := matches[1]
			algorithm := a.mapAlgorithm(algString)
			if algorithm != "" {
				usage := a.createUsage(algorithm, filename, lineNum, p.cryptoType)
				a.addFuncContext(&usage, funcCtx)
				usages = append(usages, usage)
			}
		}
	}

	// Check JCA/JCE patterns with variable arguments (infer from context)
	varPatterns := []struct {
		pattern    *regexp.Regexp
		cryptoType string
		fallback   string
	}{
		{cipherVarPattern, "encryption", "AES"},          // Most common cipher
		{messageDigestVarPattern, "hash", "SHA-256"},     // Most common hash
		{keyGenVarPattern, "key-generation", "AES"},      // Most common symmetric key
		{keyPairGenVarPattern, "key-generation", "RSA"},  // Most common asymmetric
		{signatureVarPattern, "signature", "RSA"},        // Most common signature
		{macVarPattern, "mac", "HMAC"},                   // HMAC is the standard
		{secureRandomPattern, "random", "SecureRandom"},  // Track secure random usage
		{secretKeySpecPattern, "encryption", "AES"},      // Most common symmetric
	}

	for _, p := range varPatterns {
		if p.pattern.MatchString(line) {
			// Try to infer algorithm from class name, method name, or line context
			algorithm := a.inferAlgorithmFromContext(line, filename, funcCtx)
			if algorithm == "" && p.fallback != "" {
				algorithm = p.fallback
			}
			if algorithm != "" {
				usage := a.createUsage(algorithm, filename, lineNum, p.cryptoType)
				a.addFuncContext(&usage, funcCtx)
				usages = append(usages, usage)
			}
		}
	}

	// Check Bouncy Castle patterns
	if matches := bouncyCastlePattern.FindStringSubmatch(line); len(matches) > 1 {
		algorithm := a.mapAlgorithm(matches[1])
		if algorithm != "" {
			usage := a.createUsage(algorithm, filename, lineNum, "bouncy-castle")
			a.addFuncContext(&usage, funcCtx)
			usages = append(usages, usage)
		}
	}

	// Check Spring Security patterns
	if matches := springCryptoPattern.FindStringSubmatch(line); len(matches) > 1 {
		algorithm := a.mapSpringEncoder(matches[1])
		usage := a.createUsage(algorithm, filename, lineNum, "spring-security")
		a.addFuncContext(&usage, funcCtx)
		usages = append(usages, usage)
	}

	return usages
}

// inferAlgorithmFromContext tries to infer the algorithm from class/method names or file path.
func (a *JavaAnalyzer) inferAlgorithmFromContext(line, filename string, funcCtx *javaFuncContext) string {
	// Try to find algorithm hint in class name from context
	if funcCtx != nil && funcCtx.ClassName != "" {
		if matches := algInClassPattern.FindStringSubmatch(funcCtx.ClassName); len(matches) > 1 {
			return a.normalizeAlgorithmName(matches[1])
		}
	}

	// Try to find algorithm hint in file name
	baseName := filepath.Base(filename)
	if matches := algInClassPattern.FindStringSubmatch(baseName); len(matches) > 1 {
		return a.normalizeAlgorithmName(matches[1])
	}

	// Try to find algorithm hint in the line itself
	if matches := algInClassPattern.FindStringSubmatch(line); len(matches) > 1 {
		return a.normalizeAlgorithmName(matches[1])
	}

	return ""
}

// normalizeAlgorithmName normalizes common algorithm name variants.
func (a *JavaAnalyzer) normalizeAlgorithmName(name string) string {
	switch strings.ToUpper(name) {
	case "AES":
		return "AES"
	case "DES":
		return "DES"
	case "RSA":
		return "RSA"
	case "ECDSA":
		return "ECDSA"
	case "DSA":
		return "DSA"
	case "BLOWFISH":
		return "Blowfish"
	case "TWOFISH":
		return "Twofish"
	case "CHACHA":
		return "ChaCha20"
	case "SALSA":
		return "Salsa20"
	case "SHA256":
		return "SHA-256"
	case "SHA512":
		return "SHA-512"
	case "MD5":
		return "MD5"
	case "HMAC":
		return "HMAC"
	case "PBKDF":
		return "PBKDF2"
	case "BCRYPT":
		return "bcrypt"
	case "SCRYPT":
		return "scrypt"
	case "ARGON":
		return "Argon2"
	default:
		return name
	}
}

// mapAlgorithm maps Java algorithm strings to standard names.
func (a *JavaAnalyzer) mapAlgorithm(algString string) string {
	// Direct match
	if mapped, ok := javaCryptoAlgorithms[algString]; ok {
		return mapped
	}

	// Try uppercase
	if mapped, ok := javaCryptoAlgorithms[strings.ToUpper(algString)]; ok {
		return mapped
	}

	// Partial matching for complex algorithm strings
	algUpper := strings.ToUpper(algString)
	if strings.Contains(algUpper, "AES") {
		if strings.Contains(algUpper, "GCM") {
			return "AES-GCM"
		}
		return "AES"
	}
	if strings.Contains(algUpper, "RSA") {
		return "RSA"
	}
	if strings.Contains(algUpper, "ECDSA") {
		return "ECDSA"
	}
	if strings.Contains(algUpper, "SHA256") || strings.Contains(algUpper, "SHA-256") {
		return "SHA-256"
	}
	if strings.Contains(algUpper, "SHA512") || strings.Contains(algUpper, "SHA-512") {
		return "SHA-512"
	}
	if strings.Contains(algUpper, "MD5") {
		return "MD5"
	}
	if strings.Contains(algUpper, "DES") {
		if strings.Contains(algUpper, "3DES") || strings.Contains(algUpper, "DESEDE") || strings.Contains(algUpper, "TRIPLE") {
			return "3DES"
		}
		return "DES"
	}

	return algString
}

// mapSpringEncoder maps Spring Security encoder classes.
func (a *JavaAnalyzer) mapSpringEncoder(encoder string) string {
	switch encoder {
	case "BCryptPasswordEncoder":
		return "bcrypt"
	case "Argon2PasswordEncoder":
		return "Argon2"
	case "SCryptPasswordEncoder":
		return "scrypt"
	case "Pbkdf2PasswordEncoder":
		return "PBKDF2"
	case "StandardPasswordEncoder":
		return "SHA-256" // Deprecated, uses SHA-256
	default:
		return encoder
	}
}

// addFuncContext adds function context to a usage.
func (a *JavaAnalyzer) addFuncContext(usage *types.CryptoUsage, funcCtx *javaFuncContext) {
	if funcCtx != nil {
		if funcCtx.ClassName != "" {
			usage.Function = funcCtx.ClassName + "." + funcCtx.Name
		} else {
			usage.Function = funcCtx.Name
		}
		usage.InExported = funcCtx.IsPublic
	}
}

// createUsage creates a CryptoUsage from detected crypto.
func (a *JavaAnalyzer) createUsage(algorithm, filename string, line int, callPath string) types.CryptoUsage {
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
