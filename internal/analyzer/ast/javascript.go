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

// JavaScriptAnalyzer analyzes JavaScript/TypeScript source code for cryptographic usage.
type JavaScriptAnalyzer struct{}

// NewJavaScriptAnalyzer creates a new JavaScript AST analyzer.
func NewJavaScriptAnalyzer() *JavaScriptAnalyzer {
	return &JavaScriptAnalyzer{}
}

// Common patterns for detecting crypto in JavaScript
var (
	// Import patterns
	requirePattern    = regexp.MustCompile(`require\s*\(\s*['"]([^'"]+)['"]\s*\)`)
	importPattern     = regexp.MustCompile(`import\s+.*?\s+from\s+['"]([^'"]+)['"]`)
	importDynPattern  = regexp.MustCompile(`import\s*\(\s*['"]([^'"]+)['"]\s*\)`)

	// Function detection patterns
	jsFuncDeclPattern   = regexp.MustCompile(`(?:async\s+)?function\s+(\w+)\s*\(`)
	jsMethodPattern     = regexp.MustCompile(`(\w+)\s*\([^)]*\)\s*{`)
	jsArrowFuncPattern  = regexp.MustCompile(`(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s*)?\([^)]*\)\s*=>`)
	jsClassMethodPattern = regexp.MustCompile(`(?:async\s+)?(\w+)\s*\([^)]*\)\s*{`)
	jsExportPattern     = regexp.MustCompile(`^(?:export\s+(?:default\s+)?(?:async\s+)?(?:function|class|const|let|var)\s+(\w+)|module\.exports\s*[.=]|exports\.(\w+))`)
	jsClassPattern      = regexp.MustCompile(`class\s+(\w+)`)

	// Crypto function call patterns
	cryptoMethodPattern = regexp.MustCompile(`crypto\.(createCipher|createDecipher|createCipheriv|createDecipheriv|createSign|createVerify|createHash|createHmac|generateKeyPair|generateKeyPairSync|randomBytes|scrypt|scryptSync|pbkdf2|pbkdf2Sync)\s*\(`)

	// Common crypto library function patterns
	bcryptPattern     = regexp.MustCompile(`bcrypt\.(hash|compare|genSalt|hashSync|compareSync|genSaltSync)\s*\(`)
	jwtPattern        = regexp.MustCompile(`(jwt|jsonwebtoken)\.(sign|verify|decode)\s*\(`)
	cryptoJSPattern   = regexp.MustCompile(`CryptoJS\.(AES|DES|TripleDES|Rabbit|RC4|MD5|SHA1|SHA256|SHA512|SHA3|RIPEMD160|HmacMD5|HmacSHA1|HmacSHA256|HmacSHA512)\.(encrypt|decrypt|hash)\s*\(`)
	nodeForgePattern  = regexp.MustCompile(`forge\.(pki|cipher|md|hmac|random|util)\.(rsa|aes|des|md5|sha1|sha256|sha512)`)

	// Algorithm string patterns in crypto calls
	algStringPattern = regexp.MustCompile(`['"]([a-zA-Z0-9-]+)['"]`)
)

// Known crypto algorithms in JavaScript
var jsAlgorithmMap = map[string]string{
	"aes-128-cbc":     "AES-128",
	"aes-192-cbc":     "AES-192",
	"aes-256-cbc":     "AES-256",
	"aes-128-gcm":     "AES-128-GCM",
	"aes-256-gcm":     "AES-256-GCM",
	"aes-128-ctr":     "AES-128",
	"aes-256-ctr":     "AES-256",
	"des":             "DES",
	"des-ede3":        "3DES",
	"des-ede3-cbc":    "3DES",
	"rc4":             "RC4",
	"md5":             "MD5",
	"sha1":            "SHA-1",
	"sha256":          "SHA-256",
	"sha384":          "SHA-384",
	"sha512":          "SHA-512",
	"sha3-256":        "SHA3-256",
	"sha3-512":        "SHA3-512",
	"rsa":             "RSA",
	"rsa-sha256":      "RSA",
	"ecdsa":           "ECDSA",
	"ed25519":         "Ed25519",
	"x25519":          "X25519",
	"curve25519":      "X25519",
	"secp256k1":       "ECDSA",
	"prime256v1":      "P-256",
	"secp384r1":       "P-384",
	"secp521r1":       "P-521",
	"hs256":           "HMAC-SHA256",
	"hs384":           "HMAC-SHA384",
	"hs512":           "HMAC-SHA512",
	"rs256":           "RS256",
	"rs384":           "RS384",
	"rs512":           "RS512",
	"es256":           "ES256",
	"es384":           "ES384",
	"es512":           "ES512",
	"ps256":           "PS256",
	"ps384":           "PS384",
	"ps512":           "PS512",
}

// AnalyzeDirectory analyzes all JavaScript files in a directory.
func (a *JavaScriptAnalyzer) AnalyzeDirectory(dir string) ([]types.CryptoUsage, error) {
	var allUsages []types.CryptoUsage

	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Skip directories
		if info.IsDir() {
			// Skip common non-source directories
			base := filepath.Base(path)
			if base == "node_modules" || base == ".git" || base == "test" || base == "tests" || base == "__tests__" {
				return filepath.SkipDir
			}
			return nil
		}

		// Only process JavaScript/TypeScript files
		ext := strings.ToLower(filepath.Ext(path))
		if ext != ".js" && ext != ".mjs" && ext != ".cjs" && ext != ".ts" && ext != ".tsx" {
			return nil
		}

		// Skip test files
		base := filepath.Base(path)
		if strings.Contains(base, ".test.") || strings.Contains(base, ".spec.") || strings.HasSuffix(base, "_test.js") {
			return nil
		}

		// Skip minified files
		if strings.HasSuffix(base, ".min.js") {
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

// jsFuncContext tracks function context during JavaScript file analysis.
type jsFuncContext struct {
	Name       string
	ClassName  string // for methods within classes
	IsExported bool
	BraceDepth int // brace depth when function started
}

// AnalyzeFile analyzes a single JavaScript file for cryptographic usage.
func (a *JavaScriptAnalyzer) AnalyzeFile(filename string) ([]types.CryptoUsage, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var usages []types.CryptoUsage
	imports := make(map[string]bool)
	var funcStack []*jsFuncContext
	var currentClass string
	braceDepth := 0
	exportedNames := make(map[string]bool)

	scanner := bufio.NewScanner(file)
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := scanner.Text()
		trimmedLine := strings.TrimSpace(line)

		// Track brace depth changes
		braceChange := strings.Count(line, "{") - strings.Count(line, "}")

		// Check for exports (to track which functions are exported)
		a.checkExports(trimmedLine, exportedNames)

		// Check for class declarations
		if matches := jsClassPattern.FindStringSubmatch(trimmedLine); len(matches) > 1 {
			currentClass = matches[1]
		}

		// Check for function declarations
		if ctx := a.detectFunctionDecl(trimmedLine, currentClass, braceDepth, exportedNames); ctx != nil {
			funcStack = append(funcStack, ctx)
		}

		// Update brace depth after function detection
		braceDepth += braceChange

		// Pop functions that have ended (brace depth decreased below their start)
		for len(funcStack) > 0 && braceDepth < funcStack[len(funcStack)-1].BraceDepth {
			funcStack = funcStack[:len(funcStack)-1]
		}

		// Clear class context when exiting class scope
		if currentClass != "" && braceDepth == 0 {
			currentClass = ""
		}

		// Check for crypto imports
		a.checkImports(line, imports)

		// Check for crypto usage with function context
		var currentFunc *jsFuncContext
		if len(funcStack) > 0 {
			currentFunc = funcStack[len(funcStack)-1]
		}
		lineUsages := a.checkCryptoUsageWithContext(line, lineNum, filename, imports, currentFunc)
		usages = append(usages, lineUsages...)
	}

	return usages, scanner.Err()
}

// checkExports checks for export declarations and tracks exported names.
func (a *JavaScriptAnalyzer) checkExports(line string, exportedNames map[string]bool) {
	// Check for module.exports = functionName
	if strings.HasPrefix(line, "module.exports") {
		// Track that we have module-level exports
		exportedNames["__module__"] = true
		// Try to find specific name: module.exports = someName
		if idx := strings.Index(line, "="); idx > 0 {
			rest := strings.TrimSpace(line[idx+1:])
			if match := regexp.MustCompile(`^(\w+)`).FindStringSubmatch(rest); len(match) > 1 {
				exportedNames[match[1]] = true
			}
		}
	}

	// Check for exports.functionName
	if strings.HasPrefix(line, "exports.") {
		if match := regexp.MustCompile(`^exports\.(\w+)`).FindStringSubmatch(line); len(match) > 1 {
			exportedNames[match[1]] = true
		}
	}

	// Check for export function/class/const
	if strings.HasPrefix(line, "export ") {
		if match := jsExportPattern.FindStringSubmatch(line); len(match) > 1 {
			if match[1] != "" {
				exportedNames[match[1]] = true
			}
			if match[2] != "" {
				exportedNames[match[2]] = true
			}
		}
	}
}

// detectFunctionDecl detects function declarations and returns context if found.
func (a *JavaScriptAnalyzer) detectFunctionDecl(line, currentClass string, braceDepth int, exportedNames map[string]bool) *jsFuncContext {
	var name string
	isExported := false

	// Check for function declaration
	if matches := jsFuncDeclPattern.FindStringSubmatch(line); len(matches) > 1 {
		name = matches[1]
	}

	// Check for arrow function
	if name == "" {
		if matches := jsArrowFuncPattern.FindStringSubmatch(line); len(matches) > 1 {
			name = matches[1]
		}
	}

	// Check for class method (only if inside a class)
	if name == "" && currentClass != "" {
		if matches := jsClassMethodPattern.FindStringSubmatch(line); len(matches) > 1 {
			// Avoid matching control flow keywords
			candidate := matches[1]
			if candidate != "if" && candidate != "for" && candidate != "while" && candidate != "switch" && candidate != "catch" {
				name = candidate
			}
		}
	}

	if name == "" {
		return nil
	}

	// Check if this function is exported
	if exportedNames[name] || strings.HasPrefix(strings.TrimSpace(line), "export ") {
		isExported = true
	}

	// Class methods are considered "exported" if the class is exported
	if currentClass != "" && exportedNames[currentClass] {
		isExported = true
	}

	return &jsFuncContext{
		Name:       name,
		ClassName:  currentClass,
		IsExported: isExported,
		BraceDepth: braceDepth + 1, // Account for opening brace
	}
}

// checkCryptoUsageWithContext checks a line for crypto function calls with function context.
func (a *JavaScriptAnalyzer) checkCryptoUsageWithContext(line string, lineNum int, filename string, imports map[string]bool, funcCtx *jsFuncContext) []types.CryptoUsage {
	usages := a.checkCryptoUsage(line, lineNum, filename, imports)

	// Add function context to all usages
	if funcCtx != nil {
		for i := range usages {
			if funcCtx.ClassName != "" {
				usages[i].Function = funcCtx.ClassName + "." + funcCtx.Name
			} else {
				usages[i].Function = funcCtx.Name
			}
			usages[i].InExported = funcCtx.IsExported
		}
	}

	return usages
}

// checkImports checks a line for crypto-related imports.
func (a *JavaScriptAnalyzer) checkImports(line string, imports map[string]bool) {
	// Check require() calls
	matches := requirePattern.FindAllStringSubmatch(line, -1)
	for _, match := range matches {
		if len(match) > 1 {
			pkg := match[1]
			if a.isCryptoPackage(pkg) {
				imports[pkg] = true
			}
		}
	}

	// Check import statements
	matches = importPattern.FindAllStringSubmatch(line, -1)
	for _, match := range matches {
		if len(match) > 1 {
			pkg := match[1]
			if a.isCryptoPackage(pkg) {
				imports[pkg] = true
			}
		}
	}

	// Check dynamic imports
	matches = importDynPattern.FindAllStringSubmatch(line, -1)
	for _, match := range matches {
		if len(match) > 1 {
			pkg := match[1]
			if a.isCryptoPackage(pkg) {
				imports[pkg] = true
			}
		}
	}
}

// isCryptoPackage checks if a package name is crypto-related.
func (a *JavaScriptAnalyzer) isCryptoPackage(pkg string) bool {
	cryptoPackages := []string{
		"crypto",
		"bcrypt",
		"bcryptjs",
		"jsonwebtoken",
		"jose",
		"crypto-js",
		"node-forge",
		"tweetnacl",
		"libsodium",
		"sodium-native",
		"argon2",
		"scrypt",
		"pbkdf2",
		"elliptic",
		"secp256k1",
		"ed25519",
		"noble-curves",
		"@noble/curves",
		"@noble/hashes",
		"@noble/secp256k1",
		"@noble/ed25519",
		"webcrypto",
		"subtle-crypto",
	}

	for _, cp := range cryptoPackages {
		if pkg == cp || strings.HasPrefix(pkg, cp+"/") {
			return true
		}
	}

	return false
}

// checkCryptoUsage checks a line for crypto function calls and returns usages.
func (a *JavaScriptAnalyzer) checkCryptoUsage(line string, lineNum int, filename string, imports map[string]bool) []types.CryptoUsage {
	var usages []types.CryptoUsage

	// Check Node.js crypto module usage
	if cryptoMethodPattern.MatchString(line) {
		matches := cryptoMethodPattern.FindStringSubmatch(line)
		if len(matches) > 1 {
			method := matches[1]
			alg := a.detectAlgorithmFromCryptoCall(line, method)
			if alg != "" {
				usages = append(usages, a.createUsage(alg, filename, lineNum, method+"()"))
			}
		}
	}

	// Check bcrypt usage
	if bcryptPattern.MatchString(line) {
		usages = append(usages, a.createUsage("bcrypt", filename, lineNum, "bcrypt"))
	}

	// Check JWT usage
	if jwtPattern.MatchString(line) {
		// Try to detect the algorithm from the line
		alg := a.detectJWTAlgorithm(line)
		if alg != "" {
			usages = append(usages, a.createUsage(alg, filename, lineNum, "jwt"))
		} else {
			// Default to RS256 if we can't detect
			usages = append(usages, a.createUsage("RS256", filename, lineNum, "jwt"))
		}
	}

	// Check CryptoJS usage
	if cryptoJSPattern.MatchString(line) {
		matches := cryptoJSPattern.FindStringSubmatch(line)
		if len(matches) > 1 {
			alg := a.mapCryptoJSAlgorithm(matches[1])
			usages = append(usages, a.createUsage(alg, filename, lineNum, "CryptoJS"))
		}
	}

	// Check node-forge usage
	if nodeForgePattern.MatchString(line) {
		alg := a.detectForgeAlgorithm(line)
		if alg != "" {
			usages = append(usages, a.createUsage(alg, filename, lineNum, "node-forge"))
		}
	}

	return usages
}

// detectAlgorithmFromCryptoCall tries to extract the algorithm from a crypto.* call.
func (a *JavaScriptAnalyzer) detectAlgorithmFromCryptoCall(line, method string) string {
	// Look for algorithm string in the line
	matches := algStringPattern.FindAllStringSubmatch(line, -1)
	for _, match := range matches {
		if len(match) > 1 {
			alg := strings.ToLower(match[1])
			if mapped, ok := jsAlgorithmMap[alg]; ok {
				return mapped
			}
		}
	}

	// Default based on method
	switch method {
	case "createHash":
		return "SHA-256" // Common default
	case "createHmac":
		return "HMAC-SHA256"
	case "createSign", "createVerify":
		return "RSA"
	case "generateKeyPair", "generateKeyPairSync":
		if strings.Contains(line, "rsa") {
			return "RSA"
		}
		if strings.Contains(line, "ec") || strings.Contains(line, "ecdsa") {
			return "ECDSA"
		}
		if strings.Contains(line, "ed25519") {
			return "Ed25519"
		}
		return "RSA" // Default
	case "scrypt", "scryptSync":
		return "scrypt"
	case "pbkdf2", "pbkdf2Sync":
		return "PBKDF2"
	}

	return ""
}

// detectJWTAlgorithm tries to detect JWT algorithm from the line.
func (a *JavaScriptAnalyzer) detectJWTAlgorithm(line string) string {
	lineLower := strings.ToLower(line)

	algorithms := []struct {
		pattern string
		alg     string
	}{
		{"rs256", "RS256"},
		{"rs384", "RS384"},
		{"rs512", "RS512"},
		{"es256", "ES256"},
		{"es384", "ES384"},
		{"es512", "ES512"},
		{"ps256", "PS256"},
		{"ps384", "PS384"},
		{"ps512", "PS512"},
		{"hs256", "HS256"},
		{"hs384", "HS384"},
		{"hs512", "HS512"},
		{"eddsa", "EdDSA"},
	}

	for _, a := range algorithms {
		if strings.Contains(lineLower, a.pattern) {
			return a.alg
		}
	}

	return ""
}

// mapCryptoJSAlgorithm maps CryptoJS algorithm names.
func (a *JavaScriptAnalyzer) mapCryptoJSAlgorithm(alg string) string {
	switch strings.ToUpper(alg) {
	case "AES":
		return "AES"
	case "DES":
		return "DES"
	case "TRIPLEDES":
		return "3DES"
	case "RABBIT":
		return "Rabbit"
	case "RC4":
		return "RC4"
	case "MD5":
		return "MD5"
	case "SHA1":
		return "SHA-1"
	case "SHA256":
		return "SHA-256"
	case "SHA512":
		return "SHA-512"
	case "SHA3":
		return "SHA3"
	case "RIPEMD160":
		return "RIPEMD-160"
	case "HMACMD5":
		return "HMAC-MD5"
	case "HMACSHA1":
		return "HMAC-SHA1"
	case "HMACSHA256":
		return "HMAC-SHA256"
	case "HMACSHA512":
		return "HMAC-SHA512"
	default:
		return alg
	}
}

// detectForgeAlgorithm detects algorithm from node-forge usage.
func (a *JavaScriptAnalyzer) detectForgeAlgorithm(line string) string {
	lineLower := strings.ToLower(line)

	if strings.Contains(lineLower, "rsa") {
		return "RSA"
	}
	if strings.Contains(lineLower, "aes") {
		return "AES"
	}
	if strings.Contains(lineLower, "des") {
		return "DES"
	}
	if strings.Contains(lineLower, "md5") {
		return "MD5"
	}
	if strings.Contains(lineLower, "sha1") {
		return "SHA-1"
	}
	if strings.Contains(lineLower, "sha256") {
		return "SHA-256"
	}
	if strings.Contains(lineLower, "sha512") {
		return "SHA-512"
	}

	return ""
}

// createUsage creates a CryptoUsage from detected crypto.
func (a *JavaScriptAnalyzer) createUsage(algorithm, filename string, line int, callPath string) types.CryptoUsage {
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
