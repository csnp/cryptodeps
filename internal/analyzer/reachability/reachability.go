// Copyright 2025-2026 CyberSecurity NonProfit (CSNP)
// SPDX-License-Identifier: Apache-2.0

// Package reachability provides call graph analysis to determine if crypto
// in dependencies is actually reachable from user code.
package reachability

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"

	"github.com/csnp/qramm-cryptodeps/pkg/types"
)

// CryptoTarget represents a known crypto package/function to track.
type CryptoTarget struct {
	Package   string   // e.g., "crypto/rsa", "github.com/golang-jwt/jwt/v5"
	Functions []string // specific functions, empty means any function in package
	Algorithm string   // the algorithm this represents
}

// knownCryptoTargets maps import paths to crypto algorithms.
var knownCryptoTargets = []CryptoTarget{
	// Standard library
	{Package: "crypto/rsa", Algorithm: "RSA"},
	{Package: "crypto/ecdsa", Algorithm: "ECDSA"},
	{Package: "crypto/ed25519", Algorithm: "Ed25519"},
	{Package: "crypto/dsa", Algorithm: "DSA"},
	{Package: "crypto/aes", Algorithm: "AES"},
	{Package: "crypto/des", Algorithm: "DES"},
	{Package: "crypto/rc4", Algorithm: "RC4"},
	{Package: "crypto/sha1", Algorithm: "SHA-1"},
	{Package: "crypto/sha256", Algorithm: "SHA-256"},
	{Package: "crypto/sha512", Algorithm: "SHA-512"},
	{Package: "crypto/md5", Algorithm: "MD5"},
	{Package: "crypto/hmac", Algorithm: "HMAC"},
	// golang.org/x/crypto
	{Package: "golang.org/x/crypto/bcrypt", Algorithm: "bcrypt"},
	{Package: "golang.org/x/crypto/argon2", Algorithm: "Argon2"},
	{Package: "golang.org/x/crypto/chacha20poly1305", Algorithm: "ChaCha20-Poly1305"},
	{Package: "golang.org/x/crypto/curve25519", Algorithm: "X25519"},
	{Package: "golang.org/x/crypto/ed25519", Algorithm: "Ed25519"},
	{Package: "golang.org/x/crypto/nacl", Algorithm: "NaCl"},
	{Package: "golang.org/x/crypto/scrypt", Algorithm: "scrypt"},
	{Package: "golang.org/x/crypto/ssh", Algorithm: "SSH"},
	// Popular third-party (generic)
	{Package: "github.com/cloudflare/circl", Algorithm: "PQC"},
	{Package: "filippo.io/age", Algorithm: "age"},
	{Package: "filippo.io/edwards25519", Algorithm: "Ed25519"},
}

// jwtSigningMethods maps JWT signing method constants to algorithms.
// These are detected as variable/constant references, not function calls.
var jwtSigningMethods = map[string]string{
	// HMAC (symmetric) - quantum partial risk
	"SigningMethodHS256": "HS256",
	"SigningMethodHS384": "HS384",
	"SigningMethodHS512": "HS512",
	// RSA - quantum vulnerable
	"SigningMethodRS256": "RS256",
	"SigningMethodRS384": "RS384",
	"SigningMethodRS512": "RS512",
	// RSA-PSS - quantum vulnerable
	"SigningMethodPS256": "RS256", // PS256 uses RSA-PSS
	"SigningMethodPS384": "RS384",
	"SigningMethodPS512": "RS512",
	// ECDSA - quantum vulnerable
	"SigningMethodES256": "ES256",
	"SigningMethodES384": "ES384",
	"SigningMethodES512": "ES512",
	// EdDSA - quantum vulnerable
	"SigningMethodEdDSA": "Ed25519",
}

// jwtPackages lists known JWT package import paths.
var jwtPackages = []string{
	"github.com/golang-jwt/jwt",
	"github.com/golang-jwt/jwt/v4",
	"github.com/golang-jwt/jwt/v5",
	"github.com/dgrijalva/jwt-go", // legacy
}

// CallNode represents a function in the call graph.
type CallNode struct {
	Package  string   // full package path
	Function string   // function name
	File     string   // source file
	Line     int      // line number
	Calls    []string // functions this calls (as "pkg.Func" strings)
	CalledBy []string // functions that call this
}

// CallGraph represents the project's call graph.
type CallGraph struct {
	Nodes       map[string]*CallNode // key: "pkg.Func"
	EntryPoints []string             // main functions, init functions, exported handlers
	CryptoCalls map[string][]string  // algorithm -> list of call sites ("pkg.Func")
}

// Analyzer performs reachability analysis on Go source code.
type Analyzer struct {
	projectPath string
	moduleName  string
	fset        *token.FileSet
	graph       *CallGraph
	imports     map[string]string // alias -> full path for current file
}

// getPackageAlias determines the package alias from an import path.
// Handles versioned paths like "github.com/foo/bar/v5" -> "bar" (not "v5").
func getPackageAlias(importPath string) string {
	parts := strings.Split(importPath, "/")
	if len(parts) == 0 {
		return importPath
	}

	lastPart := parts[len(parts)-1]

	// Check if last part is a version (v2, v3, v5, etc.)
	if len(lastPart) >= 2 && lastPart[0] == 'v' {
		isVersion := true
		for _, c := range lastPart[1:] {
			if c < '0' || c > '9' {
				isVersion = false
				break
			}
		}
		// If it's a version and there's a previous component, use that
		if isVersion && len(parts) >= 2 {
			return parts[len(parts)-2]
		}
	}

	return lastPart
}

// NewAnalyzer creates a new reachability analyzer.
func NewAnalyzer(projectPath string) *Analyzer {
	return &Analyzer{
		projectPath: projectPath,
		fset:        token.NewFileSet(),
		graph: &CallGraph{
			Nodes:       make(map[string]*CallNode),
			EntryPoints: make([]string, 0),
			CryptoCalls: make(map[string][]string),
		},
	}
}

// Analyze performs reachability analysis and returns crypto traces.
func (a *Analyzer) Analyze() (map[string][]types.CallTrace, error) {
	// Get module name from go.mod
	a.moduleName = a.getModuleName()

	// Find all Go source files
	goFiles, err := a.findGoFiles()
	if err != nil {
		return nil, err
	}

	// Parse all files and build call graph
	for _, file := range goFiles {
		if err := a.parseFile(file); err != nil {
			// Continue on parse errors (some files may be invalid)
			continue
		}
	}

	// Find paths from entry points to crypto calls
	traces := a.findCryptoTraces()

	return traces, nil
}

// getModuleName extracts the module name from go.mod.
func (a *Analyzer) getModuleName() string {
	goModPath := filepath.Join(a.projectPath, "go.mod")
	content, err := os.ReadFile(goModPath)
	if err != nil {
		return ""
	}

	lines := strings.Split(string(content), "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "module ") {
			return strings.TrimSpace(strings.TrimPrefix(line, "module "))
		}
	}
	return ""
}

// findGoFiles finds all .go files in the project (excluding vendor, testdata).
func (a *Analyzer) findGoFiles() ([]string, error) {
	var files []string

	err := filepath.Walk(a.projectPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil // Skip errors
		}

		// Skip directories we don't want
		if info.IsDir() {
			name := info.Name()
			if name == "vendor" || name == "testdata" || name == ".git" || name == "node_modules" {
				return filepath.SkipDir
			}
			return nil
		}

		// Only .go files, skip tests for now (they don't affect production reachability)
		if strings.HasSuffix(path, ".go") && !strings.HasSuffix(path, "_test.go") {
			files = append(files, path)
		}

		return nil
	})

	return files, err
}

// parseFile parses a Go file and extracts call information.
func (a *Analyzer) parseFile(filePath string) error {
	file, err := parser.ParseFile(a.fset, filePath, nil, parser.ParseComments)
	if err != nil {
		return err
	}

	// Get package path
	relPath, _ := filepath.Rel(a.projectPath, filePath)
	pkgDir := filepath.Dir(relPath)
	pkgPath := a.moduleName
	if pkgDir != "." {
		pkgPath = a.moduleName + "/" + strings.ReplaceAll(pkgDir, string(filepath.Separator), "/")
	}

	// Build import map for this file
	a.imports = make(map[string]string)
	for _, imp := range file.Imports {
		path := strings.Trim(imp.Path.Value, `"`)
		var alias string
		if imp.Name != nil {
			alias = imp.Name.Name
		} else {
			// Use last component of path as alias, handling versioned paths
			alias = getPackageAlias(path)
		}
		a.imports[alias] = path
	}

	// Visit all function declarations
	ast.Inspect(file, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.FuncDecl:
			a.processFuncDecl(node, pkgPath, filePath)
		}
		return true
	})

	return nil
}

// processFuncDecl processes a function declaration.
func (a *Analyzer) processFuncDecl(fn *ast.FuncDecl, pkgPath, filePath string) {
	funcName := fn.Name.Name

	// For methods, include receiver type
	if fn.Recv != nil && len(fn.Recv.List) > 0 {
		if t, ok := fn.Recv.List[0].Type.(*ast.StarExpr); ok {
			if ident, ok := t.X.(*ast.Ident); ok {
				funcName = ident.Name + "." + funcName
			}
		} else if ident, ok := fn.Recv.List[0].Type.(*ast.Ident); ok {
			funcName = ident.Name + "." + funcName
		}
	}

	fullName := pkgPath + "." + funcName
	pos := a.fset.Position(fn.Pos())

	node := &CallNode{
		Package:  pkgPath,
		Function: funcName,
		File:     filePath,
		Line:     pos.Line,
		Calls:    make([]string, 0),
		CalledBy: make([]string, 0),
	}

	// Check if this is an entry point
	if funcName == "main" || funcName == "init" || ast.IsExported(fn.Name.Name) {
		a.graph.EntryPoints = append(a.graph.EntryPoints, fullName)
	}

	// Find all function calls and crypto references in the body
	if fn.Body != nil {
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			switch expr := n.(type) {
			case *ast.CallExpr:
				a.processCall(expr, node, fullName)
			case *ast.SelectorExpr:
				// Check for JWT signing method references (e.g., jwt.SigningMethodHS256)
				a.processJWTSigningMethod(expr, fullName)
			}
			return true
		})
	}

	a.graph.Nodes[fullName] = node
}

// processJWTSigningMethod detects JWT signing method constant references.
func (a *Analyzer) processJWTSigningMethod(sel *ast.SelectorExpr, callerName string) {
	ident, ok := sel.X.(*ast.Ident)
	if !ok {
		return
	}

	// Check if this is a JWT package
	pkgPath, ok := a.imports[ident.Name]
	if !ok {
		return
	}

	isJWTPackage := false
	for _, jwtPkg := range jwtPackages {
		if strings.HasPrefix(pkgPath, jwtPkg) {
			isJWTPackage = true
			break
		}
	}
	if !isJWTPackage {
		return
	}

	// Check if this is a signing method constant
	if algorithm, ok := jwtSigningMethods[sel.Sel.Name]; ok {
		// Record this as a crypto call for the specific algorithm
		if a.graph.CryptoCalls[algorithm] == nil {
			a.graph.CryptoCalls[algorithm] = make([]string, 0)
		}
		a.graph.CryptoCalls[algorithm] = append(a.graph.CryptoCalls[algorithm], callerName)
	}
}

// processCall processes a function call expression.
func (a *Analyzer) processCall(call *ast.CallExpr, caller *CallNode, callerName string) {
	var calledPkg, calledFunc string

	switch fn := call.Fun.(type) {
	case *ast.SelectorExpr:
		// pkg.Func() or receiver.Method()
		if ident, ok := fn.X.(*ast.Ident); ok {
			// Check if this is a package alias
			if fullPath, ok := a.imports[ident.Name]; ok {
				calledPkg = fullPath
				calledFunc = fn.Sel.Name
			} else {
				// It's a method call on a variable
				calledFunc = fn.Sel.Name
			}
		}
	case *ast.Ident:
		// Local function call
		calledPkg = caller.Package
		calledFunc = fn.Name
	}

	if calledPkg == "" || calledFunc == "" {
		return
	}

	callSite := calledPkg + "." + calledFunc
	caller.Calls = append(caller.Calls, callSite)

	// Check if this is a crypto call
	for _, target := range knownCryptoTargets {
		if strings.HasPrefix(calledPkg, target.Package) {
			// This is a crypto call!
			if a.graph.CryptoCalls[target.Algorithm] == nil {
				a.graph.CryptoCalls[target.Algorithm] = make([]string, 0)
			}
			a.graph.CryptoCalls[target.Algorithm] = append(
				a.graph.CryptoCalls[target.Algorithm],
				callerName,
			)
		}
	}
}

// findCryptoTraces finds paths from entry points to crypto calls.
func (a *Analyzer) findCryptoTraces() map[string][]types.CallTrace {
	traces := make(map[string][]types.CallTrace)

	for algorithm, callSites := range a.graph.CryptoCalls {
		traces[algorithm] = make([]types.CallTrace, 0)

		for _, callSite := range callSites {
			// Find paths from any entry point to this call site
			for _, entry := range a.graph.EntryPoints {
				path := a.findPath(entry, callSite, make(map[string]bool))
				if path != nil {
					trace := types.CallTrace{
						EntryPoint: entry,
						Path:       path,
						TargetFunc: callSite,
						TargetPkg:  a.getPackageFromCallSite(callSite),
					}
					traces[algorithm] = append(traces[algorithm], trace)
				}
			}
		}
	}

	return traces
}

// findPath finds a path from start to target using BFS.
func (a *Analyzer) findPath(start, target string, visited map[string]bool) []string {
	if start == target {
		return []string{start}
	}

	if visited[start] {
		return nil
	}
	visited[start] = true

	node, ok := a.graph.Nodes[start]
	if !ok {
		return nil
	}

	for _, call := range node.Calls {
		// Direct call to target
		if call == target {
			return []string{start, target}
		}

		// Recursive search
		subPath := a.findPath(call, target, visited)
		if subPath != nil {
			return append([]string{start}, subPath...)
		}
	}

	return nil
}

// getPackageFromCallSite extracts the package from a call site string.
func (a *Analyzer) getPackageFromCallSite(callSite string) string {
	lastDot := strings.LastIndex(callSite, ".")
	if lastDot == -1 {
		return ""
	}
	return callSite[:lastDot]
}

// ClassifyFindings classifies crypto findings by reachability.
func ClassifyFindings(findings []types.CryptoUsage, traces map[string][]types.CallTrace) []types.CryptoUsage {
	result := make([]types.CryptoUsage, len(findings))
	copy(result, findings)

	for i := range result {
		algo := result[i].Algorithm
		if algoTraces, ok := traces[algo]; ok && len(algoTraces) > 0 {
			// Check if any trace is direct (2 steps) or indirect
			hasDirect := false
			for _, t := range algoTraces {
				if len(t.Path) <= 2 {
					hasDirect = true
					break
				}
			}

			if hasDirect {
				result[i].Reachability = types.ReachabilityConfirmed
			} else {
				result[i].Reachability = types.ReachabilityReachable
			}
			result[i].Traces = algoTraces
		} else {
			result[i].Reachability = types.ReachabilityAvailable
		}
	}

	return result
}
