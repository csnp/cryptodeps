// Copyright 2025-2026 CyberSecurity NonProfit (CSNP)
// SPDX-License-Identifier: Apache-2.0

package reachability

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/csnp/qramm-cryptodeps/pkg/types"
)

func TestGetPackageAlias(t *testing.T) {
	tests := []struct {
		name       string
		importPath string
		want       string
	}{
		{
			name:       "simple package",
			importPath: "fmt",
			want:       "fmt",
		},
		{
			name:       "standard library with path",
			importPath: "crypto/rsa",
			want:       "rsa",
		},
		{
			name:       "github package",
			importPath: "github.com/golang-jwt/jwt",
			want:       "jwt",
		},
		{
			name:       "versioned v5",
			importPath: "github.com/golang-jwt/jwt/v5",
			want:       "jwt",
		},
		{
			name:       "versioned v4",
			importPath: "github.com/golang-jwt/jwt/v4",
			want:       "jwt",
		},
		{
			name:       "versioned v2",
			importPath: "github.com/foo/bar/v2",
			want:       "bar",
		},
		{
			name:       "golang.org/x/crypto subpackage",
			importPath: "golang.org/x/crypto/bcrypt",
			want:       "bcrypt",
		},
		{
			name:       "package ending with number but not version",
			importPath: "github.com/foo/sha256",
			want:       "sha256",
		},
		{
			name:       "empty string",
			importPath: "",
			want:       "",
		},
		{
			name:       "single component",
			importPath: "mypackage",
			want:       "mypackage",
		},
		{
			name:       "versioned v10",
			importPath: "github.com/foo/bar/v10",
			want:       "bar",
		},
		{
			name:       "not a version - vfoo",
			importPath: "github.com/foo/bar/vfoo",
			want:       "vfoo",
		},
		{
			name:       "not a version - v2beta",
			importPath: "github.com/foo/bar/v2beta",
			want:       "v2beta",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := getPackageAlias(tt.importPath)
			if got != tt.want {
				t.Errorf("getPackageAlias(%q) = %q, want %q", tt.importPath, got, tt.want)
			}
		})
	}
}

func TestNewAnalyzer(t *testing.T) {
	a := NewAnalyzer("/some/path")
	if a == nil {
		t.Fatal("NewAnalyzer returned nil")
	}
	if a.projectPath != "/some/path" {
		t.Errorf("projectPath = %q, want %q", a.projectPath, "/some/path")
	}
	if a.fset == nil {
		t.Error("fset is nil")
	}
	if a.graph == nil {
		t.Error("graph is nil")
	}
	if a.graph.Nodes == nil {
		t.Error("graph.Nodes is nil")
	}
	if a.graph.EntryPoints == nil {
		t.Error("graph.EntryPoints is nil")
	}
	if a.graph.CryptoCalls == nil {
		t.Error("graph.CryptoCalls is nil")
	}
}

func TestClassifyFindings(t *testing.T) {
	tests := []struct {
		name     string
		findings []types.CryptoUsage
		traces   map[string][]types.CallTrace
		want     []types.Reachability
	}{
		{
			name: "no traces - all available",
			findings: []types.CryptoUsage{
				{Algorithm: "RSA"},
				{Algorithm: "AES"},
			},
			traces: map[string][]types.CallTrace{},
			want:   []types.Reachability{types.ReachabilityAvailable, types.ReachabilityAvailable},
		},
		{
			name: "direct trace - confirmed",
			findings: []types.CryptoUsage{
				{Algorithm: "RSA"},
			},
			traces: map[string][]types.CallTrace{
				"RSA": {
					{
						EntryPoint: "main.main",
						Path:       []string{"main.main", "crypto/rsa.GenerateKey"},
					},
				},
			},
			want: []types.Reachability{types.ReachabilityConfirmed},
		},
		{
			name: "indirect trace - reachable",
			findings: []types.CryptoUsage{
				{Algorithm: "RSA"},
			},
			traces: map[string][]types.CallTrace{
				"RSA": {
					{
						EntryPoint: "main.main",
						Path:       []string{"main.main", "pkg.Helper", "internal.DoThing", "crypto/rsa.GenerateKey"},
					},
				},
			},
			want: []types.Reachability{types.ReachabilityReachable},
		},
		{
			name: "mixed - one confirmed, one available",
			findings: []types.CryptoUsage{
				{Algorithm: "RSA"},
				{Algorithm: "AES"},
			},
			traces: map[string][]types.CallTrace{
				"RSA": {
					{
						EntryPoint: "main.main",
						Path:       []string{"main.main", "crypto/rsa.GenerateKey"},
					},
				},
			},
			want: []types.Reachability{types.ReachabilityConfirmed, types.ReachabilityAvailable},
		},
		{
			name: "multiple traces - use best (confirmed over reachable)",
			findings: []types.CryptoUsage{
				{Algorithm: "RSA"},
			},
			traces: map[string][]types.CallTrace{
				"RSA": {
					{
						EntryPoint: "main.main",
						Path:       []string{"main.main", "pkg.A", "pkg.B", "crypto/rsa.GenerateKey"},
					},
					{
						EntryPoint: "main.init",
						Path:       []string{"main.init", "crypto/rsa.GenerateKey"},
					},
				},
			},
			want: []types.Reachability{types.ReachabilityConfirmed},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ClassifyFindings(tt.findings, tt.traces)
			if len(result) != len(tt.want) {
				t.Fatalf("got %d results, want %d", len(result), len(tt.want))
			}
			for i, want := range tt.want {
				if result[i].Reachability != want {
					t.Errorf("result[%d].Reachability = %q, want %q", i, result[i].Reachability, want)
				}
			}
		})
	}
}

func TestFindPath(t *testing.T) {
	a := NewAnalyzer("")

	// Build a simple call graph:
	// main -> helper -> crypto
	a.graph.Nodes["pkg.main"] = &CallNode{
		Package:  "pkg",
		Function: "main",
		Calls:    []string{"pkg.helper"},
	}
	a.graph.Nodes["pkg.helper"] = &CallNode{
		Package:  "pkg",
		Function: "helper",
		Calls:    []string{"crypto/rsa.GenerateKey"},
	}
	a.graph.Nodes["crypto/rsa.GenerateKey"] = &CallNode{
		Package:  "crypto/rsa",
		Function: "GenerateKey",
		Calls:    []string{},
	}

	tests := []struct {
		name   string
		start  string
		target string
		want   []string
	}{
		{
			name:   "direct path",
			start:  "pkg.helper",
			target: "crypto/rsa.GenerateKey",
			want:   []string{"pkg.helper", "crypto/rsa.GenerateKey"},
		},
		{
			name:   "indirect path",
			start:  "pkg.main",
			target: "crypto/rsa.GenerateKey",
			want:   []string{"pkg.main", "pkg.helper", "crypto/rsa.GenerateKey"},
		},
		{
			name:   "same node",
			start:  "pkg.main",
			target: "pkg.main",
			want:   []string{"pkg.main"},
		},
		{
			name:   "no path",
			start:  "crypto/rsa.GenerateKey",
			target: "pkg.main",
			want:   nil,
		},
		{
			name:   "unknown start",
			start:  "unknown.func",
			target: "pkg.main",
			want:   nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := a.findPath(tt.start, tt.target, make(map[string]bool))
			if tt.want == nil {
				if got != nil {
					t.Errorf("findPath() = %v, want nil", got)
				}
				return
			}
			if got == nil {
				t.Errorf("findPath() = nil, want %v", tt.want)
				return
			}
			if len(got) != len(tt.want) {
				t.Errorf("findPath() = %v, want %v", got, tt.want)
				return
			}
			for i := range tt.want {
				if got[i] != tt.want[i] {
					t.Errorf("findPath()[%d] = %q, want %q", i, got[i], tt.want[i])
				}
			}
		})
	}
}

func TestFindPathCycleDetection(t *testing.T) {
	a := NewAnalyzer("")

	// Build a cyclic call graph:
	// a -> b -> c -> a (cycle)
	a.graph.Nodes["pkg.a"] = &CallNode{
		Package:  "pkg",
		Function: "a",
		Calls:    []string{"pkg.b"},
	}
	a.graph.Nodes["pkg.b"] = &CallNode{
		Package:  "pkg",
		Function: "b",
		Calls:    []string{"pkg.c"},
	}
	a.graph.Nodes["pkg.c"] = &CallNode{
		Package:  "pkg",
		Function: "c",
		Calls:    []string{"pkg.a"}, // cycle back to a
	}

	// Should not infinite loop - target doesn't exist
	got := a.findPath("pkg.a", "pkg.nonexistent", make(map[string]bool))
	if got != nil {
		t.Errorf("findPath with cycle = %v, want nil", got)
	}
}

func TestGetPackageFromCallSite(t *testing.T) {
	a := NewAnalyzer("")

	tests := []struct {
		name     string
		callSite string
		want     string
	}{
		{
			name:     "standard library",
			callSite: "crypto/rsa.GenerateKey",
			want:     "crypto/rsa",
		},
		{
			name:     "github package",
			callSite: "github.com/foo/bar.DoThing",
			want:     "github.com/foo/bar",
		},
		{
			name:     "method on type",
			callSite: "pkg.Type.Method",
			want:     "pkg.Type",
		},
		{
			name:     "no dot",
			callSite: "nodot",
			want:     "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := a.getPackageFromCallSite(tt.callSite)
			if got != tt.want {
				t.Errorf("getPackageFromCallSite(%q) = %q, want %q", tt.callSite, got, tt.want)
			}
		})
	}
}

func TestJWTSigningMethods(t *testing.T) {
	// Verify the JWT signing methods map has expected entries
	expectedMethods := map[string]string{
		"SigningMethodHS256": "HS256",
		"SigningMethodHS384": "HS384",
		"SigningMethodHS512": "HS512",
		"SigningMethodRS256": "RS256",
		"SigningMethodRS384": "RS384",
		"SigningMethodRS512": "RS512",
		"SigningMethodES256": "ES256",
		"SigningMethodES384": "ES384",
		"SigningMethodES512": "ES512",
		"SigningMethodEdDSA": "Ed25519",
	}

	for method, algo := range expectedMethods {
		if got, ok := jwtSigningMethods[method]; !ok {
			t.Errorf("jwtSigningMethods missing %q", method)
		} else if got != algo {
			t.Errorf("jwtSigningMethods[%q] = %q, want %q", method, got, algo)
		}
	}
}

func TestKnownCryptoTargets(t *testing.T) {
	// Verify essential crypto targets are present
	expectedTargets := map[string]string{
		"crypto/rsa":                          "RSA",
		"crypto/ecdsa":                        "ECDSA",
		"crypto/ed25519":                      "Ed25519",
		"crypto/aes":                          "AES",
		"crypto/sha256":                       "SHA-256",
		"golang.org/x/crypto/bcrypt":          "bcrypt",
		"golang.org/x/crypto/argon2":          "Argon2",
		"golang.org/x/crypto/chacha20poly1305": "ChaCha20-Poly1305",
	}

	for pkg, algo := range expectedTargets {
		found := false
		for _, target := range knownCryptoTargets {
			if target.Package == pkg {
				found = true
				if target.Algorithm != algo {
					t.Errorf("knownCryptoTargets[%q].Algorithm = %q, want %q", pkg, target.Algorithm, algo)
				}
				break
			}
		}
		if !found {
			t.Errorf("knownCryptoTargets missing package %q", pkg)
		}
	}
}

// Integration tests with actual Go source files

func TestAnalyzeWithTestdata(t *testing.T) {
	// Create testdata directory
	testDir := t.TempDir()

	// Create go.mod
	goMod := `module testproject

go 1.21
`
	if err := os.WriteFile(filepath.Join(testDir, "go.mod"), []byte(goMod), 0644); err != nil {
		t.Fatal(err)
	}

	// Create main.go with crypto usage
	mainGo := `package main

import (
	"crypto/rsa"
	"crypto/rand"
	"fmt"
)

func main() {
	key, err := generateKey()
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(key)
}

func generateKey() (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, 2048)
}
`
	if err := os.WriteFile(filepath.Join(testDir, "main.go"), []byte(mainGo), 0644); err != nil {
		t.Fatal(err)
	}

	// Run analysis
	a := NewAnalyzer(testDir)
	traces, err := a.Analyze()
	if err != nil {
		t.Fatalf("Analyze() error = %v", err)
	}

	// Verify RSA was detected
	rsaTraces, ok := traces["RSA"]
	if !ok {
		t.Error("RSA not detected in traces")
	}
	if len(rsaTraces) == 0 {
		t.Error("No RSA traces found")
	}

	// Verify the trace path
	if len(rsaTraces) > 0 {
		trace := rsaTraces[0]
		if trace.EntryPoint == "" {
			t.Error("RSA trace has empty entry point")
		}
		if len(trace.Path) < 2 {
			t.Errorf("RSA trace path too short: %v", trace.Path)
		}
	}
}

func TestAnalyzeJWTUsage(t *testing.T) {
	// Create testdata directory
	testDir := t.TempDir()

	// Create go.mod
	goMod := `module testproject

go 1.21

require github.com/golang-jwt/jwt/v5 v5.0.0
`
	if err := os.WriteFile(filepath.Join(testDir, "go.mod"), []byte(goMod), 0644); err != nil {
		t.Fatal(err)
	}

	// Create main.go with JWT usage
	mainGo := `package main

import (
	"fmt"
	"github.com/golang-jwt/jwt/v5"
)

func main() {
	token := createToken()
	fmt.Println(token)
}

func createToken() string {
	claims := jwt.MapClaims{
		"user": "test",
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, _ := token.SignedString([]byte("secret"))
	return tokenString
}
`
	if err := os.WriteFile(filepath.Join(testDir, "main.go"), []byte(mainGo), 0644); err != nil {
		t.Fatal(err)
	}

	// Run analysis
	a := NewAnalyzer(testDir)
	traces, err := a.Analyze()
	if err != nil {
		t.Fatalf("Analyze() error = %v", err)
	}

	// Verify HS256 was detected
	hs256Traces, ok := traces["HS256"]
	if !ok {
		t.Error("HS256 not detected in traces")
	}
	if len(hs256Traces) == 0 {
		t.Error("No HS256 traces found")
	}
}

func TestAnalyzeNoGoFiles(t *testing.T) {
	// Create empty testdata directory
	testDir := t.TempDir()

	// Create go.mod only
	goMod := `module testproject

go 1.21
`
	if err := os.WriteFile(filepath.Join(testDir, "go.mod"), []byte(goMod), 0644); err != nil {
		t.Fatal(err)
	}

	// Run analysis
	a := NewAnalyzer(testDir)
	traces, err := a.Analyze()
	if err != nil {
		t.Fatalf("Analyze() error = %v", err)
	}

	// Should return empty traces, not error
	if len(traces) != 0 {
		t.Errorf("Expected empty traces for project with no Go files, got %d", len(traces))
	}
}

func TestAnalyzeNoCrypto(t *testing.T) {
	// Create testdata directory
	testDir := t.TempDir()

	// Create go.mod
	goMod := `module testproject

go 1.21
`
	if err := os.WriteFile(filepath.Join(testDir, "go.mod"), []byte(goMod), 0644); err != nil {
		t.Fatal(err)
	}

	// Create main.go without crypto
	mainGo := `package main

import "fmt"

func main() {
	fmt.Println("Hello, World!")
}
`
	if err := os.WriteFile(filepath.Join(testDir, "main.go"), []byte(mainGo), 0644); err != nil {
		t.Fatal(err)
	}

	// Run analysis
	a := NewAnalyzer(testDir)
	traces, err := a.Analyze()
	if err != nil {
		t.Fatalf("Analyze() error = %v", err)
	}

	// Should return empty traces
	if len(traces) != 0 {
		t.Errorf("Expected empty traces for project without crypto, got %d", len(traces))
	}
}

func TestFindGoFilesSkipsVendor(t *testing.T) {
	testDir := t.TempDir()

	// Create go.mod
	goMod := `module testproject

go 1.21
`
	if err := os.WriteFile(filepath.Join(testDir, "go.mod"), []byte(goMod), 0644); err != nil {
		t.Fatal(err)
	}

	// Create main.go
	mainGo := `package main

func main() {}
`
	if err := os.WriteFile(filepath.Join(testDir, "main.go"), []byte(mainGo), 0644); err != nil {
		t.Fatal(err)
	}

	// Create vendor directory with Go file
	vendorDir := filepath.Join(testDir, "vendor", "github.com", "somelib")
	if err := os.MkdirAll(vendorDir, 0755); err != nil {
		t.Fatal(err)
	}
	vendorGo := `package somelib

import "crypto/rsa"

func DoThing() { _ = rsa.PublicKey{} }
`
	if err := os.WriteFile(filepath.Join(vendorDir, "lib.go"), []byte(vendorGo), 0644); err != nil {
		t.Fatal(err)
	}

	// Run analysis
	a := NewAnalyzer(testDir)
	files, err := a.findGoFiles()
	if err != nil {
		t.Fatalf("findGoFiles() error = %v", err)
	}

	// Should only have main.go, not vendor files
	if len(files) != 1 {
		t.Errorf("Expected 1 file, got %d: %v", len(files), files)
	}
	for _, f := range files {
		if filepath.Base(f) != "main.go" {
			t.Errorf("Unexpected file: %s", f)
		}
	}
}

func TestFindGoFilesSkipsTestFiles(t *testing.T) {
	testDir := t.TempDir()

	// Create go.mod
	goMod := `module testproject

go 1.21
`
	if err := os.WriteFile(filepath.Join(testDir, "go.mod"), []byte(goMod), 0644); err != nil {
		t.Fatal(err)
	}

	// Create main.go and main_test.go
	mainGo := `package main

func main() {}
`
	testGo := `package main

import "testing"

func TestMain(t *testing.T) {}
`
	if err := os.WriteFile(filepath.Join(testDir, "main.go"), []byte(mainGo), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(testDir, "main_test.go"), []byte(testGo), 0644); err != nil {
		t.Fatal(err)
	}

	// Run analysis
	a := NewAnalyzer(testDir)
	files, err := a.findGoFiles()
	if err != nil {
		t.Fatalf("findGoFiles() error = %v", err)
	}

	// Should only have main.go, not test files
	if len(files) != 1 {
		t.Errorf("Expected 1 file, got %d: %v", len(files), files)
	}
	for _, f := range files {
		if filepath.Base(f) != "main.go" {
			t.Errorf("Unexpected file: %s", f)
		}
	}
}

func TestEntryPointDetection(t *testing.T) {
	testDir := t.TempDir()

	// Create go.mod
	goMod := `module testproject

go 1.21
`
	if err := os.WriteFile(filepath.Join(testDir, "go.mod"), []byte(goMod), 0644); err != nil {
		t.Fatal(err)
	}

	// Create main.go with various entry points
	mainGo := `package main

func init() {}

func main() {}

func ExportedFunc() {}

func privateFunc() {}
`
	if err := os.WriteFile(filepath.Join(testDir, "main.go"), []byte(mainGo), 0644); err != nil {
		t.Fatal(err)
	}

	// Run analysis
	a := NewAnalyzer(testDir)
	_, err := a.Analyze()
	if err != nil {
		t.Fatalf("Analyze() error = %v", err)
	}

	// Check entry points
	entryPoints := a.graph.EntryPoints

	hasMain := false
	hasInit := false
	hasExported := false
	hasPrivate := false

	for _, ep := range entryPoints {
		switch {
		case ep == "testproject.main":
			hasMain = true
		case ep == "testproject.init":
			hasInit = true
		case ep == "testproject.ExportedFunc":
			hasExported = true
		case ep == "testproject.privateFunc":
			hasPrivate = true
		}
	}

	if !hasMain {
		t.Error("main() not detected as entry point")
	}
	if !hasInit {
		t.Error("init() not detected as entry point")
	}
	if !hasExported {
		t.Error("ExportedFunc() not detected as entry point")
	}
	if hasPrivate {
		t.Error("privateFunc() incorrectly detected as entry point")
	}
}
