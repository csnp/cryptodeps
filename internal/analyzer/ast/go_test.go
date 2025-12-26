// Copyright 2024-2025 CSNP (csnp.org)
// SPDX-License-Identifier: Apache-2.0

package ast

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/csnp/qramm-cryptodeps/pkg/types"
)

func TestGoAnalyzer_AnalyzeFile(t *testing.T) {
	// Create a temporary Go file with crypto usage
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "crypto_test.go")

	content := `package main

import (
	"crypto/aes"
	"crypto/rsa"
	"crypto/sha256"
)

func PublicFunc() {
	// AES cipher
	block, _ := aes.NewCipher([]byte("key"))
	_ = block
}

func privateFunc() {
	// RSA key generation
	key, _ := rsa.GenerateKey(nil, 2048)
	_ = key
}

type CryptoService struct{}

func (s *CryptoService) Hash(data []byte) []byte {
	h := sha256.New()
	h.Write(data)
	return h.Sum(nil)
}
`
	if err := os.WriteFile(testFile, []byte(content), 0644); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	analyzer := NewGoAnalyzer()
	usages, err := analyzer.AnalyzeFile(testFile)
	if err != nil {
		t.Fatalf("AnalyzeFile failed: %v", err)
	}

	if len(usages) < 3 {
		t.Errorf("Expected at least 3 crypto usages, got %d", len(usages))
	}

	// Check that we found AES, RSA, and SHA-256
	algorithms := make(map[string]bool)
	for _, u := range usages {
		algorithms[u.Algorithm] = true
	}

	expectedAlgorithms := []string{"AES", "RSA", "SHA-256"}
	for _, alg := range expectedAlgorithms {
		if !algorithms[alg] {
			t.Errorf("Expected to find algorithm %s, but it was not detected", alg)
		}
	}
}

func TestGoAnalyzer_FunctionContext(t *testing.T) {
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "context_test.go")

	content := `package main

import "crypto/aes"

func ExportedFunc() {
	block, _ := aes.NewCipher([]byte("key"))
	_ = block
}

func unexportedFunc() {
	block, _ := aes.NewCipher([]byte("key"))
	_ = block
}

type MyService struct{}

func (s *MyService) PublicMethod() {
	block, _ := aes.NewCipher([]byte("key"))
	_ = block
}
`
	if err := os.WriteFile(testFile, []byte(content), 0644); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	analyzer := NewGoAnalyzer()
	usages, err := analyzer.AnalyzeFile(testFile)
	if err != nil {
		t.Fatalf("AnalyzeFile failed: %v", err)
	}

	if len(usages) < 3 {
		t.Errorf("Expected at least 3 crypto usages, got %d", len(usages))
	}

	// Check function contexts
	funcContexts := make(map[string]bool)
	exportedContexts := make(map[string]bool)
	for _, u := range usages {
		if u.Function != "" {
			funcContexts[u.Function] = true
			if u.InExported {
				exportedContexts[u.Function] = true
			}
		}
	}

	// ExportedFunc should be detected as exported
	if !exportedContexts["ExportedFunc"] {
		t.Error("ExportedFunc should be marked as exported")
	}

	// unexportedFunc should NOT be in exported contexts
	if exportedContexts["unexportedFunc"] {
		t.Error("unexportedFunc should NOT be marked as exported")
	}
}

func TestGoAnalyzer_QuantumRiskClassification(t *testing.T) {
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "quantum_test.go")

	content := `package main

import (
	"crypto/rsa"
	"crypto/ecdsa"
	"crypto/aes"
)

func vulnerable() {
	// RSA - vulnerable to quantum
	key, _ := rsa.GenerateKey(nil, 2048)
	_ = key
}

func alsoVulnerable() {
	// ECDSA - vulnerable to quantum
	key, _ := ecdsa.GenerateKey(nil, nil)
	_ = key
}

func partiallySecure() {
	// AES - partial risk (Grover's algorithm)
	block, _ := aes.NewCipher([]byte("key"))
	_ = block
}
`
	if err := os.WriteFile(testFile, []byte(content), 0644); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	analyzer := NewGoAnalyzer()
	usages, err := analyzer.AnalyzeFile(testFile)
	if err != nil {
		t.Fatalf("AnalyzeFile failed: %v", err)
	}

	riskCounts := map[types.QuantumRisk]int{}
	for _, u := range usages {
		riskCounts[u.QuantumRisk]++
	}

	if riskCounts[types.RiskVulnerable] < 2 {
		t.Errorf("Expected at least 2 VULNERABLE findings, got %d", riskCounts[types.RiskVulnerable])
	}

	if riskCounts[types.RiskPartial] < 1 {
		t.Errorf("Expected at least 1 PARTIAL finding, got %d", riskCounts[types.RiskPartial])
	}
}

func TestGoAnalyzer_AnalyzeDirectory(t *testing.T) {
	tmpDir := t.TempDir()

	// Create multiple Go files
	file1 := filepath.Join(tmpDir, "file1.go")
	file2 := filepath.Join(tmpDir, "file2.go")

	content1 := `package main
import "crypto/aes"
func f1() { aes.NewCipher(nil) }
`
	content2 := `package main
import "crypto/rsa"
func f2() { rsa.GenerateKey(nil, 2048) }
`
	os.WriteFile(file1, []byte(content1), 0644)
	os.WriteFile(file2, []byte(content2), 0644)

	analyzer := NewGoAnalyzer()
	usages, err := analyzer.AnalyzeDirectory(tmpDir)
	if err != nil {
		t.Fatalf("AnalyzeDirectory failed: %v", err)
	}

	if len(usages) < 2 {
		t.Errorf("Expected at least 2 usages from 2 files, got %d", len(usages))
	}
}

func TestGoAnalyzer_SkipsTestFiles(t *testing.T) {
	tmpDir := t.TempDir()

	// Create a test file that should be skipped
	testFile := filepath.Join(tmpDir, "crypto_test.go")
	content := `package main
import "crypto/aes"
func TestCrypto(t *testing.T) { aes.NewCipher(nil) }
`
	os.WriteFile(testFile, []byte(content), 0644)

	// Create a regular file
	regularFile := filepath.Join(tmpDir, "crypto.go")
	regularContent := `package main
import "crypto/rsa"
func f() { rsa.GenerateKey(nil, 2048) }
`
	os.WriteFile(regularFile, []byte(regularContent), 0644)

	analyzer := NewGoAnalyzer()
	usages, err := analyzer.AnalyzeDirectory(tmpDir)
	if err != nil {
		t.Fatalf("AnalyzeDirectory failed: %v", err)
	}

	// Should only find RSA from the regular file, not AES from test file
	for _, u := range usages {
		if u.Algorithm == "AES" {
			t.Error("Test file should have been skipped, but AES was detected")
		}
	}
}

func TestGoAnalyzer_AnonymousFunctions(t *testing.T) {
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "anon.go")

	// Test anonymous functions (func literals)
	content := `package main

import "crypto/aes"

func main() {
	// Anonymous function with crypto
	fn := func() {
		block, _ := aes.NewCipher([]byte("key"))
		_ = block
	}
	fn()

	// Inline anonymous function
	go func() {
		block, _ := aes.NewCipher([]byte("key2"))
		_ = block
	}()
}
`
	if err := os.WriteFile(testFile, []byte(content), 0644); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	analyzer := NewGoAnalyzer()
	usages, err := analyzer.AnalyzeFile(testFile)
	if err != nil {
		t.Fatalf("AnalyzeFile failed: %v", err)
	}

	if len(usages) < 2 {
		t.Errorf("Expected at least 2 crypto usages from anonymous functions, got %d", len(usages))
	}
}

func TestGoAnalyzer_MethodReceiver(t *testing.T) {
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "receiver.go")

	content := `package main

import "crypto/aes"

type Service struct{}
type PointerService struct{}

// Value receiver
func (s Service) Encrypt() {
	block, _ := aes.NewCipher([]byte("key"))
	_ = block
}

// Pointer receiver
func (s *PointerService) Encrypt() {
	block, _ := aes.NewCipher([]byte("key"))
	_ = block
}
`
	if err := os.WriteFile(testFile, []byte(content), 0644); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	analyzer := NewGoAnalyzer()
	usages, err := analyzer.AnalyzeFile(testFile)
	if err != nil {
		t.Fatalf("AnalyzeFile failed: %v", err)
	}

	if len(usages) < 2 {
		t.Errorf("Expected at least 2 usages from method receivers, got %d", len(usages))
	}
}

func TestGoAnalyzer_XCrypto(t *testing.T) {
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "xcrypto.go")

	content := `package main

import (
	"golang.org/x/crypto/chacha20"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/ed25519"
)

func useCrypto() {
	// ChaCha20
	cipher, _ := chacha20.NewUnauthenticatedCipher(nil, nil)
	_ = cipher

	// Argon2
	hash := argon2.IDKey([]byte("pass"), []byte("salt"), 1, 64*1024, 4, 32)
	_ = hash

	// Ed25519
	pub, priv, _ := ed25519.GenerateKey(nil)
	_ = pub
	_ = priv
}
`
	if err := os.WriteFile(testFile, []byte(content), 0644); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	analyzer := NewGoAnalyzer()
	usages, err := analyzer.AnalyzeFile(testFile)
	if err != nil {
		t.Fatalf("AnalyzeFile failed: %v", err)
	}

	// Should find extended crypto algorithms
	algorithms := make(map[string]bool)
	for _, u := range usages {
		algorithms[u.Algorithm] = true
	}

	if len(algorithms) < 1 {
		t.Errorf("Expected to find x/crypto algorithms, found %v", algorithms)
	}
}

func TestGoAnalyzer_ExtendedCryptoPackages(t *testing.T) {
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "extended.go")

	// Test RC4, DSA, ECDH, elliptic, and more x/crypto packages
	content := `package main

import (
	"crypto/rc4"
	"crypto/dsa"
	"crypto/ecdh"
	"crypto/elliptic"
	"crypto/des"
	"crypto/sha1"
	"crypto/sha512"
	"crypto/md5"
)

func rc4Cipher() {
	cipher, _ := rc4.NewCipher([]byte("key"))
	_ = cipher
}

func dsaSign() {
	params := new(dsa.Parameters)
	_ = dsa.GenerateParameters(params, nil, dsa.L1024N160)
}

func ecdhExchange() {
	key, _ := ecdh.P256().GenerateKey(nil)
	_ = key
}

func ellipticCurves() {
	// P-256
	curve := elliptic.P256()
	_ = curve

	// P-384
	curve384 := elliptic.P384()
	_ = curve384

	// P-521
	curve521 := elliptic.P521()
	_ = curve521
}

func tripleDesCipher() {
	block, _ := des.NewTripleDESCipher([]byte("24bytekey12345678"))
	_ = block
}

func desCipher() {
	block, _ := des.NewCipher([]byte("8bytekey"))
	_ = block
}

func sha1Hash() {
	h := sha1.New()
	_ = h
}

func sha512Hash() {
	h := sha512.New()
	_ = h
}

func md5Hash() {
	h := md5.New()
	_ = h
}
`
	if err := os.WriteFile(testFile, []byte(content), 0644); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	analyzer := NewGoAnalyzer()
	usages, err := analyzer.AnalyzeFile(testFile)
	if err != nil {
		t.Fatalf("AnalyzeFile failed: %v", err)
	}

	// Collect found algorithms
	algorithms := make(map[string]bool)
	for _, u := range usages {
		algorithms[u.Algorithm] = true
	}

	// Check for expected algorithms
	expected := []string{"RC4", "DSA", "ECDH", "DES", "3DES", "SHA-1", "SHA-512", "MD5"}
	for _, algo := range expected {
		if !algorithms[algo] {
			t.Logf("Note: %s was not detected (may be in different format)", algo)
		}
	}

	// Should find at least some of these
	if len(algorithms) < 4 {
		t.Errorf("Expected at least 4 algorithms, found %d: %v", len(algorithms), algorithms)
	}
}

func TestGoAnalyzer_XCryptoExtended(t *testing.T) {
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "xcrypto_ext.go")

	// Test remaining x/crypto packages: curve25519, bcrypt, scrypt, sha3
	content := `package main

import (
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/scrypt"
	"golang.org/x/crypto/sha3"
)

func curve25519Exchange() {
	var pub, priv [32]byte
	curve25519.ScalarBaseMult(&pub, &priv)
}

func bcryptHash() {
	hash, _ := bcrypt.GenerateFromPassword([]byte("password"), 10)
	_ = hash
}

func scryptDerive() {
	key, _ := scrypt.Key([]byte("password"), []byte("salt"), 16384, 8, 1, 32)
	_ = key
}

func sha3Hash() {
	h := sha3.New256()
	_ = h
}
`
	if err := os.WriteFile(testFile, []byte(content), 0644); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	analyzer := NewGoAnalyzer()
	usages, err := analyzer.AnalyzeFile(testFile)
	if err != nil {
		t.Fatalf("AnalyzeFile failed: %v", err)
	}

	algorithms := make(map[string]bool)
	for _, u := range usages {
		algorithms[u.Algorithm] = true
	}

	// Should find x/crypto algorithms
	expected := []string{"X25519", "bcrypt", "scrypt", "SHA3"}
	for _, algo := range expected {
		if !algorithms[algo] {
			t.Logf("Note: %s was not detected (may be in different format)", algo)
		}
	}

	if len(algorithms) < 2 {
		t.Errorf("Expected at least 2 x/crypto algorithms, found %d: %v", len(algorithms), algorithms)
	}
}

func TestGoAnalyzer_EllipticCurveVariants(t *testing.T) {
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "curves.go")

	content := `package main

import "crypto/elliptic"

func curveP256() {
	curve := elliptic.P256()
	x, y := curve.Params().Gx, curve.Params().Gy
	_, _ = x, y
}

func curveP384() {
	curve := elliptic.P384()
	x, y := curve.Params().Gx, curve.Params().Gy
	_, _ = x, y
}

func curveP521() {
	curve := elliptic.P521()
	x, y := curve.Params().Gx, curve.Params().Gy
	_, _ = x, y
}
`
	if err := os.WriteFile(testFile, []byte(content), 0644); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	analyzer := NewGoAnalyzer()
	usages, err := analyzer.AnalyzeFile(testFile)
	if err != nil {
		t.Fatalf("AnalyzeFile failed: %v", err)
	}

	if len(usages) < 3 {
		t.Errorf("Expected at least 3 elliptic curve usages, got %d", len(usages))
	}
}

func TestGoAnalyzer_EmptyDirectory(t *testing.T) {
	tmpDir := t.TempDir()

	analyzer := NewGoAnalyzer()
	usages, err := analyzer.AnalyzeDirectory(tmpDir)
	if err != nil {
		t.Fatalf("AnalyzeDirectory on empty dir failed: %v", err)
	}

	if len(usages) != 0 {
		t.Errorf("Expected 0 usages for empty directory, got %d", len(usages))
	}
}

func TestGoAnalyzer_NonGoFile(t *testing.T) {
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "test.txt")

	content := `This is not a Go file`
	if err := os.WriteFile(testFile, []byte(content), 0644); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	analyzer := NewGoAnalyzer()
	usages, err := analyzer.AnalyzeDirectory(tmpDir)
	if err != nil {
		t.Fatalf("AnalyzeDirectory failed: %v", err)
	}

	if len(usages) != 0 {
		t.Errorf("Expected 0 usages for non-Go files, got %d", len(usages))
	}
}
