// Copyright 2024-2025 CSNP (csnp.org)
// SPDX-License-Identifier: Apache-2.0

package ast

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/csnp/qramm-cryptodeps/pkg/types"
)

func TestPythonAnalyzer_AnalyzeFile(t *testing.T) {
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "crypto.py")

	content := `import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
from cryptography.hazmat.primitives.asymmetric import RSA

def hash_data(data):
    return hashlib.sha256(data).hexdigest()

def encrypt_data(data, key):
    cipher = Cipher(algorithms.AES(key), mode)
    return cipher.encryptor().update(data)

def generate_keys():
    # RSA key generation
    private_key = RSA.generate(2048)
    return private_key
`
	if err := os.WriteFile(testFile, []byte(content), 0644); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	analyzer := NewPythonAnalyzer()
	usages, err := analyzer.AnalyzeFile(testFile)
	if err != nil {
		t.Fatalf("AnalyzeFile failed: %v", err)
	}

	if len(usages) < 3 {
		t.Errorf("Expected at least 3 crypto usages, got %d", len(usages))
	}

	algorithms := make(map[string]bool)
	for _, u := range usages {
		algorithms[u.Algorithm] = true
	}

	if !algorithms["SHA-256"] {
		t.Error("Expected to find SHA-256")
	}
	if !algorithms["AES"] {
		t.Error("Expected to find AES")
	}
	if !algorithms["RSA"] {
		t.Error("Expected to find RSA")
	}
}

func TestPythonAnalyzer_BcryptDetection(t *testing.T) {
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "auth.py")

	content := `import bcrypt

def hash_password(password):
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode(), salt)

def verify_password(password, hashed):
    return bcrypt.checkpw(password.encode(), hashed)
`
	if err := os.WriteFile(testFile, []byte(content), 0644); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	analyzer := NewPythonAnalyzer()
	usages, err := analyzer.AnalyzeFile(testFile)
	if err != nil {
		t.Fatalf("AnalyzeFile failed: %v", err)
	}

	if len(usages) < 2 {
		t.Errorf("Expected at least 2 bcrypt usages, got %d", len(usages))
	}

	for _, u := range usages {
		if u.Algorithm != "bcrypt" {
			t.Errorf("Expected bcrypt algorithm, got %s", u.Algorithm)
		}
	}
}

func TestPythonAnalyzer_JWTDetection(t *testing.T) {
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "jwt_auth.py")

	content := `import jwt

def create_token(payload, secret):
    return jwt.encode(payload, secret, algorithm='RS256')

def verify_token(token, public_key):
    return jwt.decode(token, public_key, algorithms=['RS256'])
`
	if err := os.WriteFile(testFile, []byte(content), 0644); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	analyzer := NewPythonAnalyzer()
	usages, err := analyzer.AnalyzeFile(testFile)
	if err != nil {
		t.Fatalf("AnalyzeFile failed: %v", err)
	}

	if len(usages) < 2 {
		t.Errorf("Expected at least 2 JWT usages, got %d", len(usages))
	}

	foundRS256 := false
	for _, u := range usages {
		if u.Algorithm == "RS256" {
			foundRS256 = true
			if u.QuantumRisk != types.RiskVulnerable {
				t.Errorf("RS256 should be VULNERABLE, got %s", u.QuantumRisk)
			}
		}
	}

	if !foundRS256 {
		t.Error("Expected to find RS256")
	}
}

func TestPythonAnalyzer_FunctionContext(t *testing.T) {
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "service.py")

	content := `import hashlib

def public_function():
    return hashlib.sha256(b"data").hexdigest()

def _private_function():
    return hashlib.md5(b"data").hexdigest()

class CryptoService:
    def public_method(self, data):
        return hashlib.sha512(data).hexdigest()

    def _private_method(self, data):
        return hashlib.sha1(data).hexdigest()
`
	if err := os.WriteFile(testFile, []byte(content), 0644); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	analyzer := NewPythonAnalyzer()
	usages, err := analyzer.AnalyzeFile(testFile)
	if err != nil {
		t.Fatalf("AnalyzeFile failed: %v", err)
	}

	// Check function contexts
	publicFuncs := make(map[string]bool)
	privateFuncs := make(map[string]bool)
	for _, u := range usages {
		if u.Function != "" {
			if u.InExported {
				publicFuncs[u.Function] = true
			} else {
				privateFuncs[u.Function] = true
			}
		}
	}

	// public_function should be marked as public (InExported = true)
	if !publicFuncs["public_function"] {
		t.Error("public_function should be marked as public")
	}

	// _private_function should be private (InExported = false)
	if publicFuncs["_private_function"] {
		t.Error("_private_function should NOT be marked as public")
	}
}

func TestPythonAnalyzer_ClassMethodContext(t *testing.T) {
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "class_test.py")

	content := `import hashlib

class HashService:
    def hash(self, data):
        return hashlib.sha256(data).hexdigest()
`
	if err := os.WriteFile(testFile, []byte(content), 0644); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	analyzer := NewPythonAnalyzer()
	usages, err := analyzer.AnalyzeFile(testFile)
	if err != nil {
		t.Fatalf("AnalyzeFile failed: %v", err)
	}

	if len(usages) == 0 {
		t.Fatal("Expected at least 1 usage")
	}

	// Check that class.method format is captured
	found := false
	for _, u := range usages {
		if u.Function == "HashService.hash" {
			found = true
		}
	}

	if !found {
		t.Error("Expected function to be 'HashService.hash'")
	}
}

func TestPythonAnalyzer_HMACDetection(t *testing.T) {
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "hmac_test.py")

	content := `import hmac
import hashlib

def create_signature(key, message):
    return hmac.new(key, message, hashlib.sha256).hexdigest()

def verify_signature(key, message, signature):
    expected = hmac.new(key, message, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature)
`
	if err := os.WriteFile(testFile, []byte(content), 0644); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	analyzer := NewPythonAnalyzer()
	usages, err := analyzer.AnalyzeFile(testFile)
	if err != nil {
		t.Fatalf("AnalyzeFile failed: %v", err)
	}

	foundHMAC := false
	for _, u := range usages {
		if u.Algorithm == "HMAC-SHA256" || u.Algorithm == "HMAC" {
			foundHMAC = true
		}
	}

	if !foundHMAC {
		t.Error("Expected to find HMAC usage")
	}
}

func TestPythonAnalyzer_SkipsTestFiles(t *testing.T) {
	tmpDir := t.TempDir()

	// Create test files that should be skipped
	testFile := filepath.Join(tmpDir, "test_crypto.py")
	conftest := filepath.Join(tmpDir, "conftest.py")
	content := `import hashlib
hashlib.sha256(b"test")
`
	os.WriteFile(testFile, []byte(content), 0644)
	os.WriteFile(conftest, []byte(content), 0644)

	// Create regular file
	regularFile := filepath.Join(tmpDir, "crypto.py")
	regularContent := `import hashlib
hashlib.md5(b"data")
`
	os.WriteFile(regularFile, []byte(regularContent), 0644)

	analyzer := NewPythonAnalyzer()
	usages, err := analyzer.AnalyzeDirectory(tmpDir)
	if err != nil {
		t.Fatalf("AnalyzeDirectory failed: %v", err)
	}

	// Should only find MD5 from regular file
	for _, u := range usages {
		if u.Algorithm == "SHA-256" {
			t.Error("Test files should have been skipped")
		}
	}
}

func TestPythonAnalyzer_CryptographyLibrary(t *testing.T) {
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "crypto_lib.py")

	content := `from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

def encrypt(key, data):
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv))
    return cipher.encryptor().update(data)

def hash_data(data):
    digest = hashes.Hash(hashes.SHA512())
    digest.update(data)
    return digest.finalize()

def generate_ec_key():
    return ec.generate_private_key(ec.SECP384R1())
`
	if err := os.WriteFile(testFile, []byte(content), 0644); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	analyzer := NewPythonAnalyzer()
	usages, err := analyzer.AnalyzeFile(testFile)
	if err != nil {
		t.Fatalf("AnalyzeFile failed: %v", err)
	}

	algorithms := make(map[string]bool)
	for _, u := range usages {
		algorithms[u.Algorithm] = true
	}

	if !algorithms["AES"] {
		t.Error("Expected to find AES")
	}
	if !algorithms["SHA-512"] {
		t.Error("Expected to find SHA-512")
	}
}

func TestPythonAnalyzer_IndentationTracking(t *testing.T) {
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "indent.py")

	content := `import hashlib

class Service:
    def method1(self):
        hashlib.sha256(b"in method1")

    def method2(self):
        hashlib.md5(b"in method2")

def standalone():
    hashlib.sha512(b"standalone")
`
	if err := os.WriteFile(testFile, []byte(content), 0644); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	analyzer := NewPythonAnalyzer()
	usages, err := analyzer.AnalyzeFile(testFile)
	if err != nil {
		t.Fatalf("AnalyzeFile failed: %v", err)
	}

	// Verify each usage has the correct function context
	funcForAlg := make(map[string]string)
	for _, u := range usages {
		funcForAlg[u.Algorithm] = u.Function
	}

	if funcForAlg["SHA-256"] != "Service.method1" {
		t.Errorf("SHA-256 should be in Service.method1, got %s", funcForAlg["SHA-256"])
	}
	if funcForAlg["MD5"] != "Service.method2" {
		t.Errorf("MD5 should be in Service.method2, got %s", funcForAlg["MD5"])
	}
	if funcForAlg["SHA-512"] != "standalone" {
		t.Errorf("SHA-512 should be in standalone, got %s", funcForAlg["SHA-512"])
	}
}

func TestPythonAnalyzer_PyCryptodomePatterns(t *testing.T) {
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "pycrypto.py")

	content := `from Crypto.Cipher import AES, DES, DES3
from Crypto.Hash import SHA256, SHA512, MD5
from Crypto.PublicKey import RSA, DSA, ECC
from Crypto.Signature import pkcs1_15, pss

def use_aes():
    cipher = Cipher.AES.new(key, AES.MODE_CBC)
    return cipher

def use_des():
    cipher = Cipher.DES.new(key, DES.MODE_CBC)
    return cipher

def use_des3():
    cipher = Cipher.DES3.new(key, DES3.MODE_CBC)
    return cipher

def use_sha256():
    h = Hash.SHA256.new()
    return h

def use_sha512():
    h = Hash.SHA512.new()
    return h

def use_md5():
    h = Hash.MD5.new()
    return h

def use_rsa():
    key = PublicKey.RSA.generate(2048)
    return key

def use_dsa():
    key = PublicKey.DSA.generate(2048)
    return key

def use_ecc():
    key = PublicKey.ECC.generate(curve='P-256')
    return key
`
	if err := os.WriteFile(testFile, []byte(content), 0644); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	analyzer := NewPythonAnalyzer()
	usages, err := analyzer.AnalyzeFile(testFile)
	if err != nil {
		t.Fatalf("AnalyzeFile failed: %v", err)
	}

	algorithms := make(map[string]bool)
	for _, u := range usages {
		algorithms[u.Algorithm] = true
	}

	expected := []string{"AES", "DES", "3DES", "SHA-256", "SHA-512", "MD5", "RSA", "DSA", "ECDSA"}
	for _, alg := range expected {
		if !algorithms[alg] {
			t.Errorf("Expected to find %s", alg)
		}
	}
}

func TestPythonAnalyzer_PasslibPatterns(t *testing.T) {
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "passlib_test.py")

	content := `from passlib.hash import bcrypt, argon2, pbkdf2_sha256

def hash_bcrypt():
    return passlib.hash.bcrypt.hash("password")

def hash_argon2():
    return passlib.hash.argon2.hash("password")

def hash_pbkdf2():
    return passlib.hash.pbkdf2.hash("password")

def hash_sha256_crypt():
    return passlib.hash.sha256_crypt.hash("password")

def hash_sha512_crypt():
    return passlib.hash.sha512_crypt.hash("password")
`
	if err := os.WriteFile(testFile, []byte(content), 0644); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	analyzer := NewPythonAnalyzer()
	usages, err := analyzer.AnalyzeFile(testFile)
	if err != nil {
		t.Fatalf("AnalyzeFile failed: %v", err)
	}

	algorithms := make(map[string]bool)
	for _, u := range usages {
		algorithms[u.Algorithm] = true
	}

	expected := []string{"bcrypt", "Argon2", "PBKDF2", "SHA-256", "SHA-512"}
	for _, alg := range expected {
		if !algorithms[alg] {
			t.Errorf("Expected to find passlib algorithm %s", alg)
		}
	}
}

func TestPythonAnalyzer_NaClPatterns(t *testing.T) {
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "nacl_test.py")

	// Use correct NaCl pattern: nacl.secret.SecretBox, nacl.public.Box, nacl.signing.SigningKey
	content := `from nacl.secret import SecretBox
from nacl.public import Box
from nacl.signing import SigningKey

def use_secretbox():
    box = nacl.secret.SecretBox(key)
    return box

def use_box():
    box = nacl.public.Box(private_key, public_key)
    return box

def use_signing():
    key = nacl.signing.SigningKey.generate()
    return key

def use_verify():
    key = nacl.signing.VerifyKey(public_key)
    return key
`
	if err := os.WriteFile(testFile, []byte(content), 0644); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	analyzer := NewPythonAnalyzer()
	usages, err := analyzer.AnalyzeFile(testFile)
	if err != nil {
		t.Fatalf("AnalyzeFile failed: %v", err)
	}

	algorithms := make(map[string]bool)
	for _, u := range usages {
		algorithms[u.Algorithm] = true
	}

	// Should find at least one NaCl algorithm
	expectedAny := []string{"XSalsa20", "X25519", "Ed25519"}
	foundCount := 0
	for _, alg := range expectedAny {
		if algorithms[alg] {
			foundCount++
		}
	}
	if foundCount == 0 {
		t.Errorf("Expected to find at least one NaCl algorithm, found: %v", algorithms)
	}
}

func TestPythonAnalyzer_JWTAlgorithmVariants(t *testing.T) {
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "jwt_algs.py")

	content := `import jwt

def use_rs256():
    return jwt.encode(payload, key, algorithm="RS256")

def use_es256():
    return jwt.encode(payload, key, algorithm="ES256")

def use_hs256():
    return jwt.encode(payload, key, algorithm="HS256")

def use_default():
    return jwt.encode(payload, key)
`
	if err := os.WriteFile(testFile, []byte(content), 0644); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	analyzer := NewPythonAnalyzer()
	usages, err := analyzer.AnalyzeFile(testFile)
	if err != nil {
		t.Fatalf("AnalyzeFile failed: %v", err)
	}

	algorithms := make(map[string]bool)
	for _, u := range usages {
		algorithms[u.Algorithm] = true
	}

	expected := []string{"RS256", "ES256", "HS256"}
	for _, alg := range expected {
		if !algorithms[alg] {
			t.Errorf("Expected to find JWT algorithm %s, found: %v", alg, algorithms)
		}
	}
}

func TestPythonAnalyzer_HashlibVariants(t *testing.T) {
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "hashlib_all.py")

	content := `import hashlib

def test_all_hashes():
    h1 = hashlib.sha256(b"data")
    h2 = hashlib.sha384(b"data")
    h3 = hashlib.sha512(b"data")
    h4 = hashlib.sha1(b"data")
    h5 = hashlib.md5(b"data")
    h6 = hashlib.blake2b(b"data")
    h7 = hashlib.blake2s(b"data")
    h8 = hashlib.sha3_256(b"data")
    h9 = hashlib.sha3_512(b"data")
    h10 = hashlib.new("sha256", b"data")
    return h1, h2, h3, h4, h5, h6, h7, h8, h9, h10
`
	if err := os.WriteFile(testFile, []byte(content), 0644); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	analyzer := NewPythonAnalyzer()
	usages, err := analyzer.AnalyzeFile(testFile)
	if err != nil {
		t.Fatalf("AnalyzeFile failed: %v", err)
	}

	algorithms := make(map[string]bool)
	for _, u := range usages {
		algorithms[u.Algorithm] = true
	}

	expected := []string{"SHA-256", "SHA-384", "SHA-512", "SHA-1", "MD5", "BLAKE2b", "BLAKE2s", "SHA3-256", "SHA3-512"}
	for _, alg := range expected {
		if !algorithms[alg] {
			t.Errorf("Expected to find hashlib algorithm %s", alg)
		}
	}
}

func TestPythonAnalyzer_IsCryptoPackage(t *testing.T) {
	analyzer := NewPythonAnalyzer()

	tests := []struct {
		pkg  string
		want bool
	}{
		{"cryptography", true},
		{"Crypto", true},
		{"Cryptodome", true},
		{"hashlib", true},
		{"hmac", true},
		{"bcrypt", true},
		{"argon2", true},
		{"nacl", true},
		{"PyNaCl", true},
		{"jwt", true},
		{"passlib", true},
		{"ssl", true},
		{"secrets", true},
		{"crypt", true},
		{"gnupg", true},
		{"pgp", true},
		{"os", false},
		{"sys", false},
		{"json", false},
		{"cryptography.hazmat", true},
		{"Crypto.Cipher", true},
		{"ssl.SSLContext", true},
	}

	for _, tt := range tests {
		t.Run(tt.pkg, func(t *testing.T) {
			got := analyzer.isCryptoPackage(tt.pkg)
			if got != tt.want {
				t.Errorf("isCryptoPackage(%q) = %v, want %v", tt.pkg, got, tt.want)
			}
		})
	}
}

func TestPythonAnalyzer_HMACVariants(t *testing.T) {
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "hmac_all.py")

	content := `import hmac
import hashlib

def hmac_sha256():
    return hmac.new(key, msg, hashlib.sha256)

def hmac_sha512():
    return hmac.new(key, msg, hashlib.sha512)

def hmac_sha1():
    return hmac.new(key, msg, hashlib.sha1)

def hmac_md5():
    return hmac.new(key, msg, hashlib.md5)

def hmac_compare():
    return hmac.compare_digest(a, b)
`
	if err := os.WriteFile(testFile, []byte(content), 0644); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	analyzer := NewPythonAnalyzer()
	usages, err := analyzer.AnalyzeFile(testFile)
	if err != nil {
		t.Fatalf("AnalyzeFile failed: %v", err)
	}

	algorithms := make(map[string]bool)
	for _, u := range usages {
		algorithms[u.Algorithm] = true
	}

	expected := []string{"HMAC-SHA256", "HMAC-SHA512", "HMAC-SHA1", "HMAC-MD5", "HMAC"}
	foundCount := 0
	for _, alg := range expected {
		if algorithms[alg] {
			foundCount++
		}
	}
	if foundCount < 3 {
		t.Errorf("Expected to find multiple HMAC algorithms, found: %v", algorithms)
	}
}
