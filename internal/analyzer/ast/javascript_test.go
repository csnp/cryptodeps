// Copyright 2024-2025 CSNP (csnp.org)
// SPDX-License-Identifier: Apache-2.0

package ast

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/csnp/qramm-cryptodeps/pkg/types"
)

func TestJavaScriptAnalyzer_AnalyzeFile(t *testing.T) {
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "crypto.js")

	content := `const crypto = require('crypto');

function hashData(data) {
    return crypto.createHash('sha256').update(data).digest('hex');
}

function encrypt(data, key) {
    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
    return cipher.update(data);
}

function generateKeys() {
    return crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
}
`
	if err := os.WriteFile(testFile, []byte(content), 0644); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	analyzer := NewJavaScriptAnalyzer()
	usages, err := analyzer.AnalyzeFile(testFile)
	if err != nil {
		t.Fatalf("AnalyzeFile failed: %v", err)
	}

	if len(usages) < 3 {
		t.Errorf("Expected at least 3 crypto usages, got %d", len(usages))
	}

	// Check algorithms found
	algorithms := make(map[string]bool)
	for _, u := range usages {
		algorithms[u.Algorithm] = true
	}

	if !algorithms["SHA-256"] && !algorithms["sha256"] {
		t.Error("Expected to find SHA-256")
	}
	if !algorithms["AES-256-GCM"] && !algorithms["AES"] {
		t.Error("Expected to find AES")
	}
	if !algorithms["RSA"] {
		t.Error("Expected to find RSA")
	}
}

func TestJavaScriptAnalyzer_BcryptDetection(t *testing.T) {
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "auth.js")

	content := `const bcrypt = require('bcrypt');

async function hashPassword(password) {
    const salt = await bcrypt.genSalt(10);
    return bcrypt.hash(password, salt);
}

async function verifyPassword(password, hash) {
    return bcrypt.compare(password, hash);
}
`
	if err := os.WriteFile(testFile, []byte(content), 0644); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	analyzer := NewJavaScriptAnalyzer()
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
		// bcrypt should be quantum-safe (password hashing)
		if u.QuantumRisk == types.RiskVulnerable {
			t.Error("bcrypt should not be marked as VULNERABLE")
		}
	}
}

func TestJavaScriptAnalyzer_JWTDetection(t *testing.T) {
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "jwt.js")

	content := `const jwt = require('jsonwebtoken');

function createToken(payload, secret) {
    return jwt.sign(payload, secret, { algorithm: 'RS256' });
}

function verifyToken(token, publicKey) {
    return jwt.verify(token, publicKey);
}
`
	if err := os.WriteFile(testFile, []byte(content), 0644); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	analyzer := NewJavaScriptAnalyzer()
	usages, err := analyzer.AnalyzeFile(testFile)
	if err != nil {
		t.Fatalf("AnalyzeFile failed: %v", err)
	}

	if len(usages) < 2 {
		t.Errorf("Expected at least 2 JWT usages, got %d", len(usages))
	}

	// Check that RS256 was detected
	foundRS256 := false
	for _, u := range usages {
		if u.Algorithm == "RS256" {
			foundRS256 = true
			// RS256 uses RSA, should be vulnerable
			if u.QuantumRisk != types.RiskVulnerable {
				t.Errorf("RS256 should be VULNERABLE, got %s", u.QuantumRisk)
			}
		}
	}

	if !foundRS256 {
		t.Error("Expected to find RS256 algorithm")
	}
}

func TestJavaScriptAnalyzer_FunctionContext(t *testing.T) {
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "exports.js")

	content := `const crypto = require('crypto');

export function publicHash(data) {
    return crypto.createHash('sha256').update(data).digest();
}

function privateEncrypt(data) {
    return crypto.createCipheriv('aes-256-cbc', key, iv);
}

class CryptoService {
    hash(data) {
        return crypto.createHash('md5').update(data).digest();
    }
}

module.exports = { publicHash };
`
	if err := os.WriteFile(testFile, []byte(content), 0644); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	analyzer := NewJavaScriptAnalyzer()
	usages, err := analyzer.AnalyzeFile(testFile)
	if err != nil {
		t.Fatalf("AnalyzeFile failed: %v", err)
	}

	// Check that function contexts are captured
	functionNames := make(map[string]bool)
	for _, u := range usages {
		if u.Function != "" {
			functionNames[u.Function] = true
		}
	}

	if len(functionNames) == 0 {
		t.Error("Expected function context to be captured for at least some usages")
	}
}

func TestJavaScriptAnalyzer_CryptoJSDetection(t *testing.T) {
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "cryptojs.js")

	content := `import CryptoJS from 'crypto-js';

function encryptData(data, key) {
    return CryptoJS.AES.encrypt(data, key).toString();
}

function hashData(data) {
    return CryptoJS.SHA256.hash(data).toString();
}

function weakHash(data) {
    return CryptoJS.MD5.hash(data).toString();
}
`
	if err := os.WriteFile(testFile, []byte(content), 0644); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	analyzer := NewJavaScriptAnalyzer()
	usages, err := analyzer.AnalyzeFile(testFile)
	if err != nil {
		t.Fatalf("AnalyzeFile failed: %v", err)
	}

	algorithms := make(map[string]bool)
	for _, u := range usages {
		algorithms[u.Algorithm] = true
	}

	if !algorithms["AES"] {
		t.Error("Expected to find AES from CryptoJS")
	}
	if !algorithms["SHA-256"] {
		t.Error("Expected to find SHA-256 from CryptoJS")
	}
	if !algorithms["MD5"] {
		t.Error("Expected to find MD5 from CryptoJS")
	}
}

func TestJavaScriptAnalyzer_SkipsTestFiles(t *testing.T) {
	tmpDir := t.TempDir()

	// Create test files that should be skipped
	testFile := filepath.Join(tmpDir, "crypto.test.js")
	specFile := filepath.Join(tmpDir, "crypto.spec.js")
	content := `const crypto = require('crypto');
crypto.createHash('sha256');
`
	os.WriteFile(testFile, []byte(content), 0644)
	os.WriteFile(specFile, []byte(content), 0644)

	// Create regular file
	regularFile := filepath.Join(tmpDir, "crypto.js")
	regularContent := `const crypto = require('crypto');
crypto.createHash('md5');
`
	os.WriteFile(regularFile, []byte(regularContent), 0644)

	analyzer := NewJavaScriptAnalyzer()
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

func TestJavaScriptAnalyzer_TypeScriptSupport(t *testing.T) {
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "crypto.ts")

	content := `import * as crypto from 'crypto';

interface HashResult {
    hash: string;
}

function hashData(data: string): HashResult {
    const hash = crypto.createHash('sha512').update(data).digest('hex');
    return { hash };
}
`
	if err := os.WriteFile(testFile, []byte(content), 0644); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	analyzer := NewJavaScriptAnalyzer()
	usages, err := analyzer.AnalyzeFile(testFile)
	if err != nil {
		t.Fatalf("AnalyzeFile failed: %v", err)
	}

	if len(usages) == 0 {
		t.Error("Expected to find crypto usage in TypeScript file")
	}

	found := false
	for _, u := range usages {
		if u.Algorithm == "SHA-512" {
			found = true
		}
	}
	if !found {
		t.Error("Expected to find SHA-512 in TypeScript file")
	}
}

func TestJavaScriptAnalyzer_NodeForgeDetection(t *testing.T) {
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "forge.js")

	// Use the correct forge pattern: forge.pki.rsa, forge.cipher.aes, forge.md.md5, etc.
	content := `const forge = require('node-forge');

function encryptRSA(data) {
    const keypair = forge.pki.rsa.generateKeyPair({ bits: 2048 });
    return keypair.publicKey.encrypt(data);
}

function encryptAES(data, key) {
    const cipher = forge.cipher.aes.createEncryptionCipher(key);
    return cipher.update(data);
}

function encryptDES(data, key) {
    const cipher = forge.cipher.des.createEncryptionCipher(key);
    return cipher.update(data);
}

function hashMD5(data) {
    const md = forge.md.md5.create();
    md.update(data);
    return md.digest().toHex();
}

function hashSHA1(data) {
    const md = forge.md.sha1.create();
    md.update(data);
    return md.digest().toHex();
}

function hashSHA256(data) {
    const md = forge.md.sha256.create();
    md.update(data);
    return md.digest().toHex();
}

function hashSHA512(data) {
    const md = forge.md.sha512.create();
    md.update(data);
    return md.digest().toHex();
}
`
	if err := os.WriteFile(testFile, []byte(content), 0644); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	analyzer := NewJavaScriptAnalyzer()
	usages, err := analyzer.AnalyzeFile(testFile)
	if err != nil {
		t.Fatalf("AnalyzeFile failed: %v", err)
	}

	algorithms := make(map[string]bool)
	for _, u := range usages {
		algorithms[u.Algorithm] = true
	}

	expected := []string{"RSA", "AES", "DES", "MD5", "SHA-1", "SHA-256", "SHA-512"}
	for _, alg := range expected {
		if !algorithms[alg] {
			t.Errorf("Expected to find node-forge algorithm %s, found: %v", alg, algorithms)
		}
	}
}

func TestJavaScriptAnalyzer_CryptoJSVariants(t *testing.T) {
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "cryptojs_all.js")

	content := `import CryptoJS from 'crypto-js';

function test_algorithms() {
    // Encryption algorithms
    const aes = CryptoJS.AES.encrypt(data, key);
    const des = CryptoJS.DES.encrypt(data, key);
    const tripledes = CryptoJS.TripleDES.encrypt(data, key);
    const rabbit = CryptoJS.Rabbit.encrypt(data, key);
    const rc4 = CryptoJS.RC4.encrypt(data, key);

    // Hash algorithms
    const md5 = CryptoJS.MD5(data);
    const sha1 = CryptoJS.SHA1(data);
    const sha256 = CryptoJS.SHA256(data);
    const sha512 = CryptoJS.SHA512(data);
    const sha3 = CryptoJS.SHA3(data);
    const ripemd160 = CryptoJS.RIPEMD160(data);

    // HMAC
    const hmacmd5 = CryptoJS.HmacMD5(data, key);
    const hmacsha1 = CryptoJS.HmacSHA1(data, key);
    const hmacsha256 = CryptoJS.HmacSHA256(data, key);
    const hmacsha512 = CryptoJS.HmacSHA512(data, key);

    // KDF
    const pbkdf2 = CryptoJS.PBKDF2(password, salt);

    return { aes, des, tripledes, rabbit, rc4, md5, sha1, sha256, sha512, sha3, ripemd160 };
}
`
	if err := os.WriteFile(testFile, []byte(content), 0644); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	analyzer := NewJavaScriptAnalyzer()
	usages, err := analyzer.AnalyzeFile(testFile)
	if err != nil {
		t.Fatalf("AnalyzeFile failed: %v", err)
	}

	algorithms := make(map[string]bool)
	for _, u := range usages {
		algorithms[u.Algorithm] = true
	}

	// At minimum we should find several CryptoJS algorithms
	if len(algorithms) < 5 {
		t.Errorf("Expected to find multiple CryptoJS algorithms, found: %v", algorithms)
	}
}

func TestJavaScriptAnalyzer_CryptoCallPatterns(t *testing.T) {
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "crypto_calls.js")

	content := `const crypto = require('crypto');

// Various hash algorithms
function hashSHA256(data) {
    return crypto.createHash('sha256').update(data).digest();
}

function hashSHA384(data) {
    return crypto.createHash('sha384').update(data).digest();
}

function hashSHA512(data) {
    return crypto.createHash('sha512').update(data).digest();
}

function hashMD5(data) {
    return crypto.createHash('md5').update(data).digest();
}

// HMAC functions
function hmacSHA256(data, key) {
    return crypto.createHmac('sha256', key).update(data).digest();
}

// Key generation
function generateRSAKeys() {
    return crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
}

function generateECKeys() {
    return crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
}

function generateEd25519Keys() {
    return crypto.generateKeyPairSync('ed25519');
}

// Sign/verify
function signData(data, privateKey) {
    return crypto.createSign('SHA256').update(data).sign(privateKey);
}

function verifyData(data, signature, publicKey) {
    return crypto.createVerify('SHA256').update(data).verify(publicKey, signature);
}

// KDF
function deriveWithScrypt(password, salt) {
    return crypto.scryptSync(password, salt, 32);
}

function deriveWithPBKDF2(password, salt) {
    return crypto.pbkdf2Sync(password, salt, 100000, 32, 'sha256');
}

// Cipher
function encryptAES(data, key) {
    return crypto.createCipheriv('aes-256-cbc', key, iv).update(data);
}
`
	if err := os.WriteFile(testFile, []byte(content), 0644); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	analyzer := NewJavaScriptAnalyzer()
	usages, err := analyzer.AnalyzeFile(testFile)
	if err != nil {
		t.Fatalf("AnalyzeFile failed: %v", err)
	}

	algorithms := make(map[string]bool)
	for _, u := range usages {
		algorithms[u.Algorithm] = true
	}

	expected := []string{"SHA-256", "SHA-384", "SHA-512", "MD5", "RSA", "ECDSA", "Ed25519", "scrypt", "PBKDF2", "AES-256-CBC"}
	foundCount := 0
	for _, alg := range expected {
		if algorithms[alg] {
			foundCount++
		}
	}

	if foundCount < 5 {
		t.Errorf("Expected to find multiple crypto algorithms, found: %v", algorithms)
	}
}

func TestJavaScriptAnalyzer_JWTVariants(t *testing.T) {
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "jwt_algs.js")

	content := `const jwt = require('jsonwebtoken');

function signRS256(payload, key) {
    return jwt.sign(payload, key, { algorithm: 'RS256' });
}

function signRS384(payload, key) {
    return jwt.sign(payload, key, { algorithm: 'RS384' });
}

function signRS512(payload, key) {
    return jwt.sign(payload, key, { algorithm: 'RS512' });
}

function signES256(payload, key) {
    return jwt.sign(payload, key, { algorithm: 'ES256' });
}

function signES384(payload, key) {
    return jwt.sign(payload, key, { algorithm: 'ES384' });
}

function signPS256(payload, key) {
    return jwt.sign(payload, key, { algorithm: 'PS256' });
}

function signHS256(payload, key) {
    return jwt.sign(payload, key, { algorithm: 'HS256' });
}

function signEdDSA(payload, key) {
    return jwt.sign(payload, key, { algorithm: 'EdDSA' });
}
`
	if err := os.WriteFile(testFile, []byte(content), 0644); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	analyzer := NewJavaScriptAnalyzer()
	usages, err := analyzer.AnalyzeFile(testFile)
	if err != nil {
		t.Fatalf("AnalyzeFile failed: %v", err)
	}

	algorithms := make(map[string]bool)
	for _, u := range usages {
		algorithms[u.Algorithm] = true
	}

	expected := []string{"RS256", "RS384", "RS512", "ES256", "ES384", "PS256", "HS256", "EdDSA"}
	for _, alg := range expected {
		if !algorithms[alg] {
			t.Errorf("Expected to find JWT algorithm %s, found: %v", alg, algorithms)
		}
	}
}

func TestJavaScriptAnalyzer_ESModuleImports(t *testing.T) {
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "esmodule.js")

	content := `import crypto from 'crypto';
import bcrypt from 'bcryptjs';
import { sign, verify } from 'jsonwebtoken';

async function hashWithBcrypt(password) {
    return await bcrypt.hash(password, 10);
}

function createToken(payload) {
    return sign(payload, secret, { algorithm: 'ES256' });
}
`
	if err := os.WriteFile(testFile, []byte(content), 0644); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	analyzer := NewJavaScriptAnalyzer()
	usages, err := analyzer.AnalyzeFile(testFile)
	if err != nil {
		t.Fatalf("AnalyzeFile failed: %v", err)
	}

	algorithms := make(map[string]bool)
	for _, u := range usages {
		algorithms[u.Algorithm] = true
	}

	if !algorithms["bcrypt"] {
		t.Error("Expected to find bcrypt from ES module import")
	}
}

func TestJavaScriptAnalyzer_ExportPatterns(t *testing.T) {
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "exports.mjs")

	content := `import crypto from 'crypto';

export function hashData(data) {
    return crypto.createHash('sha256').update(data).digest();
}

export const encrypt = (data, key) => {
    return crypto.createCipheriv('aes-256-gcm', key, iv).update(data);
};

export default {
    hash: hashData,
    encrypt
};

module.exports = { hashData, encrypt };
`
	if err := os.WriteFile(testFile, []byte(content), 0644); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	analyzer := NewJavaScriptAnalyzer()
	usages, err := analyzer.AnalyzeFile(testFile)
	if err != nil {
		t.Fatalf("AnalyzeFile failed: %v", err)
	}

	// Check that exports are detected
	exportedFuncs := make(map[string]bool)
	for _, u := range usages {
		if u.InExported {
			exportedFuncs[u.Function] = true
		}
	}

	if len(usages) == 0 {
		t.Error("Expected to find crypto usages in exported functions")
	}
}

func TestJavaScriptAnalyzer_IsCryptoPackage(t *testing.T) {
	analyzer := NewJavaScriptAnalyzer()

	tests := []struct {
		pkg  string
		want bool
	}{
		{"crypto", true},
		{"crypto-js", true},
		{"bcrypt", true},
		{"bcryptjs", true},
		{"jsonwebtoken", true},
		{"jose", true},
		{"node-forge", true},
		{"tweetnacl", true},
		{"libsodium", true},
		{"sodium-native", true},
		{"argon2", true},
		{"scrypt", true},
		{"pbkdf2", true},
		{"elliptic", true},
		{"@noble/curves", true},
		{"@noble/hashes", true},
		{"express", false},
		{"lodash", false},
		{"axios", false},
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

func TestJavaScriptAnalyzer_AnalyzeDirectory(t *testing.T) {
	tmpDir := t.TempDir()

	// Create JS files
	file1 := filepath.Join(tmpDir, "crypto1.js")
	file2 := filepath.Join(tmpDir, "crypto2.ts")
	file3 := filepath.Join(tmpDir, "crypto3.mjs")

	content1 := `const crypto = require('crypto');
crypto.createHash('sha256');
`
	content2 := `import * as crypto from 'crypto';
crypto.createHash('sha512');
`
	content3 := `import bcrypt from 'bcrypt';
bcrypt.hash(password, 10);
`
	os.WriteFile(file1, []byte(content1), 0644)
	os.WriteFile(file2, []byte(content2), 0644)
	os.WriteFile(file3, []byte(content3), 0644)

	analyzer := NewJavaScriptAnalyzer()
	usages, err := analyzer.AnalyzeDirectory(tmpDir)
	if err != nil {
		t.Fatalf("AnalyzeDirectory failed: %v", err)
	}

	if len(usages) < 3 {
		t.Errorf("Expected at least 3 usages from 3 files, got %d", len(usages))
	}
}
