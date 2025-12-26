// Copyright 2024-2025 CSNP (csnp.org)
// SPDX-License-Identifier: Apache-2.0

package ast

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/csnp/qramm-cryptodeps/pkg/types"
)

func TestJavaAnalyzer_AnalyzeFile(t *testing.T) {
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "CryptoService.java")

	content := `package com.example;

import javax.crypto.Cipher;
import java.security.MessageDigest;
import java.security.KeyPairGenerator;

public class CryptoService {

    public byte[] encrypt(byte[] data, byte[] key) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        return cipher.doFinal(data);
    }

    public byte[] hash(byte[] data) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        return md.digest(data);
    }

    public void generateKeys() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
    }
}
`
	if err := os.WriteFile(testFile, []byte(content), 0644); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	analyzer := NewJavaAnalyzer()
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

	if !algorithms["AES-GCM"] && !algorithms["AES"] {
		t.Error("Expected to find AES")
	}
	if !algorithms["SHA-256"] {
		t.Error("Expected to find SHA-256")
	}
	if !algorithms["RSA"] {
		t.Error("Expected to find RSA")
	}
}

func TestJavaAnalyzer_FunctionContext(t *testing.T) {
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "Service.java")

	content := `package com.example;

import javax.crypto.Cipher;

public class Service {

    public void publicMethod() throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
    }

    private void privateMethod() throws Exception {
        Cipher cipher = Cipher.getInstance("DES");
    }
}
`
	if err := os.WriteFile(testFile, []byte(content), 0644); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	analyzer := NewJavaAnalyzer()
	usages, err := analyzer.AnalyzeFile(testFile)
	if err != nil {
		t.Fatalf("AnalyzeFile failed: %v", err)
	}

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

	if !publicFuncs["Service.publicMethod"] {
		t.Error("publicMethod should be marked as public")
	}
	if publicFuncs["Service.privateMethod"] {
		t.Error("privateMethod should NOT be marked as public")
	}
}

func TestJavaAnalyzer_QuantumRiskClassification(t *testing.T) {
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "Quantum.java")

	content := `package com.example;

import javax.crypto.Cipher;
import java.security.KeyPairGenerator;
import java.security.Signature;

public class Quantum {

    public void vulnerable() throws Exception {
        // RSA - vulnerable to quantum
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");

        // ECDSA - vulnerable to quantum
        Signature sig = Signature.getInstance("SHA256withECDSA");
    }

    public void partialRisk() throws Exception {
        // AES - partial risk (Grover's algorithm)
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
    }
}
`
	if err := os.WriteFile(testFile, []byte(content), 0644); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	analyzer := NewJavaAnalyzer()
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

func TestJavaAnalyzer_SpringSecurityDetection(t *testing.T) {
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "SecurityConfig.java")

	content := `package com.example;

import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

public class SecurityConfig {

    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
`
	if err := os.WriteFile(testFile, []byte(content), 0644); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	analyzer := NewJavaAnalyzer()
	usages, err := analyzer.AnalyzeFile(testFile)
	if err != nil {
		t.Fatalf("AnalyzeFile failed: %v", err)
	}

	foundBcrypt := false
	for _, u := range usages {
		if u.Algorithm == "bcrypt" {
			foundBcrypt = true
		}
	}

	if !foundBcrypt {
		t.Error("Expected to find bcrypt from BCryptPasswordEncoder")
	}
}

func TestJavaAnalyzer_MACDetection(t *testing.T) {
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "MacService.java")

	content := `package com.example;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class MacService {

    public byte[] createHmac(byte[] data, byte[] key) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        SecretKeySpec keySpec = new SecretKeySpec(key, "HmacSHA256");
        mac.init(keySpec);
        return mac.doFinal(data);
    }
}
`
	if err := os.WriteFile(testFile, []byte(content), 0644); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	analyzer := NewJavaAnalyzer()
	usages, err := analyzer.AnalyzeFile(testFile)
	if err != nil {
		t.Fatalf("AnalyzeFile failed: %v", err)
	}

	foundHMAC := false
	for _, u := range usages {
		if u.Algorithm == "HMAC-SHA256" {
			foundHMAC = true
		}
	}

	if !foundHMAC {
		t.Error("Expected to find HMAC-SHA256")
	}
}

func TestJavaAnalyzer_SkipsTestFiles(t *testing.T) {
	tmpDir := t.TempDir()

	// Create test files that should be skipped
	testFile := filepath.Join(tmpDir, "CryptoTest.java")
	testsFile := filepath.Join(tmpDir, "CryptoTests.java")
	content := `package com.example;
import javax.crypto.Cipher;
public class CryptoTest {
    public void test() throws Exception {
        Cipher.getInstance("AES");
    }
}
`
	os.WriteFile(testFile, []byte(content), 0644)
	os.WriteFile(testsFile, []byte(content), 0644)

	// Create regular file
	regularFile := filepath.Join(tmpDir, "Crypto.java")
	regularContent := `package com.example;
import javax.crypto.Cipher;
public class Crypto {
    public void encrypt() throws Exception {
        Cipher.getInstance("DES");
    }
}
`
	os.WriteFile(regularFile, []byte(regularContent), 0644)

	analyzer := NewJavaAnalyzer()
	usages, err := analyzer.AnalyzeDirectory(tmpDir)
	if err != nil {
		t.Fatalf("AnalyzeDirectory failed: %v", err)
	}

	// Should only find DES from regular file
	for _, u := range usages {
		if u.Algorithm == "AES" {
			t.Error("Test files should have been skipped")
		}
	}
}

func TestJavaAnalyzer_AlgorithmInference(t *testing.T) {
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "AesCipherService.java")

	content := `package com.example;

import javax.crypto.Cipher;

public class AesCipherService {

    private String algorithmName = "AES";

    public Cipher getCipher() throws Exception {
        // Algorithm in variable, should be inferred from class name
        return Cipher.getInstance(algorithmName);
    }
}
`
	if err := os.WriteFile(testFile, []byte(content), 0644); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	analyzer := NewJavaAnalyzer()
	usages, err := analyzer.AnalyzeFile(testFile)
	if err != nil {
		t.Fatalf("AnalyzeFile failed: %v", err)
	}

	foundAES := false
	for _, u := range usages {
		if u.Algorithm == "AES" {
			foundAES = true
		}
	}

	if !foundAES {
		t.Error("Expected to infer AES from class name AesCipherService")
	}
}

func TestJavaAnalyzer_KotlinSupport(t *testing.T) {
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "CryptoService.kt")

	content := `package com.example

import javax.crypto.Cipher
import java.security.MessageDigest

class CryptoService {

    fun encrypt(data: ByteArray, key: ByteArray): ByteArray {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        return cipher.doFinal(data)
    }

    fun hash(data: ByteArray): ByteArray {
        val md = MessageDigest.getInstance("SHA-512")
        return md.digest(data)
    }
}
`
	if err := os.WriteFile(testFile, []byte(content), 0644); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	analyzer := NewJavaAnalyzer()
	usages, err := analyzer.AnalyzeFile(testFile)
	if err != nil {
		t.Fatalf("AnalyzeFile failed: %v", err)
	}

	if len(usages) < 2 {
		t.Errorf("Expected at least 2 crypto usages in Kotlin file, got %d", len(usages))
	}

	algorithms := make(map[string]bool)
	for _, u := range usages {
		algorithms[u.Algorithm] = true
	}

	if !algorithms["AES-GCM"] && !algorithms["AES"] {
		t.Error("Expected to find AES in Kotlin file")
	}
	if !algorithms["SHA-512"] {
		t.Error("Expected to find SHA-512 in Kotlin file")
	}
}

func TestJavaAnalyzer_VariableBasedPatterns(t *testing.T) {
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "DynamicCrypto.java")

	content := `package com.example;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;

public class DynamicCrypto {

    public void dynamicCipher(String algorithm) throws Exception {
        // Algorithm passed as variable
        Cipher cipher = Cipher.getInstance(algorithm);
    }

    public void createKey(byte[] keyBytes) {
        SecretKeySpec key = new SecretKeySpec(keyBytes, getAlgorithm());
    }

    public byte[] secureRandomBytes() throws Exception {
        SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
        byte[] bytes = new byte[32];
        random.nextBytes(bytes);
        return bytes;
    }

    private String getAlgorithm() {
        return "AES";
    }
}
`
	if err := os.WriteFile(testFile, []byte(content), 0644); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	analyzer := NewJavaAnalyzer()
	usages, err := analyzer.AnalyzeFile(testFile)
	if err != nil {
		t.Fatalf("AnalyzeFile failed: %v", err)
	}

	// Should detect Cipher.getInstance, SecretKeySpec, and SecureRandom
	if len(usages) < 3 {
		t.Errorf("Expected at least 3 usages from variable-based patterns, got %d", len(usages))
	}

	foundSecureRandom := false
	for _, u := range usages {
		if u.Algorithm == "SecureRandom" {
			foundSecureRandom = true
		}
	}

	if !foundSecureRandom {
		t.Error("Expected to find SecureRandom usage")
	}
}

func TestJavaAnalyzer_SpringEncoders(t *testing.T) {
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "SecurityConfig.java")

	content := `package com.example;

import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.argon2.Argon2PasswordEncoder;
import org.springframework.security.crypto.scrypt.SCryptPasswordEncoder;
import org.springframework.security.crypto.password.Pbkdf2PasswordEncoder;
import org.springframework.security.crypto.password.StandardPasswordEncoder;

public class SecurityConfig {

    public BCryptPasswordEncoder bcryptEncoder() {
        return new BCryptPasswordEncoder();
    }

    public Argon2PasswordEncoder argon2Encoder() {
        return new Argon2PasswordEncoder(16, 32, 1, 65536, 10);
    }

    public SCryptPasswordEncoder scryptEncoder() {
        return new SCryptPasswordEncoder();
    }

    public Pbkdf2PasswordEncoder pbkdf2Encoder() {
        return new Pbkdf2PasswordEncoder();
    }

    public StandardPasswordEncoder standardEncoder() {
        return new StandardPasswordEncoder();
    }
}
`
	if err := os.WriteFile(testFile, []byte(content), 0644); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	analyzer := NewJavaAnalyzer()
	usages, err := analyzer.AnalyzeFile(testFile)
	if err != nil {
		t.Fatalf("AnalyzeFile failed: %v", err)
	}

	algorithms := make(map[string]bool)
	for _, u := range usages {
		algorithms[u.Algorithm] = true
	}

	expected := []string{"bcrypt", "Argon2", "scrypt", "PBKDF2", "SHA-256"}
	for _, alg := range expected {
		if !algorithms[alg] {
			t.Errorf("Expected to find Spring encoder algorithm %s, found: %v", alg, algorithms)
		}
	}
}

func TestJavaAnalyzer_AlgorithmVariants(t *testing.T) {
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "AlgorithmTest.java")

	content := `package com.example;

import javax.crypto.Cipher;
import java.security.MessageDigest;

public class AlgorithmTest {

    // Various algorithm string formats
    public void testAesGcm() throws Exception {
        Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
    }

    public void testRsaOaep() throws Exception {
        Cipher c = Cipher.getInstance("RSA/ECB/OAEPWITHSHA-256ANDMGF1PADDING");
    }

    public void testDesEde() throws Exception {
        Cipher c = Cipher.getInstance("DESede/CBC/PKCS5Padding");
    }

    public void testTripleDes() throws Exception {
        Cipher c = Cipher.getInstance("3DES/CBC/PKCS5Padding");
    }

    public void testBlowfish() throws Exception {
        Cipher c = Cipher.getInstance("Blowfish/CBC/PKCS5Padding");
    }

    public void testTwofish() throws Exception {
        Cipher c = Cipher.getInstance("Twofish/CBC/PKCS5Padding");
    }

    public void testChaCha() throws Exception {
        Cipher c = Cipher.getInstance("ChaCha20-Poly1305");
    }

    public void testSha384() throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-384");
    }

    public void testEcdsa() throws Exception {
        java.security.Signature sig = java.security.Signature.getInstance("SHA256withECDSA");
    }

    public void testDsa() throws Exception {
        java.security.Signature sig = java.security.Signature.getInstance("SHA256withDSA");
    }
}
`
	if err := os.WriteFile(testFile, []byte(content), 0644); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	analyzer := NewJavaAnalyzer()
	usages, err := analyzer.AnalyzeFile(testFile)
	if err != nil {
		t.Fatalf("AnalyzeFile failed: %v", err)
	}

	algorithms := make(map[string]bool)
	for _, u := range usages {
		algorithms[u.Algorithm] = true
	}

	// Should find multiple algorithm variants
	if len(algorithms) < 5 {
		t.Errorf("Expected to find multiple algorithm variants, found: %v", algorithms)
	}
}

func TestJavaAnalyzer_AnalyzeDirectory(t *testing.T) {
	tmpDir := t.TempDir()

	// Create multiple Java files
	file1 := filepath.Join(tmpDir, "Crypto1.java")
	file2 := filepath.Join(tmpDir, "Crypto2.java")
	file3 := filepath.Join(tmpDir, "Crypto3.kt")

	content1 := `package com.example;
import javax.crypto.Cipher;
public class Crypto1 {
    public void test() throws Exception {
        Cipher c = Cipher.getInstance("AES");
    }
}
`
	content2 := `package com.example;
import java.security.MessageDigest;
public class Crypto2 {
    public void test() throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
    }
}
`
	content3 := `package com.example
import java.security.KeyPairGenerator
class Crypto3 {
    fun test() {
        val kpg = KeyPairGenerator.getInstance("RSA")
    }
}
`
	os.WriteFile(file1, []byte(content1), 0644)
	os.WriteFile(file2, []byte(content2), 0644)
	os.WriteFile(file3, []byte(content3), 0644)

	analyzer := NewJavaAnalyzer()
	usages, err := analyzer.AnalyzeDirectory(tmpDir)
	if err != nil {
		t.Fatalf("AnalyzeDirectory failed: %v", err)
	}

	if len(usages) < 3 {
		t.Errorf("Expected at least 3 usages from 3 files, got %d", len(usages))
	}

	algorithms := make(map[string]bool)
	for _, u := range usages {
		algorithms[u.Algorithm] = true
	}

	if !algorithms["AES"] {
		t.Error("Expected to find AES")
	}
	if !algorithms["SHA-256"] {
		t.Error("Expected to find SHA-256")
	}
	if !algorithms["RSA"] {
		t.Error("Expected to find RSA")
	}
}
