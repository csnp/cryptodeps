// Copyright 2024-2025 CSNP (csnp.org)
// SPDX-License-Identifier: Apache-2.0

// Package main demonstrates a typical application with mixed quantum vulnerability levels.
// This example is intentionally designed to showcase CryptoDeps analysis capabilities.
//
// Run: cryptodeps analyze examples/vulnerable-demo
package main

import (
	"crypto/rand"
	"fmt"
	"log"
	"time"

	"github.com/cloudflare/circl/kem/mlkem/mlkem768"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/ed25519"
)

func main() {
	fmt.Println("=== CryptoDeps Demo: Quantum Vulnerability Examples ===\n")

	// VULNERABLE: RSA-based JWT signing (broken by Shor's algorithm)
	demoJWTSigning()

	// VULNERABLE: Ed25519 signatures (broken by Shor's algorithm)
	demoEd25519()

	// SAFE: Argon2 password hashing (quantum resistant)
	demoArgon2()

	// SAFE: bcrypt password hashing (quantum resistant)
	demoBcrypt()

	// SAFE: ChaCha20-Poly1305 symmetric encryption (Grover halves security, but still safe with 256-bit keys)
	demoChaChaPoly()

	// SAFE: ML-KEM post-quantum key encapsulation (NIST FIPS 203)
	demoMLKEM()

	fmt.Println("\n=== Analysis Complete ===")
	fmt.Println("Run 'cryptodeps analyze examples/vulnerable-demo' to see the quantum risk assessment")
}

// demoJWTSigning demonstrates RS256 JWT signing - VULNERABLE to quantum attacks
func demoJWTSigning() {
	fmt.Println("1. JWT with RS256 (VULNERABLE)")
	fmt.Println("   - RSA signatures are broken by Shor's algorithm")
	fmt.Println("   - Remediation: Use symmetric HS256/HS512 or wait for PQ-JWT standards")

	// Create a token with claims
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub":  "user123",
		"name": "Demo User",
		"exp":  time.Now().Add(time.Hour).Unix(),
	})

	// In real usage, this would use RSA keys
	tokenString, _ := token.SignedString([]byte("demo-secret-key"))
	fmt.Printf("   Token: %s...\n\n", tokenString[:50])
}

// demoEd25519 demonstrates Ed25519 signatures - VULNERABLE to quantum attacks
func demoEd25519() {
	fmt.Println("2. Ed25519 Digital Signatures (VULNERABLE)")
	fmt.Println("   - Elliptic curve signatures are broken by Shor's algorithm")
	fmt.Println("   - Remediation: Migrate to ML-DSA (FIPS 204)")

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		log.Fatal(err)
	}

	message := []byte("Hello, quantum world!")
	signature := ed25519.Sign(priv, message)

	valid := ed25519.Verify(pub, message, signature)
	fmt.Printf("   Signature valid: %v\n\n", valid)
}

// demoArgon2 demonstrates Argon2 password hashing - SAFE from quantum attacks
func demoArgon2() {
	fmt.Println("3. Argon2 Password Hashing (SAFE)")
	fmt.Println("   - Memory-hard function resistant to quantum speedups")
	fmt.Println("   - Grover's algorithm provides limited advantage")

	password := []byte("secure-password-123")
	salt := make([]byte, 16)
	rand.Read(salt)

	hash := argon2.IDKey(password, salt, 1, 64*1024, 4, 32)
	fmt.Printf("   Hash: %x...\n\n", hash[:16])
}

// demoBcrypt demonstrates bcrypt password hashing - SAFE from quantum attacks
func demoBcrypt() {
	fmt.Println("4. bcrypt Password Hashing (SAFE)")
	fmt.Println("   - Cost-based hashing resistant to quantum speedups")

	password := []byte("another-secure-password")
	hash, err := bcrypt.GenerateFromPassword(password, bcrypt.DefaultCost)
	if err != nil {
		log.Fatal(err)
	}

	err = bcrypt.CompareHashAndPassword(hash, password)
	fmt.Printf("   Password verified: %v\n\n", err == nil)
}

// demoChaChaPoly demonstrates ChaCha20-Poly1305 - SAFE (256-bit symmetric)
func demoChaChaPoly() {
	fmt.Println("5. ChaCha20-Poly1305 AEAD (SAFE)")
	fmt.Println("   - 256-bit symmetric encryption")
	fmt.Println("   - Grover reduces to 128-bit security (still safe)")

	key := make([]byte, chacha20poly1305.KeySize)
	rand.Read(key)

	aead, err := chacha20poly1305.New(key)
	if err != nil {
		log.Fatal(err)
	}

	nonce := make([]byte, aead.NonceSize())
	rand.Read(nonce)

	plaintext := []byte("Secret message for the quantum era")
	ciphertext := aead.Seal(nil, nonce, plaintext, nil)
	fmt.Printf("   Encrypted: %x...\n\n", ciphertext[:16])
}

// demoMLKEM demonstrates ML-KEM (Kyber) - SAFE post-quantum KEM
func demoMLKEM() {
	fmt.Println("6. ML-KEM-768 Post-Quantum KEM (SAFE)")
	fmt.Println("   - NIST FIPS 203 standardized")
	fmt.Println("   - Resistant to both classical and quantum attacks")

	// Generate key pair
	pk, sk, err := mlkem768.GenerateKeyPair(rand.Reader)
	if err != nil {
		log.Fatal(err)
	}

	// Encapsulate (sender side)
	ct, ss1, err := mlkem768.Encapsulate(rand.Reader, pk)
	if err != nil {
		log.Fatal(err)
	}

	// Decapsulate (receiver side)
	ss2, err := mlkem768.Decapsulate(sk, ct)
	if err != nil {
		log.Fatal(err)
	}

	// Shared secrets should match
	match := string(ss1[:]) == string(ss2[:])
	fmt.Printf("   Shared secret established: %v\n", match)
	fmt.Printf("   Public key size: %d bytes\n", len(pk))
	fmt.Printf("   Ciphertext size: %d bytes\n", len(ct))
}
