// Copyright 2024 CSNP (csnp.org)
// SPDX-License-Identifier: Apache-2.0

package crypto

import "github.com/csnp/qramm-cryptodeps/pkg/types"

// ImportPattern represents a crypto library import pattern for an ecosystem.
type ImportPattern struct {
	Pattern     string          // Import path or module pattern
	Ecosystem   types.Ecosystem
	Description string
	Algorithms  []string // Known algorithms this library provides
}

// CryptoImportPatterns defines known crypto-related imports for each ecosystem.
var CryptoImportPatterns = map[types.Ecosystem][]ImportPattern{
	types.EcosystemGo: {
		// Standard library
		{Pattern: "crypto", Ecosystem: types.EcosystemGo, Description: "Go crypto stdlib", Algorithms: []string{}},
		{Pattern: "crypto/aes", Ecosystem: types.EcosystemGo, Description: "AES encryption", Algorithms: []string{"AES"}},
		{Pattern: "crypto/cipher", Ecosystem: types.EcosystemGo, Description: "Block cipher modes", Algorithms: []string{"AES-GCM", "AES-CBC"}},
		{Pattern: "crypto/des", Ecosystem: types.EcosystemGo, Description: "DES encryption", Algorithms: []string{"DES", "3DES"}},
		{Pattern: "crypto/dsa", Ecosystem: types.EcosystemGo, Description: "DSA signatures", Algorithms: []string{"DSA"}},
		{Pattern: "crypto/ecdh", Ecosystem: types.EcosystemGo, Description: "ECDH key exchange", Algorithms: []string{"ECDH", "X25519"}},
		{Pattern: "crypto/ecdsa", Ecosystem: types.EcosystemGo, Description: "ECDSA signatures", Algorithms: []string{"ECDSA"}},
		{Pattern: "crypto/ed25519", Ecosystem: types.EcosystemGo, Description: "Ed25519 signatures", Algorithms: []string{"Ed25519"}},
		{Pattern: "crypto/elliptic", Ecosystem: types.EcosystemGo, Description: "Elliptic curves", Algorithms: []string{"P-256", "P-384", "P-521"}},
		{Pattern: "crypto/hmac", Ecosystem: types.EcosystemGo, Description: "HMAC", Algorithms: []string{"HMAC"}},
		{Pattern: "crypto/md5", Ecosystem: types.EcosystemGo, Description: "MD5 hash", Algorithms: []string{"MD5"}},
		{Pattern: "crypto/rand", Ecosystem: types.EcosystemGo, Description: "Cryptographic RNG", Algorithms: []string{}},
		{Pattern: "crypto/rc4", Ecosystem: types.EcosystemGo, Description: "RC4 cipher", Algorithms: []string{"RC4"}},
		{Pattern: "crypto/rsa", Ecosystem: types.EcosystemGo, Description: "RSA encryption", Algorithms: []string{"RSA"}},
		{Pattern: "crypto/sha1", Ecosystem: types.EcosystemGo, Description: "SHA-1 hash", Algorithms: []string{"SHA-1"}},
		{Pattern: "crypto/sha256", Ecosystem: types.EcosystemGo, Description: "SHA-256 hash", Algorithms: []string{"SHA-256"}},
		{Pattern: "crypto/sha512", Ecosystem: types.EcosystemGo, Description: "SHA-512 hash", Algorithms: []string{"SHA-512"}},
		{Pattern: "crypto/tls", Ecosystem: types.EcosystemGo, Description: "TLS protocol", Algorithms: []string{"RSA", "ECDSA", "AES-GCM", "ChaCha20"}},
		{Pattern: "crypto/x509", Ecosystem: types.EcosystemGo, Description: "X.509 certificates", Algorithms: []string{"RSA", "ECDSA"}},
		// Extended library
		{Pattern: "golang.org/x/crypto", Ecosystem: types.EcosystemGo, Description: "Extended crypto library", Algorithms: []string{}},
		{Pattern: "golang.org/x/crypto/bcrypt", Ecosystem: types.EcosystemGo, Description: "bcrypt hashing", Algorithms: []string{"bcrypt"}},
		{Pattern: "golang.org/x/crypto/chacha20", Ecosystem: types.EcosystemGo, Description: "ChaCha20 cipher", Algorithms: []string{"ChaCha20"}},
		{Pattern: "golang.org/x/crypto/chacha20poly1305", Ecosystem: types.EcosystemGo, Description: "ChaCha20-Poly1305", Algorithms: []string{"ChaCha20", "Poly1305"}},
		{Pattern: "golang.org/x/crypto/curve25519", Ecosystem: types.EcosystemGo, Description: "Curve25519", Algorithms: []string{"X25519"}},
		{Pattern: "golang.org/x/crypto/ed25519", Ecosystem: types.EcosystemGo, Description: "Ed25519", Algorithms: []string{"Ed25519"}},
		{Pattern: "golang.org/x/crypto/nacl", Ecosystem: types.EcosystemGo, Description: "NaCl crypto", Algorithms: []string{"X25519", "XSalsa20", "Poly1305"}},
		{Pattern: "golang.org/x/crypto/sha3", Ecosystem: types.EcosystemGo, Description: "SHA-3 hash", Algorithms: []string{"SHA3"}},
		{Pattern: "golang.org/x/crypto/argon2", Ecosystem: types.EcosystemGo, Description: "Argon2 KDF", Algorithms: []string{"Argon2"}},
		{Pattern: "golang.org/x/crypto/scrypt", Ecosystem: types.EcosystemGo, Description: "scrypt KDF", Algorithms: []string{"scrypt"}},
		{Pattern: "golang.org/x/crypto/pbkdf2", Ecosystem: types.EcosystemGo, Description: "PBKDF2 KDF", Algorithms: []string{"PBKDF2"}},
		{Pattern: "golang.org/x/crypto/ssh", Ecosystem: types.EcosystemGo, Description: "SSH protocol", Algorithms: []string{"RSA", "ECDSA", "Ed25519"}},
		// Third-party
		{Pattern: "github.com/golang-jwt/jwt", Ecosystem: types.EcosystemGo, Description: "JWT library", Algorithms: []string{"RS256", "ES256", "HS256"}},
		{Pattern: "github.com/dgrijalva/jwt-go", Ecosystem: types.EcosystemGo, Description: "JWT library (deprecated)", Algorithms: []string{"RS256", "ES256", "HS256"}},
	},
	types.EcosystemNPM: {
		// Node.js built-in
		{Pattern: "crypto", Ecosystem: types.EcosystemNPM, Description: "Node.js crypto module", Algorithms: []string{}},
		{Pattern: "node:crypto", Ecosystem: types.EcosystemNPM, Description: "Node.js crypto module", Algorithms: []string{}},
		{Pattern: "tls", Ecosystem: types.EcosystemNPM, Description: "Node.js TLS module", Algorithms: []string{}},
		{Pattern: "node:tls", Ecosystem: types.EcosystemNPM, Description: "Node.js TLS module", Algorithms: []string{}},
		// Third-party
		{Pattern: "bcrypt", Ecosystem: types.EcosystemNPM, Description: "bcrypt hashing", Algorithms: []string{"bcrypt"}},
		{Pattern: "bcryptjs", Ecosystem: types.EcosystemNPM, Description: "bcrypt in JS", Algorithms: []string{"bcrypt"}},
		{Pattern: "crypto-js", Ecosystem: types.EcosystemNPM, Description: "Crypto-JS library", Algorithms: []string{"AES", "DES", "3DES", "MD5", "SHA-1", "SHA-256"}},
		{Pattern: "jsonwebtoken", Ecosystem: types.EcosystemNPM, Description: "JWT library", Algorithms: []string{"RS256", "ES256", "HS256"}},
		{Pattern: "jose", Ecosystem: types.EcosystemNPM, Description: "JOSE/JWT library", Algorithms: []string{"RS256", "ES256", "HS256"}},
		{Pattern: "node-rsa", Ecosystem: types.EcosystemNPM, Description: "RSA library", Algorithms: []string{"RSA"}},
		{Pattern: "node-forge", Ecosystem: types.EcosystemNPM, Description: "Forge crypto library", Algorithms: []string{"RSA", "AES", "DES", "MD5", "SHA-1", "SHA-256"}},
		{Pattern: "tweetnacl", Ecosystem: types.EcosystemNPM, Description: "TweetNaCl", Algorithms: []string{"X25519", "Ed25519", "XSalsa20"}},
		{Pattern: "sodium-native", Ecosystem: types.EcosystemNPM, Description: "libsodium bindings", Algorithms: []string{"X25519", "Ed25519", "ChaCha20"}},
		{Pattern: "libsodium-wrappers", Ecosystem: types.EcosystemNPM, Description: "libsodium WASM", Algorithms: []string{"X25519", "Ed25519", "ChaCha20"}},
		{Pattern: "argon2", Ecosystem: types.EcosystemNPM, Description: "Argon2 hashing", Algorithms: []string{"Argon2"}},
		{Pattern: "scrypt", Ecosystem: types.EcosystemNPM, Description: "scrypt KDF", Algorithms: []string{"scrypt"}},
		{Pattern: "pbkdf2", Ecosystem: types.EcosystemNPM, Description: "PBKDF2 KDF", Algorithms: []string{"PBKDF2"}},
	},
	types.EcosystemPyPI: {
		// Standard library
		{Pattern: "hashlib", Ecosystem: types.EcosystemPyPI, Description: "Python hash library", Algorithms: []string{"MD5", "SHA-1", "SHA-256", "SHA-512"}},
		{Pattern: "hmac", Ecosystem: types.EcosystemPyPI, Description: "Python HMAC", Algorithms: []string{"HMAC"}},
		{Pattern: "ssl", Ecosystem: types.EcosystemPyPI, Description: "Python SSL/TLS", Algorithms: []string{}},
		{Pattern: "secrets", Ecosystem: types.EcosystemPyPI, Description: "Python secrets module", Algorithms: []string{}},
		// Third-party
		{Pattern: "cryptography", Ecosystem: types.EcosystemPyPI, Description: "PyCA cryptography", Algorithms: []string{"RSA", "ECDSA", "Ed25519", "AES", "ChaCha20"}},
		{Pattern: "Crypto", Ecosystem: types.EcosystemPyPI, Description: "PyCrypto (deprecated)", Algorithms: []string{"RSA", "AES", "DES", "MD5", "SHA-1"}},
		{Pattern: "Cryptodome", Ecosystem: types.EcosystemPyPI, Description: "PyCryptodome", Algorithms: []string{"RSA", "ECDSA", "AES", "ChaCha20", "MD5", "SHA-1"}},
		{Pattern: "pycryptodome", Ecosystem: types.EcosystemPyPI, Description: "PyCryptodome", Algorithms: []string{"RSA", "ECDSA", "AES", "ChaCha20"}},
		{Pattern: "nacl", Ecosystem: types.EcosystemPyPI, Description: "PyNaCl", Algorithms: []string{"X25519", "Ed25519", "XSalsa20"}},
		{Pattern: "pynacl", Ecosystem: types.EcosystemPyPI, Description: "PyNaCl", Algorithms: []string{"X25519", "Ed25519", "XSalsa20"}},
		{Pattern: "bcrypt", Ecosystem: types.EcosystemPyPI, Description: "bcrypt hashing", Algorithms: []string{"bcrypt"}},
		{Pattern: "argon2", Ecosystem: types.EcosystemPyPI, Description: "Argon2 hashing", Algorithms: []string{"Argon2"}},
		{Pattern: "passlib", Ecosystem: types.EcosystemPyPI, Description: "Password hashing", Algorithms: []string{"bcrypt", "Argon2", "PBKDF2", "scrypt"}},
		{Pattern: "PyJWT", Ecosystem: types.EcosystemPyPI, Description: "JWT library", Algorithms: []string{"RS256", "ES256", "HS256"}},
		{Pattern: "python-jose", Ecosystem: types.EcosystemPyPI, Description: "JOSE library", Algorithms: []string{"RS256", "ES256", "HS256"}},
		{Pattern: "jwcrypto", Ecosystem: types.EcosystemPyPI, Description: "JWK/JWT library", Algorithms: []string{"RS256", "ES256", "HS256"}},
		{Pattern: "paramiko", Ecosystem: types.EcosystemPyPI, Description: "SSH library", Algorithms: []string{"RSA", "ECDSA", "Ed25519"}},
	},
	types.EcosystemMaven: {
		// Java standard
		{Pattern: "javax.crypto", Ecosystem: types.EcosystemMaven, Description: "Java Crypto Extension", Algorithms: []string{}},
		{Pattern: "java.security", Ecosystem: types.EcosystemMaven, Description: "Java Security API", Algorithms: []string{}},
		{Pattern: "javax.net.ssl", Ecosystem: types.EcosystemMaven, Description: "Java SSL/TLS", Algorithms: []string{}},
		// Bouncy Castle
		{Pattern: "org.bouncycastle", Ecosystem: types.EcosystemMaven, Description: "Bouncy Castle", Algorithms: []string{"RSA", "ECDSA", "Ed25519", "AES", "ChaCha20"}},
		{Pattern: "org.bouncycastle.jce", Ecosystem: types.EcosystemMaven, Description: "Bouncy Castle JCE", Algorithms: []string{}},
		{Pattern: "org.bouncycastle.crypto", Ecosystem: types.EcosystemMaven, Description: "Bouncy Castle Crypto", Algorithms: []string{}},
		// JWT libraries
		{Pattern: "io.jsonwebtoken", Ecosystem: types.EcosystemMaven, Description: "JJWT library", Algorithms: []string{"RS256", "ES256", "HS256"}},
		{Pattern: "com.auth0.jwt", Ecosystem: types.EcosystemMaven, Description: "Auth0 JWT", Algorithms: []string{"RS256", "ES256", "HS256"}},
		{Pattern: "com.nimbusds.jose", Ecosystem: types.EcosystemMaven, Description: "Nimbus JOSE+JWT", Algorithms: []string{"RS256", "ES256", "HS256"}},
		// Google
		{Pattern: "com.google.crypto.tink", Ecosystem: types.EcosystemMaven, Description: "Google Tink", Algorithms: []string{"AES-GCM", "ChaCha20", "ECDSA", "Ed25519"}},
		// Apache
		{Pattern: "org.apache.commons.codec", Ecosystem: types.EcosystemMaven, Description: "Commons Codec", Algorithms: []string{"MD5", "SHA-1", "SHA-256"}},
		// Spring Security
		{Pattern: "org.springframework.security.crypto", Ecosystem: types.EcosystemMaven, Description: "Spring Security Crypto", Algorithms: []string{"bcrypt", "Argon2", "scrypt", "PBKDF2"}},
	},
}

// GetPatternsForEcosystem returns all crypto import patterns for an ecosystem.
func GetPatternsForEcosystem(ecosystem types.Ecosystem) []ImportPattern {
	return CryptoImportPatterns[ecosystem]
}

// IsCryptoImport checks if an import path matches a known crypto library.
func IsCryptoImport(importPath string, ecosystem types.Ecosystem) (ImportPattern, bool) {
	patterns := CryptoImportPatterns[ecosystem]
	for _, p := range patterns {
		if importPath == p.Pattern || matchesPrefix(importPath, p.Pattern) {
			return p, true
		}
	}
	return ImportPattern{}, false
}

// matchesPrefix checks if an import path starts with a pattern prefix.
func matchesPrefix(importPath, pattern string) bool {
	if len(importPath) > len(pattern) && importPath[:len(pattern)] == pattern {
		// Check if it's a subpackage (has / after pattern)
		return importPath[len(pattern)] == '/'
	}
	return false
}
