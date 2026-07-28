// Copyright 2025-2026 CyberSecurity NonProfit (CSNP)
// SPDX-License-Identifier: Apache-2.0

// Package crypto provides cryptographic algorithm classification and remediation guidance.
package crypto

import (
	"strings"

	"github.com/csnp/qramm-cryptodeps/pkg/types"
)

// Remediation provides detailed migration guidance for a cryptographic algorithm.
type Remediation struct {
	// Summary is a one-line description of the recommended action
	Summary string `json:"summary"`

	// Replacement is the recommended post-quantum algorithm
	Replacement string `json:"replacement"`

	// NISTStandard is the relevant NIST FIPS standard (e.g., "FIPS 203")
	NISTStandard string `json:"nistStandard,omitempty"`

	// Timeline indicates urgency (immediate, short-term, medium-term)
	Timeline string `json:"timeline"`

	// Effort estimates migration complexity (low, medium, high)
	Effort string `json:"effort"`

	// Libraries lists recommended PQC libraries by ecosystem
	Libraries map[types.Ecosystem][]string `json:"libraries,omitempty"`

	// Notes provides additional context
	Notes string `json:"notes,omitempty"`
}

// remediationDB maps algorithm patterns to remediation guidance
var remediationDB = map[string]Remediation{
	// Key Exchange - Vulnerable to Shor's algorithm
	"RSA": {
		Summary:      "Migrate to ML-KEM (Kyber) for key encapsulation",
		Replacement:  "ML-KEM-768 or ML-KEM-1024",
		NISTStandard: "FIPS 203",
		Timeline:     "immediate",
		Effort:       "medium",
		Libraries: map[types.Ecosystem][]string{
			types.EcosystemGo:    {"github.com/cloudflare/circl/kem/mlkem"},
			types.EcosystemNPM:   {"@noble/post-quantum", "pqcrypto"},
			types.EcosystemPyPI:  {"pqcrypto", "liboqs-python"},
			types.EcosystemMaven: {"org.bouncycastle:bcprov-jdk18on"},
		},
		Notes: "RSA key exchange is completely broken by quantum computers. Prioritize migration for key exchange; RSA signatures can follow.",
	},
	"ECDH": {
		Summary:      "Migrate to ML-KEM (Kyber) for key exchange",
		Replacement:  "ML-KEM-768",
		NISTStandard: "FIPS 203",
		Timeline:     "immediate",
		Effort:       "medium",
		Libraries: map[types.Ecosystem][]string{
			types.EcosystemGo:    {"github.com/cloudflare/circl/kem/mlkem"},
			types.EcosystemNPM:   {"@noble/post-quantum"},
			types.EcosystemPyPI:  {"pqcrypto", "liboqs-python"},
			types.EcosystemMaven: {"org.bouncycastle:bcprov-jdk18on"},
		},
		Notes: "ECDH is vulnerable to Shor's algorithm. Use hybrid key exchange (ECDH + ML-KEM) during transition.",
	},
	"DH": {
		Summary:      "Migrate to ML-KEM (Kyber) for key exchange",
		Replacement:  "ML-KEM-768",
		NISTStandard: "FIPS 203",
		Timeline:     "immediate",
		Effort:       "medium",
		Libraries: map[types.Ecosystem][]string{
			types.EcosystemGo:    {"github.com/cloudflare/circl/kem/mlkem"},
			types.EcosystemNPM:   {"@noble/post-quantum"},
			types.EcosystemPyPI:  {"pqcrypto"},
			types.EcosystemMaven: {"org.bouncycastle:bcprov-jdk18on"},
		},
		Notes: "Diffie-Hellman is vulnerable to Shor's algorithm regardless of key size.",
	},
	"X25519": {
		Summary:      "Migrate to ML-KEM or use hybrid X25519+ML-KEM",
		Replacement:  "ML-KEM-768 or X25519Kyber768Draft00",
		NISTStandard: "FIPS 203",
		Timeline:     "short-term",
		Effort:       "low",
		Libraries: map[types.Ecosystem][]string{
			types.EcosystemGo:    {"github.com/cloudflare/circl/kem/mlkem", "github.com/cloudflare/circl/kem/hybrid"},
			types.EcosystemNPM:   {"@noble/post-quantum"},
			types.EcosystemPyPI:  {"pqcrypto"},
			types.EcosystemMaven: {"org.bouncycastle:bcprov-jdk18on"},
		},
		Notes: "X25519 is excellent for current use but needs PQC hybrid for long-term security.",
	},

	// Digital Signatures - Vulnerable to Shor's algorithm
	"ECDSA": {
		Summary:      "Migrate to ML-DSA (Dilithium) for digital signatures",
		Replacement:  "ML-DSA-65 or ML-DSA-87",
		NISTStandard: "FIPS 204",
		Timeline:     "immediate",
		Effort:       "medium",
		Libraries: map[types.Ecosystem][]string{
			types.EcosystemGo:    {"github.com/cloudflare/circl/sign/mldsa"},
			types.EcosystemNPM:   {"@noble/post-quantum", "pqcrypto"},
			types.EcosystemPyPI:  {"pqcrypto", "liboqs-python"},
			types.EcosystemMaven: {"org.bouncycastle:bcprov-jdk18on"},
		},
		Notes: "ECDSA signatures can be forged by quantum computers. Critical for code signing and authentication.",
	},
	"Ed25519": {
		Summary:      "Plan migration to ML-DSA; prioritize if signing long-lived data or certificates",
		Replacement:  "ML-DSA-65 (FIPS 204)",
		NISTStandard: "FIPS 204",
		Timeline:     "short-term",
		Effort:       "low",
		Libraries: map[types.Ecosystem][]string{
			types.EcosystemGo:    {"github.com/cloudflare/circl/sign/mldsa"},
			types.EcosystemNPM:   {"@noble/post-quantum"},
			types.EcosystemPyPI:  {"pqcrypto"},
			types.EcosystemMaven: {"org.bouncycastle:bcprov-jdk18on"},
		},
		Notes: "Ed25519 signatures are quantum-vulnerable via Shor's algorithm. Priority depends on what you're signing: (1) Long-lived certificates/documents - migrate soon, (2) Short-lived auth tokens - lower priority, (3) Code signing - consider hybrid approach. ML-DSA has similar API patterns, making migration straightforward when ready.",
	},
	"Ed448": {
		Summary:      "Migrate to ML-DSA-87 for digital signatures",
		Replacement:  "ML-DSA-87",
		NISTStandard: "FIPS 204",
		Timeline:     "immediate",
		Effort:       "low",
		Libraries: map[types.Ecosystem][]string{
			types.EcosystemGo:    {"github.com/cloudflare/circl/sign/mldsa"},
			types.EcosystemNPM:   {"@noble/post-quantum"},
			types.EcosystemPyPI:  {"pqcrypto"},
			types.EcosystemMaven: {"org.bouncycastle:bcprov-jdk18on"},
		},
		Notes: "For high-security applications currently using Ed448.",
	},
	"DSA": {
		Summary:      "Migrate to ML-DSA (Dilithium) for digital signatures",
		Replacement:  "ML-DSA-65",
		NISTStandard: "FIPS 204",
		Timeline:     "immediate",
		Effort:       "medium",
		Notes:        "DSA is deprecated even for classical security. Prioritize migration.",
	},

	// Hash-based Signatures (already quantum-safe but worth noting)
	"SLH-DSA": {
		Summary:      "Already quantum-safe (stateless hash-based)",
		Replacement:  "No change needed",
		NISTStandard: "FIPS 205",
		Timeline:     "none",
		Effort:       "none",
		Notes:        "SLH-DSA (SPHINCS+) is quantum-safe. Consider for long-term document signing.",
	},

	// Symmetric Encryption - Partial vulnerability (Grover's algorithm)
	"AES": {
		Summary:      "Ensure AES-256 key size for quantum resistance",
		Replacement:  "AES-256-GCM",
		NISTStandard: "",
		Timeline:     "short-term",
		Effort:       "low",
		Libraries: map[types.Ecosystem][]string{
			types.EcosystemGo:    {"crypto/aes (256-bit keys)"},
			types.EcosystemNPM:   {"crypto (256-bit keys)", "@noble/ciphers"},
			types.EcosystemPyPI:  {"cryptography (AES-256)", "pycryptodome"},
			types.EcosystemMaven: {"org.bouncycastle:bcprov-jdk18on"},
		},
		Notes: "AES with 256-bit keys provides 128-bit post-quantum security (Grover's halves effective strength). AES-128 is reduced to 64-bit security and should be upgraded. Verify your implementation uses AES-256.",
	},
	"AES-128": {
		Summary:      "Increase to AES-256 for quantum resistance",
		Replacement:  "AES-256",
		NISTStandard: "",
		Timeline:     "medium-term",
		Effort:       "low",
		Notes:        "Grover's algorithm reduces AES-128 to 64-bit security. AES-256 provides 128-bit post-quantum security.",
	},
	"AES-192": {
		Summary:      "Consider upgrading to AES-256",
		Replacement:  "AES-256",
		NISTStandard: "",
		Timeline:     "medium-term",
		Effort:       "low",
		Notes:        "AES-192 provides ~96-bit post-quantum security, but AES-256 is recommended.",
	},
	"AES-256": {
		Summary:      "Already quantum-safe (128-bit post-quantum security)",
		Replacement:  "No change needed",
		NISTStandard: "",
		Timeline:     "none",
		Effort:       "none",
		Notes:        "AES-256 maintains 128-bit security against Grover's algorithm.",
	},
	"ChaCha20": {
		Summary:      "Already quantum-safe (256-bit key)",
		Replacement:  "No change needed",
		NISTStandard: "",
		Timeline:     "none",
		Effort:       "none",
		Notes:        "ChaCha20 with 256-bit keys provides 128-bit post-quantum security.",
	},
	"3DES": {
		Summary:      "Migrate to AES-256 immediately",
		Replacement:  "AES-256-GCM",
		NISTStandard: "",
		Timeline:     "immediate",
		Effort:       "medium",
		Notes:        "3DES is deprecated for classical security. Quantum concerns are secondary.",
	},
	"DES": {
		Summary:      "Migrate to AES-256 immediately",
		Replacement:  "AES-256-GCM",
		NISTStandard: "",
		Timeline:     "immediate",
		Effort:       "medium",
		Notes:        "DES is completely broken classically. Remove immediately.",
	},
	"Blowfish": {
		Summary:      "Migrate to AES-256 or ChaCha20",
		Replacement:  "AES-256-GCM or ChaCha20-Poly1305",
		NISTStandard: "",
		Timeline:     "short-term",
		Effort:       "low",
		Notes:        "Blowfish has a 64-bit block size, vulnerable to birthday attacks at scale.",
	},

	// Hash Functions - Partial vulnerability
	"MD5": {
		Summary:      "Migrate to SHA-256 or SHA-3 immediately",
		Replacement:  "SHA-256 or SHA3-256",
		NISTStandard: "",
		Timeline:     "immediate",
		Effort:       "low",
		Notes:        "MD5 is broken classically. Replace immediately regardless of quantum.",
	},
	"SHA-1": {
		Summary:      "Migrate to SHA-256 or SHA-3",
		Replacement:  "SHA-256 or SHA3-256",
		NISTStandard: "",
		Timeline:     "immediate",
		Effort:       "low",
		Notes:        "SHA-1 has known collision attacks. Replace for both classical and quantum security.",
	},
	"SHA-256": {
		Summary:      "Consider SHA-384/SHA-512 for long-term security",
		Replacement:  "SHA-384 or SHA-512 (optional)",
		NISTStandard: "",
		Timeline:     "medium-term",
		Effort:       "low",
		Notes:        "SHA-256 provides ~128-bit post-quantum collision resistance. Adequate for most uses.",
	},
	"SHA-384": {
		Summary:      "Already quantum-safe",
		Replacement:  "No change needed",
		NISTStandard: "",
		Timeline:     "none",
		Effort:       "none",
		Notes:        "SHA-384 provides ~192-bit post-quantum collision resistance.",
	},
	"SHA-512": {
		Summary:      "Already quantum-safe",
		Replacement:  "No change needed",
		NISTStandard: "",
		Timeline:     "none",
		Effort:       "none",
		Notes:        "SHA-512 provides ~256-bit post-quantum collision resistance.",
	},
	"SHA3-256": {
		Summary:      "Already quantum-safe",
		Replacement:  "No change needed",
		NISTStandard: "",
		Timeline:     "none",
		Effort:       "none",
		Notes:        "SHA-3 is quantum-resistant by design.",
	},

	// Password Hashing
	"bcrypt": {
		Summary:      "Already quantum-safe for password hashing",
		Replacement:  "No change needed (consider Argon2id for new systems)",
		NISTStandard: "",
		Timeline:     "none",
		Effort:       "none",
		Notes:        "Password hashing with bcrypt remains secure. Argon2id is the modern recommendation.",
	},
	"scrypt": {
		Summary:      "Already quantum-safe for password hashing",
		Replacement:  "No change needed",
		NISTStandard: "",
		Timeline:     "none",
		Effort:       "none",
		Notes:        "scrypt remains secure against quantum attacks for password hashing.",
	},
	"Argon2": {
		Summary:      "Already quantum-safe (recommended for new systems)",
		Replacement:  "No change needed",
		NISTStandard: "",
		Timeline:     "none",
		Effort:       "none",
		Notes:        "Argon2id is the recommended password hashing algorithm.",
	},
	"PBKDF2": {
		Summary:      "Consider Argon2id for new systems, increase iterations",
		Replacement:  "Argon2id (for new systems)",
		NISTStandard: "",
		Timeline:     "medium-term",
		Effort:       "low",
		Notes:        "PBKDF2 with SHA-256 and high iterations remains acceptable.",
	},

	// JWT/JWS Algorithms - Asymmetric (quantum-vulnerable but wait for PQ-JWT standards)
	"RS256": {
		Summary:      "Wait for PQ-JWT standards; use HS256/HS512 if symmetric signing is acceptable",
		Replacement:  "HS256/HS512 (now) or PQ-JWT algorithms (when standardized)",
		NISTStandard: "FIPS 204",
		Timeline:     "short-term",
		Effort:       "low",
		Notes:        "For short-lived tokens (<24h), the quantum threat is not immediate. IETF is developing PQ-JWT standards - avoid migrating twice by waiting unless you have long-lived tokens or harvest-now-decrypt-later concerns.",
	},
	"RS384": {
		Summary:      "Wait for PQ-JWT standards; use HS384/HS512 if symmetric signing is acceptable",
		Replacement:  "HS384/HS512 (now) or PQ-JWT algorithms (when standardized)",
		NISTStandard: "FIPS 204",
		Timeline:     "short-term",
		Effort:       "low",
		Notes:        "RSA JWT signatures are quantum-vulnerable but short token lifetimes reduce risk. Monitor IETF PQ-JWT working group for standardized replacements.",
	},
	"RS512": {
		Summary:      "Wait for PQ-JWT standards; use HS512 if symmetric signing is acceptable",
		Replacement:  "HS512 (now) or PQ-JWT algorithms (when standardized)",
		NISTStandard: "FIPS 204",
		Timeline:     "short-term",
		Effort:       "low",
		Notes:        "RSA JWT signatures are quantum-vulnerable but short token lifetimes reduce risk. Monitor IETF PQ-JWT working group for standardized replacements.",
	},
	"ES256": {
		Summary:      "Wait for PQ-JWT standards; use HS256/HS512 if symmetric signing is acceptable",
		Replacement:  "HS256/HS512 (now) or PQ-JWT algorithms (when standardized)",
		NISTStandard: "FIPS 204",
		Timeline:     "short-term",
		Effort:       "low",
		Notes:        "ECDSA JWT signatures are quantum-vulnerable but short token lifetimes reduce risk. For immediate mitigation, switch to HMAC-based signing if your architecture supports shared secrets.",
	},
	"ES384": {
		Summary:      "Wait for PQ-JWT standards; use HS384/HS512 if symmetric signing is acceptable",
		Replacement:  "HS384/HS512 (now) or PQ-JWT algorithms (when standardized)",
		NISTStandard: "FIPS 204",
		Timeline:     "short-term",
		Effort:       "low",
		Notes:        "ECDSA JWT signatures are quantum-vulnerable. Monitor IETF PQ-JWT working group for standardized post-quantum JWT algorithms.",
	},
	"ES512": {
		Summary:      "Wait for PQ-JWT standards; use HS512 if symmetric signing is acceptable",
		Replacement:  "HS512 (now) or PQ-JWT algorithms (when standardized)",
		NISTStandard: "FIPS 204",
		Timeline:     "short-term",
		Effort:       "low",
		Notes:        "ECDSA JWT signatures are quantum-vulnerable. Monitor IETF PQ-JWT working group for standardized post-quantum JWT algorithms.",
	},
	// JWT/JWS Algorithms - Symmetric (quantum-resistant)
	"HS256": {
		Summary:      "Adequate for most use cases; upgrade to HS512 for defense-in-depth",
		Replacement:  "HS512 (optional, for added security margin)",
		NISTStandard: "",
		Timeline:     "none",
		Effort:       "low",
		Notes:        "HMAC-SHA256 with a strong secret provides ~128-bit post-quantum security (Grover's halves effective key strength). This is sufficient for most applications. Upgrade to HS512 only if you want extra margin.",
	},
	"HS384": {
		Summary:      "Quantum-safe, no action required",
		Replacement:  "No change needed",
		NISTStandard: "",
		Timeline:     "none",
		Effort:       "none",
		Notes:        "HMAC-SHA384 provides strong post-quantum security (~192-bit). No migration needed.",
	},
	"HS512": {
		Summary:      "Quantum-safe, no action required",
		Replacement:  "No change needed",
		NISTStandard: "",
		Timeline:     "none",
		Effort:       "none",
		Notes:        "HMAC-SHA512 provides strong post-quantum security (~256-bit). This is the recommended JWT signing method for quantum readiness.",
	},
	"EdDSA": {
		Summary:      "Wait for PQ-JWT standards unless migrating from RSA/ECDSA now",
		Replacement:  "PQ-JWT algorithms (when standardized)",
		NISTStandard: "FIPS 204",
		Timeline:     "short-term",
		Effort:       "low",
		Notes:        "EdDSA is quantum-vulnerable but offers better performance than RSA. If migrating from RS*/ES* now, EdDSA is a reasonable interim step. For new systems, consider HS512 or wait for PQ-JWT.",
	},

	// TLS/SSL
	"TLS 1.2": {
		Summary:      "Upgrade to TLS 1.3 and enable PQC key exchange",
		Replacement:  "TLS 1.3 with X25519Kyber768",
		NISTStandard: "",
		Timeline:     "short-term",
		Effort:       "low",
		Notes:        "TLS 1.3 supports hybrid PQC key exchange. Chrome and other browsers already support it.",
	},
	"TLS 1.3": {
		Summary:      "Enable hybrid PQC key exchange (X25519Kyber768)",
		Replacement:  "TLS 1.3 with X25519Kyber768Draft00",
		NISTStandard: "",
		Timeline:     "short-term",
		Effort:       "low",
		Notes:        "Enable PQC hybrid mode in your TLS configuration. Supported by major browsers.",
	},

	// Authenticated Encryption - Quantum-safe with 256-bit keys
	"ChaCha20-Poly1305": {
		Summary:      "Already quantum-safe (256-bit key)",
		Replacement:  "No change needed",
		NISTStandard: "",
		Timeline:     "none",
		Effort:       "none",
		Notes:        "ChaCha20-Poly1305 with 256-bit keys provides 128-bit post-quantum security.",
	},
	"AES-GCM": {
		Summary:      "Ensure AES-256-GCM for quantum resistance",
		Replacement:  "AES-256-GCM",
		NISTStandard: "",
		Timeline:     "short-term",
		Effort:       "low",
		Libraries: map[types.Ecosystem][]string{
			types.EcosystemGo:    {"crypto/aes + crypto/cipher"},
			types.EcosystemNPM:   {"crypto", "@noble/ciphers"},
			types.EcosystemPyPI:  {"cryptography", "pycryptodome"},
			types.EcosystemMaven: {"org.bouncycastle:bcprov-jdk18on"},
		},
		Notes: "AES-GCM with 256-bit keys provides 128-bit post-quantum security. Verify key size is 256 bits.",
	},
	"A256GCM": {
		Summary:      "Already quantum-safe (256-bit key)",
		Replacement:  "No change needed",
		NISTStandard: "",
		Timeline:     "none",
		Effort:       "none",
		Notes:        "A256GCM uses AES-256-GCM which provides 128-bit post-quantum security.",
	},

	// MAC Functions - Quantum-safe
	"HMAC": {
		Summary:      "Already quantum-safe with strong hash function",
		Replacement:  "No change needed (use HMAC-SHA256 or stronger)",
		NISTStandard: "",
		Timeline:     "none",
		Effort:       "none",
		Notes:        "HMAC with SHA-256 or stronger provides adequate post-quantum security for authentication.",
	},
	"HMAC-SHA256": {
		Summary:      "Already quantum-safe",
		Replacement:  "No change needed",
		NISTStandard: "",
		Timeline:     "none",
		Effort:       "none",
		Notes:        "HMAC-SHA256 provides 128-bit post-quantum security for authentication.",
	},
	"HMAC-SHA512": {
		Summary:      "Already quantum-safe",
		Replacement:  "No change needed",
		NISTStandard: "",
		Timeline:     "none",
		Effort:       "none",
		Notes:        "HMAC-SHA512 provides strong post-quantum security for authentication.",
	},
	"HMAC-SHA1": {
		Summary:      "Upgrade to HMAC-SHA256 or stronger",
		Replacement:  "HMAC-SHA256",
		NISTStandard: "",
		Timeline:     "medium-term",
		Effort:       "low",
		Notes:        "HMAC-SHA1 is still secure for authentication but SHA-1 is deprecated. Upgrade when convenient.",
	},
	"Poly1305": {
		Summary:      "Already quantum-safe (use with ChaCha20 or XSalsa20)",
		Replacement:  "No change needed",
		NISTStandard: "",
		Timeline:     "none",
		Effort:       "none",
		Notes:        "Poly1305 is a secure MAC that provides adequate post-quantum authentication security.",
	},

	// Stream Ciphers - Quantum-safe with 256-bit keys
	"XSalsa20": {
		Summary:      "Already quantum-safe (256-bit key)",
		Replacement:  "No change needed",
		NISTStandard: "",
		Timeline:     "none",
		Effort:       "none",
		Notes:        "XSalsa20 with 256-bit keys provides 128-bit post-quantum security.",
	},
	"XSalsa20-Poly1305": {
		Summary:      "Already quantum-safe (256-bit key)",
		Replacement:  "No change needed",
		NISTStandard: "",
		Timeline:     "none",
		Effort:       "none",
		Notes:        "XSalsa20-Poly1305 (NaCl secretbox) provides authenticated encryption with 128-bit post-quantum security.",
	},

	// Post-Quantum Algorithms - Already quantum-safe
	"ML-KEM": {
		Summary:      "Already quantum-safe (NIST standardized)",
		Replacement:  "No change needed",
		NISTStandard: "FIPS 203",
		Timeline:     "none",
		Effort:       "none",
		Notes:        "ML-KEM (Kyber) is NIST-standardized post-quantum key encapsulation. You're already quantum-ready!",
	},
	"ML-DSA": {
		Summary:      "Already quantum-safe (NIST standardized)",
		Replacement:  "No change needed",
		NISTStandard: "FIPS 204",
		Timeline:     "none",
		Effort:       "none",
		Notes:        "ML-DSA (Dilithium) is NIST-standardized post-quantum digital signature. You're already quantum-ready!",
	},

	// NIST Elliptic Curves - Vulnerable to Shor's algorithm
	"P-256": {
		Summary:      "Migrate to ML-DSA for signatures or ML-KEM for key exchange",
		Replacement:  "ML-DSA-65 (signatures) or ML-KEM-768 (key exchange)",
		NISTStandard: "FIPS 203/204",
		Timeline:     "immediate",
		Effort:       "medium",
		Libraries: map[types.Ecosystem][]string{
			types.EcosystemGo:    {"github.com/cloudflare/circl"},
			types.EcosystemNPM:   {"@noble/post-quantum"},
			types.EcosystemPyPI:  {"pqcrypto", "liboqs-python"},
			types.EcosystemMaven: {"org.bouncycastle:bcprov-jdk18on"},
		},
		Notes: "P-256 (secp256r1/prime256v1) is vulnerable to Shor's algorithm.",
	},
	"P-384": {
		Summary:      "Migrate to ML-DSA for signatures or ML-KEM for key exchange",
		Replacement:  "ML-DSA-65 (signatures) or ML-KEM-768 (key exchange)",
		NISTStandard: "FIPS 203/204",
		Timeline:     "immediate",
		Effort:       "medium",
		Notes:        "P-384 (secp384r1) is vulnerable to Shor's algorithm.",
	},
	"P-521": {
		Summary:      "Migrate to ML-DSA for signatures or ML-KEM for key exchange",
		Replacement:  "ML-DSA-87 (signatures) or ML-KEM-1024 (key exchange)",
		NISTStandard: "FIPS 203/204",
		Timeline:     "immediate",
		Effort:       "medium",
		Notes:        "P-521 (secp521r1) is vulnerable to Shor's algorithm.",
	},
	"secp256k1": {
		Summary:      "Migrate to ML-DSA for signatures",
		Replacement:  "ML-DSA-65",
		NISTStandard: "FIPS 204",
		Timeline:     "immediate",
		Effort:       "medium",
		Notes:        "secp256k1 (Bitcoin curve) is vulnerable to Shor's algorithm. Critical for blockchain applications.",
	},

	// RSA Variants
	"PS256": {
		Summary:      "Wait for PQ-JWT standards; use HS256/HS512 if symmetric signing is acceptable",
		Replacement:  "HS256/HS512 (now) or PQ-JWT algorithms (when standardized)",
		NISTStandard: "FIPS 204",
		Timeline:     "short-term",
		Effort:       "low",
		Notes:        "RSA-PSS (PS256) is quantum-vulnerable. For short-lived tokens, monitor IETF PQ-JWT working group.",
	},
	"PS384": {
		Summary:      "Wait for PQ-JWT standards; use HS384/HS512 if symmetric signing is acceptable",
		Replacement:  "HS384/HS512 (now) or PQ-JWT algorithms (when standardized)",
		NISTStandard: "FIPS 204",
		Timeline:     "short-term",
		Effort:       "low",
		Notes:        "RSA-PSS (PS384) is quantum-vulnerable. For short-lived tokens, monitor IETF PQ-JWT working group.",
	},
	"PS512": {
		Summary:      "Wait for PQ-JWT standards; use HS512 if symmetric signing is acceptable",
		Replacement:  "HS512 (now) or PQ-JWT algorithms (when standardized)",
		NISTStandard: "FIPS 204",
		Timeline:     "short-term",
		Effort:       "low",
		Notes:        "RSA-PSS (PS512) is quantum-vulnerable. For short-lived tokens, monitor IETF PQ-JWT working group.",
	},
	"RSA-OAEP": {
		Summary:      "Migrate to ML-KEM for key encapsulation",
		Replacement:  "ML-KEM-768 or ML-KEM-1024",
		NISTStandard: "FIPS 203",
		Timeline:     "immediate",
		Effort:       "medium",
		Notes:        "RSA-OAEP is quantum-vulnerable for key transport. Use ML-KEM for post-quantum key encapsulation.",
	},
	"RSA-PSS": {
		Summary:      "Migrate to ML-DSA for digital signatures",
		Replacement:  "ML-DSA-65 or ML-DSA-87",
		NISTStandard: "FIPS 204",
		Timeline:     "immediate",
		Effort:       "medium",
		Notes:        "RSA-PSS is quantum-vulnerable for signatures. Use ML-DSA for post-quantum signatures.",
	},

	// ECDH Variants
	"ECDH-ES": {
		Summary:      "Migrate to ML-KEM or hybrid ECDH+ML-KEM",
		Replacement:  "ML-KEM-768",
		NISTStandard: "FIPS 203",
		Timeline:     "immediate",
		Effort:       "medium",
		Notes:        "ECDH-ES (Ephemeral-Static) is quantum-vulnerable. Use ML-KEM for JWE key agreement.",
	},

	// Modern Hash Functions - Quantum-safe
	"BLAKE2b": {
		Summary:      "Already quantum-safe",
		Replacement:  "No change needed",
		NISTStandard: "",
		Timeline:     "none",
		Effort:       "none",
		Notes:        "BLAKE2b provides strong post-quantum collision resistance.",
	},
	"BLAKE2s": {
		Summary:      "Already quantum-safe",
		Replacement:  "No change needed",
		NISTStandard: "",
		Timeline:     "none",
		Effort:       "none",
		Notes:        "BLAKE2s provides strong post-quantum collision resistance.",
	},
	"BLAKE3": {
		Summary:      "Already quantum-safe",
		Replacement:  "No change needed",
		NISTStandard: "",
		Timeline:     "none",
		Effort:       "none",
		Notes:        "BLAKE3 provides strong post-quantum collision resistance.",
	},

	// Chinese National Algorithms (GB/T standards)
	"SM2": {
		Summary:      "Migrate to ML-DSA for signatures or ML-KEM for key exchange",
		Replacement:  "ML-DSA-65 (signatures) or ML-KEM-768 (key exchange)",
		NISTStandard: "FIPS 203/204",
		Timeline:     "immediate",
		Effort:       "medium",
		Notes:        "SM2 (Chinese elliptic curve) is vulnerable to Shor's algorithm.",
	},
	"SM3": {
		Summary:      "Already quantum-safe (256-bit hash)",
		Replacement:  "No change needed",
		NISTStandard: "",
		Timeline:     "none",
		Effort:       "none",
		Notes:        "SM3 is a 256-bit hash providing adequate post-quantum collision resistance.",
	},
	"SM4": {
		Summary:      "Already quantum-safe (128-bit block cipher)",
		Replacement:  "No change needed (consider AES-256 for compatibility)",
		NISTStandard: "",
		Timeline:     "none",
		Effort:       "none",
		Notes:        "SM4 is a 128-bit block cipher. Similar quantum properties to AES-128.",
	},
}

// GetDetailedRemediation returns comprehensive remediation guidance for an algorithm.
// It matches against known patterns and returns detailed guidance including
// NIST standards, timeline, effort, and library recommendations.
func GetDetailedRemediation(algorithm string, cryptoType string, ecosystem types.Ecosystem) *Remediation {
	// Normalize algorithm name
	algo := strings.ToUpper(strings.TrimSpace(algorithm))

	// Direct match first
	if r, ok := remediationDB[algorithm]; ok {
		return enrichWithEcosystem(&r, ecosystem)
	}

	// Pattern matching for common variants
	patterns := []struct {
		contains string
		key      string
	}{
		// Post-quantum algorithms (check first)
		{"ML-KEM", "ML-KEM"},
		{"MLKEM", "ML-KEM"},
		{"ML-DSA", "ML-DSA"},
		{"MLDSA", "ML-DSA"},
		{"SLH-DSA", "SLH-DSA"},
		{"SLHDSA", "SLH-DSA"},
		// Key exchange
		{"RSA-OAEP", "RSA-OAEP"},
		{"RSA-PSS", "RSA-PSS"},
		{"RSA", "RSA"},
		{"ECDH-ES", "ECDH-ES"},
		{"ECDH", "ECDH"},
		{"ECDSA", "ECDSA"},
		{"ED25519", "Ed25519"},
		{"ED448", "Ed448"},
		{"X25519", "X25519"},
		{"CURVE25519", "X25519"},
		{"DIFFIE-HELLMAN", "DH"},
		// NIST curves
		{"SECP256K1", "secp256k1"},
		{"P-521", "P-521"},
		{"P-384", "P-384"},
		{"P-256", "P-256"},
		// Symmetric encryption
		{"A256GCM", "A256GCM"},
		{"AES-256-GCM", "AES-256"},
		{"AES-GCM", "AES-GCM"},
		{"AES-256", "AES-256"},
		{"AES-128", "AES-128"},
		{"AES-192", "AES-192"},
		{"AES", "AES"},
		{"CHACHA20-POLY1305", "ChaCha20-Poly1305"},
		{"CHACHA20POLY1305", "ChaCha20-Poly1305"},
		{"CHACHA20", "ChaCha20"},
		{"CHACHA", "ChaCha20"},
		{"XSALSA20-POLY1305", "XSalsa20-Poly1305"},
		{"XSALSA20POLY1305", "XSalsa20-Poly1305"},
		{"XSALSA20", "XSalsa20"},
		{"3DES", "3DES"},
		{"TRIPLE-DES", "3DES"},
		{"TRIPLEDES", "3DES"},
		{"BLOWFISH", "Blowfish"},
		{"DES", "DES"},
		// Chinese algorithms
		{"SM2", "SM2"},
		{"SM3", "SM3"},
		{"SM4", "SM4"},
		// Hash functions
		{"BLAKE3", "BLAKE3"},
		{"BLAKE2B", "BLAKE2b"},
		{"BLAKE2S", "BLAKE2s"},
		{"SHA-512", "SHA-512"},
		{"SHA512", "SHA-512"},
		{"SHA-384", "SHA-384"},
		{"SHA384", "SHA-384"},
		{"SHA-256", "SHA-256"},
		{"SHA256", "SHA-256"},
		{"SHA3-256", "SHA3-256"},
		{"SHA-1", "SHA-1"},
		{"SHA1", "SHA-1"},
		{"MD5", "MD5"},
		// MACs
		{"HMAC-SHA512", "HMAC-SHA512"},
		{"HMAC-SHA256", "HMAC-SHA256"},
		{"HMAC-SHA1", "HMAC-SHA1"},
		{"HMAC", "HMAC"},
		{"POLY1305", "Poly1305"},
		// Password hashing
		{"BCRYPT", "bcrypt"},
		{"SCRYPT", "scrypt"},
		{"ARGON2", "Argon2"},
		{"PBKDF2", "PBKDF2"},
		// JWT algorithms
		{"PS256", "PS256"},
		{"PS384", "PS384"},
		{"PS512", "PS512"},
		{"RS256", "RS256"},
		{"RS384", "RS384"},
		{"RS512", "RS512"},
		{"ES256", "ES256"},
		{"ES384", "ES384"},
		{"ES512", "ES512"},
		{"HS256", "HS256"},
		{"HS384", "HS384"},
		{"HS512", "HS512"},
		{"EDDSA", "EdDSA"},
		{"DSA", "DSA"},
	}

	for _, p := range patterns {
		if strings.Contains(algo, p.contains) {
			if r, ok := remediationDB[p.key]; ok {
				return enrichWithEcosystem(&r, ecosystem)
			}
		}
	}

	// Default remediation for unknown algorithms
	return &Remediation{
		Summary:     "Review algorithm for quantum vulnerability",
		Replacement: "Consult NIST PQC guidelines",
		Timeline:    "unknown",
		Effort:      "unknown",
		Notes:       "This algorithm was not found in the remediation database. Please review manually.",
	}
}

// enrichWithEcosystem returns a copy with ecosystem-specific library recommendations
func enrichWithEcosystem(r *Remediation, ecosystem types.Ecosystem) *Remediation {
	result := *r // Copy
	return &result
}

// GetRemediationSummary returns a concise one-line remediation string for display.
// It first checks the comprehensive remediation database, then falls back to
// the simpler algorithm database.
func GetRemediationSummary(algorithm string, cryptoType string, ecosystem types.Ecosystem) string {
	// Try detailed remediation first
	r := GetDetailedRemediation(algorithm, cryptoType, ecosystem)
	if r != nil && r.Summary != "" {
		return r.Summary
	}

	// Fall back to simple remediation from algorithm database
	return GetRemediation(algorithm)
}

// GetLibraryRecommendations returns PQC library recommendations for an ecosystem.
func GetLibraryRecommendations(algorithm string, ecosystem types.Ecosystem) []string {
	r := GetDetailedRemediation(algorithm, "", ecosystem)
	if r == nil || r.Libraries == nil {
		return nil
	}
	return r.Libraries[ecosystem]
}
