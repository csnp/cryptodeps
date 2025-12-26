// Copyright 2024-2025 CSNP (csnp.org)
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
		{"RSA", "RSA"},
		{"ECDSA", "ECDSA"},
		{"ECDH", "ECDH"},
		{"ED25519", "Ed25519"},
		{"ED448", "Ed448"},
		{"X25519", "X25519"},
		{"CURVE25519", "X25519"},
		{"DIFFIE-HELLMAN", "DH"},
		{"AES-256", "AES-256"},
		{"AES-128", "AES-128"},
		{"AES-192", "AES-192"},
		{"CHACHA20", "ChaCha20"},
		{"CHACHA", "ChaCha20"},
		{"3DES", "3DES"},
		{"TRIPLE-DES", "3DES"},
		{"TRIPLEDES", "3DES"},
		{"BLOWFISH", "Blowfish"},
		{"SHA-512", "SHA-512"},
		{"SHA512", "SHA-512"},
		{"SHA-384", "SHA-384"},
		{"SHA384", "SHA-384"},
		{"SHA-256", "SHA-256"},
		{"SHA256", "SHA-256"},
		{"SHA-1", "SHA-1"},
		{"SHA1", "SHA-1"},
		{"MD5", "MD5"},
		{"BCRYPT", "bcrypt"},
		{"SCRYPT", "scrypt"},
		{"ARGON2", "Argon2"},
		{"PBKDF2", "PBKDF2"},
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
		{"DES", "DES"},
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
