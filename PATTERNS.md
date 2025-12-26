# Detection Patterns

CryptoDeps uses a curated database of cryptographic patterns to identify quantum-vulnerable algorithms in your dependencies. This document describes the detection methodology and the patterns used.

## Detection Methodology

CryptoDeps combines two complementary approaches:

1. **Package Database** - A curated database of 1,100+ known cryptographic packages with verified algorithm signatures
2. **Import Pattern Matching** - Detection of crypto library imports across ecosystems for packages not in the database
3. **AST Analysis** - Language-specific parsing to identify actual crypto usage
4. **Reachability Analysis** - Call graph tracing to determine which crypto is actually invoked (Go only)

---

## Quantum Risk Classification

| Risk Level | Symbol | Quantum Threat | Examples |
|------------|--------|----------------|----------|
| **VULNERABLE** | `[!]` | Shor's algorithm completely breaks | RSA, ECDSA, Ed25519, ECDH, DH, DSA |
| **PARTIAL** | `[~]` | Grover's algorithm halves security | AES-128, SHA-256, HMAC-SHA256 |
| **SAFE** | `[OK]` | Quantum-resistant | AES-256, SHA-384+, ChaCha20, ML-KEM, ML-DSA |

---

## Algorithm Classifications

### Asymmetric Cryptography (VULNERABLE)

Completely broken by Shor's algorithm. Requires migration to post-quantum alternatives.

| Algorithm | Type | Severity | Remediation |
|-----------|------|----------|-------------|
| RSA | Encryption/Signature | High | ML-KEM (FIPS 203) or ML-DSA (FIPS 204) |
| RSA-2048 | Encryption/Signature | Medium | ML-KEM (FIPS 203) or ML-DSA (FIPS 204) |
| RSA-4096 | Encryption/Signature | Medium | ML-KEM (FIPS 203) or ML-DSA (FIPS 204) |
| ECDSA | Signature | High | ML-DSA (FIPS 204) or SLH-DSA (FIPS 205) |
| ECDH | Key Exchange | High | ML-KEM (FIPS 203) |
| Ed25519 | Signature | High | ML-DSA (FIPS 204) |
| Ed448 | Signature | High | ML-DSA (FIPS 204) |
| X25519 | Key Exchange | High | ML-KEM (FIPS 203) |
| DSA | Signature | High | ML-DSA (FIPS 204) |
| DH/DHE | Key Exchange | High | ML-KEM (FIPS 203) |
| P-256/P-384/P-521 | Elliptic Curves | High | ML-KEM (FIPS 203) |
| secp256k1 | Elliptic Curve | High | ML-KEM (FIPS 203) |

### JWT/JWS Algorithms (VULNERABLE)

Asymmetric JWT algorithms are quantum-vulnerable.

| Algorithm | Description | Severity | Remediation |
|-----------|-------------|----------|-------------|
| RS256 | RSA PKCS#1 v1.5 + SHA-256 | High | HS256/HS512 or wait for PQ-JWT |
| RS384 | RSA PKCS#1 v1.5 + SHA-384 | High | HS384/HS512 or wait for PQ-JWT |
| RS512 | RSA PKCS#1 v1.5 + SHA-512 | High | HS512 or wait for PQ-JWT |
| ES256 | ECDSA P-256 + SHA-256 | High | HS256/HS512 or wait for PQ-JWT |
| ES384 | ECDSA P-384 + SHA-384 | High | HS384/HS512 or wait for PQ-JWT |
| ES512 | ECDSA P-521 + SHA-512 | High | HS512 or wait for PQ-JWT |
| PS256 | RSA-PSS + SHA-256 | High | HS256/HS512 or wait for PQ-JWT |
| PS384 | RSA-PSS + SHA-384 | High | HS384/HS512 or wait for PQ-JWT |
| PS512 | RSA-PSS + SHA-512 | High | HS512 or wait for PQ-JWT |

### Symmetric Cryptography (PARTIAL/SAFE)

Security reduced by Grover's algorithm (halves effective key length).

| Algorithm | Risk | Severity | Post-Quantum Security | Remediation |
|-----------|------|----------|----------------------|-------------|
| AES-128 | PARTIAL | Low | 64-bit | Upgrade to AES-256 |
| AES-192 | PARTIAL | Info | 96-bit | Consider AES-256 |
| AES-256 | SAFE | Info | 128-bit | No action needed |
| AES-GCM | PARTIAL | Info | Depends on key size | Use AES-256-GCM |
| AES-CBC | PARTIAL | Info | Depends on key size | Use AES-256-GCM |
| ChaCha20 | SAFE | Info | 128-bit | No action needed |
| XChaCha20 | SAFE | Info | 128-bit | No action needed |
| Poly1305 | SAFE | Info | Quantum-safe | No action needed |

### HMAC Algorithms (PARTIAL/SAFE)

| Algorithm | Risk | Severity | Remediation |
|-----------|------|----------|-------------|
| HS256 | PARTIAL | Info | Consider HS512 for stronger security |
| HS384 | PARTIAL | Info | Consider HS512 for stronger security |
| HS512 | SAFE | Info | No action needed |
| HMAC-MD5 | VULNERABLE | Critical | Replace with HMAC-SHA256+ |
| HMAC-SHA1 | PARTIAL | Medium | Upgrade to HMAC-SHA256+ |
| HMAC-SHA256 | PARTIAL | Info | Consider HMAC-SHA512 |
| HMAC-SHA384 | SAFE | Info | No action needed |
| HMAC-SHA512 | SAFE | Info | No action needed |

### Hash Functions

| Algorithm | Risk | Severity | Remediation |
|-----------|------|----------|-------------|
| MD5 | VULNERABLE | Critical | Replace with SHA-256 or SHA-3 |
| SHA-1 | VULNERABLE | Critical | Replace with SHA-256 or SHA-3 |
| SHA-256 | PARTIAL | Info | Consider SHA-384/512 for long-term |
| SHA-384 | SAFE | Info | No action needed |
| SHA-512 | SAFE | Info | No action needed |
| SHA-3 | SAFE | Info | No action needed |
| BLAKE2 | SAFE | Info | No action needed |
| BLAKE3 | SAFE | Info | No action needed |

### Broken Classical Algorithms

These should be replaced regardless of quantum concerns.

| Algorithm | Risk | Severity | Remediation |
|-----------|------|----------|-------------|
| DES | VULNERABLE | Critical | Replace with AES-256 |
| 3DES | VULNERABLE | High | Replace with AES-256 |
| RC4 | VULNERABLE | Critical | Replace with AES-256 or ChaCha20 |
| RC2 | VULNERABLE | Critical | Replace with AES-256 |

### Post-Quantum Algorithms (SAFE)

NIST-standardized quantum-resistant algorithms.

| Algorithm | Type | Standard | Description |
|-----------|------|----------|-------------|
| ML-KEM | Key Exchange | FIPS 203 | Module-Lattice Key Encapsulation (Kyber) |
| ML-DSA | Signature | FIPS 204 | Module-Lattice Digital Signature (Dilithium) |
| SLH-DSA | Signature | FIPS 205 | Stateless Hash-Based Signature (SPHINCS+) |
| Kyber | Key Exchange | NIST | Pre-standardization name for ML-KEM |
| Dilithium | Signature | NIST | Pre-standardization name for ML-DSA |
| SPHINCS+ | Signature | NIST | Pre-standardization name for SLH-DSA |

---

## Import Patterns by Ecosystem

### Go

#### Standard Library

| Import | Description | Algorithms |
|--------|-------------|------------|
| `crypto/aes` | AES encryption | AES |
| `crypto/cipher` | Block cipher modes | AES-GCM, AES-CBC |
| `crypto/des` | DES encryption | DES, 3DES |
| `crypto/dsa` | DSA signatures | DSA |
| `crypto/ecdh` | ECDH key exchange | ECDH, X25519 |
| `crypto/ecdsa` | ECDSA signatures | ECDSA |
| `crypto/ed25519` | Ed25519 signatures | Ed25519 |
| `crypto/elliptic` | Elliptic curves | P-256, P-384, P-521 |
| `crypto/hmac` | HMAC | HMAC |
| `crypto/md5` | MD5 hash | MD5 |
| `crypto/rc4` | RC4 cipher | RC4 |
| `crypto/rsa` | RSA encryption | RSA |
| `crypto/sha1` | SHA-1 hash | SHA-1 |
| `crypto/sha256` | SHA-256 hash | SHA-256 |
| `crypto/sha512` | SHA-512 hash | SHA-512 |
| `crypto/tls` | TLS protocol | RSA, ECDSA, AES-GCM |
| `crypto/x509` | X.509 certificates | RSA, ECDSA |

#### Extended Library (golang.org/x/crypto)

| Import | Description | Algorithms |
|--------|-------------|------------|
| `x/crypto/bcrypt` | bcrypt hashing | bcrypt |
| `x/crypto/chacha20` | ChaCha20 cipher | ChaCha20 |
| `x/crypto/chacha20poly1305` | AEAD | ChaCha20, Poly1305 |
| `x/crypto/curve25519` | Curve25519 | X25519 |
| `x/crypto/ed25519` | Ed25519 | Ed25519 |
| `x/crypto/nacl` | NaCl crypto | X25519, XSalsa20, Poly1305 |
| `x/crypto/sha3` | SHA-3 hash | SHA3 |
| `x/crypto/argon2` | Argon2 KDF | Argon2 |
| `x/crypto/scrypt` | scrypt KDF | scrypt |
| `x/crypto/pbkdf2` | PBKDF2 KDF | PBKDF2 |
| `x/crypto/ssh` | SSH protocol | RSA, ECDSA, Ed25519 |

#### Third-Party

| Import | Description | Algorithms |
|--------|-------------|------------|
| `github.com/golang-jwt/jwt` | JWT library | RS256, ES256, HS256 |
| `github.com/dgrijalva/jwt-go` | JWT (deprecated) | RS256, ES256, HS256 |

### npm (Node.js)

#### Built-in Modules

| Import | Description |
|--------|-------------|
| `crypto` | Node.js crypto module |
| `node:crypto` | Node.js crypto module (ESM) |
| `tls` | Node.js TLS module |
| `node:tls` | Node.js TLS module (ESM) |

#### Third-Party

| Import | Description | Algorithms |
|--------|-------------|------------|
| `bcrypt` | bcrypt hashing | bcrypt |
| `bcryptjs` | bcrypt in pure JS | bcrypt |
| `crypto-js` | Crypto-JS library | AES, DES, 3DES, MD5, SHA-1, SHA-256 |
| `jsonwebtoken` | JWT library | RS256, ES256, HS256 |
| `jose` | JOSE/JWT library | RS256, ES256, HS256 |
| `node-rsa` | RSA library | RSA |
| `node-forge` | Forge crypto | RSA, AES, DES, MD5, SHA-1, SHA-256 |
| `tweetnacl` | TweetNaCl | X25519, Ed25519, XSalsa20 |
| `sodium-native` | libsodium bindings | X25519, Ed25519, ChaCha20 |
| `libsodium-wrappers` | libsodium WASM | X25519, Ed25519, ChaCha20 |
| `argon2` | Argon2 hashing | Argon2 |
| `scrypt` | scrypt KDF | scrypt |
| `pbkdf2` | PBKDF2 KDF | PBKDF2 |

### Python (PyPI)

#### Standard Library

| Import | Description | Algorithms |
|--------|-------------|------------|
| `hashlib` | Hash functions | MD5, SHA-1, SHA-256, SHA-512 |
| `hmac` | HMAC | HMAC |
| `ssl` | SSL/TLS | Various |
| `secrets` | Secure random | N/A |

#### Third-Party

| Import | Description | Algorithms |
|--------|-------------|------------|
| `cryptography` | PyCA cryptography | RSA, ECDSA, Ed25519, AES, ChaCha20 |
| `Crypto` | PyCrypto (deprecated) | RSA, AES, DES, MD5, SHA-1 |
| `Cryptodome` | PyCryptodome | RSA, ECDSA, AES, ChaCha20, MD5, SHA-1 |
| `nacl` / `pynacl` | PyNaCl | X25519, Ed25519, XSalsa20 |
| `bcrypt` | bcrypt hashing | bcrypt |
| `argon2` | Argon2 hashing | Argon2 |
| `passlib` | Password hashing | bcrypt, Argon2, PBKDF2, scrypt |
| `PyJWT` | JWT library | RS256, ES256, HS256 |
| `python-jose` | JOSE library | RS256, ES256, HS256 |
| `jwcrypto` | JWK/JWT library | RS256, ES256, HS256 |
| `paramiko` | SSH library | RSA, ECDSA, Ed25519 |

### Maven (Java)

#### Standard Library

| Import | Description |
|--------|-------------|
| `javax.crypto` | Java Crypto Extension |
| `java.security` | Java Security API |
| `javax.net.ssl` | Java SSL/TLS |

#### Third-Party

| Import | Description | Algorithms |
|--------|-------------|------------|
| `org.bouncycastle` | Bouncy Castle | RSA, ECDSA, Ed25519, AES, ChaCha20 |
| `io.jsonwebtoken` | JJWT library | RS256, ES256, HS256 |
| `com.auth0.jwt` | Auth0 JWT | RS256, ES256, HS256 |
| `com.nimbusds.jose` | Nimbus JOSE+JWT | RS256, ES256, HS256 |
| `com.google.crypto.tink` | Google Tink | AES-GCM, ChaCha20, ECDSA, Ed25519 |
| `org.apache.commons.codec` | Commons Codec | MD5, SHA-1, SHA-256 |
| `org.springframework.security.crypto` | Spring Security | bcrypt, Argon2, scrypt, PBKDF2 |

---

## Adding New Patterns

To add detection for a new package or algorithm:

1. **For package database entries**: Submit a PR adding the package to `data/crypto-database.json`
2. **For import patterns**: Submit a PR modifying `pkg/crypto/patterns.go`
3. **For algorithm classifications**: Submit a PR modifying `pkg/crypto/quantum.go`

See [CONTRIBUTING.md](CONTRIBUTING.md) for submission guidelines.

---

## References

- [NIST FIPS 203: ML-KEM](https://csrc.nist.gov/pubs/fips/203/final)
- [NIST FIPS 204: ML-DSA](https://csrc.nist.gov/pubs/fips/204/final)
- [NIST FIPS 205: SLH-DSA](https://csrc.nist.gov/pubs/fips/205/final)
- [NSA CNSA 2.0](https://media.defense.gov/2022/Sep/07/2003071834/-1/-1/0/CSA_CNSA_2.0_ALGORITHMS_.PDF)
