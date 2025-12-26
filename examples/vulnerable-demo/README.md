# Vulnerable Demo

This example demonstrates a typical application with mixed quantum vulnerability levels.
Use it to test CryptoDeps analysis capabilities.

## Usage

```bash
# From the project root
cryptodeps analyze examples/vulnerable-demo

# Or with JSON output
cryptodeps analyze examples/vulnerable-demo --format json
```

## Expected Output

The demo includes:

| Library | Algorithm | Quantum Risk | Notes |
|---------|-----------|--------------|-------|
| golang-jwt/jwt | RS256, ES256 | VULNERABLE | Broken by Shor's algorithm |
| x/crypto | Ed25519 | VULNERABLE | Elliptic curves broken by Shor |
| x/crypto | Argon2, bcrypt | SAFE | Memory-hard, quantum resistant |
| x/crypto | ChaCha20-Poly1305 | SAFE | 256-bit symmetric |
| cloudflare/circl | ML-KEM-768 | SAFE | NIST FIPS 203 post-quantum |

## Running the Demo Code

```bash
cd examples/vulnerable-demo
go run main.go
```

This will demonstrate each cryptographic operation with explanations.
