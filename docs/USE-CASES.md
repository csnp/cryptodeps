# Background

The problem CryptoDeps helps with, how it compares with other tools, and the standards behind its guidance. Start with the [README](../README.md) if you are new to CryptoDeps.

## The Quantum Computing Challenge

Quantum computers will break RSA, ECDSA, and Diffie-Hellman within the next decade. This isn't speculation: the NSA, NIST, and major technology companies are already migrating to post-quantum cryptography (PQC).

The challenge? **You can't migrate what you can't find.**

Your code might be quantum-safe, but what about your **dependencies**? The average software project has 300-1000+ transitive dependencies. Each one potentially uses cryptographic algorithms that quantum computers will break. Traditional security scanners miss this: they focus on CVEs, not cryptographic readiness.

What CryptoDeps reads in each ecosystem is described in the [README](../README.md#what-it-finds).

## Why CryptoDeps

CryptoDeps is purpose-built for quantum readiness assessment:

| Capability | CryptoDeps | grep/ripgrep | Commercial Tools |
|------------|------------|--------------|------------------|
| Declared dependency analysis | Yes | No | Some |
| Reachability analysis | Yes (Go) | No | Rarely |
| Quantum risk classification | Yes | No | Some |
| Context-aware confidence | Yes | No | Varies |
| CBOM output | Yes | No | Rarely |
| SARIF for GitHub Security | Yes | No | Yes |
| GitHub URL scanning | Yes | No | Some |
| Migration guidance | Yes | No | Varies |
| Multi-ecosystem support | Yes | Manual | Varies |
| Open source | Yes | Yes | No |
| Price | Free | Free | $$ |

### What These Capabilities Mean

- **Declared dependency analysis**: Scans what your manifests declare. Go `// indirect` requirements are included, so a tidied `go.mod` covers the closure; npm, Python and Maven are direct-only because lock files are not parsed
- **Reachability analysis**: Traces call graphs to find crypto your code actually invokes
- **Quantum risk classification**: Categorizes by threat level (VULNERABLE, PARTIAL, SAFE)
- **Context-aware confidence**: Distinguishes confirmed usage from mere availability
- **CBOM output**: Cryptographic Bill of Materials for OMB M-23-02 compliance
- **SARIF output**: Integrates with GitHub Security tab
- **GitHub URL scanning**: Analyze any public/private GitHub repository directly
- **Migration guidance**: Actionable recommendations with NIST standards references
- **Multi-ecosystem support**: Go, npm, Python, Maven from a single tool

## References

### NIST Post-Quantum Cryptography Standards

- [FIPS 203 - ML-KEM](https://csrc.nist.gov/pubs/fips/203/final): Module-Lattice-Based Key-Encapsulation Mechanism (replaces RSA/ECDH)
- [FIPS 204 - ML-DSA](https://csrc.nist.gov/pubs/fips/204/final): Module-Lattice-Based Digital Signature Algorithm (replaces RSA/ECDSA)
- [FIPS 205 - SLH-DSA](https://csrc.nist.gov/pubs/fips/205/final): Stateless Hash-Based Digital Signature Algorithm
- [NIST SP 800-131A Rev 2](https://csrc.nist.gov/publications/detail/sp/800-131a/rev-2/final): Transitioning cryptographic algorithms and key lengths

### Additional Resources

- [NSA CNSA 2.0](https://media.defense.gov/2022/Sep/07/2003071834/-1/-1/0/CSA_CNSA_2.0_ALGORITHMS_.PDF): Commercial National Security Algorithm Suite
- [OMB M-23-02](https://www.whitehouse.gov/wp-content/uploads/2022/11/M-23-02-M-Memo-on-Migrating-to-Post-Quantum-Cryptography.pdf): Federal PQC Migration Requirements
- [CISA Post-Quantum Cryptography Initiative](https://www.cisa.gov/quantum)
- [CycloneDX CBOM](https://cyclonedx.org/capabilities/cbom/): Cryptographic Bill of Materials
