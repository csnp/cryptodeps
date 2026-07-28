// Copyright 2025-2026 CyberSecurity NonProfit (CSNP)
// SPDX-License-Identifier: Apache-2.0

// Package registry fetches crypto package information from package registries.
package registry

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/csnp/qramm-cryptodeps/pkg/types"
)

// PackageInfo contains information about a package from a registry.
type PackageInfo struct {
	Name        string
	Version     string
	Description string
	Ecosystem   types.Ecosystem
	Downloads   int64
	Repository  string
	Keywords    []string
	License     string
	UpdatedAt   time.Time
}

// Client defines the interface for registry clients.
type Client interface {
	// Name returns the registry name.
	Name() string
	// Ecosystem returns the ecosystem this client handles.
	Ecosystem() types.Ecosystem
	// SearchCrypto searches for crypto-related packages.
	SearchCrypto(ctx context.Context) ([]PackageInfo, error)
}

// Fetcher aggregates results from multiple registry clients.
type Fetcher struct {
	clients []Client
	timeout time.Duration
}

// NewFetcher creates a new registry fetcher with all supported clients.
func NewFetcher() *Fetcher {
	return &Fetcher{
		clients: []Client{
			NewNPMClient(),
			NewPyPIClient(),
			NewGoClient(),
			NewMavenClient(),
		},
		timeout: 60 * time.Second,
	}
}

// FetchResult contains results from a single registry.
type FetchResult struct {
	Ecosystem types.Ecosystem
	Packages  []PackageInfo
	Error     error
}

// FetchAll fetches crypto packages from all registries concurrently.
func (f *Fetcher) FetchAll(ctx context.Context) ([]PackageInfo, []error) {
	ctx, cancel := context.WithTimeout(ctx, f.timeout)
	defer cancel()

	var wg sync.WaitGroup
	results := make(chan FetchResult, len(f.clients))

	for _, client := range f.clients {
		wg.Add(1)
		go func(c Client) {
			defer wg.Done()
			packages, err := c.SearchCrypto(ctx)
			results <- FetchResult{
				Ecosystem: c.Ecosystem(),
				Packages:  packages,
				Error:     err,
			}
		}(client)
	}

	go func() {
		wg.Wait()
		close(results)
	}()

	var allPackages []PackageInfo
	var errors []error

	for result := range results {
		if result.Error != nil {
			errors = append(errors, fmt.Errorf("%s: %w", result.Ecosystem, result.Error))
			continue
		}
		allPackages = append(allPackages, result.Packages...)
	}

	return allPackages, errors
}

// cryptoKeywords are terms that indicate a package is crypto-related.
var cryptoKeywords = []string{
	"crypto", "cryptography", "encryption", "decrypt",
	"cipher", "aes", "rsa", "ecdsa", "ed25519",
	"sha256", "sha512", "hash", "hmac", "pbkdf",
	"jwt", "jws", "jwe", "jose",
	"tls", "ssl", "certificate", "x509",
	"bcrypt", "scrypt", "argon2",
	"pgp", "gpg", "openpgp",
	"nacl", "sodium", "curve25519",
	"ecdh", "diffie-hellman", "key-exchange",
	"signature", "signing", "verify",
	"pem", "pkcs", "asn1",
	"random", "prng", "csprng",
	"post-quantum", "pqc", "kyber", "dilithium",
}

// isCryptoRelated checks if a package appears to be crypto-related.
func isCryptoRelated(name, description string, keywords []string) bool {
	// Check package name
	nameLower := toLowerCase(name)
	for _, kw := range cryptoKeywords {
		if containsWord(nameLower, kw) {
			return true
		}
	}

	// Check description
	descLower := toLowerCase(description)
	for _, kw := range cryptoKeywords {
		if containsWord(descLower, kw) {
			return true
		}
	}

	// Check keywords
	for _, keyword := range keywords {
		kwLower := toLowerCase(keyword)
		for _, cryptoKw := range cryptoKeywords {
			if kwLower == cryptoKw || containsWord(kwLower, cryptoKw) {
				return true
			}
		}
	}

	return false
}

func toLowerCase(s string) string {
	result := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		result[i] = c
	}
	return string(result)
}

func containsWord(s, word string) bool {
	if len(word) > len(s) {
		return false
	}
	for i := 0; i <= len(s)-len(word); i++ {
		if s[i:i+len(word)] == word {
			// Check word boundaries
			before := i == 0 || !isAlphaNum(s[i-1])
			after := i+len(word) == len(s) || !isAlphaNum(s[i+len(word)])
			if before && after {
				return true
			}
			// Also match as substring for compound words
			if i > 0 && s[i-1] == '-' {
				return true
			}
			if i+len(word) < len(s) && s[i+len(word)] == '-' {
				return true
			}
		}
	}
	// Fallback: simple substring match for short keywords
	if len(word) >= 4 {
		for i := 0; i <= len(s)-len(word); i++ {
			if s[i:i+len(word)] == word {
				return true
			}
		}
	}
	return false
}

func isAlphaNum(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
}
