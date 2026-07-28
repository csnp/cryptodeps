// Copyright 2025-2026 CyberSecurity NonProfit (CSNP)
// SPDX-License-Identifier: Apache-2.0

package registry

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/csnp/qramm-cryptodeps/pkg/types"
)

// GoClient fetches packages from the Go ecosystem.
type GoClient struct {
	httpClient *http.Client
	proxyURL   string
}

// NewGoClient creates a new Go module client.
func NewGoClient() *GoClient {
	return &GoClient{
		httpClient: &http.Client{Timeout: 30 * time.Second},
		proxyURL:   "https://proxy.golang.org",
	}
}

func (c *GoClient) Name() string {
	return "go"
}

func (c *GoClient) Ecosystem() types.Ecosystem {
	return types.EcosystemGo
}

// SearchCrypto returns known crypto-related Go packages.
// The Go module proxy doesn't have a search API, so we maintain a list
// of known crypto packages and verify they exist.
func (c *GoClient) SearchCrypto(ctx context.Context) ([]PackageInfo, error) {
	knownPackages := []string{
		// Standard library extensions
		"golang.org/x/crypto",

		// Popular crypto libraries
		"github.com/cloudflare/circl",
		"github.com/ProtonMail/go-crypto",
		"filippo.io/age",
		"filippo.io/edwards25519",

		// JWT libraries
		"github.com/golang-jwt/jwt/v5",
		"github.com/golang-jwt/jwt/v4",
		"github.com/lestrrat-go/jwx/v2",
		"github.com/go-jose/go-jose/v3",
		"gopkg.in/square/go-jose.v2",

		// TLS/Certificate
		"github.com/cloudflare/cfssl",
		"github.com/smallstep/certificates",
		"github.com/caddyserver/certmagic",

		// Password hashing
		"golang.org/x/crypto/bcrypt",
		"golang.org/x/crypto/argon2",
		"golang.org/x/crypto/scrypt",
		"github.com/alexedwards/argon2id",

		// Encryption
		"github.com/minio/sio",
		"github.com/secure-io/sio-go",
		"golang.org/x/crypto/nacl",
		"golang.org/x/crypto/chacha20poly1305",

		// SSH
		"golang.org/x/crypto/ssh",
		"github.com/gliderlabs/ssh",

		// PGP/GPG
		"github.com/ProtonMail/gopenpgp/v2",
		"golang.org/x/crypto/openpgp",

		// Random
		"crypto/rand",

		// Post-quantum
		"github.com/cloudflare/circl/kem",
		"github.com/cloudflare/circl/sign",
		"github.com/open-quantum-safe/liboqs-go",

		// Misc crypto
		"github.com/gtank/cryptopasta",
		"github.com/awnumar/memguard",
		"github.com/hashicorp/vault/api",
		"github.com/aws/aws-sdk-go-v2/service/kms",
		"cloud.google.com/go/kms",
	}

	var packages []PackageInfo
	for _, path := range knownPackages {
		pkg, err := c.getPackage(ctx, path)
		if err != nil {
			continue
		}
		packages = append(packages, pkg)
	}

	return packages, nil
}

func (c *GoClient) getPackage(ctx context.Context, modulePath string) (PackageInfo, error) {
	// Get latest version from proxy
	listURL := fmt.Sprintf("%s/%s/@latest", c.proxyURL, modulePath)

	req, err := http.NewRequestWithContext(ctx, "GET", listURL, nil)
	if err != nil {
		return PackageInfo{}, err
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return PackageInfo{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return PackageInfo{}, fmt.Errorf("go proxy returned status %d for %s", resp.StatusCode, modulePath)
	}

	var info struct {
		Version string    `json:"Version"`
		Time    time.Time `json:"Time"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
		return PackageInfo{}, err
	}

	return PackageInfo{
		Name:        modulePath,
		Version:     info.Version,
		Description: "", // Go proxy doesn't provide descriptions
		Ecosystem:   types.EcosystemGo,
		UpdatedAt:   info.Time,
	}, nil
}
