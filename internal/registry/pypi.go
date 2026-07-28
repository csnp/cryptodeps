// Copyright 2025-2026 CyberSecurity NonProfit (CSNP)
// SPDX-License-Identifier: Apache-2.0

package registry

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/csnp/qramm-cryptodeps/pkg/types"
)

// PyPIClient fetches packages from PyPI.
type PyPIClient struct {
	httpClient *http.Client
	baseURL    string
}

// NewPyPIClient creates a new PyPI client.
func NewPyPIClient() *PyPIClient {
	return &PyPIClient{
		httpClient: &http.Client{Timeout: 30 * time.Second},
		baseURL:    "https://pypi.org",
	}
}

func (c *PyPIClient) Name() string {
	return "pypi"
}

func (c *PyPIClient) Ecosystem() types.Ecosystem {
	return types.EcosystemPyPI
}

// pypiSearchResponse represents PyPI search results.
type pypiSearchResponse struct {
	Info struct {
		Name        string   `json:"name"`
		Version     string   `json:"version"`
		Summary     string   `json:"summary"`
		Keywords    string   `json:"keywords"`
		License     string   `json:"license"`
		ProjectURL  string   `json:"project_url"`
		Classifiers []string `json:"classifiers"`
	} `json:"info"`
}

// SearchCrypto searches PyPI for crypto-related packages.
func (c *PyPIClient) SearchCrypto(ctx context.Context) ([]PackageInfo, error) {
	// PyPI doesn't have a great search API, so we use known crypto packages
	// and verify they exist
	knownPackages := []string{
		"cryptography", "pycryptodome", "pycryptodomex",
		"PyNaCl", "bcrypt", "argon2-cffi", "passlib",
		"PyJWT", "python-jose", "jwcrypto", "authlib",
		"paramiko", "pyOpenSSL", "certifi", "ssl-cert-check",
		"hashlib", "hmac", "secrets",
		"ecdsa", "ed25519", "rsa", "pycrypto",
		"tinyec", "fastecdsa", "coincurve",
		"libnacl", "donna25519", "x25519",
		"pqcrypto", "liboqs-python", "kyber-py",
		"scrypt", "hashids", "itsdangerous",
		"fernet", "keyczar", "simple-crypt",
		"gnupg", "python-gnupg", "pgpy",
		"tlslite-ng", "pyopenssl",
		"oscrypto", "asn1crypto", "certvalidator",
	}

	var packages []PackageInfo
	for _, name := range knownPackages {
		pkg, err := c.getPackage(ctx, name)
		if err != nil {
			continue // Package might not exist or be unavailable
		}
		packages = append(packages, pkg)
	}

	return packages, nil
}

func (c *PyPIClient) getPackage(ctx context.Context, name string) (PackageInfo, error) {
	pkgURL := fmt.Sprintf("%s/pypi/%s/json", c.baseURL, url.PathEscape(name))

	req, err := http.NewRequestWithContext(ctx, "GET", pkgURL, nil)
	if err != nil {
		return PackageInfo{}, err
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return PackageInfo{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return PackageInfo{}, fmt.Errorf("pypi returned status %d for %s", resp.StatusCode, name)
	}

	var pypiResp pypiSearchResponse
	if err := json.NewDecoder(resp.Body).Decode(&pypiResp); err != nil {
		return PackageInfo{}, err
	}

	// Parse keywords from comma-separated string
	var keywords []string
	if pypiResp.Info.Keywords != "" {
		for _, kw := range splitKeywords(pypiResp.Info.Keywords) {
			if kw != "" {
				keywords = append(keywords, kw)
			}
		}
	}

	return PackageInfo{
		Name:        pypiResp.Info.Name,
		Version:     pypiResp.Info.Version,
		Description: pypiResp.Info.Summary,
		Ecosystem:   types.EcosystemPyPI,
		Keywords:    keywords,
		License:     pypiResp.Info.License,
		Repository:  pypiResp.Info.ProjectURL,
	}, nil
}

func splitKeywords(s string) []string {
	var result []string
	var current string
	for _, c := range s {
		if c == ',' || c == ' ' || c == ';' {
			if current != "" {
				result = append(result, current)
				current = ""
			}
		} else {
			current += string(c)
		}
	}
	if current != "" {
		result = append(result, current)
	}
	return result
}
