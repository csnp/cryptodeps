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

// NPMClient fetches packages from the npm registry.
type NPMClient struct {
	httpClient *http.Client
	baseURL    string
}

// NewNPMClient creates a new npm registry client.
func NewNPMClient() *NPMClient {
	return &NPMClient{
		httpClient: &http.Client{Timeout: 30 * time.Second},
		baseURL:    "https://registry.npmjs.org",
	}
}

func (c *NPMClient) Name() string {
	return "npm"
}

func (c *NPMClient) Ecosystem() types.Ecosystem {
	return types.EcosystemNPM
}

// npmSearchResponse represents the npm search API response.
type npmSearchResponse struct {
	Objects []struct {
		Package struct {
			Name        string   `json:"name"`
			Version     string   `json:"version"`
			Description string   `json:"description"`
			Keywords    []string `json:"keywords"`
			Links       struct {
				Repository string `json:"repository"`
			} `json:"links"`
			Publisher struct {
				Username string `json:"username"`
			} `json:"publisher"`
		} `json:"package"`
		Score struct {
			Final float64 `json:"final"`
		} `json:"score"`
		Downloads struct {
			Weekly int64 `json:"weekly"`
		} `json:"downloads,omitempty"`
	} `json:"objects"`
	Total int `json:"total"`
}

// SearchCrypto searches npm for crypto-related packages.
func (c *NPMClient) SearchCrypto(ctx context.Context) ([]PackageInfo, error) {
	searchTerms := []string{
		"crypto", "encryption", "cryptography",
		"cipher", "jwt", "jose",
		"bcrypt", "argon2", "scrypt",
		"pgp", "nacl", "tls",
	}

	seen := make(map[string]bool)
	var packages []PackageInfo

	for _, term := range searchTerms {
		results, err := c.search(ctx, term)
		if err != nil {
			continue // Skip failed searches, try others
		}

		for _, pkg := range results {
			if seen[pkg.Name] {
				continue
			}
			seen[pkg.Name] = true

			// Verify it's actually crypto-related
			if isCryptoRelated(pkg.Name, pkg.Description, pkg.Keywords) {
				packages = append(packages, pkg)
			}
		}
	}

	return packages, nil
}

func (c *NPMClient) search(ctx context.Context, query string) ([]PackageInfo, error) {
	searchURL := fmt.Sprintf("%s/-/v1/search?text=%s&size=100&quality=0.5&popularity=0.5&maintenance=0.0",
		c.baseURL, url.QueryEscape(query))

	req, err := http.NewRequestWithContext(ctx, "GET", searchURL, nil)
	if err != nil {
		return nil, err
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("npm search returned status %d", resp.StatusCode)
	}

	var searchResp npmSearchResponse
	if err := json.NewDecoder(resp.Body).Decode(&searchResp); err != nil {
		return nil, err
	}

	var packages []PackageInfo
	for _, obj := range searchResp.Objects {
		packages = append(packages, PackageInfo{
			Name:        obj.Package.Name,
			Version:     obj.Package.Version,
			Description: obj.Package.Description,
			Ecosystem:   types.EcosystemNPM,
			Keywords:    obj.Package.Keywords,
			Repository:  obj.Package.Links.Repository,
		})
	}

	return packages, nil
}
