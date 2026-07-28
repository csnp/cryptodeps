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

// MavenClient fetches packages from Maven Central.
type MavenClient struct {
	httpClient *http.Client
	baseURL    string
}

// NewMavenClient creates a new Maven Central client.
func NewMavenClient() *MavenClient {
	return &MavenClient{
		httpClient: &http.Client{Timeout: 30 * time.Second},
		baseURL:    "https://search.maven.org",
	}
}

func (c *MavenClient) Name() string {
	return "maven"
}

func (c *MavenClient) Ecosystem() types.Ecosystem {
	return types.EcosystemMaven
}

// mavenSearchResponse represents Maven Central search results.
type mavenSearchResponse struct {
	Response struct {
		NumFound int `json:"numFound"`
		Docs     []struct {
			ID             string `json:"id"`
			Group          string `json:"g"`
			Artifact       string `json:"a"`
			LatestVersion  string `json:"latestVersion"`
			RepositoryID   string `json:"repositoryId"`
			Timestamp      int64  `json:"timestamp"`
			VersionCount   int    `json:"versionCount"`
			Text           []string `json:"text"`
		} `json:"docs"`
	} `json:"response"`
}

// SearchCrypto searches Maven Central for crypto-related packages.
func (c *MavenClient) SearchCrypto(ctx context.Context) ([]PackageInfo, error) {
	searchTerms := []string{
		"crypto", "encryption", "cipher",
		"bouncy castle", "bouncycastle",
		"jwt", "jose", "jjwt",
		"bcrypt", "argon2", "scrypt",
		"pgp", "openpgp",
		"tls", "ssl",
	}

	seen := make(map[string]bool)
	var packages []PackageInfo

	for _, term := range searchTerms {
		results, err := c.search(ctx, term)
		if err != nil {
			continue
		}

		for _, pkg := range results {
			key := pkg.Name
			if seen[key] {
				continue
			}
			seen[key] = true
			packages = append(packages, pkg)
		}
	}

	// Also add well-known packages directly
	knownPackages := []struct {
		group    string
		artifact string
	}{
		{"org.bouncycastle", "bcprov-jdk18on"},
		{"org.bouncycastle", "bcpkix-jdk18on"},
		{"org.bouncycastle", "bcpg-jdk18on"},
		{"io.jsonwebtoken", "jjwt-api"},
		{"com.auth0", "java-jwt"},
		{"com.nimbusds", "nimbus-jose-jwt"},
		{"org.springframework.security", "spring-security-crypto"},
		{"at.favre.lib", "bcrypt"},
		{"de.mkammerer", "argon2-jvm"},
		{"com.google.crypto.tink", "tink"},
		{"org.apache.shiro", "shiro-crypto-cipher"},
		{"org.jasypt", "jasypt"},
		{"com.lambdaworks", "scrypt"},
		{"org.mindrot", "jbcrypt"},
		{"javax.crypto", "jce"},
	}

	for _, known := range knownPackages {
		key := known.group + ":" + known.artifact
		if seen[key] {
			continue
		}
		seen[key] = true

		pkg, err := c.getPackage(ctx, known.group, known.artifact)
		if err != nil {
			continue
		}
		packages = append(packages, pkg)
	}

	return packages, nil
}

func (c *MavenClient) search(ctx context.Context, query string) ([]PackageInfo, error) {
	searchURL := fmt.Sprintf("%s/solrsearch/select?q=%s&rows=50&wt=json",
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
		return nil, fmt.Errorf("maven search returned status %d", resp.StatusCode)
	}

	var searchResp mavenSearchResponse
	if err := json.NewDecoder(resp.Body).Decode(&searchResp); err != nil {
		return nil, err
	}

	var packages []PackageInfo
	for _, doc := range searchResp.Response.Docs {
		// Filter for crypto-related packages
		name := doc.Group + ":" + doc.Artifact
		desc := ""
		if len(doc.Text) > 0 {
			desc = doc.Text[0]
		}

		if !isCryptoRelated(name, desc, nil) {
			continue
		}

		packages = append(packages, PackageInfo{
			Name:        name,
			Version:     doc.LatestVersion,
			Description: desc,
			Ecosystem:   types.EcosystemMaven,
			UpdatedAt:   time.Unix(doc.Timestamp/1000, 0),
		})
	}

	return packages, nil
}

func (c *MavenClient) getPackage(ctx context.Context, group, artifact string) (PackageInfo, error) {
	searchURL := fmt.Sprintf("%s/solrsearch/select?q=g:%%22%s%%22+AND+a:%%22%s%%22&rows=1&wt=json",
		c.baseURL, url.QueryEscape(group), url.QueryEscape(artifact))

	req, err := http.NewRequestWithContext(ctx, "GET", searchURL, nil)
	if err != nil {
		return PackageInfo{}, err
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return PackageInfo{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return PackageInfo{}, fmt.Errorf("maven returned status %d", resp.StatusCode)
	}

	var searchResp mavenSearchResponse
	if err := json.NewDecoder(resp.Body).Decode(&searchResp); err != nil {
		return PackageInfo{}, err
	}

	if len(searchResp.Response.Docs) == 0 {
		return PackageInfo{}, fmt.Errorf("package not found: %s:%s", group, artifact)
	}

	doc := searchResp.Response.Docs[0]
	desc := ""
	if len(doc.Text) > 0 {
		desc = doc.Text[0]
	}

	return PackageInfo{
		Name:        group + ":" + artifact,
		Version:     doc.LatestVersion,
		Description: desc,
		Ecosystem:   types.EcosystemMaven,
		UpdatedAt:   time.Unix(doc.Timestamp/1000, 0),
	}, nil
}
