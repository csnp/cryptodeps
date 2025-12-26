// Copyright 2024-2025 CSNP (csnp.org)
// SPDX-License-Identifier: Apache-2.0

package analyzer

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// GitHubRepo represents a parsed GitHub repository URL.
type GitHubRepo struct {
	Owner  string
	Repo   string
	Branch string // optional, defaults to default branch
	Path   string // optional, subpath in repo
}

// githubPatterns matches various GitHub URL formats
var githubPatterns = []*regexp.Regexp{
	// https://github.com/owner/repo
	regexp.MustCompile(`^https?://github\.com/([^/]+)/([^/]+?)(?:\.git)?/?$`),
	// https://github.com/owner/repo/tree/branch
	regexp.MustCompile(`^https?://github\.com/([^/]+)/([^/]+)/tree/([^/]+)(?:/(.*))?$`),
	// github.com/owner/repo (no protocol)
	regexp.MustCompile(`^github\.com/([^/]+)/([^/]+?)(?:\.git)?/?$`),
	// owner/repo shorthand
	regexp.MustCompile(`^([a-zA-Z0-9_-]+)/([a-zA-Z0-9_.-]+)$`),
}

// IsGitHubURL checks if the path looks like a GitHub URL or shorthand.
// It returns false if the path exists as a local file/directory.
func IsGitHubURL(path string) bool {
	// If the path exists locally, it's not a GitHub URL
	if _, err := os.Stat(path); err == nil {
		return false
	}

	// Explicit GitHub URLs always match
	if strings.HasPrefix(path, "https://github.com/") ||
		strings.HasPrefix(path, "http://github.com/") ||
		strings.HasPrefix(path, "github.com/") {
		return true
	}

	// Check shorthand pattern (owner/repo) - but only if it looks like a valid repo
	// and not like a local path (no dots except in repo name, no slashes beyond owner/repo)
	shorthandPattern := regexp.MustCompile(`^([a-zA-Z0-9_-]+)/([a-zA-Z0-9_.-]+)$`)
	if shorthandPattern.MatchString(path) {
		// Additional check: if it contains path-like segments, it's probably local
		parts := strings.Split(path, "/")
		if len(parts) == 2 {
			// Looks like owner/repo shorthand
			return true
		}
	}

	return false
}

// ParseGitHubURL parses a GitHub URL into its components.
func ParseGitHubURL(url string) (*GitHubRepo, error) {
	for _, pattern := range githubPatterns {
		matches := pattern.FindStringSubmatch(url)
		if matches != nil {
			repo := &GitHubRepo{
				Owner: matches[1],
				Repo:  strings.TrimSuffix(matches[2], ".git"),
			}
			if len(matches) > 3 && matches[3] != "" {
				repo.Branch = matches[3]
			}
			if len(matches) > 4 && matches[4] != "" {
				repo.Path = matches[4]
			}
			return repo, nil
		}
	}
	return nil, fmt.Errorf("invalid GitHub URL: %s", url)
}

// FetchGitHubManifests downloads manifest files from a GitHub repository.
// Returns a temporary directory containing the manifest files.
func FetchGitHubManifests(repo *GitHubRepo) (string, error) {
	// Create temp directory
	tempDir, err := os.MkdirTemp("", "cryptodeps-github-*")
	if err != nil {
		return "", fmt.Errorf("failed to create temp directory: %w", err)
	}

	// Get default branch if not specified
	branch := repo.Branch
	if branch == "" {
		branch, err = getDefaultBranch(repo.Owner, repo.Repo)
		if err != nil {
			os.RemoveAll(tempDir)
			return "", err
		}
	}

	// List of manifest files to look for
	manifests := []string{
		"go.mod",
		"go.sum",
		"package.json",
		"package-lock.json",
		"requirements.txt",
		"pyproject.toml",
		"pom.xml",
	}

	// Prepend path if specified
	basePath := repo.Path
	if basePath != "" && !strings.HasSuffix(basePath, "/") {
		basePath += "/"
	}

	found := false
	for _, manifest := range manifests {
		remotePath := basePath + manifest
		content, err := fetchRawFile(repo.Owner, repo.Repo, branch, remotePath)
		if err != nil {
			continue // File doesn't exist, try next
		}

		// Write to temp directory
		localPath := filepath.Join(tempDir, manifest)
		if err := os.WriteFile(localPath, content, 0644); err != nil {
			os.RemoveAll(tempDir)
			return "", fmt.Errorf("failed to write %s: %w", manifest, err)
		}
		found = true
	}

	if !found {
		os.RemoveAll(tempDir)
		return "", fmt.Errorf("no supported manifest files found in %s/%s", repo.Owner, repo.Repo)
	}

	return tempDir, nil
}

// getDefaultBranch fetches the default branch of a repository.
func getDefaultBranch(owner, repo string) (string, error) {
	url := fmt.Sprintf("https://api.github.com/repos/%s/%s", owner, repo)

	client := &http.Client{Timeout: 30 * time.Second}
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("Accept", "application/vnd.github.v3+json")
	req.Header.Set("User-Agent", "CryptoDeps/1.0")

	// Use GitHub token if available
	if token := os.Getenv("GITHUB_TOKEN"); token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to fetch repo info: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("GitHub API error: %s", resp.Status)
	}

	var repoInfo struct {
		DefaultBranch string `json:"default_branch"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&repoInfo); err != nil {
		return "", fmt.Errorf("failed to parse repo info: %w", err)
	}

	return repoInfo.DefaultBranch, nil
}

// fetchRawFile downloads a raw file from GitHub.
func fetchRawFile(owner, repo, branch, path string) ([]byte, error) {
	url := fmt.Sprintf("https://raw.githubusercontent.com/%s/%s/%s/%s", owner, repo, branch, path)

	client := &http.Client{Timeout: 30 * time.Second}
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("User-Agent", "CryptoDeps/1.0")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("file not found: %s", path)
	}

	return io.ReadAll(resp.Body)
}

// CleanupTempDir removes a temporary directory created by FetchGitHubManifests.
func CleanupTempDir(dir string) {
	if strings.Contains(dir, "cryptodeps-github-") {
		os.RemoveAll(dir)
	}
}
