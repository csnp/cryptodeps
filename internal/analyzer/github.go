// Copyright 2025-2026 CyberSecurity NonProfit (CSNP)
// SPDX-License-Identifier: Apache-2.0

package analyzer

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/csnp/qramm-cryptodeps/internal/githubapi"
	"github.com/csnp/qramm-cryptodeps/internal/netguard"
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

// ResolveTarget decides what an analyze argument names, before anything else
// runs. It returns nil for a local path and the repository for an argument that
// is to be fetched from GitHub.
//
// Under --offline, an argument with no local file or directory of that name is
// an error. It used to be read as owner/repo before --offline was consulted, so
// a mistyped local path such as servics/api for services/api was sent to
// api.github.com, carrying GITHUB_TOKEN when that was set, and if a public
// repository of that name existed the scan reported on it instead.
func ResolveTarget(arg string) (*GitHubRepo, error) {
	if _, err := os.Stat(arg); err == nil || !errors.Is(err, fs.ErrNotExist) {
		// It exists, or it cannot be checked (a permission error, for
		// example). Either way it is a local path, and the analysis reports
		// what it finds there.
		return nil, nil
	}
	if netguard.Offline() {
		msg := fmt.Sprintf("No file or directory named %s.", arg)
		if IsGitHubURL(arg) {
			msg += " --offline does not fetch repositories."
		}
		return nil, errors.New(msg)
	}
	if !IsGitHubURL(arg) {
		return nil, nil
	}
	return ParseGitHubURL(arg)
}

// FetchNotice is the first line printed when an argument is fetched from
// GitHub. It says that no local path of that name was found, because the same
// argument names a local directory whenever one exists.
func FetchNotice(arg string, repo *GitHubRepo) string {
	return fmt.Sprintf("No file or directory named %s was found, so fetching the GitHub repository %s/%s instead...",
		arg, repo.Owner, repo.Repo)
}

// RepositoryURL is the canonical URL of the repository.
func (r *GitHubRepo) RepositoryURL() string {
	return "https://github.com/" + r.Owner + "/" + r.Repo
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

// githubClient carries every request to GitHub. It is built by netguard, so
// --offline refuses its connections whichever caller reaches it.
var githubClient = netguard.Client(30 * time.Second)

// FetchGitHubManifests downloads manifest files from a GitHub repository.
// It returns a temporary directory containing the manifest files, and the
// branch they were read from: the one the argument named, or the repository's
// default branch.
func FetchGitHubManifests(repo *GitHubRepo) (dir string, branch string, err error) {
	if err := netguard.Check("fetch " + repo.Owner + "/" + repo.Repo + " from GitHub"); err != nil {
		return "", "", err
	}

	// Create temp directory
	tempDir, err := os.MkdirTemp("", "cryptodeps-github-*")
	if err != nil {
		return "", "", fmt.Errorf("failed to create temp directory: %w", err)
	}

	// Get default branch if not specified
	branch = repo.Branch
	if branch == "" {
		branch, err = getDefaultBranch(repo.Owner, repo.Repo)
		if err != nil {
			os.RemoveAll(tempDir)
			return "", "", err
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
			return "", "", fmt.Errorf("failed to write %s: %w", manifest, err)
		}
		found = true
	}

	if !found {
		os.RemoveAll(tempDir)
		return "", "", fmt.Errorf("no supported manifest files found in %s/%s", repo.Owner, repo.Repo)
	}

	return tempDir, branch, nil
}

// githubAPI is the GitHub API the repository lookup uses. It is a variable so
// that a test can point it at a local server.
var githubAPI = "https://api.github.com"

// getDefaultBranch fetches the default branch of a repository.
func getDefaultBranch(owner, repo string) (string, error) {
	url := fmt.Sprintf("%s/repos/%s/%s", githubAPI, owner, repo)

	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("Accept", "application/vnd.github.v3+json")
	req.Header.Set("User-Agent", "CryptoDeps/1.0")

	// Use GitHub token if available
	if token := os.Getenv("GITHUB_TOKEN"); token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	resp, err := githubClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to fetch repo info: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		if limited := githubapi.RateLimited(resp, ""); limited != nil {
			return "", limited
		}
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

	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("User-Agent", "CryptoDeps/1.0")

	resp, err := githubClient.Do(req)
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
