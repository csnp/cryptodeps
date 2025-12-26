// Copyright 2024-2025 CSNP (csnp.org)
// SPDX-License-Identifier: Apache-2.0

package database

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/csnp/qramm-cryptodeps/pkg/types"
)

const (
	// DefaultRepoAPI is the GitHub API endpoint for the releases.
	DefaultRepoAPI = "https://api.github.com/repos/csnp/qramm-cryptodeps/releases"

	// DatabaseFileName is the name of the locally cached database file.
	DatabaseFileName = "crypto-database.json"

	// CacheDir is the directory name for caching the database.
	CacheDir = ".cryptodeps"

	// DefaultCacheMaxAge is how long before the cache is considered stale.
	// After this duration, auto-update will fetch a fresh copy.
	DefaultCacheMaxAge = 7 * 24 * time.Hour // 7 days
)

// UpdateConfig contains configuration for database updates.
type UpdateConfig struct {
	// URL to fetch the database from (defaults to DefaultDatabaseURL)
	URL string

	// CacheDir is the directory to cache the database (defaults to ~/.cryptodeps)
	CacheDir string

	// Timeout for HTTP requests
	Timeout time.Duration

	// Verbose enables verbose output
	Verbose bool
}

// DefaultUpdateConfig returns the default update configuration.
func DefaultUpdateConfig() *UpdateConfig {
	homeDir, _ := os.UserHomeDir()
	return &UpdateConfig{
		URL:      "", // Empty means auto-discover from GitHub releases
		CacheDir: filepath.Join(homeDir, CacheDir),
		Timeout:  30 * time.Second,
		Verbose:  false,
	}
}

// UpdateResult contains the result of a database update.
type UpdateResult struct {
	Success       bool
	PackagesAdded int
	TotalPackages int
	CachePath     string
	Message       string
}

// Updater handles database updates from remote sources.
type Updater struct {
	config *UpdateConfig
	client *http.Client
}

// NewUpdater creates a new database updater.
func NewUpdater(config *UpdateConfig) *Updater {
	if config == nil {
		config = DefaultUpdateConfig()
	}

	return &Updater{
		config: config,
		client: &http.Client{
			Timeout: config.Timeout,
		},
	}
}

// RemoteDatabase represents the structure of the remote database file.
type RemoteDatabase struct {
	Version   string                  `json:"version"`
	UpdatedAt string                  `json:"updatedAt"`
	Packages  []types.PackageAnalysis `json:"packages"`
}

// Update fetches the latest database from the remote source and caches it locally.
func (u *Updater) Update() (*UpdateResult, error) {
	result := &UpdateResult{}

	// Ensure cache directory exists
	if err := os.MkdirAll(u.config.CacheDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create cache directory: %w", err)
	}

	// Determine the URL to fetch from
	fetchURL := u.config.URL
	if fetchURL == "" {
		// Find database URL from GitHub releases
		if u.config.Verbose {
			fmt.Println("Looking up latest database release...")
		}
		url, err := u.findDatabaseURL()
		if err != nil {
			return nil, fmt.Errorf("failed to find database: %w", err)
		}
		fetchURL = url
	}

	if u.config.Verbose {
		fmt.Printf("Fetching database from %s...\n", fetchURL)
	}

	var body []byte
	var err error

	// Support local files for testing (starts with / or .)
	if strings.HasPrefix(fetchURL, "/") || strings.HasPrefix(fetchURL, "./") {
		body, err = os.ReadFile(fetchURL)
		if err != nil {
			return nil, fmt.Errorf("failed to read local database: %w", err)
		}
	} else {
		// Fetch from HTTP(S)
		resp, err := u.client.Get(fetchURL)
		if err != nil {
			return nil, fmt.Errorf("failed to fetch database: %w", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("failed to fetch database: HTTP %d", resp.StatusCode)
		}

		// Read the response body
		body, err = io.ReadAll(resp.Body)
		if err != nil {
			return nil, fmt.Errorf("failed to read database: %w", err)
		}
	}

	// Parse to validate the JSON
	var remoteDB RemoteDatabase
	if err := json.Unmarshal(body, &remoteDB); err != nil {
		return nil, fmt.Errorf("failed to parse database: %w", err)
	}

	// Save to cache
	cachePath := filepath.Join(u.config.CacheDir, DatabaseFileName)
	if err := os.WriteFile(cachePath, body, 0644); err != nil {
		return nil, fmt.Errorf("failed to save database: %w", err)
	}

	result.Success = true
	result.TotalPackages = len(remoteDB.Packages)
	result.CachePath = cachePath
	result.Message = fmt.Sprintf("Database updated: %d packages (version %s)", len(remoteDB.Packages), remoteDB.Version)

	if u.config.Verbose {
		fmt.Printf("Saved database to %s\n", cachePath)
	}

	return result, nil
}

// findDatabaseURL searches GitHub releases to find the crypto-database.json asset.
// It looks for releases with the database file attached, preferring db-* tagged releases.
func (u *Updater) findDatabaseURL() (string, error) {
	req, err := http.NewRequest("GET", DefaultRepoAPI, nil)
	if err != nil {
		return "", err
	}

	req.Header.Set("Accept", "application/vnd.github.v3+json")
	req.Header.Set("User-Agent", "CryptoDeps/1.0")

	// Use GitHub token if available for higher rate limits
	if token := os.Getenv("GITHUB_TOKEN"); token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	resp, err := u.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to fetch releases: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("GitHub API error: HTTP %d", resp.StatusCode)
	}

	var releases []struct {
		TagName string `json:"tag_name"`
		Assets  []struct {
			Name               string `json:"name"`
			BrowserDownloadURL string `json:"browser_download_url"`
		} `json:"assets"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&releases); err != nil {
		return "", fmt.Errorf("failed to parse releases: %w", err)
	}

	// Find the first release with crypto-database.json, preferring db-* tags
	for _, release := range releases {
		if strings.HasPrefix(release.TagName, "db-") {
			for _, asset := range release.Assets {
				if asset.Name == DatabaseFileName {
					return asset.BrowserDownloadURL, nil
				}
			}
		}
	}

	// Fallback: check any release for the file
	for _, release := range releases {
		for _, asset := range release.Assets {
			if asset.Name == DatabaseFileName {
				return asset.BrowserDownloadURL, nil
			}
		}
	}

	return "", fmt.Errorf("no database release found")
}

// GetCachePath returns the path to the cached database file.
func (u *Updater) GetCachePath() string {
	return filepath.Join(u.config.CacheDir, DatabaseFileName)
}

// IsCacheAvailable checks if a cached database exists.
func (u *Updater) IsCacheAvailable() bool {
	_, err := os.Stat(u.GetCachePath())
	return err == nil
}

// GetCacheInfo returns information about the cached database.
func (u *Updater) GetCacheInfo() (*CacheInfo, error) {
	cachePath := u.GetCachePath()

	info, err := os.Stat(cachePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil // No cache available
		}
		return nil, err
	}

	// Read and parse to get package count
	data, err := os.ReadFile(cachePath)
	if err != nil {
		return nil, err
	}

	var remoteDB RemoteDatabase
	if err := json.Unmarshal(data, &remoteDB); err != nil {
		return nil, err
	}

	return &CacheInfo{
		Path:         cachePath,
		ModifiedAt:   info.ModTime(),
		Size:         info.Size(),
		PackageCount: len(remoteDB.Packages),
		Version:      remoteDB.Version,
	}, nil
}

// CacheInfo contains information about the cached database.
type CacheInfo struct {
	Path         string
	ModifiedAt   time.Time
	Size         int64
	PackageCount int
	Version      string
}

// IsCacheStale checks if the cache is older than maxAge.
// Returns true if no cache exists or if the cache is stale.
func (u *Updater) IsCacheStale(maxAge time.Duration) bool {
	cachePath := u.GetCachePath()
	info, err := os.Stat(cachePath)
	if err != nil {
		return true // No cache = stale
	}
	return time.Since(info.ModTime()) > maxAge
}

// AutoUpdate checks if the cache is stale and updates silently if needed.
// This is designed to run transparently during normal operations.
// Returns true if an update was performed, false otherwise.
// Errors are silently ignored to not disrupt the user experience.
func (u *Updater) AutoUpdate() bool {
	// Don't auto-update if cache is fresh
	if !u.IsCacheStale(DefaultCacheMaxAge) {
		return false
	}

	// Attempt silent update (no verbose output)
	u.config.Verbose = false
	_, err := u.Update()
	return err == nil
}

// LoadCachedDatabase loads the cached database and merges it with the embedded data.
func (db *Database) LoadCachedDatabase() error {
	updater := NewUpdater(nil)

	if !updater.IsCacheAvailable() {
		return nil // No cache to load, embedded data is used
	}

	cachePath := updater.GetCachePath()
	data, err := os.ReadFile(cachePath)
	if err != nil {
		return fmt.Errorf("failed to read cached database: %w", err)
	}

	var remoteDB RemoteDatabase
	if err := json.Unmarshal(data, &remoteDB); err != nil {
		return fmt.Errorf("failed to parse cached database: %w", err)
	}

	// Add cached packages to the index (they take priority over embedded)
	for i := range remoteDB.Packages {
		db.addToIndex(&remoteDB.Packages[i])
	}

	return nil
}

// NewWithCachedData creates a database with both embedded and cached data.
func NewWithCachedData() *Database {
	return NewWithAutoUpdate(false)
}

// NewWithAutoUpdate creates a database and optionally auto-updates if the cache is stale.
// When autoUpdate is true and the cache is older than 7 days, it will silently fetch
// the latest database in the background. This provides a seamless user experience
// while keeping the database current.
func NewWithAutoUpdate(autoUpdate bool) *Database {
	db := NewEmbedded()

	// Auto-update if requested and cache is stale
	if autoUpdate {
		updater := NewUpdater(nil)
		updater.AutoUpdate() // Silent, errors ignored
	}

	// Load cached data (fails silently if not available)
	_ = db.LoadCachedDatabase()

	return db
}
