// Copyright 2025-2026 CyberSecurity NonProfit (CSNP)
// SPDX-License-Identifier: Apache-2.0

package database

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/csnp/qramm-cryptodeps/internal/githubapi"
	"github.com/csnp/qramm-cryptodeps/pkg/types"
)

func TestDefaultUpdateConfig(t *testing.T) {
	config := DefaultUpdateConfig()

	// URL defaults to empty (auto-discover from GitHub releases)
	if config.URL != "" {
		t.Errorf("URL = %q, want empty (auto-discover)", config.URL)
	}
	if config.Timeout != 30*time.Second {
		t.Errorf("Timeout = %v, want 30s", config.Timeout)
	}
	if config.CacheDir == "" {
		t.Error("CacheDir is empty")
	}
}

func TestNewUpdater(t *testing.T) {
	// With nil config
	u := NewUpdater(nil)
	if u == nil {
		t.Fatal("NewUpdater returned nil")
	}
	// URL defaults to empty (auto-discover)
	if u.config.URL != "" {
		t.Errorf("Default URL should be empty for auto-discover")
	}

	// With custom config
	config := &UpdateConfig{
		URL:     "https://custom.url/db.json",
		Timeout: 10 * time.Second,
	}
	u = NewUpdater(config)
	if u.config.URL != "https://custom.url/db.json" {
		t.Errorf("Custom URL not set")
	}
}

func TestUpdaterUpdate(t *testing.T) {
	// Create a test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		db := RemoteDatabase{
			Version:   "1.0.0",
			UpdatedAt: time.Now().Format(time.RFC3339),
			Packages: []types.PackageAnalysis{
				{
					Package:   "test-pkg",
					Ecosystem: types.EcosystemGo,
					Crypto: []types.CryptoUsage{
						{Algorithm: "RSA", QuantumRisk: types.RiskVulnerable},
					},
				},
			},
		}
		json.NewEncoder(w).Encode(db)
	}))
	defer server.Close()

	// Create temp cache directory
	tmpDir, err := os.MkdirTemp("", "cryptodeps-test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	config := &UpdateConfig{
		URL:      server.URL,
		CacheDir: tmpDir,
		Timeout:  5 * time.Second,
		Verbose:  false,
	}

	updater := NewUpdater(config)
	result, err := updater.Update()
	if err != nil {
		t.Fatalf("Update failed: %v", err)
	}

	if !result.Success {
		t.Error("Update should succeed")
	}
	if result.TotalPackages != 1 {
		t.Errorf("TotalPackages = %d, want 1", result.TotalPackages)
	}

	// Verify cache file was created
	cachePath := filepath.Join(tmpDir, DatabaseFileName)
	if _, err := os.Stat(cachePath); os.IsNotExist(err) {
		t.Error("Cache file was not created")
	}
}

func TestUpdaterUpdateFromLocalFile(t *testing.T) {
	// Create temp directories
	tmpDir, err := os.MkdirTemp("", "cryptodeps-test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	// Create a local database file
	db := RemoteDatabase{
		Version:   "1.0.0",
		UpdatedAt: time.Now().Format(time.RFC3339),
		Packages: []types.PackageAnalysis{
			{Package: "local-pkg", Ecosystem: types.EcosystemNPM},
		},
	}
	dbPath := filepath.Join(tmpDir, "local-db.json")
	data, _ := json.Marshal(db)
	os.WriteFile(dbPath, data, 0644)

	cacheDir := filepath.Join(tmpDir, "cache")

	config := &UpdateConfig{
		URL:      dbPath, // Local file path
		CacheDir: cacheDir,
		Timeout:  5 * time.Second,
	}

	updater := NewUpdater(config)
	result, err := updater.Update()
	if err != nil {
		t.Fatalf("Update from local file failed: %v", err)
	}

	if result.TotalPackages != 1 {
		t.Errorf("TotalPackages = %d, want 1", result.TotalPackages)
	}
}

func TestUpdaterUpdateHTTPError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	tmpDir, _ := os.MkdirTemp("", "cryptodeps-test")
	defer os.RemoveAll(tmpDir)

	config := &UpdateConfig{
		URL:      server.URL,
		CacheDir: tmpDir,
		Timeout:  5 * time.Second,
	}

	updater := NewUpdater(config)
	_, err := updater.Update()
	if err == nil {
		t.Error("Update should fail with HTTP 404")
	}
}

func TestUpdaterUpdateInvalidJSON(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("not valid json"))
	}))
	defer server.Close()

	tmpDir, _ := os.MkdirTemp("", "cryptodeps-test")
	defer os.RemoveAll(tmpDir)

	config := &UpdateConfig{
		URL:      server.URL,
		CacheDir: tmpDir,
		Timeout:  5 * time.Second,
	}

	updater := NewUpdater(config)
	_, err := updater.Update()
	if err == nil {
		t.Error("Update should fail with invalid JSON")
	}
}

func TestUpdaterCachePath(t *testing.T) {
	config := &UpdateConfig{
		CacheDir: "/test/cache",
	}
	updater := NewUpdater(config)

	path := updater.GetCachePath()
	expected := "/test/cache/" + DatabaseFileName
	if path != expected {
		t.Errorf("GetCachePath = %q, want %q", path, expected)
	}
}

func TestUpdaterIsCacheAvailable(t *testing.T) {
	tmpDir, _ := os.MkdirTemp("", "cryptodeps-test")
	defer os.RemoveAll(tmpDir)

	config := &UpdateConfig{CacheDir: tmpDir}
	updater := NewUpdater(config)

	// No cache yet
	if updater.IsCacheAvailable() {
		t.Error("Cache should not be available initially")
	}

	// Create cache file
	cachePath := filepath.Join(tmpDir, DatabaseFileName)
	os.WriteFile(cachePath, []byte(`{"version":"1.0.0","packages":[]}`), 0644)

	if !updater.IsCacheAvailable() {
		t.Error("Cache should be available after creation")
	}
}

func TestUpdaterIsCacheStale(t *testing.T) {
	tmpDir, _ := os.MkdirTemp("", "cryptodeps-test")
	defer os.RemoveAll(tmpDir)

	config := &UpdateConfig{CacheDir: tmpDir}
	updater := NewUpdater(config)

	// No cache = stale
	if !updater.IsCacheStale(time.Hour) {
		t.Error("Non-existent cache should be stale")
	}

	// Create fresh cache
	cachePath := filepath.Join(tmpDir, DatabaseFileName)
	os.WriteFile(cachePath, []byte(`{"version":"1.0.0","packages":[]}`), 0644)

	// Fresh cache should not be stale
	if updater.IsCacheStale(time.Hour) {
		t.Error("Fresh cache should not be stale")
	}

	// With very short max age, should be stale
	time.Sleep(10 * time.Millisecond)
	if !updater.IsCacheStale(time.Millisecond) {
		t.Error("Cache should be stale with 1ms max age")
	}
}

func TestUpdaterGetCacheInfo(t *testing.T) {
	tmpDir, _ := os.MkdirTemp("", "cryptodeps-test")
	defer os.RemoveAll(tmpDir)

	config := &UpdateConfig{CacheDir: tmpDir}
	updater := NewUpdater(config)

	// No cache
	info, err := updater.GetCacheInfo()
	if err != nil {
		t.Fatalf("GetCacheInfo error: %v", err)
	}
	if info != nil {
		t.Error("GetCacheInfo should return nil for non-existent cache")
	}

	// Create cache
	db := RemoteDatabase{
		Version:  "2.0.0",
		Packages: []types.PackageAnalysis{{Package: "pkg1"}, {Package: "pkg2"}},
	}
	data, _ := json.Marshal(db)
	cachePath := filepath.Join(tmpDir, DatabaseFileName)
	os.WriteFile(cachePath, data, 0644)

	info, err = updater.GetCacheInfo()
	if err != nil {
		t.Fatalf("GetCacheInfo error: %v", err)
	}
	if info == nil {
		t.Fatal("GetCacheInfo should return info")
	}
	if info.Version != "2.0.0" {
		t.Errorf("Version = %q, want 2.0.0", info.Version)
	}
	if info.PackageCount != 2 {
		t.Errorf("PackageCount = %d, want 2", info.PackageCount)
	}
}

func TestUpdaterAutoUpdate(t *testing.T) {
	// Create a test server
	callCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		db := RemoteDatabase{Version: "1.0.0", Packages: []types.PackageAnalysis{}}
		json.NewEncoder(w).Encode(db)
	}))
	defer server.Close()

	tmpDir, _ := os.MkdirTemp("", "cryptodeps-test")
	defer os.RemoveAll(tmpDir)

	config := &UpdateConfig{
		URL:      server.URL,
		CacheDir: tmpDir,
		Timeout:  5 * time.Second,
	}

	updater := NewUpdater(config)

	// First auto-update should fetch (no cache)
	updated, err := updater.AutoUpdate()
	if err != nil {
		t.Fatalf("AutoUpdate failed: %v", err)
	}
	if !updated {
		t.Error("AutoUpdate should return true when cache is stale/missing")
	}
	if callCount != 1 {
		t.Errorf("Should have made 1 request, made %d", callCount)
	}

	// Immediate second call should not fetch (cache is fresh)
	updated, err = updater.AutoUpdate()
	if err != nil {
		t.Errorf("AutoUpdate with a fresh cache returned an error: %v", err)
	}
	if updated {
		t.Error("AutoUpdate should return false when cache is fresh")
	}
	if callCount != 1 {
		t.Errorf("Should still have made 1 request, made %d", callCount)
	}
}

func TestNewWithAutoUpdate(t *testing.T) {
	// Just verify it doesn't crash
	db, failure := NewWithAutoUpdate(false)
	if db == nil {
		t.Fatal("NewWithAutoUpdate returned nil")
	}
	if failure != nil {
		t.Errorf("NewWithAutoUpdate(false) reported an update failure: %v", failure.Err)
	}

	stats := db.Stats()
	if stats.TotalPackages == 0 {
		t.Error("Should have embedded data")
	}
}

func TestNewWithCachedData(t *testing.T) {
	db := NewWithCachedData()
	if db == nil {
		t.Fatal("NewWithCachedData returned nil")
	}

	// Should at least have embedded data
	stats := db.Stats()
	if stats.TotalPackages == 0 {
		t.Error("Should have embedded data")
	}
}

func TestLoadCachedDatabase(t *testing.T) {
	// Create a cache with additional packages
	tmpDir, _ := os.MkdirTemp("", "cryptodeps-test")
	defer os.RemoveAll(tmpDir)

	// We need to temporarily set the home directory
	// This is complex, so we'll just test that the method doesn't panic
	db := NewEmbedded()
	err := db.LoadCachedDatabase()
	// Should not error even if no cache exists
	if err != nil {
		t.Errorf("LoadCachedDatabase should not error: %v", err)
	}
}

// rateLimitedAPI stands in for the GitHub API once the caller's quota is used
// up: 403, X-RateLimit-Remaining 0 and the reset time, which is the answer an
// unauthenticated caller gets after 60 requests in an hour. It counts requests.
func rateLimitedAPI(t *testing.T, reset time.Time) (*httptest.Server, *int) {
	t.Helper()
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.Header().Set("X-RateLimit-Limit", "60")
		w.Header().Set("X-RateLimit-Remaining", "0")
		w.Header().Set("X-RateLimit-Reset", strconv.FormatInt(reset.Unix(), 10))
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprint(w, `{"message":"API rate limit exceeded"}`)
	}))
	t.Cleanup(server.Close)
	return server, &calls
}

// useReleasesAPI points the release lookup at url for one test.
func useReleasesAPI(t *testing.T, url string) {
	t.Helper()
	previous := releasesAPI
	releasesAPI = url
	t.Cleanup(func() { releasesAPI = previous })
}

// A user who ran `cryptodeps update` once the unauthenticated quota was used up
// read "GitHub API error: HTTP 403", which names neither the cause, nor when it
// clears, nor either way round it.
func TestUpdateNamesGitHubRateLimit(t *testing.T) {
	t.Setenv("GITHUB_TOKEN", "")
	reset := time.Date(2026, 10, 16, 21, 42, 0, 0, time.UTC)
	server, _ := rateLimitedAPI(t, reset)
	useReleasesAPI(t, server.URL)

	_, err := NewUpdater(&UpdateConfig{CacheDir: t.TempDir(), Timeout: 5 * time.Second}).Update()
	if err == nil {
		t.Fatal("Update succeeded against a rate-limited API")
	}
	msg := err.Error()
	t.Logf("update prints: Error: update failed: %s", msg)
	for _, want := range []string{
		"rate limit",
		"GITHUB_TOKEN",
		"--url",
		"crypto-database.json",
		"https://github.com/csnp/cryptodeps/releases",
		reset.Local().Format("15:04"),
	} {
		if !strings.Contains(msg, want) {
			t.Errorf("update error does not contain %q:\n%s", want, msg)
		}
	}
	if strings.Contains(msg, "HTTP 403") {
		t.Errorf("update error still reads as a bare status:\n%s", msg)
	}
	var rl *githubapi.RateLimitError
	if !errors.As(err, &rl) {
		t.Errorf("update error does not wrap a *githubapi.RateLimitError: %v", err)
	}
}

// Every other refusal keeps naming its status code.
func TestUpdateKeepsOtherStatusCodes(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-RateLimit-Remaining", "41")
		w.WriteHeader(http.StatusForbidden)
	}))
	defer server.Close()
	useReleasesAPI(t, server.URL)

	_, err := NewUpdater(&UpdateConfig{CacheDir: t.TempDir(), Timeout: 5 * time.Second}).Update()
	if err == nil {
		t.Fatal("Update succeeded against a 403")
	}
	if !strings.Contains(err.Error(), "HTTP 403") || strings.Contains(err.Error(), "rate limit") {
		t.Errorf("a 403 with quota left should name its status, not the rate limit: %v", err)
	}
}

// The automatic update before a scan used to discard its error. The scan then
// ran on whatever database was left, so one project gave two different answers
// on two runs and nothing said why. A failure is now returned together with the
// database the scan is going to use.
func TestNewWithAutoUpdateReportsFailureAndBuiltInFallback(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("GITHUB_TOKEN", "")
	server, calls := rateLimitedAPI(t, time.Now().Add(25*time.Minute))
	useReleasesAPI(t, server.URL)

	db, failure := NewWithAutoUpdate(true)
	if *calls == 0 {
		t.Fatal("no update was attempted with an empty cache")
	}
	if failure == nil {
		t.Fatal("a failed automatic update was not reported")
	}
	var rl *githubapi.RateLimitError
	if !errors.As(failure.Err, &rl) {
		t.Errorf("failure.Err does not carry the rate limit: %v", failure.Err)
	}

	builtIn := NewEmbedded().Stats().TotalPackages
	want := types.DatabaseInfo{Source: types.DatabaseBuiltIn, PackageCount: builtIn}
	if failure.Used != want {
		t.Errorf("failure.Used = %+v, want %+v", failure.Used, want)
	}
	if got := db.Info(); got != failure.Used {
		t.Errorf("db.Info() = %+v, but the failure reported %+v", got, failure.Used)
	}

	notice := failure.Notice()
	t.Logf("analyze prints on stderr:\n%s", notice)
	for _, want := range []string{
		"rate limit",
		"built-in database",
		fmt.Sprintf("%d packages", builtIn),
		"cryptodeps update",
		"GITHUB_TOKEN",
	} {
		if !strings.Contains(notice, want) {
			t.Errorf("notice does not contain %q:\n%s", want, notice)
		}
	}
}

// With a stale downloaded copy in place, the scan falls back to that copy, and
// the notice names its version and date rather than calling it built-in.
func TestNewWithAutoUpdateReportsCachedFallback(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("GITHUB_TOKEN", "")
	server, _ := rateLimitedAPI(t, time.Now().Add(25*time.Minute))
	useReleasesAPI(t, server.URL)

	data, err := json.Marshal(RemoteDatabase{
		Version:   "1.1.0",
		UpdatedAt: "2026-10-12T09:18:55Z",
		Packages: []types.PackageAnalysis{
			{Package: "cached-only-package", Ecosystem: types.EcosystemNPM},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	cacheDir := filepath.Join(home, CacheDir)
	if err := os.MkdirAll(cacheDir, 0o755); err != nil {
		t.Fatal(err)
	}
	cachePath := filepath.Join(cacheDir, DatabaseFileName)
	if err := os.WriteFile(cachePath, data, 0o644); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-8 * 24 * time.Hour)
	if err := os.Chtimes(cachePath, old, old); err != nil {
		t.Fatal(err)
	}

	db, failure := NewWithAutoUpdate(true)
	if failure == nil {
		t.Fatal("a failed automatic update was not reported")
	}
	used := failure.Used
	if used.Source != types.DatabaseDownloaded || used.Version != "1.1.0" || used.UpdatedAt != "2026-10-12T09:18:55Z" {
		t.Errorf("failure.Used = %+v, want the downloaded copy 1.1.0 of 2026-10-12T09:18:55Z", used)
	}
	if used.PackageCount != db.Stats().TotalPackages {
		t.Errorf("failure.Used.PackageCount = %d, db.Stats() = %d", used.PackageCount, db.Stats().TotalPackages)
	}
	notice := failure.Notice()
	for _, want := range []string{"1.1.0", "2026-10-12", fmt.Sprintf("%d packages", used.PackageCount)} {
		if !strings.Contains(notice, want) {
			t.Errorf("notice does not contain %q:\n%s", want, notice)
		}
	}
	if strings.Contains(notice, "built-in") {
		t.Errorf("notice calls the downloaded copy built-in:\n%s", notice)
	}
}

// No attempt, no notice: --offline, and a cache that is still fresh.
func TestNewWithAutoUpdateIsQuietWhenNothingFailed(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	server, calls := rateLimitedAPI(t, time.Now().Add(25*time.Minute))
	useReleasesAPI(t, server.URL)

	if _, failure := NewWithAutoUpdate(false); failure != nil || *calls != 0 {
		t.Errorf("offline: failure = %v, requests = %d; want neither", failure, *calls)
	}

	cacheDir := filepath.Join(home, CacheDir)
	if err := os.MkdirAll(cacheDir, 0o755); err != nil {
		t.Fatal(err)
	}
	data, _ := json.Marshal(RemoteDatabase{Version: "1.1.0"})
	if err := os.WriteFile(filepath.Join(cacheDir, DatabaseFileName), data, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, failure := NewWithAutoUpdate(true); failure != nil || *calls != 0 {
		t.Errorf("fresh cache: failure = %v, requests = %d; want neither", failure, *calls)
	}
}

// A failure that is not the rate limit is still reported, in its own words, and
// does not send the user to GITHUB_TOKEN for a problem a token cannot fix.
func TestNewWithAutoUpdateReportsUnreachableServer(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("GITHUB_TOKEN", "")
	server := httptest.NewServer(http.NotFoundHandler())
	url := server.URL
	server.Close() // nothing listens here any more
	useReleasesAPI(t, url)

	_, failure := NewWithAutoUpdate(true)
	if failure == nil {
		t.Fatal("a failed automatic update was not reported")
	}
	notice := failure.Notice()
	for _, want := range []string{"built-in database", "cryptodeps update"} {
		if !strings.Contains(notice, want) {
			t.Errorf("notice does not contain %q:\n%s", want, notice)
		}
	}
	if strings.Contains(notice, "GITHUB_TOKEN") {
		t.Errorf("notice suggests GITHUB_TOKEN for a server that could not be reached:\n%s", notice)
	}
}
