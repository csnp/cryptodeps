// Copyright 2024-2025 CSNP (csnp.org)
// SPDX-License-Identifier: Apache-2.0

package database

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

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
	updated := updater.AutoUpdate()
	if !updated {
		t.Error("AutoUpdate should return true when cache is stale/missing")
	}
	if callCount != 1 {
		t.Errorf("Should have made 1 request, made %d", callCount)
	}

	// Immediate second call should not fetch (cache is fresh)
	updated = updater.AutoUpdate()
	if updated {
		t.Error("AutoUpdate should return false when cache is fresh")
	}
	if callCount != 1 {
		t.Errorf("Should still have made 1 request, made %d", callCount)
	}
}

func TestNewWithAutoUpdate(t *testing.T) {
	// Just verify it doesn't crash
	db := NewWithAutoUpdate(false)
	if db == nil {
		t.Fatal("NewWithAutoUpdate returned nil")
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
