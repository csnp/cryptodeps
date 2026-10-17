// Copyright 2025-2026 CyberSecurity NonProfit (CSNP)
// SPDX-License-Identifier: Apache-2.0

package database

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/csnp/qramm-cryptodeps/pkg/types"
)

// With a GITHUB_TOKEN that GitHub refuses, `cryptodeps update` failed with
// "GitHub API error: HTTP 401" while the same command without the token
// downloaded the database. The release list is public, so the lookup is sent
// again without the token and the download goes ahead.
func TestUpdateSucceedsWhenGitHubRefusesTheToken(t *testing.T) {
	t.Setenv("GITHUB_TOKEN", "not-a-real"+"-token")

	db, err := json.Marshal(RemoteDatabase{
		Version:  "9.9.9",
		Packages: []types.PackageAnalysis{{Package: "only-package", Ecosystem: types.EcosystemNPM}},
	})
	if err != nil {
		t.Fatal(err)
	}
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/releases":
			if r.Header.Get("Authorization") != "" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			fmt.Fprintf(w, `[{"tag_name":"db-1","assets":[{"name":%q,"browser_download_url":%q}]}]`,
				DatabaseFileName, server.URL+"/db")
		case "/db":
			w.Write(db)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()
	useReleasesAPI(t, server.URL+"/releases")

	result, err := NewUpdater(&UpdateConfig{CacheDir: t.TempDir(), Timeout: 5 * time.Second}).Update()
	if err != nil {
		t.Fatalf("Update failed with a refused token: %v", err)
	}
	if result.TotalPackages != 1 {
		t.Errorf("TotalPackages = %d, want 1", result.TotalPackages)
	}
}
