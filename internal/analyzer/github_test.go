// Copyright 2025-2026 CyberSecurity NonProfit (CSNP)
// SPDX-License-Identifier: Apache-2.0

package analyzer

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/csnp/qramm-cryptodeps/internal/githubapi"
)

// useGitHubAPI points the repository lookup at url for one test.
func useGitHubAPI(t *testing.T, url string) {
	t.Helper()
	previous := githubAPI
	githubAPI = url
	t.Cleanup(func() { githubAPI = previous })
}

// `cryptodeps analyze owner/repo` with the unauthenticated quota used up printed
// "GitHub API error: 403 Forbidden". It now names the rate limit, when it
// resets, and GITHUB_TOKEN, through the same helper as `cryptodeps update`.
func TestFetchGitHubManifestsNamesRateLimit(t *testing.T) {
	t.Setenv("GITHUB_TOKEN", "")
	reset := time.Date(2026, 10, 16, 21, 42, 0, 0, time.UTC)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-RateLimit-Limit", "60")
		w.Header().Set("X-RateLimit-Remaining", "0")
		w.Header().Set("X-RateLimit-Reset", strconv.FormatInt(reset.Unix(), 10))
		w.WriteHeader(http.StatusForbidden)
	}))
	defer server.Close()
	useGitHubAPI(t, server.URL)

	_, err := FetchGitHubManifests(&GitHubRepo{Owner: "example", Repo: "project"})
	if err == nil {
		t.Fatal("FetchGitHubManifests succeeded against a rate-limited API")
	}
	msg := err.Error()
	t.Logf("analyze owner/repo prints: Error: failed to fetch from GitHub: %s", msg)
	for _, want := range []string{"rate limit", "GITHUB_TOKEN", reset.Local().Format("15:04")} {
		if !strings.Contains(msg, want) {
			t.Errorf("error does not contain %q:\n%s", want, msg)
		}
	}
	if strings.Contains(msg, "403 Forbidden") {
		t.Errorf("error still reads as a bare status:\n%s", msg)
	}
	// analyze has no --url flag; offering it here would be a dead end.
	if strings.Contains(msg, "--url") {
		t.Errorf("error offers --url, which analyze does not have:\n%s", msg)
	}
	var rl *githubapi.RateLimitError
	if !errors.As(err, &rl) {
		t.Errorf("error is not a *githubapi.RateLimitError: %v", err)
	}
}

// Every other refusal keeps naming its status.
func TestFetchGitHubManifestsKeepsOtherStatusCodes(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-RateLimit-Remaining", "0")
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()
	useGitHubAPI(t, server.URL)

	_, err := FetchGitHubManifests(&GitHubRepo{Owner: "example", Repo: "missing"})
	if err == nil {
		t.Fatal("FetchGitHubManifests succeeded against a 404")
	}
	if !strings.Contains(err.Error(), "404") || strings.Contains(err.Error(), "rate limit") {
		t.Errorf("a 404 should name its status, not the rate limit: %v", err)
	}
}
