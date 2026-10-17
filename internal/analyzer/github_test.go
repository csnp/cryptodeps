// Copyright 2025-2026 CyberSecurity NonProfit (CSNP)
// SPDX-License-Identifier: Apache-2.0

package analyzer

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/csnp/qramm-cryptodeps/internal/githubapi"
	"github.com/csnp/qramm-cryptodeps/internal/netguard"
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

	_, _, err := FetchGitHubManifests(&GitHubRepo{Owner: "example", Repo: "project"})
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

	_, _, err := FetchGitHubManifests(&GitHubRepo{Owner: "example", Repo: "missing"})
	if err == nil {
		t.Fatal("FetchGitHubManifests succeeded against a 404")
	}
	if !strings.Contains(err.Error(), "404") || strings.Contains(err.Error(), "rate limit") {
		t.Errorf("a 404 should name its status, not the rate limit: %v", err)
	}
}

// inEmptyDir runs the test from a new empty directory, so relative arguments
// such as servics/api name nothing on disk unless the test creates them.
func inEmptyDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	previous, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.Chdir(previous); err != nil {
			t.Fatal(err)
		}
	})
	return dir
}

func offline(t *testing.T) {
	t.Helper()
	netguard.SetOffline(true)
	t.Cleanup(func() { netguard.SetOffline(false) })
}

func TestResolveTargetOfflineRefusesAMissingPath(t *testing.T) {
	inEmptyDir(t)
	offline(t)

	cases := map[string]string{
		"servics/api":                    "No file or directory named servics/api. --offline does not fetch repositories.",
		"https://github.com/servics/api": "No file or directory named https://github.com/servics/api. --offline does not fetch repositories.",
		"./servics/api":                  "No file or directory named ./servics/api.",
	}
	for arg, want := range cases {
		repo, err := ResolveTarget(arg)
		if err == nil {
			t.Errorf("ResolveTarget(%q) = %+v with --offline set, want an error", arg, repo)
			continue
		}
		if err.Error() != want {
			t.Errorf("ResolveTarget(%q) error = %q, want %q", arg, err.Error(), want)
		}
	}
}

// An empty argument, as an empty "$SCAN_PATH" gives, was reported as
// "No file or directory named ." and one space as "named  .", which read as
// if the current directory were missing. The empty argument is now named as
// empty, and an argument the bare form would hide is quoted.
func TestResolveTargetOfflineShowsAnUnclearArgument(t *testing.T) {
	inEmptyDir(t)
	offline(t)

	cases := map[string]string{
		"":             "The path argument is empty.",
		" ":            `No file or directory named " ".`,
		"\tx":          `No file or directory named "\tx".`,
		" servics/api": `No file or directory named " servics/api".`,
		"servics/api ": `No file or directory named "servics/api ".`,
		"my dir":       "No file or directory named my dir.",
	}
	for arg, want := range cases {
		repo, err := ResolveTarget(arg)
		if err == nil {
			t.Errorf("ResolveTarget(%q) = %+v with --offline set, want an error", arg, repo)
			continue
		}
		if err.Error() != want {
			t.Errorf("ResolveTarget(%q) error = %q, want %q", arg, err.Error(), want)
		}
	}
}

// The fetch notice printed the argument and the repository with %s, so a
// newline in `analyze "https://github.com/a/b<NL>x"` split the notice over
// three lines and a tab was printed raw, while the error printed after it
// quoted the same argument. Both are now named the way the error names them.
func TestFetchNoticeShowsAnUnclearArgument(t *testing.T) {
	cases := []struct {
		arg  string
		repo GitHubRepo
		want string
	}{
		{
			"servics/api", GitHubRepo{Owner: "servics", Repo: "api"},
			"No file or directory named servics/api was found, so fetching the GitHub repository servics/api instead...",
		},
		{
			"https://github.com/a/b\nx", GitHubRepo{Owner: "a", Repo: "b\nx"},
			`No file or directory named "https://github.com/a/b\nx" was found, so fetching the GitHub repository "a/b\nx" instead...`,
		},
		{
			"https://github.com/a/b\tx", GitHubRepo{Owner: "a", Repo: "b\tx"},
			`No file or directory named "https://github.com/a/b\tx" was found, so fetching the GitHub repository "a/b\tx" instead...`,
		},
		{
			"https://github.com/a\tb/c", GitHubRepo{Owner: "a\tb", Repo: "c"},
			`No file or directory named "https://github.com/a\tb/c" was found, so fetching the GitHub repository "a\tb/c" instead...`,
		},
	}
	for _, c := range cases {
		repo := c.repo
		if got := FetchNotice(c.arg, &repo); got != c.want {
			t.Errorf("FetchNotice(%q, owner %q, repo %q) = %q, want %q", c.arg, c.repo.Owner, c.repo.Repo, got, c.want)
		}
	}
}

// A local directory shaped like owner/repo is a local path, offline or not.
func TestResolveTargetPrefersALocalPath(t *testing.T) {
	dir := inEmptyDir(t)
	if err := os.MkdirAll(filepath.Join(dir, "services", "api"), 0o755); err != nil {
		t.Fatal(err)
	}
	for _, off := range []bool{false, true} {
		netguard.SetOffline(off)
		repo, err := ResolveTarget("services/api")
		if err != nil || repo != nil {
			t.Errorf("offline=%v: ResolveTarget(services/api) = %+v, %v; want a local path", off, repo, err)
		}
	}
	netguard.SetOffline(false)
}

func TestResolveTargetOnlineReadsAMissingShorthandAsARepository(t *testing.T) {
	inEmptyDir(t)
	repo, err := ResolveTarget("servics/api")
	if err != nil {
		t.Fatal(err)
	}
	if repo == nil || repo.Owner != "servics" || repo.Repo != "api" {
		t.Fatalf("ResolveTarget(servics/api) = %+v, want servics/api", repo)
	}
	if got, want := repo.RepositoryURL(), "https://github.com/servics/api"; got != want {
		t.Errorf("RepositoryURL() = %q, want %q", got, want)
	}

	// Not shaped like a repository: reported as missing, as under --offline.
	want := "No file or directory named ./servics/api."
	if repo, err := ResolveTarget("./servics/api"); repo != nil || err == nil || err.Error() != want {
		t.Errorf("ResolveTarget(./servics/api) = %+v, %v; want the error %q", repo, err, want)
	}
}

// Without --offline, an argument that names nothing and is not read as a
// repository was left to the analysis, whose error printed it raw: " x" as
// "cannot access path: stat  x: no such file or directory", and "" as
// "cannot access path: stat : no such file or directory". It is now the error
// --offline gives.
func TestResolveTargetOnlineNamesAMissingPathAsOfflineDoes(t *testing.T) {
	inEmptyDir(t)
	t.Cleanup(func() { netguard.SetOffline(false) })

	cases := map[string]string{
		"":             "The path argument is empty.",
		" ":            `No file or directory named " ".`,
		" x":           `No file or directory named " x".`,
		"\tx":          `No file or directory named "\tx".`,
		"\x1b[2Jx":     `No file or directory named "\x1b[2Jx".`,
		" servics/api": `No file or directory named " servics/api".`,
		"servics/api ": `No file or directory named "servics/api ".`,
		"my dir":       "No file or directory named my dir.",
	}
	for arg, want := range cases {
		for _, off := range []bool{false, true} {
			netguard.SetOffline(off)
			repo, err := ResolveTarget(arg)
			if err == nil {
				t.Errorf("offline=%v: ResolveTarget(%q) = %+v, want an error", off, arg, repo)
				continue
			}
			if err.Error() != want {
				t.Errorf("offline=%v: ResolveTarget(%q) error = %q, want %q", off, arg, err.Error(), want)
			}
		}
	}
}

// The fetch refuses on its own as well, so a caller that skips ResolveTarget
// still cannot reach GitHub with --offline set.
func TestFetchGitHubManifestsRefusesWhenOffline(t *testing.T) {
	offline(t)
	dir, branch, err := FetchGitHubManifests(&GitHubRepo{Owner: "servics", Repo: "api"})
	if !errors.Is(err, netguard.ErrOffline) {
		t.Fatalf("FetchGitHubManifests = %q, %q, %v; want an error wrapping netguard.ErrOffline", dir, branch, err)
	}
}

// A repository or path holding a control character gives a URL that net/url
// refuses. Both requests discarded that error and set a header on the nil
// request, so `analyze "https://github.com/a/b<TAB>x"` panicked in the
// repository lookup and a /tree/ URL with a tab in its path panicked in the
// raw file download, each leaving its temporary directory behind. The request
// error is now returned and the directory removed.
func TestFetchGitHubManifestsReturnsARefusedURL(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("the repository lookup reached the API: %s %s", r.Method, r.URL)
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()
	useGitHubAPI(t, server.URL)

	for name, repo := range map[string]*GitHubRepo{
		"repository lookup": {Owner: "a", Repo: "b\tx"},
		"raw file":          {Owner: "a", Repo: "b", Branch: "main", Path: "x\ty"},
	} {
		t.Run(name, func(t *testing.T) {
			tmp := t.TempDir()
			t.Setenv("TMPDIR", tmp)

			dir, branch, err := FetchGitHubManifests(repo)
			if err == nil {
				t.Fatalf("FetchGitHubManifests(%+v) = %q, %q; want an error", repo, dir, branch)
			}
			if !strings.Contains(err.Error(), "invalid control character in URL") {
				t.Errorf("error does not carry the request error: %v", err)
			}
			if dir != "" {
				t.Errorf("dir = %q alongside an error, want empty", dir)
			}
			left, globErr := filepath.Glob(filepath.Join(tmp, "cryptodeps-github-*"))
			if globErr != nil {
				t.Fatal(globErr)
			}
			if len(left) != 0 {
				t.Errorf("temporary directory left behind: %q", left)
			}
		})
	}
}
