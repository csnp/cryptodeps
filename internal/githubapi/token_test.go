// Copyright 2025-2026 CyberSecurity NonProfit (CSNP)
// SPDX-License-Identifier: Apache-2.0

package githubapi

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"
)

// refusingServer answers 401 to any request with an Authorization header and
// 200 to one without, as GitHub does for a public endpoint and a bad token.
func refusingServer(t *testing.T) (*httptest.Server, *[]bool) {
	t.Helper()
	var withAuth []bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hasAuth := r.Header.Get("Authorization") != ""
		withAuth = append(withAuth, hasAuth)
		if hasAuth {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(server.Close)
	return server, &withAuth
}

func captureNotices(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	previous := noticeWriter
	noticeWriter = &buf
	t.Cleanup(func() { noticeWriter = previous })
	return &buf
}

// A token GitHub refuses is dropped and the request is sent once more without
// it, with a notice that names GITHUB_TOKEN as the cause.
func TestDoRetriesWithoutRefusedToken(t *testing.T) {
	server, withAuth := refusingServer(t)
	notices := captureNotices(t)

	req, err := http.NewRequest("GET", server.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+"not-a-real"+"-token")

	resp, err := Do(server.Client(), req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200 from the request without the token", resp.StatusCode)
	}
	if got := *withAuth; len(got) != 2 || !got[0] || got[1] {
		t.Errorf("requests carried Authorization = %v, want [true false]", got)
	}
	if notices.String() != TokenRejectedNotice+"\n" {
		t.Errorf("notice = %q, want %q", notices.String(), TokenRejectedNotice+"\n")
	}
	if req.Header.Get("Authorization") == "" {
		t.Error("Do removed the Authorization header from the caller's request")
	}
}

// Without a token a 401 is returned as it is: there is nothing to drop.
func TestDoReturnsUnauthorizedWithoutToken(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()
	notices := captureNotices(t)

	req, err := http.NewRequest("GET", server.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := Do(server.Client(), req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", resp.StatusCode)
	}
	if notices.Len() != 0 {
		t.Errorf("notice printed for a request without a token: %q", notices.String())
	}
}
