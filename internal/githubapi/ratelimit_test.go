// Copyright 2025-2026 CyberSecurity NonProfit (CSNP)
// SPDX-License-Identifier: Apache-2.0

package githubapi

import (
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"
)

func response(status int, headers map[string]string, withToken bool) *http.Response {
	req, _ := http.NewRequest("GET", "https://api.github.com/repos/example/project", nil)
	if withToken {
		req.Header.Set("Authorization", "Bearer "+"test"+"-value")
	}
	resp := &http.Response{StatusCode: status, Header: http.Header{}, Request: req}
	for k, v := range headers {
		resp.Header.Set(k, v)
	}
	return resp
}

// Only GitHub's own statement that the quota is used up is read as the rate
// limit. A 403 for any other reason, such as a private repository, keeps naming
// its status: calling it a rate limit would send the user to wait for a reset
// that changes nothing.
func TestRateLimitedRecognisesOnlyAnExhaustedQuota(t *testing.T) {
	reset := strconv.FormatInt(time.Now().Add(20*time.Minute).Unix(), 10)
	cases := []struct {
		name    string
		status  int
		headers map[string]string
		want    bool
	}{
		{"403 with quota used up", http.StatusForbidden, map[string]string{"X-RateLimit-Remaining": "0", "X-RateLimit-Reset": reset}, true},
		{"429 with quota used up", http.StatusTooManyRequests, map[string]string{"X-RateLimit-Remaining": "0", "X-RateLimit-Reset": reset}, true},
		{"403 with quota left", http.StatusForbidden, map[string]string{"X-RateLimit-Remaining": "12"}, false},
		{"403 with no rate-limit headers", http.StatusForbidden, nil, false},
		{"404 with quota used up", http.StatusNotFound, map[string]string{"X-RateLimit-Remaining": "0"}, false},
		{"200 with quota used up", http.StatusOK, map[string]string{"X-RateLimit-Remaining": "0"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := RateLimited(response(tc.status, tc.headers, false), "")
			if (got != nil) != tc.want {
				t.Fatalf("RateLimited() = %v, want rate limit: %v", got, tc.want)
			}
		})
	}
}

func TestRateLimitErrorMessage(t *testing.T) {
	reset := time.Date(2026, 10, 16, 21, 42, 0, 0, time.UTC)
	headers := map[string]string{
		"X-RateLimit-Remaining": "0",
		"X-RateLimit-Reset":     strconv.FormatInt(reset.Unix(), 10),
	}
	localReset := reset.Local().Format("15:04")

	t.Run("without a token", func(t *testing.T) {
		err := RateLimited(response(http.StatusForbidden, headers, false), "pass --url instead")
		if err == nil {
			t.Fatal("RateLimited() = nil for an exhausted quota")
		}
		msg := err.Error()
		for _, want := range []string{"rate limit", "GITHUB_TOKEN", localReset, "pass --url instead"} {
			if !strings.Contains(msg, want) {
				t.Errorf("message does not contain %q:\n%s", want, msg)
			}
		}
		if !err.Reset.Equal(reset) {
			t.Errorf("Reset = %v, want %v", err.Reset, reset)
		}
	})

	t.Run("with a token", func(t *testing.T) {
		err := RateLimited(response(http.StatusForbidden, headers, true), "")
		if err == nil {
			t.Fatal("RateLimited() = nil for an exhausted quota")
		}
		msg := err.Error()
		if !err.WithToken {
			t.Error("WithToken = false for a request that carried a token")
		}
		if strings.Contains(msg, "test-value") || strings.Contains(msg, "Bearer") {
			t.Errorf("message carries the token:\n%s", msg)
		}
		// Telling someone whose token is already set to set it is a dead end.
		if strings.Contains(strings.ToLower(msg), "set github_token") {
			t.Errorf("message tells a token holder to set GITHUB_TOKEN:\n%s", msg)
		}
		if !strings.Contains(msg, localReset) {
			t.Errorf("message does not give the reset time %q:\n%s", localReset, msg)
		}
	})

	t.Run("without a reset header", func(t *testing.T) {
		err := RateLimited(response(http.StatusForbidden, map[string]string{"X-RateLimit-Remaining": "0"}, false), "")
		if err == nil {
			t.Fatal("RateLimited() = nil for an exhausted quota")
		}
		if !err.Reset.IsZero() {
			t.Errorf("Reset = %v, want zero when GitHub did not say", err.Reset)
		}
		if strings.Contains(err.Error(), "resets") {
			t.Errorf("message states a reset time GitHub did not give:\n%s", err.Error())
		}
	})
}
