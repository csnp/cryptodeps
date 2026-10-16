// Copyright 2025-2026 CyberSecurity NonProfit (CSNP)
// SPDX-License-Identifier: Apache-2.0

// Package githubapi holds what the tool's GitHub API callers share.
package githubapi

import (
	"net/http"
	"strconv"
	"strings"
	"time"
)

// RateLimitError reports that GitHub refused a request because the caller's API
// quota is used up.
//
// Both callers used to report this as "GitHub API error: HTTP 403", which names
// neither the cause, nor when it clears, nor what to do. Without a token GitHub
// allows 60 requests an hour per address, so a shared network reaches it
// without the user having done anything unusual.
type RateLimitError struct {
	// Reset is when GitHub said the quota refills. It is zero when GitHub did
	// not say.
	Reset time.Time
	// WithToken records whether the refused request carried GITHUB_TOKEN. It
	// decides the advice: telling someone whose token is set to set it is a
	// dead end.
	WithToken bool
	// Alternative is a further way forward that only this caller can offer,
	// such as a flag of its own command. Empty for none.
	Alternative string
}

// Reason states what happened and when it clears, without advice, for callers
// that give their own next step.
func (e *RateLimitError) Reason() string {
	who := "for requests without a token"
	if e.WithToken {
		who = "for the token in GITHUB_TOKEN"
	}
	reason := "GitHub's API rate limit " + who + " is used up"
	if !e.Reset.IsZero() {
		reason += "; it resets at " + e.Reset.Local().Format("2006-01-02 15:04 MST")
	}
	return reason
}

func (e *RateLimitError) Error() string {
	var steps []string
	if e.WithToken {
		steps = append(steps, "try again after the limit resets")
	} else {
		steps = append(steps, "set GITHUB_TOKEN to a GitHub token to raise the limit")
	}
	if e.Alternative != "" {
		steps = append(steps, e.Alternative)
	}
	next := strings.Join(steps, ", or ")
	return e.Reason() + ". To continue, " + next
}

// RateLimited returns a *RateLimitError when resp is GitHub refusing a request
// because the caller's quota is used up, and nil for every other response.
//
// GitHub signals this with 403 or 429 and X-RateLimit-Remaining: 0. A 403 for
// any other reason, a private repository for instance, is not a rate limit and
// keeps its status at the call site.
//
// Only the two rate-limit headers are read. The request's Authorization header
// is checked for presence and never copied into the error.
func RateLimited(resp *http.Response, alternative string) *RateLimitError {
	if resp == nil {
		return nil
	}
	if resp.StatusCode != http.StatusForbidden && resp.StatusCode != http.StatusTooManyRequests {
		return nil
	}
	if strings.TrimSpace(resp.Header.Get("X-RateLimit-Remaining")) != "0" {
		return nil
	}
	err := &RateLimitError{Alternative: alternative}
	if seconds, parseErr := strconv.ParseInt(strings.TrimSpace(resp.Header.Get("X-RateLimit-Reset")), 10, 64); parseErr == nil && seconds > 0 {
		err.Reset = time.Unix(seconds, 0)
	}
	if resp.Request != nil && resp.Request.Header.Get("Authorization") != "" {
		err.WithToken = true
	}
	return err
}
