// Copyright 2025-2026 CyberSecurity NonProfit (CSNP)
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// readmeBadge matches a linked badge image, [![alt](image)](link).
var readmeBadge = regexp.MustCompile(`\[!\[([^\]]*)\]\(([^)\s]+)\)\]\(([^)\s]+)\)`)

// staticBadgeMessage returns the value a shields.io static badge draws, and
// false for any other image. A static badge draws the value written into its
// URL, as /badge/<label>-<value>-<color> or /static/v1?message=<value>, so
// nothing measures it. The /badge/dynamic/json, yaml, xml and toml forms draw
// a value read from the document their url parameter names.
func staticBadgeMessage(image string) (string, bool) {
	u, err := url.Parse(image)
	if err != nil || u.Host != "img.shields.io" {
		return "", false
	}
	if u.Path == "/static/v1" {
		return u.Query().Get("message"), true
	}
	content, ok := strings.CutPrefix(u.Path, "/badge/")
	if !ok || strings.HasPrefix(content, "dynamic/") {
		return "", false
	}
	// "--" is a literal dash and "__" a literal underscore; a single "_" is a space.
	content = strings.NewReplacer("--", "\x00", "__", "\x01", "_", " ").Replace(content)
	parts := strings.Split(content, "-")
	message := parts[0]
	if len(parts) > 2 {
		message = parts[len(parts)-2]
	}
	return strings.NewReplacer("\x00", "-", "\x01", "_").Replace(message), true
}

// TestStaticBadgeMessage checks staticBadgeMessage on badge URLs. Each one
// marked static drew the value given here when fetched from shields.io on
// 2026-10-17, and the /badge/dynamic/json one drew the default branch it read
// from the GitHub API.
func TestStaticBadgeMessage(t *testing.T) {
	for _, c := range []struct {
		image   string
		message string
		static  bool
	}{
		{"https://img.shields.io/badge/go%20report-A-brightgreen", "A", true},
		{"https://img.shields.io/badge/License-Apache%202.0-blue.svg", "Apache 2.0", true},
		{"https://img.shields.io/badge/a--b-c__d_e-blue", "c_d e", true},
		{"https://img.shields.io/badge/just%20message-blue", "just message", true},
		{"https://img.shields.io/static/v1?label=go%20report&message=Z&color=blue", "Z", true},
		{"https://img.shields.io/badge/dynamic/json?url=https%3A%2F%2Fapi.github.com%2Frepos%2Fcsnp%2Fcryptodeps&query=%24.default_branch&label=branch", "", false},
		{"https://img.shields.io/github/go-mod/go-version/csnp/qramm-cryptodeps", "", false},
		{"https://github.com/csnp/qramm-cryptodeps/actions/workflows/ci.yml/badge.svg", "", false},
	} {
		message, static := staticBadgeMessage(c.image)
		if message != c.message || static != c.static {
			t.Errorf("staticBadgeMessage(%s) = %q, %v; want %q, %v", c.image, message, static, c.message, c.static)
		}
	}
}

// repoFileHolds reports whether link names a file in the repository whose
// text contains every word of value, ignoring case.
func repoFileHolds(link, value string) bool {
	u, err := url.Parse(link)
	if err != nil || u.Scheme != "" || u.Host != "" || u.Path == "" {
		return false
	}
	b, err := os.ReadFile(filepath.Join(repoRoot, filepath.FromSlash(u.Path)))
	if err != nil {
		return false
	}
	text := strings.ToLower(string(b))
	for _, word := range strings.Fields(strings.ToLower(value)) {
		if !strings.Contains(text, word) {
			return false
		}
	}
	return true
}

// TestDocsReadmeBadgesTakeTheirValuesFromASource covers a "go report: A"
// badge in the README header. It was a shields.io static badge, so the grade
// was typed into its URL and not measured, and it linked to goreportcard.com,
// whose own badge for the module read "go report: retired" on 2026-10-17.
//
// A static badge passes only when it links to a file in the repository that
// holds its value, as the License badge links to LICENSE. Other badges, such
// as the CI workflow badge and the shields.io badge that reads go.mod, are not
// checked: the test does not reach the network, so it cannot see the value a
// service returns. A badge inside a fenced code block is an example, not one
// of the README's badges, and is skipped.
func TestDocsReadmeBadgesTakeTheirValuesFromASource(t *testing.T) {
	const file = "README.md"
	found := 0
	inFence := false
	for i, line := range strings.Split(readRepoFile(t, file), "\n") {
		if strings.HasPrefix(line, "```") {
			inFence = !inFence
		}
		if inFence {
			continue
		}
		for _, m := range readmeBadge.FindAllStringSubmatch(line, -1) {
			found++
			alt, image, link := m[1], m[2], m[3]
			message, static := staticBadgeMessage(image)
			if !static || repoFileHolds(link, message) {
				continue
			}
			t.Errorf("%s:%d: the %q badge shows %q, written into its URL %s, and links to %s, "+
				"not to a file in the repository that holds that value. Use a badge that reads "+
				"its value from a service, or remove it", file, i+1, alt, message, image, link)
		}
	}
	if found == 0 {
		t.Fatalf("%s has no badges; the badge pattern no longer matches them", file)
	}
}
