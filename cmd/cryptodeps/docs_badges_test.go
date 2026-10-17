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

// repoFileHolds reports whether link, written in the repository file from,
// names another file in the repository whose text holds every word of value.
// A link back to from does not count: from is the file the badge is drawn in,
// not a source of its value.
func repoFileHolds(from, link, value string) bool {
	u, err := url.Parse(link)
	if err != nil || u.Scheme != "" || u.Host != "" || u.Path == "" {
		return false
	}
	path := filepath.Join(repoRoot, filepath.FromSlash(u.Path))
	target, err := os.Stat(path)
	if err != nil {
		return false
	}
	if self, err := os.Stat(filepath.Join(repoRoot, filepath.FromSlash(from))); err == nil && os.SameFile(target, self) {
		return false
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	return holdsWords(string(b), value)
}

// holdsWords reports whether text holds every word of value, ignoring case,
// as a whole word: with no letter, number or underscore beside it on either
// side. The sides are matched as characters rather than as \b, which would
// need a word character after the + of a grade such as B+.
func holdsWords(text, value string) bool {
	for _, word := range strings.Fields(value) {
		whole := regexp.MustCompile(`(?i)(?:^|[^\pL\pN_])` + regexp.QuoteMeta(word) + `(?:$|[^\pL\pN_])`)
		if !whole.MatchString(text) {
			return false
		}
	}
	return true
}

// TestHoldsWords checks that holdsWords finds each word of a value only as a
// whole word.
func TestHoldsWords(t *testing.T) {
	for _, c := range []struct {
		text, value string
		holds       bool
	}{
		{"A", "A", true},
		{"github.com/spf13/cobra v1.8.0", "A", false},
		{"submitted to the Licensor, including but not limited to", "MIT", false},
		{"Apache License\n   Version 2.0, January 2004", "Apache 2.0", true},
		{"apache license version 2.0", "Apache 2.0", true},
		{"Version 12.0", "2.0", false},
		{"go report: B+\n", "B+", true},
		{"go report: B", "B+", false},
		{"go report: AB+", "B+", false},
		{"go_report_A", "A", false},
		{"", "A", false},
	} {
		if got := holdsWords(c.text, c.value); got != c.holds {
			t.Errorf("holdsWords(%q, %q) = %v, want %v", c.text, c.value, got, c.holds)
		}
	}
}

// TestRepoFileHolds checks repoFileHolds on the values and links of static
// badges drawn in README.md. go.mod holds the letter a only inside longer
// words, such as cobra and yaml, and LICENSE holds mit only inside longer
// words, such as submitted and limited, so neither holds the grade A or the
// license MIT; LICENSE holds Apache and 2.0 as whole words. A link back to
// README.md, also written as ./README.md#readme, and a link out of the
// repository do not count.
func TestRepoFileHolds(t *testing.T) {
	for _, c := range []struct {
		image, link string
		holds       bool
	}{
		{"https://img.shields.io/badge/go%20report-A-brightgreen", "go.mod", false},
		{"https://img.shields.io/badge/go%20report-A-brightgreen", "README.md", false},
		{"https://img.shields.io/badge/go%20report-A-brightgreen", "./README.md#readme", false},
		{"https://img.shields.io/badge/go%20report-A-brightgreen", "https://goreportcard.com/report/github.com/csnp/qramm-cryptodeps", false},
		{"https://img.shields.io/badge/go%20report-B%2B-brightgreen", "go.mod", false},
		{"https://img.shields.io/badge/License-MIT-blue.svg", "LICENSE", false},
		{"https://img.shields.io/badge/License-Apache%202.0-blue.svg", "LICENSE", true},
	} {
		message, _ := staticBadgeMessage(c.image)
		if got := repoFileHolds("README.md", c.link, message); got != c.holds {
			t.Errorf("repoFileHolds(%q, %q, %q) = %v, want %v", "README.md", c.link, message, got, c.holds)
		}
	}
}

// TestDocsReadmeBadgesTakeTheirValuesFromASource covers a "go report: A"
// badge in the README header. It was a shields.io static badge, so the grade
// was typed into its URL and not measured, and it linked to goreportcard.com,
// whose own badge for the module read "go report: retired" on 2026-10-17.
//
// A static badge passes only when it links to another file in the repository
// that holds each word of its value as a whole word, as the License badge
// links to LICENSE, which holds Apache and 2.0. Other badges, such as the CI
// workflow badge and the shields.io badge that reads go.mod, are not checked:
// the test does not reach the network, so it cannot see the value a service
// returns. A badge inside a fenced code block is an example, not one of the
// README's badges, and is skipped.
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
			if !static || repoFileHolds(file, link, message) {
				continue
			}
			t.Errorf("%s:%d: the %q badge shows %q, written into its URL %s, and links to %s, "+
				"not to another file in the repository that holds that value. Use a badge that reads "+
				"its value from a service, or remove it", file, i+1, alt, message, image, link)
		}
	}
	if found == 0 {
		t.Fatalf("%s has no badges; the badge pattern no longer matches them", file)
	}
}
