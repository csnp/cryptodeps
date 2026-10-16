// Copyright 2025-2026 CyberSecurity NonProfit (CSNP)
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"os"
	"regexp"
	"strconv"
	"testing"
)

// changelogReleaseHeading matches a dated release in CHANGELOG.md, such as
// "## [1.3.0] - 2026-07-30". An undated "## [Unreleased]" heading does not match.
var changelogReleaseHeading = regexp.MustCompile(`(?m)^## \[(\d+)\.(\d+)\.\d+\] - \d{4}-\d{2}-\d{2}\s*$`)

// roadmapHeading matches a release section in docs/releases.md, such as
// "## v1.4 (Planned)".
var roadmapHeading = regexp.MustCompile(`(?m)^## v(\d+)\.(\d+) \(([^)]+)\)\s*$`)

type minorVersion struct{ major, minor int }

func (v minorVersion) String() string { return fmt.Sprintf("v%d.%d", v.major, v.minor) }

func (v minorVersion) less(o minorVersion) bool {
	if v.major != o.major {
		return v.major < o.major
	}
	return v.minor < o.minor
}

func parseMinor(t *testing.T, major, minor string) minorVersion {
	t.Helper()
	ma, err := strconv.Atoi(major)
	if err != nil {
		t.Fatalf("major version %q: %v", major, err)
	}
	mi, err := strconv.Atoi(minor)
	if err != nil {
		t.Fatalf("minor version %q: %v", minor, err)
	}
	return minorVersion{ma, mi}
}

// TestRoadmapLabelsMatchPublishedReleases keeps the roadmap headings in step
// with the releases recorded in CHANGELOG.md.
//
// The roadmap kept "v1.3 (Next release)" after 1.3.0 had shipped, because
// nothing ties the label to the changelog. A dated changelog entry is the
// record that a release went out, so a roadmap section for that minor version
// has to read "Released", and the section labelled "Next release" has to be
// the lowest minor version that has not shipped yet.
func TestRoadmapLabelsMatchPublishedReleases(t *testing.T) {
	changelog, err := os.ReadFile("../../CHANGELOG.md")
	if err != nil {
		t.Fatalf("read CHANGELOG.md: %v", err)
	}
	roadmap, err := os.ReadFile("../../docs/releases.md")
	if err != nil {
		t.Fatalf("read docs/releases.md: %v", err)
	}

	released := map[minorVersion]bool{}
	for _, m := range changelogReleaseHeading.FindAllStringSubmatch(string(changelog), -1) {
		released[parseMinor(t, m[1], m[2])] = true
	}
	if len(released) == 0 {
		t.Fatal("no dated release headings found in CHANGELOG.md; the heading pattern no longer matches it")
	}

	sections := roadmapHeading.FindAllStringSubmatch(string(roadmap), -1)
	if len(sections) == 0 {
		t.Fatal("no release headings found in docs/releases.md; the heading pattern no longer matches it")
	}

	var next *minorVersion
	labelled := map[minorVersion]string{}
	for _, m := range sections {
		v, label := parseMinor(t, m[1], m[2]), m[3]
		labelled[v] = label
		switch {
		case released[v] && label != "Released":
			t.Errorf("docs/releases.md: %s is labelled %q, but CHANGELOG.md records it as released; "+
				"want %q", v, label, "Released")
		case !released[v] && label == "Released":
			t.Errorf("docs/releases.md: %s is labelled %q, but CHANGELOG.md has no dated release for it",
				v, label)
		}
		if !released[v] && (next == nil || v.less(*next)) {
			next = &v
		}
	}

	if next == nil {
		return
	}
	if got := labelled[*next]; got != "Next release" {
		t.Errorf("docs/releases.md: %s is the lowest version not yet released, so it is the next "+
			"release, but it is labelled %q; want %q", *next, got, "Next release")
	}
	for v, label := range labelled {
		if label == "Next release" && v != *next {
			t.Errorf("docs/releases.md: %s is labelled %q, but the next release is %s", v, label, *next)
		}
	}
}
