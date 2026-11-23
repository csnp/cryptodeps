// Copyright 2025-2026 CyberSecurity NonProfit (CSNP)
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"regexp"
	"strconv"
	"strings"
	"testing"
	"unicode"

	"gopkg.in/yaml.v3"

	"github.com/csnp/qramm-cryptodeps/pkg/types"
)

// repoPageLink matches a link to a heading on a page of a GitHub repository.
// The groups are the owner, the repository name, the path of the page and the
// anchor.
var repoPageLink = regexp.MustCompile(`https://github\.com/([^/\s]+)/([^/\s]+)/blob/[^/\s]+/([^#\s]+)#(\S+)`)

// headingAnchor is the anchor GitHub gives a Markdown heading: the text in
// lower case, with each space turned into a hyphen and each character that is
// not a letter, a digit, a hyphen or an underscore removed.
func headingAnchor(heading string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(heading) {
		switch {
		case r == ' ':
			b.WriteRune('-')
		case r == '-' || r == '_' || unicode.IsLetter(r) || unicode.IsDigit(r):
			b.WriteRune(r)
		}
	}
	return b.String()
}

// TestActionExitCodeOutputDescribesEveryFailOnThreshold covers the action's
// exit-code output, described as "Exit code (0=clean, 1=vulnerable, 2=error,
// 3=partial)" whatever the fail-on input was. The action passes that input to
// cryptodeps analyze as --fail-on, and codes 0 and 3 depend on it: under
// fail-on none a scan with quantum-vulnerable findings exits 0, and under
// fail-on any a project whose cryptography is all quantum-safe exits 3.
//
// The description is held to the rule that
// TestAnalyzeHelpDescribesExitCodesForEveryFailOnThreshold holds the analyze
// help to, with each threshold named the way the input is set ("fail-on
// none"). Which thresholds each entry must name is computed from
// exitCodeForSummary over a vulnerable, a partial-risk and an all-safe scan.
// The description's link must name the repository releases are published to
// and the anchor of a heading on the linked page whose section describes
// --fail-on.
func TestActionExitCodeOutputDescribesEveryFailOnThreshold(t *testing.T) {
	var action struct {
		Inputs  map[string]yaml.Node `yaml:"inputs"`
		Outputs map[string]struct {
			Description string `yaml:"description"`
		} `yaml:"outputs"`
	}
	if err := yaml.Unmarshal([]byte(readRepoFile(t, "action.yml")), &action); err != nil {
		t.Fatalf("parsing action.yml: %v", err)
	}
	if _, ok := action.Inputs["fail-on"]; !ok {
		t.Fatal("action.yml has no fail-on input, which this test names each threshold by")
	}
	output, ok := action.Outputs["exit-code"]
	if !ok {
		t.Fatal("action.yml has no exit-code output")
	}
	description := strings.Join(strings.Fields(output.Description), " ")

	// One entry per code, from "<code>: " to the start of the next entry.
	codes := map[int]string{}
	entry := regexp.MustCompile(`(?:^|\s)([0-9]+): `)
	starts := entry.FindAllStringSubmatchIndex(description, -1)
	for i, m := range starts {
		end := len(description)
		if i+1 < len(starts) {
			end = starts[i+1][0]
		}
		code, _ := strconv.Atoi(description[m[2]:m[3]])
		codes[code] = description[m[1]:end]
	}
	for _, code := range []int{ExitSuccess, ExitVulnerable, ExitError, ExitPartial} {
		if _, ok := codes[code]; !ok {
			t.Errorf("action.yml exit-code output has no entry starting %q: %q",
				strconv.Itoa(code)+": ", description)
		}
	}
	for _, code := range []int{ExitSuccess, ExitVulnerable, ExitPartial} {
		if !strings.Contains(codes[code], "fail-on") {
			t.Errorf("action.yml exit-code output describes code %d without the fail-on "+
				"input: %q", code, codes[code])
		}
	}

	vulnerable := types.ScanSummary{TotalDependencies: 1, WithCrypto: 1, QuantumVulnerable: 1}
	partial := types.ScanSummary{TotalDependencies: 1, WithCrypto: 1, QuantumPartial: 1}
	allSafe := types.ScanSummary{TotalDependencies: 1, WithCrypto: 1}
	for _, threshold := range gateThresholds {
		word := regexp.MustCompile(`\b` + threshold + `\b`)

		// A threshold under which quantum-vulnerable findings exit 0 is named
		// on the code 0 entry and excepted on the code 1 entry.
		if exitCodeForSummary(vulnerable, threshold) == ExitSuccess {
			if !strings.Contains(codes[ExitSuccess], "fail-on "+threshold) {
				t.Errorf("fail-on %s exits 0 on quantum-vulnerable findings, and the code 0 "+
					"entry does not say so: %q", threshold, codes[ExitSuccess])
			}
			if !word.MatchString(codes[ExitVulnerable]) {
				t.Errorf("fail-on %s never exits 1, and the code 1 entry does not name it: %q",
					threshold, codes[ExitVulnerable])
			}
		}

		// Every threshold that can exit 3 is named on the code 3 entry.
		for _, s := range []types.ScanSummary{vulnerable, partial, allSafe} {
			if exitCodeForSummary(s, threshold) == ExitPartial &&
				!strings.Contains(codes[ExitPartial], "fail-on "+threshold) {
				t.Errorf("fail-on %s can exit 3, and the code 3 entry does not name it: %q",
					threshold, codes[ExitPartial])
				break
			}
		}
		if exitCodeForSummary(allSafe, threshold) == ExitPartial &&
			!strings.Contains(codes[ExitPartial], "quantum-safe") {
			t.Errorf("fail-on %s exits 3 when all cryptography is quantum-safe, and the "+
				"code 3 entry does not say so: %q", threshold, codes[ExitPartial])
		}
	}

	link := repoPageLink.FindStringSubmatch(description)
	if link == nil {
		t.Fatalf("action.yml exit-code output does not link to the exit codes on the "+
			"Commands page (docs/commands.md#exit-codes): %q", description)
	}
	var goreleaser struct {
		Release struct {
			GitHub struct {
				Owner string `yaml:"owner"`
				Name  string `yaml:"name"`
			} `yaml:"github"`
		} `yaml:"release"`
	}
	if err := yaml.Unmarshal([]byte(readRepoFile(t, ".goreleaser.yml")), &goreleaser); err != nil {
		t.Fatalf("parsing .goreleaser.yml: %v", err)
	}
	repo := goreleaser.Release.GitHub.Owner + "/" + goreleaser.Release.GitHub.Name
	if got := link[1] + "/" + link[2]; got != repo {
		t.Errorf("action.yml exit-code output links to %s, and releases are published to %s: %s",
			got, repo, link[0])
	}

	page := readRepoFile(t, link[3])
	heading := ""
	inFence := false
	for _, line := range strings.Split(page, "\n") {
		if strings.HasPrefix(line, "```") {
			inFence = !inFence
		}
		level := len(line) - len(strings.TrimLeft(line, "#"))
		if inFence || level == 0 || !strings.HasPrefix(line[level:], " ") {
			continue
		}
		if text := strings.TrimSpace(line[level:]); headingAnchor(text) == link[4] {
			heading = text
			break
		}
	}
	if heading == "" {
		t.Fatalf("action.yml exit-code output links to #%s, and %s has no heading with that "+
			"anchor: %s", link[4], link[3], link[0])
	}
	if section := markdownSection(t, page, link[3], heading); !strings.Contains(section, "--fail-on") {
		t.Errorf("action.yml exit-code output links to %s, whose %q section does not "+
			"describe --fail-on", link[0], heading)
	}
}
