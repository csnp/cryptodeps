// Copyright 2025-2026 CyberSecurity NonProfit (CSNP)
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"io/fs"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// actionUse matches a workflow step that runs this action: a uses: value whose
// repository part ends in cryptodeps, which covers both names the repository
// has had. The second group is the ref after the @, when there is one.
var actionUse = regexp.MustCompile(`uses:\s*["']?([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]*cryptodeps)(?:@([^\s"'#]+))?`)

// actionDocs are the places a user copies a workflow step from. CHANGELOG.md is
// left out because its entries quote references as they were at the time.
var actionDocs = []string{"action.yml", "README.md", "CONTRIBUTING.md", "docs", "examples"}

// TestDocsActionReferencesResolve covers the usage comment in action.yml and
// both jobs in examples/github-action-workflow.yml, which said
// uses: csnp/qramm-cryptodeps@v1. The repository had release tags such as
// v1.3.1 but no v1 tag or branch, and it had been renamed to cryptodeps.
// GitHub documents that it does not redirect an action reference to a renamed
// repository, so a step copied from either place named neither a ref that
// exists nor the repository's current name.
//
// A reference must name the repository GoReleaser publishes releases to, and
// a version that has a dated release heading in CHANGELOG.md. The test does
// not reach the network, so the changelog stands in for the remote's tags.
func TestDocsActionReferencesResolve(t *testing.T) {
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
	owner, name := goreleaser.Release.GitHub.Owner, goreleaser.Release.GitHub.Name
	if owner == "" || name == "" {
		t.Fatal(".goreleaser.yml names no release.github owner and name")
	}
	repo := owner + "/" + name

	// The changelog lists releases newest first, so the first dated heading is
	// the version to suggest.
	released := map[string]bool{}
	latest := ""
	for _, h := range changelogReleaseHeading.FindAllString(readRepoFile(t, "CHANGELOG.md"), -1) {
		v := "v" + h[strings.Index(h, "[")+1:strings.Index(h, "]")]
		if latest == "" {
			latest = v
		}
		released[v] = true
	}
	if latest == "" {
		t.Fatal("no dated release headings found in CHANGELOG.md; the heading pattern no longer matches it")
	}
	want := repo + "@" + latest

	found := 0
	for _, root := range actionDocs {
		err := filepath.WalkDir(filepath.Join(repoRoot, root), func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			switch {
			case d.IsDir():
				return nil
			case !strings.HasSuffix(path, ".md") && !strings.HasSuffix(path, ".yml") && !strings.HasSuffix(path, ".yaml"):
				return nil
			}
			rel, err := filepath.Rel(repoRoot, path)
			if err != nil {
				return err
			}
			rel = filepath.ToSlash(rel)
			for i, line := range strings.Split(readRepoFile(t, rel), "\n") {
				for _, m := range actionUse.FindAllStringSubmatch(line, -1) {
					found++
					written := m[1]
					if m[2] != "" {
						written += "@" + m[2]
					}
					var problems []string
					if m[1] != repo {
						problems = append(problems, fmt.Sprintf("releases are published to %s, and GitHub "+
							"does not redirect an action reference to a renamed repository", repo))
					}
					switch {
					case m[2] == "":
						problems = append(problems, "it names no ref")
					case !released[m[2]]:
						problems = append(problems, fmt.Sprintf("CHANGELOG.md has no dated release heading for %s", m[2]))
					}
					if len(problems) > 0 {
						t.Errorf("%s:%d says uses: %s, but %s. Write %s",
							rel, i+1, written, strings.Join(problems, "; "), want)
					}
				}
			}
			return nil
		})
		if err != nil {
			t.Fatalf("walking %s: %v", root, err)
		}
	}
	if found == 0 {
		t.Fatalf("no uses: reference to the action in %s; the check above examined nothing",
			strings.Join(actionDocs, ", "))
	}
}
