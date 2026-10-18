// Copyright 2025-2026 CyberSecurity NonProfit (CSNP)
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"io/fs"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// golangciLintPin matches the Makefile line that sets the golangci-lint release
// make lint runs. The second group is its major version.
var golangciLintPin = regexp.MustCompile(`(?m)^GOLANGCI_LINT_VERSION\s*[:?]?=\s*(v(\d+)\.\d+\.\d+)\s*$`)

// golangciLintRun matches a command that runs golangci-lint. The group is the
// release after the @ that go run takes, when there is one.
var golangciLintRun = regexp.MustCompile(`golangci-lint(?:@(\S+))?\s+run\b`)

// lintDocs are the places a contributor takes the lint command from.
var lintDocs = []string{"Makefile", "README.md", "CONTRIBUTING.md", "docs"}

// golangciLintProblems returns what is wrong with the golangci-lint commands in
// files, which maps a repository path to its text and has to hold the Makefile,
// given the text of .golangci.yml. The Makefile has to pin one release as
// GOLANGCI_LINT_VERSION, with the major version of the configuration format,
// and each command golangciLintRun finds has to name that release.
func golangciLintProblems(config string, files map[string]string) ([]string, error) {
	var cfg struct {
		Version any `yaml:"version"`
	}
	if err := yaml.Unmarshal([]byte(config), &cfg); err != nil {
		return nil, fmt.Errorf("parsing .golangci.yml: %w", err)
	}
	format := "1"
	if cfg.Version != nil {
		format = fmt.Sprint(cfg.Version)
	}

	var problems []string
	pin, pinMajor := "", ""
	if m := golangciLintPin.FindStringSubmatch(files["Makefile"]); m != nil {
		pin, pinMajor = m[1], m[2]
	}
	switch {
	case pin == "":
		problems = append(problems, "the Makefile sets GOLANGCI_LINT_VERSION to no release tag "+
			"(vMAJOR.MINOR.PATCH), so make lint pins no golangci-lint release")
	case pinMajor != format:
		problems = append(problems, fmt.Sprintf("the Makefile pins golangci-lint %s, but .golangci.yml "+
			"is in the v%s configuration format", pin, format))
	}

	paths := make([]string, 0, len(files))
	for path := range files {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	inMakefile := 0
	for _, path := range paths {
		for i, line := range strings.Split(files[path], "\n") {
			for _, m := range golangciLintRun.FindAllStringSubmatch(line, -1) {
				release, want := m[1], "make lint"
				if path == "Makefile" {
					inMakefile++
					if release == "$(GOLANGCI_LINT_VERSION)" || release == "${GOLANGCI_LINT_VERSION}" {
						release = pin
					}
					want = "golangci-lint@$(GOLANGCI_LINT_VERSION)"
				}
				switch {
				case m[1] == "":
					problems = append(problems, fmt.Sprintf("%s:%d says %q, which runs whatever golangci-lint "+
						"release is installed, and .golangci.yml is in the v%s configuration format. Write %s",
						path, i+1, m[0], format, want))
				case pin != "" && release != pin:
					problems = append(problems, fmt.Sprintf("%s:%d runs golangci-lint %s, but the Makefile pins "+
						"%s for make lint. Write %s", path, i+1, release, pin, want))
				}
			}
		}
	}
	if inMakefile == 0 {
		problems = append(problems, "the Makefile runs golangci-lint nowhere, so make lint runs no pinned release")
	}
	return problems, nil
}

// TestGolangciLintProblems checks golangciLintProblems on configurations,
// Makefiles and docs. Each problem it finds has to hold the text given here,
// in order.
func TestGolangciLintProblems(t *testing.T) {
	const (
		v1Config   = "run:\n  timeout: 5m\n"
		v2Config   = "version: \"2\"\nrun:\n  timeout: 5m\n"
		v1Makefile = "GOLANGCI_LINT_VERSION := v1.64.8\n\nlint:\n" +
			"\tgo run github.com/golangci/golangci-lint/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION) run ./...\n"
		v2Makefile = "GOLANGCI_LINT_VERSION := v2.12.2\n\nlint:\n" +
			"\tgo run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@${GOLANGCI_LINT_VERSION} run ./...\n"
	)
	for _, c := range []struct {
		name   string
		config string
		files  map[string]string
		want   []string
	}{
		{"make lint in the docs", v1Config,
			map[string]string{"Makefile": v1Makefile, "CONTRIBUTING.md": "# Run linter\nmake lint\n"}, nil},
		{"go run at the pinned release in the docs", v1Config,
			map[string]string{"Makefile": v1Makefile, "CONTRIBUTING.md": "go run " +
				"github.com/golangci/golangci-lint/cmd/golangci-lint@v1.64.8 run ./...\n"}, nil},
		{"installed golangci-lint in the Makefile", v1Config,
			map[string]string{"Makefile": "lint:\n\tgolangci-lint run ./...\n"},
			[]string{"sets GOLANGCI_LINT_VERSION to no release tag", `Makefile:2 says "golangci-lint run"`}},
		{"installed golangci-lint in the docs", v1Config,
			map[string]string{"Makefile": v1Makefile, "docs/development.md": "# Run linter\ngolangci-lint run\n"},
			[]string{`docs/development.md:2 says "golangci-lint run"`}},
		{"another release in the docs", v1Config,
			map[string]string{"Makefile": v1Makefile, "CONTRIBUTING.md": "go run " +
				"github.com/golangci/golangci-lint/cmd/golangci-lint@v1.63.4 run ./...\n"},
			[]string{"CONTRIBUTING.md:1 runs golangci-lint v1.63.4, but the Makefile pins v1.64.8"}},
		{"v1 release for a v2 configuration", v2Config,
			map[string]string{"Makefile": v1Makefile},
			[]string{"pins golangci-lint v1.64.8, but .golangci.yml is in the v2 configuration format"}},
		{"v2 release for a v2 configuration", v2Config,
			map[string]string{"Makefile": v2Makefile}, nil},
		{"unquoted version 2", "version: 2\n",
			map[string]string{"Makefile": v2Makefile}, nil},
		{"no golangci-lint command in the Makefile", v1Config,
			map[string]string{"Makefile": "GOLANGCI_LINT_VERSION := v1.64.8\n\nlint:\n\tgo vet ./...\n"},
			[]string{"runs golangci-lint nowhere"}},
	} {
		problems, err := golangciLintProblems(c.config, c.files)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		ok := len(problems) == len(c.want)
		for i := 0; ok && i < len(problems); i++ {
			ok = strings.Contains(problems[i], c.want[i])
		}
		if !ok {
			t.Errorf("%s: golangciLintProblems = %q, want problems holding %q", c.name, problems, c.want)
		}
	}
}

// TestDocsLintCommandRunsTheGolangciLintReleaseTheConfigIsWrittenFor covers the
// lint target in the Makefile, three lines of CONTRIBUTING.md and the setup
// steps in docs/development.md, which ran golangci-lint with whatever release
// was installed. .golangci.yml is in the v1 configuration format, which
// golangci-lint 2.12.2 stops on with "can't load config: unsupported version
// of the configuration" and exit code 3, while the CI lint job installs
// v1.64.8 and passes.
//
// The release the Makefile pins has to have the major version of the format of
// .golangci.yml: golangci-lint migrate writes version: "2" at the top of a v2
// file, and v1.64.8 refuses a file that carries a version key.
func TestDocsLintCommandRunsTheGolangciLintReleaseTheConfigIsWrittenFor(t *testing.T) {
	files := map[string]string{}
	for _, root := range lintDocs {
		err := filepath.WalkDir(filepath.Join(repoRoot, root), func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() || (root != "Makefile" && !strings.HasSuffix(path, ".md")) {
				return nil
			}
			rel, err := filepath.Rel(repoRoot, path)
			if err != nil {
				return err
			}
			rel = filepath.ToSlash(rel)
			files[rel] = readRepoFile(t, rel)
			return nil
		})
		if err != nil {
			t.Fatalf("walking %s: %v", root, err)
		}
	}
	problems, err := golangciLintProblems(readRepoFile(t, ".golangci.yml"), files)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range problems {
		t.Error(p)
	}
}
