// Copyright 2025-2026 CyberSecurity NonProfit (CSNP)
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/csnp/qramm-cryptodeps/internal/analyzer"
	"github.com/csnp/qramm-cryptodeps/internal/manifest"
	"github.com/csnp/qramm-cryptodeps/pkg/output"
)

// TestVersionFlagPrintsWhatTheVersionCommandPrints covers --version and -v,
// which were rejected as unknown flags with exit 2 and the full usage after
// them, so that only `cryptodeps version` printed the version.
func TestVersionFlagPrintsWhatTheVersionCommandPrints(t *testing.T) {
	proxy, log := startConnectionLog(t)

	want, stderr, code := runCLI(t, proxy, "version")
	if code != ExitSuccess || !strings.HasPrefix(want, "cryptodeps ") {
		t.Fatalf("version: exit code %d, stdout %q, stderr %q", code, want, stderr)
	}
	for _, flag := range []string{"--version", "-v"} {
		stdout, stderr, code := runCLI(t, proxy, flag)
		if code != ExitSuccess {
			t.Errorf("%s: exit code %d, want %d; stderr:\n%s", flag, code, ExitSuccess, stderr)
		}
		if stdout != want {
			t.Errorf("%s printed %q, want what the version command prints, %q", flag, stdout, want)
		}
	}
	if got := log.snapshot(); len(got) != 0 {
		t.Errorf("%d connection(s) for printing the version, want 0: %q", len(got), got)
	}

	// The flag is the root command's: -v on update is still --verbose.
	if f := updateCmd.Flags().ShorthandLookup("v"); f == nil || f.Name != "verbose" {
		t.Errorf("update -v is %v, want --verbose", f)
	}
}

// TestCommandsThatTakeNoArgumentsRejectOne covers `status extra` and `version
// extra`, which ignored the argument and exited 0. update takes no argument
// either, and ignored one the same way before downloading.
func TestCommandsThatTakeNoArgumentsRejectOne(t *testing.T) {
	proxy, log := startConnectionLog(t)

	for _, command := range []string{"status", "version", "update"} {
		_, stderr, code := runCLI(t, proxy, command, "extra")
		if code != ExitError {
			t.Errorf("%s extra: exit code %d, want %d", command, code, ExitError)
		}
		want := `unknown command "extra" for "cryptodeps ` + command + `"`
		if !strings.Contains(stderr, want) {
			t.Errorf("%s extra: stderr does not say %q:\n%s", command, want, stderr)
		}
	}
	if got := log.snapshot(); len(got) != 0 {
		t.Errorf("%d connection(s) for a rejected argument, want 0: %q", len(got), got)
	}
}

// TestHelpForATopicThatNamesNoCommandExits2 covers `help bogus`, which printed
// "Unknown help topic" and the usage and exited 0.
func TestHelpForATopicThatNamesNoCommandExits2(t *testing.T) {
	proxy, _ := startConnectionLog(t)

	_, stderr, code := runCLI(t, proxy, "help", "bogus")
	if code != ExitError {
		t.Errorf("help bogus: exit code %d, want %d", code, ExitError)
	}
	if want := `unknown help topic "bogus" for "cryptodeps"`; !strings.Contains(stderr, want) {
		t.Errorf("help bogus: stderr does not say %q:\n%s", want, stderr)
	}

	// A topic that names a command still prints that command's help.
	stdout, stderr, code := runCLI(t, proxy, "help", "analyze")
	if code != ExitSuccess {
		t.Errorf("help analyze: exit code %d, want %d; stderr:\n%s", code, ExitSuccess, stderr)
	}
	if !strings.Contains(stdout, "cryptodeps analyze [path|url]") {
		t.Errorf("help analyze does not print the analyze usage:\n%s", stdout)
	}
}

// TestUnknownFormatListsTheFormats covers `--format xml`, whose error,
// "unsupported format: xml", named none of the values the flag accepts, while
// the errors for --risk, --min-severity and --fail-on list theirs.
func TestUnknownFormatListsTheFormats(t *testing.T) {
	proxy, _ := startConnectionLog(t)

	_, stderr, code := runCLI(t, proxy, "analyze", "--offline", "--format", "xml")
	if code != ExitError {
		t.Errorf("exit code %d, want %d", code, ExitError)
	}
	want := `invalid --format value "xml": expected one of ` + strings.Join(output.FormatNames(), ", ")
	if !strings.Contains(stderr, want) {
		t.Errorf("stderr does not say %q:\n%s", want, stderr)
	}
	for _, name := range output.FormatNames() {
		if _, err := output.ParseFormat(name); err != nil {
			t.Errorf("the error lists %q, which ParseFormat refuses: %v", name, err)
		}
	}
}

// TestAnalyzeHelpNamesTheManifestsItReads covers help that described the
// manifests as "go.mod, package.json, etc.", which left the rest to be found
// by trial. Every name discovery recognises is named, the ones it has no parser
// for included. go.work is left out: it is read through the go.mod files it
// lists.
func TestAnalyzeHelpNamesTheManifestsItReads(t *testing.T) {
	for name := range manifest.ManifestFiles {
		if name == "go.work" {
			continue
		}
		if !strings.Contains(analyzeCmd.Long, name) {
			t.Errorf("analyze help does not name %s", name)
		}
	}
}

// TestAnalyzeHelpRepositoryExampleHasDependencies covers the help examples
// `cryptodeps analyze golang-jwt/jwt` and its URL form, a repository whose
// go.mod declares no dependencies: following them printed "found 0
// dependencies" and "Nothing to analyze." The URL example names a directory of
// this repository, so what it fetches is checked here from the working tree,
// without a connection.
func TestAnalyzeHelpRepositoryExampleHasDependencies(t *testing.T) {
	checked := 0
	for _, line := range strings.Split(analyzeCmd.Long, "\n") {
		arg, ok := strings.CutPrefix(strings.TrimSpace(line), "cryptodeps analyze ")
		if !ok || !strings.HasPrefix(arg, "https://github.com/csnp/cryptodeps/") {
			continue
		}
		repo, err := analyzer.ParseGitHubURL(arg)
		if err != nil {
			t.Errorf("example %q is not a GitHub URL the tool accepts: %v", arg, err)
			continue
		}
		m, err := manifest.DetectAndParse(filepath.Join(repoRoot, filepath.FromSlash(repo.Path)))
		if err != nil {
			t.Errorf("example %q names %q, which holds no manifest: %v", arg, repo.Path, err)
			continue
		}
		if len(m.Dependencies) == 0 {
			t.Errorf("example %q names %s, which declares no dependencies", arg, m.Path)
		}
		checked++
	}
	if checked == 0 {
		t.Fatalf("analyze help has no example naming a directory of github.com/csnp/cryptodeps, "+
			"so what an example fetches cannot be checked:\n%s", analyzeCmd.Long)
	}
}
