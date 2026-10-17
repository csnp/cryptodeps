// Copyright 2025-2026 CyberSecurity NonProfit (CSNP)
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// --deep with --offline used to drop --deep without a word, and the report on
// a project whose dependencies are absent from the database then advised
// "Run with --deep". The scan now says once, on stderr, that --deep is skipped
// under --offline, and no report format advises --deep.
func TestDeepWithOfflineSaysDeepIsSkipped(t *testing.T) {
	proxy, _ := startConnectionLog(t)
	project := t.TempDir()
	manifest := `{"name":"fixture","version":"1.0.0","dependencies":{"cryptodeps-fixture-absent-one":"1.0.0","cryptodeps-fixture-absent-two":"2.0.0"}}`
	if err := os.WriteFile(filepath.Join(project, "package.json"), []byte(manifest), 0o644); err != nil {
		t.Fatal(err)
	}

	for _, format := range []string{"table", "markdown", "json"} {
		t.Run(format, func(t *testing.T) {
			stdout, stderr, code := runCLI(t, proxy, "analyze", project, "--deep", "--offline", "--format", format)
			if code != 0 {
				t.Fatalf("exit %d, want 0\nstdout:\n%s\nstderr:\n%s", code, stdout, stderr)
			}
			if n := strings.Count(stderr, deepSkippedOfflineNotice); n != 1 {
				t.Errorf("stderr carries the --deep skipped notice %d times, want 1:\n%s", n, stderr)
			}
			for _, advice := range []string{"Run with --deep", "Run with `--deep`", "use --deep", "try --deep"} {
				if strings.Contains(stdout, advice) {
					t.Errorf("%s output advises %q under --deep --offline:\n%s", format, advice, stdout)
				}
			}
			if format != "json" && !strings.Contains(stdout, "--deep was skipped because --offline") {
				t.Errorf("%s output does not say why --deep did not run:\n%s", format, stdout)
			}
		})
	}
}

// Without --offline the notice is not printed: --deep runs.
func TestDeepNoticeOnlyUnderOffline(t *testing.T) {
	proxy, _ := startConnectionLog(t)
	project := t.TempDir()
	if err := os.WriteFile(filepath.Join(project, "package.json"), []byte(`{"name":"fixture","version":"1.0.0"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	_, stderr, _ := runCLI(t, proxy, "analyze", project, "--offline")
	if strings.Contains(stderr, deepSkippedOfflineNotice) {
		t.Errorf("notice printed without --deep:\n%s", stderr)
	}
}

// analyze --help says what --deep needs.
func TestDeepHelpNamesWhatItNeeds(t *testing.T) {
	usage := analyzeCmd.Flags().Lookup("deep").Usage
	for _, want := range []string{"network access", "go or npm on PATH", "skipped under --offline"} {
		if !strings.Contains(usage, want) {
			t.Errorf("--deep help does not contain %q: %s", want, usage)
		}
	}
}
