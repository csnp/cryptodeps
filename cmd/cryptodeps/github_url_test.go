// Copyright 2025-2026 CyberSecurity NonProfit (CSNP)
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// A GitHub URL argument holding a control character panicked with a nil
// pointer dereference after the fetch notice, exit 2, and left an empty
// cryptodeps-github-* directory in the temporary directory. It now prints an
// error naming the argument, quoted, exits 2 and removes the directory,
// without opening a connection.
func TestGitHubURLWithAControlCharacterIsAnError(t *testing.T) {
	proxy, log := startConnectionLog(t)

	for _, arg := range []string{
		"https://github.com/a/b\tx",
		"https://github.com/a/b/tree/main/x\ty",
	} {
		t.Run(strconv.Quote(arg), func(t *testing.T) {
			// runCLI passes this process's temporary directory on, so the
			// command line creates its directory here.
			tmp := t.TempDir()
			t.Setenv("TMPDIR", tmp)

			before := len(log.snapshot())
			stdout, stderr, code := runCLI(t, proxy, "analyze", arg)

			if strings.Contains(stderr, "panic") {
				t.Fatalf("the command line panicked:\n%s", stderr)
			}
			if code != ExitError {
				t.Errorf("exit code %d, want %d", code, ExitError)
			}
			want := "Error: failed to fetch " + strconv.Quote(arg) + " from GitHub: "
			if !strings.Contains(stderr, want) {
				t.Errorf("stderr does not say %q:\n%s", want, stderr)
			}
			if !strings.Contains(stderr, "invalid control character in URL") {
				t.Errorf("stderr does not carry the request error:\n%s", stderr)
			}
			if got := log.snapshot()[before:]; len(got) != 0 {
				t.Errorf("%d connection(s) for a URL that cannot be requested, want 0: %q", len(got), got)
			}
			if stdout != "" {
				t.Errorf("a report was written:\n%s", stdout)
			}
			left, err := filepath.Glob(filepath.Join(tmp, "cryptodeps-github-*"))
			if err != nil {
				t.Fatal(err)
			}
			if len(left) != 0 {
				t.Errorf("temporary directory left behind: %q", left)
			}
		})
	}
}
