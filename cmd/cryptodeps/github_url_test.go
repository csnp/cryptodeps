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

// The fetch notice printed the argument and the repository raw, so the
// newline in `analyze "https://github.com/a/b<NL>x"` split it over three lines
// and a tab was printed as is. The notice is now one line that quotes them
// the way the error after it quotes the argument.
func TestGitHubURLWithAControlCharacterIsQuotedInTheFetchNotice(t *testing.T) {
	proxy, _ := startConnectionLog(t)

	for arg, repo := range map[string]string{
		"https://github.com/a/b\nx":             `"a/b\nx"`,
		"https://github.com/a/b\tx":             `"a/b\tx"`,
		"https://github.com/a/b/tree/main/x\ty": "a/b",
	} {
		t.Run(strconv.Quote(arg), func(t *testing.T) {
			t.Setenv("TMPDIR", t.TempDir())

			_, stderr, _ := runCLI(t, proxy, "analyze", arg)

			lines := strings.Split(stderr, "\n")
			want := "No file or directory named " + strconv.Quote(arg) +
				" was found, so fetching the GitHub repository " + repo + " instead..."
			if lines[0] != want {
				t.Errorf("first line of stderr is %q, want %q", lines[0], want)
			}
			if len(lines) < 2 || !strings.HasPrefix(lines[1], "Error: failed to fetch "+strconv.Quote(arg)) {
				t.Errorf("the error does not follow the notice on the second line:\n%s", stderr)
			}
		})
	}
}
