// Copyright 2025-2026 CyberSecurity NonProfit (CSNP)
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bufio"
	"bytes"
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// runCLIEnv makes the test binary run the cryptodeps command line instead of
// the tests. The command line runs in a process of its own because Go reads
// HTTPS_PROXY once per process, so only a fresh process routes every
// connection through the counting proxy below.
const runCLIEnv = "CRYPTODEPS_TEST_RUN_CLI"

func TestMain(m *testing.M) {
	if os.Getenv(runCLIEnv) == "1" {
		main()
		return
	}
	os.Exit(m.Run())
}

// connectionLog is a proxy that records every connection made to it and the
// first line sent on each, then answers 502. Pointing HTTPS_PROXY and
// HTTP_PROXY at it makes every outbound HTTP connection of the process under
// test visible here, without any of them leaving the machine.
type connectionLog struct {
	mu    sync.Mutex
	lines []string
}

func (c *connectionLog) record(line string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.lines = append(c.lines, line)
}

func (c *connectionLog) snapshot() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]string(nil), c.lines...)
}

func startConnectionLog(t *testing.T) (string, *connectionLog) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	log := &connectionLog{}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
				line, _ := bufio.NewReader(conn).ReadString('\n')
				// Recorded before answering, so it is in the log by the time
				// the client has seen the answer and exited.
				log.record(strings.TrimSpace(line))
				_, _ = conn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n"))
			}(conn)
		}
	}()
	return ln.Addr().String(), log
}

// runCLI runs cryptodeps with args in an empty directory and a fresh HOME,
// with every proxy variable pointed at proxy and no GITHUB_TOKEN.
//
// Under `go test -coverprofile`, as `make test` and the CI workflow run it,
// the test binary is built with coverage instrumentation, and run as the
// command line it writes its counters at exit to the directory named by
// GOCOVERDIR. Without one it prints "warning: GOCOVERDIR not set, no
// coverage data emitted" on stderr, which a test comparing stderr whole
// would take for the command line's own output. A directory of its own per
// run keeps stderr the command line's; a binary built without coverage
// ignores the variable.
func runCLI(t *testing.T, proxy string, args ...string) (stdout, stderr string, code int) {
	t.Helper()
	cmd := exec.Command(os.Args[0], args...)
	cmd.Dir = t.TempDir()
	proxyURL := "http://" + proxy
	cmd.Env = []string{
		runCLIEnv + "=1",
		"PATH=" + os.Getenv("PATH"),
		"HOME=" + t.TempDir(),
		"TMPDIR=" + os.TempDir(),
		"GOCOVERDIR=" + t.TempDir(),
		"HTTPS_PROXY=" + proxyURL,
		"HTTP_PROXY=" + proxyURL,
		"https_proxy=" + proxyURL,
		"http_proxy=" + proxyURL,
	}
	var out, errOut bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errOut
	err := cmd.Run()
	var exitErr *exec.ExitError
	switch {
	case err == nil:
		code = 0
	case errors.As(err, &exitErr):
		code = exitErr.ExitCode()
	default:
		t.Fatalf("running the command line: %v", err)
	}
	return out.String(), errOut.String(), code
}

// TestOfflineMakesNoConnectionForAnyArgument is the regression test for
// --offline fetching from GitHub.
//
// An argument shaped like owner/repo that did not exist on disk was read as a
// GitHub repository before --offline was looked at, so `analyze servics/api
// --offline`, a mistyped services/api, opened a connection to api.github.com,
// and an explicit GitHub URL was fetched the same way. With --offline set,
// none of these arguments may open any connection, and each is reported as
// not found with exit 2.
func TestOfflineMakesNoConnectionForAnyArgument(t *testing.T) {
	proxy, log := startConnectionLog(t)

	for _, arg := range []string{
		"servics/api",
		"https://github.com/servics/api",
		"github.com/servics/api",
		"https://github.com/servics/api/tree/main/sub/dir",
	} {
		t.Run(arg, func(t *testing.T) {
			before := len(log.snapshot())
			stdout, stderr, code := runCLI(t, proxy, "analyze", arg, "--offline", "--deep")

			if got := log.snapshot()[before:]; len(got) != 0 {
				t.Errorf("%d connection(s) with --offline set, want 0: %q", len(got), got)
			}
			if code != ExitError {
				t.Errorf("exit code %d, want %d", code, ExitError)
			}
			want := "No file or directory named " + arg + ". --offline does not fetch repositories."
			if !strings.Contains(stderr, want) {
				t.Errorf("stderr does not say %q:\n%s", want, stderr)
			}
			if strings.Contains(stderr, "Fetching") || strings.Contains(stderr, "fetching") {
				t.Errorf("stderr reports a fetch:\n%s", stderr)
			}
			if stdout != "" {
				t.Errorf("a report was written for an argument that names nothing:\n%s", stdout)
			}
		})
	}

	t.Run("not shaped like a repository", func(t *testing.T) {
		before := len(log.snapshot())
		_, stderr, code := runCLI(t, proxy, "analyze", "./servics/api", "--offline")
		if got := log.snapshot()[before:]; len(got) != 0 {
			t.Errorf("%d connection(s) with --offline set, want 0: %q", len(got), got)
		}
		if code != ExitError {
			t.Errorf("exit code %d, want %d", code, ExitError)
		}
		if want := "No file or directory named ./servics/api."; !strings.Contains(stderr, want) {
			t.Errorf("stderr does not say %q:\n%s", want, stderr)
		}
	})

	// An empty argument, as `analyze "$SCAN_PATH" --offline` gives when the
	// variable is unset, is named as empty rather than printed as "named .".
	t.Run("empty", func(t *testing.T) {
		before := len(log.snapshot())
		_, stderr, code := runCLI(t, proxy, "analyze", "", "--offline")
		if got := log.snapshot()[before:]; len(got) != 0 {
			t.Errorf("%d connection(s) with --offline set, want 0: %q", len(got), got)
		}
		if code != ExitError {
			t.Errorf("exit code %d, want %d", code, ExitError)
		}
		if want := "Error: The path argument is empty."; !strings.Contains(stderr, want) {
			t.Errorf("stderr does not say %q:\n%s", want, stderr)
		}
	})

	// A local project still scans under --offline, with --deep asking for
	// source downloads, and opens nothing.
	t.Run("local project", func(t *testing.T) {
		fixture, err := filepath.Abs(filepath.Join("..", "..", "testdata", "fixtures", "npm-project"))
		if err != nil {
			t.Fatal(err)
		}
		before := len(log.snapshot())
		stdout, stderr, code := runCLI(t, proxy, "analyze", fixture, "--offline", "--deep", "--format", "json")
		if got := log.snapshot()[before:]; len(got) != 0 {
			t.Errorf("%d connection(s) with --offline set, want 0: %q", len(got), got)
		}
		if code == ExitError {
			t.Errorf("exit code %d for a local project; stderr:\n%s", code, stderr)
		}
		if !strings.Contains(stdout, `"projects"`) {
			t.Errorf("no report on stdout:\n%s", stdout)
		}
	})
}

// Without --offline the same argument is fetched, and the harness above sees
// it. This is what makes a zero in the offline test mean something: the
// counting proxy does observe the connection this command line makes when it
// is allowed to.
func TestWithoutOfflineTheFetchIsAnnouncedAndObserved(t *testing.T) {
	proxy, log := startConnectionLog(t)
	_, stderr, code := runCLI(t, proxy, "analyze", "servics/api")

	got := log.snapshot()
	if len(got) == 0 {
		t.Fatal("no connection was observed, so the offline test cannot detect one either")
	}
	if got[0] != "CONNECT api.github.com:443 HTTP/1.1" {
		t.Errorf("first connection %q, want CONNECT api.github.com:443", got[0])
	}
	// The proxy answers 502, so the fetch fails.
	if code != ExitError {
		t.Errorf("exit code %d, want %d", code, ExitError)
	}
	first, _, _ := strings.Cut(stderr, "\n")
	want := "No file or directory named servics/api was found, so fetching the GitHub repository servics/api instead..."
	if first != want {
		t.Errorf("first line of stderr is %q, want %q", first, want)
	}
}

// Without --offline, an argument that names nothing and is not shaped like a
// repository was left to the analysis, so `analyze " x"` printed
// "Error: analysis failed: cannot access path: stat  x: no such file or
// directory" and `analyze ""` printed "Error: analysis failed: cannot access
// path: stat : no such file or directory". Each is now reported as --offline
// reports it, before the database refresh, so it opens no connection either.
func TestWithoutOfflineAMissingPathIsReportedAsOfflineReportsIt(t *testing.T) {
	proxy, log := startConnectionLog(t)

	for arg, want := range map[string]string{
		"":              "Error: The path argument is empty.\n",
		" x":            "Error: No file or directory named \" x\".\n",
		"\tx":           "Error: No file or directory named \"\\tx\".\n",
		"./servics/api": "Error: No file or directory named ./servics/api.\n",
	} {
		t.Run(strconv.Quote(arg), func(t *testing.T) {
			before := len(log.snapshot())
			stdout, stderr, code := runCLI(t, proxy, "analyze", arg)

			if got := log.snapshot()[before:]; len(got) != 0 {
				t.Errorf("%d connection(s) for an argument that names nothing, want 0: %q", len(got), got)
			}
			if code != ExitError {
				t.Errorf("exit code %d, want %d", code, ExitError)
			}
			if stderr != want {
				t.Errorf("stderr is %q, want %q", stderr, want)
			}
			if stdout != "" {
				t.Errorf("a report was written for an argument that names nothing:\n%s", stdout)
			}
			if _, offlineStderr, _ := runCLI(t, proxy, "analyze", arg, "--offline"); stderr != offlineStderr {
				t.Errorf("stderr is %q, and with --offline it is %q", stderr, offlineStderr)
			}
		})
	}
}
