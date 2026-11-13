// Copyright 2025-2026 CyberSecurity NonProfit (CSNP)
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// runGendbEnv makes the test binary run the generator instead of the tests, so
// that a test can run it the way the update workflow does: as a process started
// in a checkout, writing the database to stdout.
const runGendbEnv = "CRYPTODEPS_TEST_RUN_GENDB"

func TestMain(m *testing.M) {
	if os.Getenv(runGendbEnv) == "1" {
		main()
		return
	}
	os.Exit(m.Run())
}

// exportedRecord is the part of each database record these tests read.
type exportedRecord struct {
	Package  string `json:"package"`
	Analysis struct {
		Method      string `json:"method"`
		Tool        string `json:"tool"`
		ToolVersion string `json:"toolVersion"`
	} `json:"analysis"`
}

// isolatedEnv is the environment git and the generator run under in these
// tests: a home of their own and no system git configuration, so that a
// signing, hook or template setting on the machine running the tests cannot
// change what git does, and a directory outside a repository is not taken
// for part of one above it.
func isolatedEnv(t *testing.T, dir string) []string {
	t.Helper()
	home := t.TempDir()
	return []string{
		"PATH=" + os.Getenv("PATH"),
		"HOME=" + home,
		"XDG_CONFIG_HOME=" + filepath.Join(home, ".config"),
		"TMPDIR=" + os.TempDir(),
		"GIT_CONFIG_NOSYSTEM=1",
		"GIT_CEILING_DIRECTORIES=" + filepath.Dir(dir),
		"GIT_AUTHOR_NAME=fixture",
		"GIT_AUTHOR_EMAIL=fixture@example.invalid",
		"GIT_COMMITTER_NAME=fixture",
		"GIT_COMMITTER_EMAIL=fixture@example.invalid",
	}
}

// gitIn runs git in dir and returns what it printed, failing the test when it
// fails.
func gitIn(t *testing.T, dir string, env []string, args ...string) string {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is not installed, and the generator reads its version from git")
	}
	full := append([]string{"-c", "commit.gpgsign=false", "-c", "tag.gpgsign=false"}, args...)
	cmd := exec.Command("git", full...)
	cmd.Dir = dir
	cmd.Env = env
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return strings.TrimSpace(string(out))
}

// writeFile writes content to name under dir, creating its directory.
func writeFile(t *testing.T, dir, name, content string) {
	t.Helper()
	path := filepath.Join(dir, filepath.FromSlash(name))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

// checkout makes a git repository with one commit, holding the files the
// generator's version depends on and the database file the update workflow
// writes, and tags that commit with each of tags.
func checkout(t *testing.T, tags ...string) (dir string, env []string) {
	t.Helper()
	dir = t.TempDir()
	env = isolatedEnv(t, dir)
	writeFile(t, dir, "go.mod", "module example.com/fixture\n\ngo 1.21\n")
	writeFile(t, dir, "go.sum", "example.com/dep v1.0.0 h1:fixture=\n")
	writeFile(t, dir, "cmd/gendb/main.go", "package main\n\nfunc main() {}\n")
	writeFile(t, dir, "data/crypto-database.json", "{}\n")
	writeFile(t, dir, "README.md", "fixture\n")
	gitIn(t, dir, env, "init", "-q")
	gitIn(t, dir, env, "add", "go.mod", "go.sum", "cmd/gendb/main.go", "data/crypto-database.json", "README.md")
	gitIn(t, dir, env, "commit", "-q", "-m", "fixture")
	for _, tag := range tags {
		gitIn(t, dir, env, "tag", tag)
	}
	return dir, env
}

// runGendb runs the generator in dir with args, as the update workflow runs
// `go run cmd/gendb/main.go`, and returns what it wrote to stdout and stderr
// and its exit code.
func runGendb(t *testing.T, dir string, env []string, args ...string) (stdout, stderr string, code int) {
	t.Helper()
	cmd := exec.Command(os.Args[0], args...)
	cmd.Dir = dir
	// GOCOVERDIR keeps a test binary built for coverage from adding a warning
	// to stderr, as in cmd/cryptodeps.
	cmd.Env = append(append([]string{}, env...), runGendbEnv+"=1", "GOCOVERDIR="+t.TempDir())
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
		t.Fatalf("running the generator: %v", err)
	}
	return out.String(), errOut.String(), code
}

// generatedRecords runs the generator and returns the records it wrote,
// failing the test unless it exited 0 with a database on stdout.
func generatedRecords(t *testing.T, dir string, env []string, args ...string) []exportedRecord {
	t.Helper()
	stdout, stderr, code := runGendb(t, dir, env, args...)
	if code != 0 {
		t.Fatalf("generator exited %d:\n%s", code, stderr)
	}
	var export struct {
		Packages []exportedRecord `json:"packages"`
	}
	if err := json.Unmarshal([]byte(stdout), &export); err != nil {
		t.Fatalf("generator output is not a database: %v\n%s", err, stdout)
	}
	if len(export.Packages) == 0 {
		t.Fatal("generator wrote a database with no records")
	}
	if n := strings.Count(stdout, `"toolVersion": "dev"`); n != 0 {
		t.Errorf(`the database holds %d "toolVersion": "dev"`, n)
	}
	return export.Packages
}

// assertEveryRecordNames fails for each record that does not name this
// generator at version want.
func assertEveryRecordNames(t *testing.T, records []exportedRecord, want string) {
	t.Helper()
	wrong := 0
	for _, r := range records {
		if r.Analysis.Tool != "cryptodeps" || r.Analysis.ToolVersion != want {
			if wrong < 5 {
				t.Errorf("%s (%s): tool %q, toolVersion %q, want cryptodeps %q",
					r.Package, r.Analysis.Method, r.Analysis.Tool, r.Analysis.ToolVersion, want)
			}
			wrong++
		}
	}
	if wrong > 0 {
		t.Errorf("%d of %d records do not name the generator's version %q", wrong, len(records), want)
	}
}

// TestEveryRecordNamesTheGeneratorAndItsVersion is the regression test for
// issue #34 on the generator.
//
// The update workflow runs the generator with `go run` and no version, so every
// record it made by inference said "toolVersion": "dev", and every curated
// record an empty version. Run in a checkout of a release tag, it now writes
// that release on every record.
func TestEveryRecordNamesTheGeneratorAndItsVersion(t *testing.T) {
	dir, env := checkout(t, "v9.8.7")
	assertEveryRecordNames(t, generatedRecords(t, dir, env), "9.8.7")
}

// TestGeneratorVersionCountsCommitsAfterTheReleaseTag covers a checkout after a
// release, which is what the update workflow runs on, and the database release
// tags it pushes, which name no version of the generator and are passed over.
func TestGeneratorVersionCountsCommitsAfterTheReleaseTag(t *testing.T) {
	dir, env := checkout(t, "v9.8.7")
	writeFile(t, dir, "cmd/gendb/main.go", "package main\n\nfunc main() { println() }\n")
	gitIn(t, dir, env, "commit", "-q", "-a", "-m", "after the release")
	gitIn(t, dir, env, "tag", "db-v1.1.0-20261113")
	head := gitIn(t, dir, env, "rev-parse", "HEAD")

	records := generatedRecords(t, dir, env)
	got := records[0].Analysis.ToolVersion
	m := regexp.MustCompile(`^9\.8\.7-1-g([0-9a-f]{7,})$`).FindStringSubmatch(got)
	if m == nil || !strings.HasPrefix(head, m[1]) {
		t.Fatalf("toolVersion = %q, want 9.8.7-1-g followed by the start of %s", got, head)
	}
	assertEveryRecordNames(t, records, got)
}

// TestGeneratorVersionMarksUncommittedSourceChanges covers a database made from
// a checkout whose source differs from its commit, which that commit did not
// produce. The database file itself is left out of the comparison: the
// Makefile and the update workflow write it through a shell redirect, which
// empties it before the generator starts.
func TestGeneratorVersionMarksUncommittedSourceChanges(t *testing.T) {
	for _, tc := range []struct {
		name, file, content, want string
	}{
		{"changed Go file", "cmd/gendb/main.go", "package main\n\nfunc main() { println() }\n", "9.8.7-dirty"},
		{"new Go file", "internal/extra.go", "package internal\n", "9.8.7-dirty"},
		{"changed go.mod", "go.mod", "module example.com/fixture\n\ngo 1.22\n", "9.8.7-dirty"},
		{"changed go.sum", "go.sum", "", "9.8.7-dirty"},
		{"emptied database file", "data/crypto-database.json", "", "9.8.7"},
		{"changed README", "README.md", "changed\n", "9.8.7"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir, env := checkout(t, "v9.8.7")
			writeFile(t, dir, tc.file, tc.content)
			assertEveryRecordNames(t, generatedRecords(t, dir, env), tc.want)
		})
	}
}

// TestGeneratorWritesNoDatabaseWithoutAVersion covers a run where no version
// can be named: outside a git checkout with no --tool-version, or with "dev"
// passed as the version. Either way the generator exits non-zero and writes
// nothing on stdout, so the shell redirect that receives the database is left
// empty rather than holding records with no version.
func TestGeneratorWritesNoDatabaseWithoutAVersion(t *testing.T) {
	dir := t.TempDir()
	env := isolatedEnv(t, dir)
	for _, tc := range []struct {
		name, mention string
		args          []string
	}{
		{"outside a checkout", "--tool-version", nil},
		{"given dev", `"dev"`, []string{"--tool-version", "dev"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stdout, stderr, code := runGendb(t, dir, env, tc.args...)
			if code == 0 {
				t.Errorf("generator exited 0")
			}
			if stdout != "" {
				t.Errorf("generator wrote %d bytes on stdout, want none", len(stdout))
			}
			if !strings.Contains(stderr, tc.mention) {
				t.Errorf("stderr does not mention %s:\n%s", tc.mention, stderr)
			}
		})
	}
}

// TestGeneratorToolVersionFlag covers --tool-version, which names the version
// where git cannot, and is used as given in a checkout as well.
func TestGeneratorToolVersionFlag(t *testing.T) {
	t.Run("outside a checkout", func(t *testing.T) {
		dir := t.TempDir()
		env := isolatedEnv(t, dir)
		assertEveryRecordNames(t, generatedRecords(t, dir, env, "--tool-version", "1.2.3"), "1.2.3")
	})
	t.Run("in a checkout", func(t *testing.T) {
		dir, env := checkout(t, "v9.8.7")
		assertEveryRecordNames(t, generatedRecords(t, dir, env, "--tool-version", "1.2.3"), "1.2.3")
	})
}
