// Copyright 2025-2026 CyberSecurity NonProfit (CSNP)
// SPDX-License-Identifier: Apache-2.0

package manifest

import (
	"path/filepath"
	"strings"
	"testing"
)

// TestLockFilesOfOtherToolsSuggestTheManifest covers yarn.lock answering
// "unsupported manifest file: yarn.lock" when passed as the argument, while
// package-lock.json got the lock-file message naming package.json. The lock
// files of the other npm clients and of the Python tools whose manifests
// CryptoDeps reads get the same message.
func TestLockFilesOfOtherToolsSuggestTheManifest(t *testing.T) {
	for lockFile, manifest := range map[string]string{
		"yarn.lock":           "package.json",
		"pnpm-lock.yaml":      "package.json",
		"npm-shrinkwrap.json": "package.json",
		"Pipfile.lock":        "Pipfile",
		"poetry.lock":         "pyproject.toml",
	} {
		t.Run(lockFile, func(t *testing.T) {
			dir := t.TempDir()
			lockPath := filepath.Join(dir, lockFile)
			writeFile(t, lockPath, "{}\n")

			_, single := DetectAndParse(lockPath)
			_, _, all := DetectAndParseAll(lockPath)
			for name, err := range map[string]error{"DetectAndParse": single, "DetectAndParseAll": all} {
				if err == nil {
					t.Fatalf("%s(%q) returned no error", name, lockPath)
				}
				msg := err.Error()
				if !strings.Contains(msg, lockPath+" is a lock file") {
					t.Errorf("%s(%q) error does not say it is a lock file: %q", name, lockPath, msg)
				}
				if want := "cryptodeps analyze " + filepath.Join(dir, manifest); !strings.Contains(msg, want) {
					t.Errorf("%s(%q) error does not give the command %q: %q", name, lockPath, want, msg)
				}
			}
		})
	}
}

// TestDirectoryHoldingOnlyLockFilesSaysSo covers a directory holding only
// yarn.lock, which got "no supported manifest files found in DIR" and nothing
// about the lock file, while the same lock file passed as the argument named
// the manifest CryptoDeps reads instead.
func TestDirectoryHoldingOnlyLockFilesSaysSo(t *testing.T) {
	tests := []struct {
		files []string
		want  string
	}{
		{[]string{"yarn.lock"}, "yarn.lock is a lock file, and CryptoDeps reads package.json instead"},
		{[]string{"package-lock.json"}, "package-lock.json is a lock file, and CryptoDeps reads package.json instead"},
		{[]string{"go.sum", "yarn.lock", "package-lock.json"},
			"go.sum, package-lock.json and yarn.lock are lock files, and CryptoDeps reads go.mod and package.json instead"},
	}
	for _, tt := range tests {
		t.Run(strings.Join(tt.files, "+"), func(t *testing.T) {
			dir := t.TempDir()
			for _, f := range tt.files {
				writeFile(t, filepath.Join(dir, f), "{}\n")
			}

			// Both entry points: analyze uses DetectAndParseAll by default and
			// DetectAndParse under --no-workspaces.
			_, single := DetectAndParse(dir)
			_, _, all := DetectAndParseAll(dir)
			for name, err := range map[string]error{"DetectAndParse": single, "DetectAndParseAll": all} {
				if err == nil {
					t.Fatalf("%s(%q) returned no error", name, dir)
				}
				if !strings.Contains(err.Error(), tt.want) {
					t.Errorf("%s(%q) error does not say %q: %q", name, dir, tt.want, err.Error())
				}
			}
		})
	}

	// A directory holding no lock file keeps the message it had.
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "README.md"), "# x\n")
	_, _, err := DetectAndParseAll(dir)
	if err == nil || err.Error() != "no supported manifest files found in "+dir {
		t.Errorf("DetectAndParseAll(%q) = %v, want the message without a lock-file clause", dir, err)
	}
}

// TestGoModIndirectMarkerAppliesToItsOwnLine covers a require block holding
// one "// indirect" entry, after which every entry of the same block was
// reported as indirect, golang-jwt included.
func TestGoModIndirectMarkerAppliesToItsOwnLine(t *testing.T) {
	path := filepath.Join(t.TempDir(), "go.mod")
	writeFile(t, path, "module example.com/app\n\n"+
		"go 1.22\n\n"+
		"require (\n"+
		"\tfilippo.io/edwards25519 v1.1.0 // indirect\n"+
		"\tgithub.com/golang-jwt/jwt/v5 v5.2.0\n"+
		"\tgolang.org/x/crypto v0.21.0 // indirect\n"+
		"\tgolang.org/x/net v0.22.0\n"+
		")\n")

	deps, err := (&GoModParser{}).Parse(path)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{
		"filippo.io/edwards25519":      false,
		"github.com/golang-jwt/jwt/v5": true,
		"golang.org/x/crypto":          false,
		"golang.org/x/net":             true,
	}
	if len(deps) != len(want) {
		t.Fatalf("parsed %d dependencies, want %d: %+v", len(deps), len(want), deps)
	}
	for _, d := range deps {
		if direct, ok := want[d.Name]; !ok || d.Direct != direct {
			t.Errorf("%s: direct = %v, want %v", d.Name, d.Direct, direct)
		}
	}
}
