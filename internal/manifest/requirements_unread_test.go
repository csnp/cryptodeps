// Copyright 2025-2026 CyberSecurity NonProfit (CSNP)
// SPDX-License-Identifier: Apache-2.0

package manifest

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Every requirements.txt line that declares dependencies the parser skips is
// listed with its line number, option lines that declare none are not, and no
// URL from the manifest is copied into the result, not even the URL of an
// "-r" include, which pip fetches and which can carry credentials.
func TestRequirementsUnreadLines(t *testing.T) {
	dir := t.TempDir()
	content := strings.Join([]string{
		"cryptography==42.0.0",   // 1 read
		"-r extra.txt",           // 2
		"--requirement=more.txt", // 3
		"-rdev.txt",              // 4
		"paramiko[ed25519] @ https://example.invalid/p",  // 5
		"-e git+https://example.invalid/repo.git#egg=x",  // 6
		"https://example.invalid/pkg.whl",                // 7
		"-r https://example.invalid/private-reqs.txt",    // 8 a URL include
		"--requirement=https://example.invalid/more.txt", // 9 a URL include
		"--index-url https://example.invalid/simple",     // 10 not a dependency
		"-c constraints.txt",                             // 11 not a dependency
		"# -r commented.txt",                             // 12 comment
		"",
	}, "\n")
	path := filepath.Join(dir, "requirements.txt")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	m, err := DetectAndParse(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Dependencies) != 1 || m.Dependencies[0].Name != "cryptography" {
		t.Errorf("dependencies = %+v, want cryptography only", m.Dependencies)
	}

	want := []struct {
		line int
		name string
	}{
		{2, "extra.txt"}, {3, "more.txt"}, {4, "dev.txt"}, {5, "paramiko"}, {6, ""}, {7, ""}, {8, ""}, {9, ""},
	}
	if len(m.Unread) != len(want) {
		t.Fatalf("Unread = %+v, want %d entries", m.Unread, len(want))
	}
	for i, w := range want {
		got := m.Unread[i]
		if got.Line != w.line || got.Name != w.name || got.Reason == "" {
			t.Errorf("Unread[%d] = %+v, want line %d name %q and a reason", i, got, w.line, w.name)
		}
		if strings.Contains(got.Name+got.Reason, "example.invalid") {
			t.Errorf("Unread[%d] copies a URL: %+v", i, got)
		}
	}
}

// Other manifests report no unread lines.
func TestUnreadLinesOnlyForRequirementsTxt(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "package.json")
	if err := os.WriteFile(path, []byte(`{"name":"x","dependencies":{"a":"https://example.invalid/a.tgz"}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := unreadLines(path); got != nil {
		t.Errorf("unreadLines(package.json) = %+v, want nil", got)
	}
}
