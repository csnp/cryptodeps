// Copyright 2025-2026 CyberSecurity NonProfit (CSNP)
// SPDX-License-Identifier: Apache-2.0

package manifest

import (
	"bufio"
	"path/filepath"
	"strings"
	"testing"
)

// The requirements.txt reader used bufio.Scanner with its default token limit
// of 64 KiB, so a longer line stopped it with "bufio.Scanner: token too long".
// The parser returned that error and the scan refused the whole file, where
// pip reads it. A pin carrying its hashes on one line, or a long comment, can
// take a line past 64 KiB. The parser and unreadLines now read such a line,
// and the lines around it, as they read a short one.
func TestRequirementsTxtReadsLinesLongerThan64KiB(t *testing.T) {
	const fileInclude = "included requirements files are not followed"
	hashes := strings.Repeat(" --hash=sha256:FAKE", 4000)
	type dep struct {
		name    string
		version string
		line    int
	}
	cases := []struct {
		name    string
		lines   []string
		want    []dep
		include int // the line of the "-r extra.txt" include
	}{
		{"hashes on the same line", []string{
			"requests==2.31.0",
			"cryptography==42.0.0" + hashes,
			"pycryptodome==3.20.0",
			"-r extra.txt",
		}, []dep{{"requests", "2.31.0", 1}, {"cryptography", "42.0.0", 2}, {"pycryptodome", "3.20.0", 3}}, 4},
		{"hashes on a continued line", []string{
			`cryptography==42.0.0 \`,
			"   " + hashes,
			"pycryptodome==3.20.0",
			"-r extra.txt",
		}, []dep{{"cryptography", "42.0.0", 1}, {"pycryptodome", "3.20.0", 3}}, 4},
		{"comment line", []string{
			"# " + strings.Repeat("x", 70000),
			"cryptography==42.0.0",
			"-r extra.txt",
		}, []dep{{"cryptography", "42.0.0", 2}}, 3},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			longest := 0
			for _, l := range c.lines {
				if len(l) > longest {
					longest = len(l)
				}
			}
			if longest <= bufio.MaxScanTokenSize {
				t.Fatalf("longest line is %d bytes, want more than %d", longest, bufio.MaxScanTokenSize)
			}
			path := filepath.Join(t.TempDir(), "requirements.txt")
			writeFile(t, path, strings.Join(c.lines, "\n")+"\n")

			deps, err := (&PythonParser{}).Parse(path)
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			if len(deps) != len(c.want) {
				t.Fatalf("dependencies = %d, want %d", len(deps), len(c.want))
			}
			for i, w := range c.want {
				g := deps[i]
				if g.Name != w.name || g.Version != w.version || g.Line != w.line {
					t.Errorf("dependencies[%d] = %s %q at line %d, want %s %q at line %d",
						i, g.Name, g.Version, g.Line, w.name, w.version, w.line)
				}
			}

			unread := unreadLines(path)
			if len(unread) != 1 || unread[0].Line != c.include || unread[0].Name != "extra.txt" ||
				!strings.HasPrefix(unread[0].Reason, fileInclude) {
				t.Errorf("unreadLines = %+v, want the include of extra.txt at line %d", unread, c.include)
			}
		})
	}
}

// The file in the report: its first line is "cryptography==42.0.0 " followed
// by 70,000 characters. A scan of its directory failed with "found 1 manifest
// file(s) but none could be read" and exited 2. The file is now read, and the
// lines after the long one are analyzed and listed.
func TestScanReadsRequirementsTxtWithALineLongerThan64KiB(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "requirements.txt"),
		"cryptography==42.0.0 "+strings.Repeat("x", 70000)+"\npycryptodome==3.20.0\n-r extra.txt\n")

	manifests, skipped, err := DetectAndParseAll(root)
	if err != nil {
		t.Fatalf("DetectAndParseAll: %v", err)
	}
	if len(skipped) != 0 {
		t.Errorf("skipped = %+v, want none", skipped)
	}
	if len(manifests) != 1 {
		t.Fatalf("manifests = %d, want 1", len(manifests))
	}
	m := manifests[0]
	lines := make(map[string]int)
	for _, d := range m.Dependencies {
		lines[d.Name] = d.Line
		if d.Name == "pycryptodome" && d.Version != "3.20.0" {
			t.Errorf("pycryptodome version = %q, want 3.20.0", d.Version)
		}
	}
	if len(m.Dependencies) != 2 || lines["cryptography"] != 1 || lines["pycryptodome"] != 2 {
		t.Errorf("dependency lines = %v, want cryptography at line 1 and pycryptodome at line 2", lines)
	}
	if len(m.Unread) != 1 || m.Unread[0].Line != 3 || m.Unread[0].Name != "extra.txt" {
		t.Errorf("unread = %+v, want the include of extra.txt at line 3", m.Unread)
	}
}
