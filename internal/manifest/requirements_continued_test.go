// Copyright 2025-2026 CyberSecurity NonProfit (CSNP)
// SPDX-License-Identifier: Apache-2.0

package manifest

import (
	"path/filepath"
	"strings"
	"testing"
)

// pip reads a requirements.txt line that ends in a backslash together with the
// next one, so a pin can carry its hashes on the lines after it:
//
//	cryptography==42.0.0 \
//	    --hash=sha256:...
//
// The parser read one physical line at a time, so the version kept the
// backslash and was reported as "42.0.0 \". It now reads the lines unreadLines
// reads, with continued lines joined and numbered by their first line, and
// ends a requirement at its first per-requirement option, such as --hash, as
// pip does. An "-r" include or a name @ URL reference continued onto the next
// line is then skipped as a whole, where its second line was read as a
// dependency of its own or its first line gave a version of "@ \".
func TestRequirementsTxtJoinsContinuedLines(t *testing.T) {
	type dep struct {
		name    string
		version string
		line    int
	}
	cases := []struct {
		name  string
		lines []string
		want  []dep
	}{
		{"hash on the next line", []string{`cryptography==42.0.0 \`, "    --hash=sha256:FAKE"},
			[]dep{{"cryptography", "42.0.0", 1}}},
		{"several pins, hashes and comment lines", []string{
			"# pinned with hashes",
			`cryptography==42.0.0 \`,
			`    --hash=sha256:FAKE1 \`,
			"    --hash=sha256:FAKE2",
			"    # via paramiko",
			`paramiko==3.4.0 \`,
			"    --hash=sha256:FAKE3",
			"    # via -r requirements.in",
		}, []dep{{"cryptography", "42.0.0", 2}, {"paramiko", "3.4.0", 6}}},
		{"hash on the same line", []string{"cryptography==42.0.0 --hash=sha256:FAKE"},
			[]dep{{"cryptography", "42.0.0", 1}}},
		{"tab before the hash", []string{"cryptography==42.0.0\t--hash=sha256:FAKE"},
			[]dep{{"cryptography", "42.0.0", 1}}},
		{"unpinned with a hash", []string{`cryptography \`, "    --hash=sha256:FAKE"},
			[]dep{{"cryptography", "", 1}}},
		{"environment marker on the next line", []string{`pyjwt==2.8.0 \`, `    ; python_version >= "3.8"`},
			[]dep{{"pyjwt", "2.8.0", 1}}},
		{"CRLF line endings", []string{"cryptography==42.0.0 \\\r", "    --hash=sha256:FAKE\r"},
			[]dep{{"cryptography", "42.0.0", 1}}},
		{"backslash on the last line", []string{"requests==2.31.0", `cryptography==42.0.0 \`},
			[]dep{{"requests", "2.31.0", 1}, {"cryptography", "42.0.0", 2}}},
		{"include continued onto the next line", []string{`-r \`, "extra.txt", "cryptography==42.0.0"},
			[]dep{{"cryptography", "42.0.0", 3}}},
		{"name @ URL continued onto the next line", []string{`paramiko @ \`, "https://example.invalid/p", "cryptography==42.0.0"},
			[]dep{{"cryptography", "42.0.0", 3}}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "requirements.txt")
			writeFile(t, path, strings.Join(c.lines, "\n")+"\n")

			deps, err := (&PythonParser{}).Parse(path)
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			if len(deps) != len(c.want) {
				t.Fatalf("dependencies = %+v, want %d", deps, len(c.want))
			}
			for i, w := range c.want {
				g := deps[i]
				if g.Name != w.name || g.Version != w.version || g.Line != w.line {
					t.Errorf("dependencies[%d] = %s %q at line %d, want %s %q at line %d",
						i, g.Name, g.Version, g.Line, w.name, w.version, w.line)
				}
			}
		})
	}
}
