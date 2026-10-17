// Copyright 2025-2026 CyberSecurity NonProfit (CSNP)
// SPDX-License-Identifier: Apache-2.0

package manifest

import (
	"path/filepath"
	"strings"
	"testing"
)

// pip rejects a requirements.txt line with text after its version specifier,
// such as "cryptography==42.0.0 xxx". The parser took the rest of the line as
// the version, so that line was reported as cryptography at version
// "42.0.0 xxx", and with 70,000 characters after the version all of them were
// printed as part of the dependency. The version now ends where the specifier
// ends: each line below is read with the version of the same line without the
// text after it, and that line is read as it was before.
func TestRequirementsTxtVersionEndsWithItsSpecifier(t *testing.T) {
	cases := []struct {
		name    string
		line    string // a requirement with nothing after its version
		after   string // text after it, with which pip rejects the line
		version string
	}{
		{"the line in the report", "cryptography==42.0.0", " xxx", "42.0.0"},
		{"70,000 characters after the version", "cryptography==42.0.0", " " + strings.Repeat("x", 70000), "42.0.0"},
		{"a tab before the text", "cryptography==42.0.0", "\txxx", "42.0.0"},
		{"an operator with no comma before it", "cryptography==42.0.0", " >=41", "42.0.0"},
		{"an environment marker after the text", "cryptography==42.0.0", ` xxx ; python_version >= "3.8"`, "42.0.0"},
		{"a comment after the text", "cryptography==42.0.0", " xxx  # pinned", "42.0.0"},
		{"clauses joined by commas", "cryptography>=41.0, <43", " xxx", "41.0, <43"},
		{"whitespace around a comma and an operator", "cryptography>=41.0 , < 43", " xxx", "41.0 , < 43"},
		{"a comma that ends the list", "cryptography>=41.0,", " xxx", "41.0,"},
		{"no operator", "cryptography 42.0.0", " xxx", "42.0.0"},
		{"parentheses after a space", "cryptography (>= 41.0, < 43)", " xxx", "(>= 41.0, < 43)"},
		{"extras after a space", "cryptography [ssh] >= 41.0", " xxx", "[ssh] >= 41.0"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			for _, line := range []string{c.line, c.line + c.after} {
				path := filepath.Join(t.TempDir(), "requirements.txt")
				writeFile(t, path, line+"\npycryptodome==3.20.0\n")

				deps, err := (&PythonParser{}).Parse(path)
				if err != nil {
					t.Fatalf("parse: %v", err)
				}
				if len(deps) != 2 {
					t.Fatalf("dependencies = %d, want 2", len(deps))
				}
				if g := deps[0]; g.Name != "cryptography" || g.Version != c.version || g.Line != 1 {
					version := g.Version
					if len(version) > 40 {
						version = version[:40] + "..."
					}
					t.Errorf("line %.40q: dependency = %s %q at line %d, want cryptography %q at line 1",
						line, g.Name, version, g.Line, c.version)
				}
				if g := deps[1]; g.Name != "pycryptodome" || g.Version != "3.20.0" || g.Line != 2 {
					t.Errorf("line %.40q: next dependency = %s %q at line %d, want pycryptodome \"3.20.0\" at line 2",
						line, g.Name, g.Version, g.Line)
				}
			}
		})
	}
}

// Only text after a version is left out. A line with no version after its name
// and extras, such as "cryptography >=" or a name @ path reference, and a line
// with nothing after its specifier, such as "zope.interface >= 5.0" with the
// dot requirementPattern stops at, are kept whole.
func TestRequirementEndKeepsALineWithNothingAfterItsVersion(t *testing.T) {
	for _, line := range []string{
		"",
		"cryptography",
		"cryptography >=",
		"cryptography[ssh]",
		"cryptography [ssh",
		"cryptography (",
		"cryptography ()",
		"cryptography ;python_version<'3.8'",
		"paramiko @ ./vendor/paramiko-3.4.0.tar.gz",
		"zope.interface >= 5.0",
		"cryptography ( >= 41.0 , < 43 )",
	} {
		if got := requirementEnd(line); got != len(line) {
			t.Errorf("requirementEnd(%q) = %d, want %d, the whole line", line, got, len(line))
		}
	}
}
