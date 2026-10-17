// Copyright 2025-2026 CyberSecurity NonProfit (CSNP)
// SPDX-License-Identifier: Apache-2.0

package manifest

import (
	"bufio"
	"path/filepath"
	"strings"
	"testing"

	"github.com/csnp/qramm-cryptodeps/pkg/types"
)

// The go.mod reader used bufio.Scanner with its default token limit of 64 KiB,
// so a longer line stopped it with "bufio.Scanner: token too long". The parser
// returned that error and the scan refused the whole file, where the go command
// reads it. A long comment can take a line past 64 KiB. The parser now reads
// such a line, and the lines around it, as it reads a short one.
func TestGoModReadsLinesLongerThan64KiB(t *testing.T) {
	comment := "// " + strings.Repeat("x", 70000)
	type dep struct {
		name    string
		version string
		line    int
		direct  bool
	}
	cases := []struct {
		name  string
		lines []string
		want  []dep
	}{
		{"comment line before a require line", []string{
			"module example.com/x",
			"",
			"go 1.21",
			"",
			comment,
			"",
			"require golang.org/x/crypto v0.17.0",
		}, []dep{{"golang.org/x/crypto", "v0.17.0", 7, true}}},
		{"comment line inside a require block", []string{
			"module example.com/x",
			"",
			"go 1.21",
			"",
			"require (",
			"\tgithub.com/golang-jwt/jwt/v5 v5.2.0",
			"\t" + comment,
			"\tgolang.org/x/crypto v0.17.0 // indirect",
			")",
		}, []dep{{"github.com/golang-jwt/jwt/v5", "v5.2.0", 6, true}, {"golang.org/x/crypto", "v0.17.0", 8, false}}},
		{"comment at the end of a require entry", []string{
			"module example.com/x",
			"",
			"go 1.21",
			"",
			"require (",
			"\tgolang.org/x/crypto v0.17.0 " + comment,
			"\tgolang.org/x/net v0.22.0",
			")",
		}, []dep{{"golang.org/x/crypto", "v0.17.0", 6, true}, {"golang.org/x/net", "v0.22.0", 7, true}}},
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
			path := filepath.Join(t.TempDir(), "go.mod")
			writeFile(t, path, strings.Join(c.lines, "\n")+"\n")

			deps, err := (&GoModParser{}).Parse(path)
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			if len(deps) != len(c.want) {
				t.Fatalf("dependencies = %d, want %d", len(deps), len(c.want))
			}
			for i, w := range c.want {
				g := deps[i]
				if g.Name != w.name || g.Version != w.version || g.Line != w.line || g.Direct != w.direct {
					t.Errorf("dependencies[%d] = %s %q at line %d (direct %v), want %s %q at line %d (direct %v)",
						i, g.Name, g.Version, g.Line, g.Direct, w.name, w.version, w.line, w.direct)
				}
			}
		})
	}
}

// The file in the report: a comment line of 70,003 characters on line 5 and
// "require golang.org/x/crypto v0.17.0" on line 7. A scan of its directory
// failed with "found 1 manifest file(s) but none could be read" and exited 2.
// The file is now read, and golang.org/x/crypto is analyzed.
func TestScanReadsGoModWithALineLongerThan64KiB(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "go.mod"),
		"module example.com/x\n\ngo 1.21\n\n// "+strings.Repeat("x", 70000)+"\n\nrequire golang.org/x/crypto v0.17.0\n")

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
	if m.Ecosystem != types.EcosystemGo {
		t.Errorf("ecosystem = %q, want %q", m.Ecosystem, types.EcosystemGo)
	}
	if len(m.Dependencies) != 1 {
		t.Fatalf("dependencies = %+v, want golang.org/x/crypto alone", m.Dependencies)
	}
	d := m.Dependencies[0]
	if d.Name != "golang.org/x/crypto" || d.Version != "v0.17.0" || d.Line != 7 || !d.Direct {
		t.Errorf("dependency = %s %q at line %d (direct %v), want golang.org/x/crypto \"v0.17.0\" at line 7 (direct true)",
			d.Name, d.Version, d.Line, d.Direct)
	}
}
