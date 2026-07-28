// Copyright 2025-2026 CyberSecurity NonProfit (CSNP)
// SPDX-License-Identifier: Apache-2.0

package manifest

import (
	"path/filepath"
	"strings"
	"testing"
)

// TestNPMParseOrderIsStable is the regression test for output that shuffled
// between runs of the same scan.
//
// package.json dependency blocks unmarshal into maps, and Go randomises map
// iteration, so ranging over them directly made every downstream format reorder
// itself run to run. The finding set was stable; only the order moved, which is
// enough to break golden-file CI and reproducible SBOMs.
//
// Ten dependency names are used because the randomisation is per-iteration: with
// two or three names, a stable-looking result is likely by chance.
func TestNPMParseOrderIsStable(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "package.json")
	writeFile(t, path, `{
	  "name": "ordering",
	  "dependencies": {
	    "zeta": "1.0.0", "alpha": "1.0.0", "mike": "1.0.0", "bravo": "1.0.0",
	    "yankee": "1.0.0", "charlie": "1.0.0", "xray": "1.0.0", "delta": "1.0.0",
	    "whisky": "1.0.0", "echo": "1.0.0"
	  },
	  "devDependencies": {"tango": "1.0.0", "foxtrot": "1.0.0"}
	}`)

	parser := &NPMParser{}
	var first []string
	for i := 0; i < 20; i++ {
		deps, err := parser.Parse(path)
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		names := make([]string, 0, len(deps))
		for _, d := range deps {
			names = append(names, d.Name)
		}
		if i == 0 {
			first = names
			continue
		}
		if strings.Join(names, ",") != strings.Join(first, ",") {
			t.Fatalf("dependency order changed between parses of the same file:\nfirst: %v\nnow:   %v",
				first, names)
		}
	}

	if len(first) != 12 {
		t.Fatalf("got %d dependencies, want 12", len(first))
	}
	// Production dependencies come before dev dependencies, each sorted.
	if first[0] != "alpha" || first[9] != "zeta" {
		t.Errorf("production block is not sorted: %v", first[:10])
	}
	if first[10] != "foxtrot" || first[11] != "tango" {
		t.Errorf("dev block is not sorted or not last: %v", first[10:])
	}
}
