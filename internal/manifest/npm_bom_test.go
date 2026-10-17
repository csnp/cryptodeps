// Copyright 2025-2026 CyberSecurity NonProfit (CSNP)
// SPDX-License-Identifier: Apache-2.0

package manifest

import (
	"path/filepath"
	"testing"
)

// bomPackageJSON is a package.json that starts with a UTF-8 byte order mark.
const bomPackageJSON = "\xEF\xBB\xBF{\n" +
	"  \"name\": \"bom\",\n" +
	"  \"dependencies\": {\n" +
	"    \"node-forge\": \"1.0.0\"\n" +
	"  }\n" +
	"}\n"

// TestNPMParserSkipsByteOrderMark is the regression test for a package.json
// saved with a UTF-8 byte order mark. encoding/json rejected the mark, so the
// file failed with "invalid character 'ï' looking for beginning of value" and
// no dependency in it was analyzed.
func TestNPMParserSkipsByteOrderMark(t *testing.T) {
	path := filepath.Join(t.TempDir(), "package.json")
	writeFile(t, path, bomPackageJSON)

	deps, err := (&NPMParser{}).Parse(path)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(deps) != 1 {
		t.Fatalf("got %d dependencies, want 1", len(deps))
	}
	if deps[0].Name != "node-forge" || deps[0].Version != "1.0.0" {
		t.Errorf("got %s@%s, want node-forge@1.0.0", deps[0].Name, deps[0].Version)
	}
	if deps[0].Line != 4 {
		t.Errorf("node-forge reported at line %d, want 4", deps[0].Line)
	}
}

// TestDiscoveryAcceptsByteOrderMark checks the directory scan. Discovery
// validates a package.json by decoding it before any parser runs, and that
// check rejected the byte order mark as well, so the file was reported as
// "not valid JSON" and skipped.
func TestDiscoveryAcceptsByteOrderMark(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "package.json"), bomPackageJSON)

	manifests, skipped, err := DetectAndParseAll(root)
	if err != nil {
		t.Fatalf("DetectAndParseAll: %v", err)
	}
	if len(skipped) != 0 {
		t.Fatalf("package.json was skipped: %s", skipped[0].Reason)
	}
	if len(manifests) != 1 || len(manifests[0].Dependencies) != 1 {
		t.Fatalf("got %d manifests, want 1 manifest with 1 dependency", len(manifests))
	}
}

// TestNPMWorkspacesSkipByteOrderMark checks that the workspaces field of a
// root package.json saved with a byte order mark is still read.
func TestNPMWorkspacesSkipByteOrderMark(t *testing.T) {
	root := t.TempDir()
	rootManifest := filepath.Join(root, "package.json")
	writeFile(t, rootManifest, "\xEF\xBB\xBF{\"workspaces\": [\"packages/*\"]}\n")
	member := filepath.Join(root, "packages", "a", "package.json")
	writeFile(t, member, `{"name":"a"}`)

	got, err := parseNPMWorkspaces(rootManifest)
	if err != nil {
		t.Fatalf("parseNPMWorkspaces: %v", err)
	}
	// The member comes first, then the root manifest itself.
	if len(got) != 2 || got[0] != member || got[1] != rootManifest {
		t.Errorf("got workspace manifests %v, want [%s %s]", got, member, rootManifest)
	}
}
