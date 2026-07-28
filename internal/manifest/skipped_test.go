// Copyright 2025-2026 CyberSecurity NonProfit (CSNP)
// SPDX-License-Identifier: Apache-2.0

package manifest

import (
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// TestCorruptManifestIsReportedNotDropped is the regression test for a scanner
// that skipped input silently.
//
// A tree with a good and a corrupt package.json scanned only the good one, never
// mentioned the corrupt one, and reported a clean summary. The cause was not the
// parse-error path: validateManifest rejected the file during discovery, before
// any parser ran, so no parse error was ever produced.
func TestCorruptManifestIsReportedNotDropped(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "good", "package.json"),
		`{"name":"good","dependencies":{"node-forge":"1.3.1"}}`)
	// Truncated mid-object, the shape a bad merge leaves behind.
	writeFile(t, filepath.Join(root, "corrupt", "package.json"),
		`{"name":"corrupt","dependencies":{"node-forge":`)

	manifests, skipped, err := DetectAndParseAll(root)
	if err != nil {
		t.Fatalf("DetectAndParseAll: %v", err)
	}

	if len(manifests) != 1 {
		t.Fatalf("got %d parsed manifests, want 1 (the good one)", len(manifests))
	}
	if !strings.Contains(manifests[0].Path, "good") {
		t.Errorf("parsed the wrong manifest: %s", manifests[0].Path)
	}

	if len(skipped) != 1 {
		t.Fatalf("got %d skipped manifests, want 1; a corrupt manifest was dropped silently", len(skipped))
	}
	if !strings.Contains(skipped[0].Path, "corrupt") {
		t.Errorf("skipped the wrong file: %s", skipped[0].Path)
	}
	if skipped[0].Reason == "" {
		t.Error("skipped manifest carries no reason, so the user cannot tell what is wrong with the file")
	}
	if !strings.Contains(skipped[0].Reason, "JSON") {
		t.Errorf("reason %q does not identify the defect", skipped[0].Reason)
	}
}

// TestOnlyCorruptManifestDoesNotClaimNoneExist checks the error message.
//
// A tree whose only manifest is corrupt reported "no supported manifest files
// found", sending the user to look for a file that is right there.
func TestOnlyCorruptManifestDoesNotClaimNoneExist(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "package.json"), `{"name":"x","dependencies":{`)

	_, skipped, err := DetectAndParseAll(root)
	if err == nil {
		t.Fatal("expected an error when no manifest could be read")
	}
	if strings.Contains(err.Error(), "no supported manifest files found") {
		t.Errorf("error claims no manifest exists when one is present: %v", err)
	}
	if !strings.Contains(err.Error(), "package.json") {
		t.Errorf("error does not name the file that failed: %v", err)
	}
	if len(skipped) != 1 {
		t.Errorf("got %d skipped, want 1", len(skipped))
	}
}

// TestEmptyManifestIsReported covers the other validation rejection.
func TestEmptyManifestIsReported(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "good", "package.json"), `{"name":"good"}`)
	writeFile(t, filepath.Join(root, "empty", "package.json"), ``)

	_, skipped, err := DetectAndParseAll(root)
	if err != nil {
		t.Fatalf("DetectAndParseAll: %v", err)
	}
	if len(skipped) != 1 {
		t.Fatalf("got %d skipped, want 1; an empty manifest was dropped silently", len(skipped))
	}
	if !strings.Contains(skipped[0].Reason, "empty") {
		t.Errorf("reason %q does not say the file is empty", skipped[0].Reason)
	}
}

// TestValidTreeSkipsNothing guards against a change that reports everything as
// skipped, which would make the notice meaningless.
func TestValidTreeSkipsNothing(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "a", "package.json"), `{"name":"a","dependencies":{"left-pad":"1.3.0"}}`)
	writeFile(t, filepath.Join(root, "b", "requirements.txt"), "requests==2.31.0\n")
	writeFile(t, filepath.Join(root, "c", "go.mod"), "module example.com/c\n\ngo 1.21\n")

	manifests, skipped, err := DetectAndParseAll(root)
	if err != nil {
		t.Fatalf("DetectAndParseAll: %v", err)
	}
	if len(skipped) != 0 {
		t.Errorf("a valid tree reported skipped manifests: %v", skipped)
	}
	if len(manifests) != 3 {
		t.Errorf("got %d manifests, want 3", len(manifests))
	}
}

// TestDiscoveryOrderIsStable checks that repeated discovery returns the same
// order.
//
// This is a preservation guard, not a regression test, and the distinction was
// previously misstated here. The old comment claimed discovery "merged two
// layers without sorting" so the order depended on how they interleaved. That
// was wrong on both counts: filepath.Glob returns sorted matches and
// filepath.Walk is lexical, so the pre-fix code was already stable, and the old
// fixture declared no workspaces at all so it never engaged the workspace layer
// it claimed to test. Measured against the pre-fix build, the order was
// identical across 50 runs.
//
// The fixture below does declare a workspace, so both layers contribute and the
// sort actually has something to order. What the added sort changed is where the
// root package.json lands, not whether the order is stable. This test fails if
// anyone reintroduces map iteration into discovery; it does not claim to prove
// the sort fixed a nondeterminism that existed.
func TestDiscoveryOrderIsStable(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "package.json"),
		`{"name":"root","private":true,"workspaces":["zeta","alpha","mid","beta"],`+
			`"dependencies":{"left-pad":"1.3.0"}}`)
	for _, name := range []string{"zeta", "alpha", "mid", "beta"} {
		writeFile(t, filepath.Join(root, name, "package.json"),
			`{"name":"`+name+`","dependencies":{"left-pad":"1.3.0"}}`)
	}

	var first []string
	for i := 0; i < 10; i++ {
		found, _, err := DiscoverManifests(root)
		if err != nil {
			t.Fatalf("discover: %v", err)
		}
		if i == 0 {
			first = found
			continue
		}
		if strings.Join(found, "\n") != strings.Join(first, "\n") {
			t.Fatalf("discovery order changed between runs:\nfirst: %v\nnow:   %v", first, found)
		}
	}
	if len(first) != 5 {
		t.Fatalf("got %d manifests, want 5 (root plus four workspace members); "+
			"a fixture that does not engage the workspace layer cannot guard its ordering", len(first))
	}
	if !sort.StringsAreSorted(first) {
		t.Errorf("discovery returned an unsorted list, so the two layers are being "+
			"concatenated rather than ordered: %v", first)
	}
}

// TestUnsupportedManifestTypesAreNotReportedAsSkips guards the exit code of
// every polyglot repository.
//
// Discovery recognised Cargo.toml, Gemfile, composer.json and the Gradle files
// as manifests, but no parser exists for any of them, so each one became a
// reported skip. A skip forces exit 2, so a tree holding a go.mod beside a
// Cargo.toml reported an analysis error instead of the exit 1 its real
// quantum-vulnerable findings had earned. SupportedManifests has never listed
// these names: the tool was erroring on files it never claimed to read.
//
// This is the case TestValidTreeSkipsNothing was too narrow to catch, because
// its fixture used only the three manifest types that do have parsers.
func TestUnsupportedManifestTypesAreNotReportedAsSkips(t *testing.T) {
	for _, name := range []string{
		"Cargo.toml", "Gemfile", "composer.json", "build.gradle", "build.gradle.kts", "go.work",
	} {
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			writeFile(t, filepath.Join(root, "go.mod"), "module example.com/x\n\ngo 1.21\n")
			writeFile(t, filepath.Join(root, name), "placeholder\n")

			manifests, skipped, err := DetectAndParseAll(root)
			if err != nil {
				t.Fatalf("DetectAndParseAll: %v", err)
			}
			for _, s := range skipped {
				if filepath.Base(s.Path) == name {
					t.Errorf("%s was reported as a skipped manifest (%s); every skip forces "+
						"exit 2, so this turns a normal polyglot repository into an analysis error",
						name, s.Reason)
				}
			}
			// The guard must not pass by discovering nothing at all.
			if len(manifests) != 1 {
				t.Fatalf("got %d parsed manifests, want the 1 go.mod; fixture did not exercise discovery", len(manifests))
			}
		})
	}
}

// TestSupportedManifestsAllHaveParsers is the structural version of the test
// above: it fails by construction if a name is ever added to discovery without a
// parser behind it, rather than waiting for someone to notice the exit code.
func TestSupportedManifestsAllHaveParsers(t *testing.T) {
	for name, parsable := range ManifestFiles {
		if !parsable {
			continue
		}
		if _, err := getParser(name); err != nil {
			t.Errorf("%q is discoverable but has no parser (%v); it would be discovered, "+
				"fail to parse, and force exit 2 on every scan that meets one", name, err)
		}
	}
}
