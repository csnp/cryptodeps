// Copyright 2025-2026 CyberSecurity NonProfit (CSNP)
// SPDX-License-Identifier: Apache-2.0

package manifest

import (
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/csnp/qramm-cryptodeps/pkg/types"
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

// TestSupportedManifestsAllHaveParsers is the structural version of the test
// above: it fails by construction if the parsable set and the parsers disagree,
// rather than waiting for someone to notice an exit code.
//
// Both directions, because the first version checked only one. A parsable name
// with no parser forces exit 2 on every scan that meets the file. A parser that
// is no longer reachable from discovery silently stops scanning an entire
// ecosystem, which is the more dangerous of the two: flipping "pom.xml" to false
// disabled all Maven scanning and left the whole suite green.
func TestSupportedManifestsAllHaveParsers(t *testing.T) {
	for name, parsable := range ManifestFiles {
		_, err := getParser(name)
		switch {
		case parsable && err != nil:
			t.Errorf("%q is marked parsable but has no parser (%v); it would be discovered, "+
				"fail to parse, and be reported as unsupported on every scan that meets one", name, err)
		case !parsable && err == nil:
			t.Errorf("%q has a parser but is marked unparsable, so discovery routes it to the "+
				"unsupported path and that ecosystem is never scanned", name)
		}
	}

	// Every manifest the tool advertises must be reachable from discovery.
	for _, name := range SupportedManifests() {
		if !IsParsableManifest(name) {
			t.Errorf("SupportedManifests advertises %q but discovery does not treat it as "+
				"parsable, so a documented ecosystem is silently never scanned", name)
		}
	}
}

// TestUnsupportedManifestsAreStillReported is the other half of the polyglot
// fix, and the half that was got wrong first.
//
// Narrowing discovery stopped the spurious exit 2 by making these files vanish
// from every output format at exit 0. A build.gradle full of crypto dependencies
// became invisible, which is exactly the silent skip this branch exists to
// remove, and it contradicted the tool's own message that "a silently skipped
// manifest is how a scanner reports a clean tree it never read". They must be
// reported AND must not force exit 2.
func TestUnsupportedManifestsAreStillReported(t *testing.T) {
	for _, name := range []string{"Cargo.toml", "Gemfile", "composer.json", "build.gradle", "build.gradle.kts"} {
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			writeFile(t, filepath.Join(root, "go.mod"), "module example.com/x\n\ngo 1.21\n")
			writeFile(t, filepath.Join(root, name), "placeholder\n")

			_, skipped, err := DetectAndParseAll(root)
			if err != nil {
				t.Fatalf("DetectAndParseAll: %v", err)
			}

			var found *types.SkippedManifest
			for i := range skipped {
				if filepath.Base(skipped[i].Path) == name {
					found = &skipped[i]
				}
			}
			if found == nil {
				t.Fatalf("%s was not reported at all; a manifest the tool cannot read must "+
					"never be silently dropped, whatever the reason", name)
			}
			if !found.Unsupported {
				t.Errorf("%s is reported as an unread manifest rather than an unsupported "+
					"ecosystem, so it forces exit 2 and masks the real finding-based code", name)
			}
		})
	}
}

// TestUnreadableManifestStillMarksTheScanIncomplete is the paired guard: the
// Unsupported flag must not become a way for a genuinely broken manifest to stop
// counting.
func TestUnreadableManifestStillMarksTheScanIncomplete(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "good", "package.json"), `{"name":"g","dependencies":{"left-pad":"1.3.0"}}`)
	writeFile(t, filepath.Join(root, "bad", "package.json"), `{"name":"b","dependencies":`)

	_, skipped, err := DetectAndParseAll(root)
	if err != nil {
		t.Fatalf("DetectAndParseAll: %v", err)
	}
	if len(skipped) != 1 {
		t.Fatalf("got %d skipped, want 1: %+v", len(skipped), skipped)
	}
	if skipped[0].Unsupported {
		t.Error("a corrupt package.json was marked unsupported, so the scan would report " +
			"itself complete while a dependency file went unread")
	}
	if !types.IncompleteScan(skipped) {
		t.Error("IncompleteScan is false for an unreadable manifest, so the scan exits 0")
	}
}

// TestUnsupportedOnlyTreeIsNotCalledUnreadable guards the wording a user of a
// Rust or Ruby repository actually sees.
//
// When nothing parseable is found, the error explains why. Reporting a healthy
// Cargo.toml as a file that "could not be read" sends the user to look for a
// defect in a file that has none, and contradicts the tool's own classification
// of the same skip as a declared limit rather than an incomplete scan.
func TestUnsupportedOnlyTreeIsNotCalledUnreadable(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "Cargo.toml"), "[package]\nname = \"x\"\n")

	_, skipped, err := DetectAndParseAll(root)
	if err == nil {
		t.Fatal("a tree with no parseable manifest reported success")
	}
	if !types.IncompleteScan(skipped) && strings.Contains(err.Error(), "none could be read") {
		t.Errorf("error says the manifest could not be read, which IncompleteScan says is "+
			"false for it: %v", err)
	}
	if !strings.Contains(err.Error(), "no supported manifest files found") {
		t.Errorf("error does not say the ecosystem is unsupported: %v", err)
	}
	if len(skipped) != 1 || !skipped[0].Unsupported {
		t.Errorf("skipped = %+v, want one unsupported entry so the caller can report the "+
			"file rather than only the failure", skipped)
	}
}

// TestUnreadableOnlyTreeStillSaysItCouldNotBeRead is the paired direction. The
// wording split must not make a genuinely broken manifest sound supported.
func TestUnreadableOnlyTreeStillSaysItCouldNotBeRead(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "package.json"), `{"name":"b","dependencies":`)

	_, skipped, err := DetectAndParseAll(root)
	if err == nil {
		t.Fatal("a tree whose only manifest is corrupt reported success")
	}
	if !strings.Contains(err.Error(), "none could be read") {
		t.Errorf("error does not say the manifest could not be read: %v", err)
	}
	if !types.IncompleteScan(skipped) {
		t.Errorf("skipped = %+v, want an incomplete scan", skipped)
	}
}
