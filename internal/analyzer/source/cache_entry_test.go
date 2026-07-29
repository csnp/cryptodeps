// Copyright 2025-2026 CyberSecurity NonProfit (CSNP)
// SPDX-License-Identifier: Apache-2.0

package source

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/csnp/qramm-cryptodeps/pkg/types"
)

// makeDir creates dir with one file in it, so that isNonEmptyDir accepts it.
func makeDir(t *testing.T, dir string) string {
	t.Helper()
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatalf("create %s: %v", dir, err)
	}
	if err := os.WriteFile(filepath.Join(dir, "index.js"), []byte("module.exports = 1;\n"), 0644); err != nil {
		t.Fatalf("write into %s: %v", dir, err)
	}
	return dir
}

// TestResetCacheEntryRefusesAnythingWiderThanOneEntry bounds the only
// destructive operation in the fetcher.
//
// The removal took whatever path it was handed. Four separate mutations of it
// left the suite green, including one that removed the entire cache root, so
// nothing in the repository stated how much this function is allowed to delete.
// Each case below asserts the refusal and then asserts the directory is still
// there, because an error returned after a deletion is not a refusal.
func TestResetCacheEntryRefusesAnythingWiderThanOneEntry(t *testing.T) {
	cacheRoot := t.TempDir()
	fetcher := NewFetcher(cacheRoot)

	entry := makeDir(t, filepath.Join(cacheRoot, "npm", "pkg", "1.0.0"))
	extracted := makeDir(t, filepath.Join(entry, "package"))
	// A directory the cache root can be walked out of, which is what an
	// unsanitized segment would reach.
	sibling := makeDir(t, filepath.Join(filepath.Dir(cacheRoot), "victim"))

	cases := []struct {
		name string
		path string
	}{
		{"the cache root itself", cacheRoot},
		{"an ecosystem directory", filepath.Join(cacheRoot, "npm")},
		{"every version of one package", filepath.Join(cacheRoot, "npm", "pkg")},
		{"a directory outside the cache", sibling},
		{"a traversal out of the cache", cacheRoot + "/npm/../../" + filepath.Base(sibling)},
		{"below a cache entry", extracted},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// The fixture has to exist, or "it was not deleted" is trivially
			// true and this case proves nothing. A missing one fails here
			// rather than skipping, so a fixture that stops resolving cannot
			// quietly remove a case from this gate.
			before, err := os.Stat(tc.path)
			if err != nil || !before.IsDir() {
				t.Fatalf("fixture %s is not a directory, so this case asserts nothing: %v",
					tc.path, err)
			}

			err = fetcher.resetCacheEntry(tc.path)
			if err == nil {
				t.Fatalf("resetCacheEntry(%s) was allowed", tc.path)
			}
			if !strings.Contains(err.Error(), "refusing to remove") {
				t.Errorf("refusal does not say what it refused: %v", err)
			}
			if _, err := os.Stat(tc.path); err != nil {
				t.Errorf("%s was removed anyway: %v", tc.path, err)
			}
		})
	}
}

// TestResetCacheEntryRemovesOneEntry is the other half of the bound: the guard
// must not be so tight that the entry a refetch depends on is never cleared.
func TestResetCacheEntryRemovesOneEntry(t *testing.T) {
	cacheRoot := t.TempDir()
	fetcher := NewFetcher(cacheRoot)

	entry := makeDir(t, filepath.Join(cacheRoot, "npm", "pkg", "1.0.0"))
	sibling := makeDir(t, filepath.Join(cacheRoot, "npm", "pkg", "2.0.0"))

	if err := fetcher.resetCacheEntry(entry); err != nil {
		t.Fatalf("resetCacheEntry on a real entry: %v", err)
	}
	if _, err := os.Stat(entry); !os.IsNotExist(err) {
		t.Errorf("the unusable cache entry survived, so the next scan analyzes it again: %v", err)
	}
	if _, err := os.Stat(sibling); err != nil {
		t.Errorf("clearing one version removed another: %v", err)
	}
}

// TestAmbiguousCacheEntryIsKeptAndReported covers the case where the fetcher
// cannot tell which directory in an entry is the package.
//
// It used to delete the entry and fetch again, so a cache entry that may have
// held the findings was destroyed by a scan that only failed to identify it,
// and the user was shown whatever the refetch failed with rather than the
// diagnostic written for this case. With no downloader on PATH the refetch
// cannot succeed, which is what makes the difference visible.
func TestAmbiguousCacheEntryIsKeptAndReported(t *testing.T) {
	cacheRoot := t.TempDir()
	t.Setenv("PATH", t.TempDir())
	fetcher := NewFetcher(cacheRoot)

	entry := filepath.Join(cacheRoot, "npm", "pkg", "1.0.0")
	makeDir(t, filepath.Join(entry, "candidate-a"))
	makeDir(t, filepath.Join(entry, "candidate-b"))

	_, err := fetcher.Fetch(types.Dependency{
		Name:      "pkg",
		Version:   "1.0.0",
		Ecosystem: types.EcosystemNPM,
	})
	if err == nil {
		t.Fatal("an entry holding two candidate directories was resolved to one of them")
	}
	if !strings.Contains(err.Error(), "cannot identify the extracted source") {
		t.Errorf("the reported error is not the one written for this case: %v", err)
	}

	for _, dir := range []string{"candidate-a", "candidate-b"} {
		if _, statErr := os.Stat(filepath.Join(entry, dir)); statErr != nil {
			t.Errorf("%s was deleted because the fetcher could not identify it: %v", dir, statErr)
		}
	}
}
