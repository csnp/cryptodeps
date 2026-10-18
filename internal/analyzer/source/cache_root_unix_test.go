// Copyright 2025-2026 CyberSecurity NonProfit (CSNP)
// SPDX-License-Identifier: Apache-2.0

//go:build unix

package source

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
)

// TestSourceCacheIsCreatedPrivate checks the mode of every directory a fetch
// creates. The cache used to be created 0755, so every user of the machine
// could list and read the source this tool had fetched for another.
func TestSourceCacheIsCreatedPrivate(t *testing.T) {
	withoutFetchTools(t)
	redirectUserCache(t)

	f := NewFetcher("")
	if _, err := f.Fetch(leftPad); err == nil {
		t.Fatal("the fetch succeeded with no downloader on PATH, so this test is not looking at a cache miss")
	}

	root := f.CacheDir()
	for _, dir := range []string{root, filepath.Join(root, "npm"), filepath.Join(root, "npm", "left-pad")} {
		info, err := os.Lstat(dir)
		if err != nil {
			t.Errorf("the fetch did not create %s: %v", dir, err)
			continue
		}
		if perm := info.Mode().Perm(); perm != 0o700 {
			t.Errorf("%s was created with mode %04o, want 0700", dir, perm)
		}
	}
}

// TestUnwritableUserCacheDirectoryFallsBackToTheRunsOwn covers a per-user
// cache directory that cannot be created, as under a home directory the
// account cannot write to, which containers commonly have.
//
// That is no per-user cache directory at all, so the run gets one of its own,
// as it does with no home directory. It must not stop deep analysis, which the
// temporary directory used to serve, and must not fall back to a fixed path.
func TestUnwritableUserCacheDirectoryFallsBackToTheRunsOwn(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root can create a directory whatever the mode of its parent")
	}
	withoutFetchTools(t)
	userCache, tmp := redirectUserCache(t)
	if err := os.MkdirAll(userCache, 0o700); err != nil {
		t.Fatalf("create the user cache directory: %v", err)
	}
	if err := os.Chmod(userCache, 0o500); err != nil {
		t.Fatalf("make the user cache directory read-only: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(userCache, 0o700) })

	f := NewFetcher("")
	_, err := f.Fetch(leftPad)
	if err == nil {
		t.Fatal("the fetch succeeded with no downloader on PATH, so this test is not looking at a cache miss")
	}
	if !strings.Contains(err.Error(), "npm pack failed") {
		t.Errorf("the fetch stopped before the downloader, so deep analysis cannot run at all: %v", err)
	}
	root := f.CacheDir()
	if filepath.Dir(root) != tmp || !strings.HasPrefix(filepath.Base(root), perRunPrefix) {
		t.Errorf("the source cache is %s, not a directory of the run's own in %s", root, tmp)
	}
	if _, statErr := os.Lstat(filepath.Join(userCache, cacheDirName)); !os.IsNotExist(statErr) {
		t.Errorf("something was created in the read-only user cache directory: %v", statErr)
	}

	if err := f.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if names := dirNames(t, tmp); len(names) != 0 {
		t.Errorf("the temporary directory still holds %v after Close", names)
	}
}

// TestSourceCacheRefusesADirectoryOtherUsersCanWrite covers the root and each
// entry directory being writable by its group or by everyone. Whoever can
// write there can choose what this tool reads as a package's source.
func TestSourceCacheRefusesADirectoryOtherUsersCanWrite(t *testing.T) {
	withoutFetchTools(t)
	for _, tc := range []struct {
		name string
		dir  string // relative to the cache root
		mode os.FileMode
		// planted lays out a cache hit below the root, so that a fetcher that
		// does not check reads it. Without one, it writes into the root.
		planted bool
	}{
		{"root writable by its group", "", 0o770, false},
		{"root writable by everyone", "", 0o707, false},
		{"ecosystem directory writable by its group", "npm", 0o775, true},
		{"package directory writable by everyone", "npm/left-pad", 0o757, true},
		{"version entry writable by its group", "npm/left-pad/1.3.0", 0o775, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := filepath.Join(t.TempDir(), "cache")
			if err := os.Mkdir(root, 0o700); err != nil {
				t.Fatalf("create the cache root: %v", err)
			}
			if tc.planted {
				makeDir(t, filepath.Join(root, "npm", "left-pad", "1.3.0", npmExtractedDir))
			}
			path := filepath.Join(root, filepath.FromSlash(tc.dir))
			// chmod, unlike mkdir, is not narrowed by the umask.
			if err := os.Chmod(path, tc.mode); err != nil {
				t.Fatalf("set the mode of %s: %v", path, err)
			}
			before := tree(t, root)

			got, err := NewFetcher(root).Fetch(leftPad)
			if err == nil {
				t.Fatalf("%s was used, and the fetch returned %q", path, got)
			}
			assertRefused(t, err, "other users can write to it")
			if after := tree(t, root); after != before {
				t.Errorf("the refused fetch changed the cache:\nbefore:\n%s\nafter:\n%s", before, after)
			}
		})
	}
}

// TestSourceCacheRefusesADirectoryAnotherUserOwns covers a cache directory
// created by another account, which that account can change at any time.
//
// Making one needs a privilege a test run does not hold, so the file system
// root stands in for it: it belongs to root on every Unix this tool ships for.
func TestSourceCacheRefusesADirectoryAnotherUserOwns(t *testing.T) {
	withoutFetchTools(t)
	const root = "/"
	info, err := os.Lstat(root)
	if err != nil {
		t.Fatalf("inspect %s: %v", root, err)
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		t.Fatalf("no owner reported for %s", root)
	}
	if int(st.Uid) == os.Geteuid() {
		t.Skipf("%s belongs to the user running the tests, so it cannot stand in for another user's directory", root)
	}

	_, err = NewFetcher(root).Fetch(leftPad)
	assertRefused(t, err, "belongs to another user")
}

// TestFetchStagesInsideTheRootAndRenamesIntoPlace pins where a fetch downloads
// and extracts: in a directory of its own inside the cache root, renamed into
// place as the cache entry only once the extractor has finished.
//
// The downloader and the extractor are stubs. The extractor records the
// directory it was asked to extract into.
func TestFetchStagesInsideTheRootAndRenamesIntoPlace(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status int // the extractor's exit status
	}{
		{"extraction completes", 0},
		{"extraction fails part way", 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bin := t.TempDir()
			record := filepath.Join(t.TempDir(), "extracted-into")
			stubs := map[string]string{
				"npm": "#!/bin/sh\n: > left-pad-1.3.0.tgz\n",
				"tar": "#!/bin/sh\nwhile [ $# -gt 0 ]; do case \"$1\" in -C) shift; D=\"$1\";; esac; shift; done\n" +
					"printf '%s' \"$D\" > '" + record + "'\n" +
					"/bin/mkdir -p \"$D/package\"\nprintf 'module.exports=1;\\n' > \"$D/package/index.js\"\n" +
					"exit " + strconv.Itoa(tc.status) + "\n",
			}
			for name, script := range stubs {
				if err := os.WriteFile(filepath.Join(bin, name), []byte(script), 0o755); err != nil {
					t.Fatalf("write stub %s: %v", name, err)
				}
			}
			t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))

			root := filepath.Join(t.TempDir(), "cache")
			entry := filepath.Join(root, "npm", "left-pad", "1.3.0")
			got, err := NewFetcher(root).Fetch(leftPad)

			recorded, readErr := os.ReadFile(record)
			if readErr != nil {
				t.Fatalf("the extractor never ran, so this test cannot say where it extracted: %v (fetch: %v)",
					readErr, err)
			}
			staging := string(recorded)
			if filepath.Dir(staging) != root || staging == entry {
				t.Errorf("the archive was extracted into %s, not into a directory of its own directly "+
					"inside the cache root %s", staging, root)
			}
			if _, statErr := os.Lstat(staging); !os.IsNotExist(statErr) {
				t.Errorf("the directory the archive was extracted into is still there: %s (%v)", staging, statErr)
			}
			if names := dirNames(t, root); len(names) != 1 || names[0] != "npm" {
				t.Errorf("the cache root holds %v after the fetch, want only the ecosystem directory", names)
			}

			if tc.status != 0 {
				if err == nil || !strings.Contains(err.Error(), "extract") {
					t.Errorf("a failed extraction was not reported as one: %q, %v", got, err)
				}
				if _, statErr := os.Lstat(entry); !os.IsNotExist(statErr) {
					t.Errorf("a failed extraction left a cache entry at %s (%v)", entry, statErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("fetch: %v", err)
			}
			if want := filepath.Join(entry, npmExtractedDir); got != want {
				t.Errorf("fetch returned %q, want %q", got, want)
			}
			if info, statErr := os.Lstat(entry); statErr != nil || info.Mode().Perm() != 0o700 {
				t.Errorf("the cache entry %s is not a private directory: %v, %v", entry, info, statErr)
			}
		})
	}
}
