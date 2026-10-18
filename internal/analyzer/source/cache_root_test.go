// Copyright 2025-2026 CyberSecurity NonProfit (CSNP)
// SPDX-License-Identifier: Apache-2.0

package source

import (
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/csnp/qramm-cryptodeps/pkg/types"
)

// leftPad is the dependency the cache tests fetch. With no downloader on PATH,
// a fetch of it that misses the cache fails at once, without the network.
var leftPad = types.Dependency{Name: "left-pad", Version: "1.3.0", Ecosystem: types.EcosystemNPM}

// redirectUserCache points the per-user cache directory and the temporary
// directory at fresh directories for the rest of the test, and returns both.
//
// os.UserCacheDir and os.TempDir read different variables on each platform, so
// every one of them is set. The answer is checked to be inside the test's own
// directory: a test that wrote into the cache of the user running it would be
// reading and changing state it does not own.
func redirectUserCache(t *testing.T) (userCache, tmp string) {
	t.Helper()
	home := t.TempDir()
	tmp = t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CACHE_HOME", filepath.Join(home, ".cache"))
	t.Setenv("LocalAppData", filepath.Join(home, "AppData", "Local"))
	for _, name := range []string{"TMPDIR", "TMP", "TEMP"} {
		t.Setenv(name, tmp)
	}
	userCache, err := os.UserCacheDir()
	if err != nil {
		t.Fatalf("no user cache directory under the test home %s: %v", home, err)
	}
	if !strings.HasPrefix(userCache, home+string(filepath.Separator)) {
		t.Fatalf("the user cache directory %s is outside the test home %s", userCache, home)
	}
	return userCache, tmp
}

// tree lists what is under dir, relative to it, with the contents of each
// file, so that a test can say whether a refused fetch created, removed or
// changed anything there. Links are listed, not followed.
func tree(t *testing.T, dir string) string {
	t.Helper()
	var lines []string
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || path == dir {
			return err
		}
		rel, err := filepath.Rel(dir, path)
		if err != nil {
			return err
		}
		if d.Type().IsRegular() {
			content, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			rel += " = " + string(content)
		}
		lines = append(lines, rel)
		return nil
	})
	if err != nil {
		t.Fatalf("list %s: %v", dir, err)
	}
	return strings.Join(lines, "\n")
}

// dirNames returns the names of the entries in dir.
func dirNames(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read %s: %v", dir, err)
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.Name())
	}
	return names
}

// symlink plants a link at link pointing to target. Windows allows one only
// with a privilege a test run may not hold, so there the case is skipped; on
// every other platform a failure here is a broken fixture and fails the test.
func symlink(t *testing.T, target, link string) {
	t.Helper()
	if err := os.Symlink(target, link); err != nil {
		if runtime.GOOS == "windows" {
			t.Skipf("cannot create a symbolic link here: %v", err)
		}
		t.Fatalf("plant a link at %s: %v", link, err)
	}
}

// assertRefused fails unless err is the source cache refusing a directory for
// the reason given. With no downloader on PATH every fetch here fails anyway,
// so a test that asserted only on the error would pass for a fetcher with no
// checks at all.
func assertRefused(t *testing.T, err error, reason string) {
	t.Helper()
	if err == nil {
		t.Fatalf("the fetch was not refused")
	}
	if !strings.Contains(err.Error(), "refusing to use") || !strings.Contains(err.Error(), reason) {
		t.Errorf("the fetch failed, but not by refusing a directory that %s: %v", reason, err)
	}
}

// TestSourceCacheIsKeptInTheUserCacheDirectory is the regression test for the
// location of the --deep source cache.
//
// It was one fixed directory in the system temporary directory, the same path
// for every user of the machine, and nothing removed it. It now lives in the
// per-user cache directory.
func TestSourceCacheIsKeptInTheUserCacheDirectory(t *testing.T) {
	withoutFetchTools(t)
	userCache, tmp := redirectUserCache(t)

	f := NewFetcher("")
	if dir := f.CacheDir(); !strings.HasPrefix(dir, userCache+string(filepath.Separator)) {
		t.Errorf("the source cache is %s, which is not in the user cache directory %s", dir, userCache)
	}

	// A fetch that misses the cache creates it, and has to create it there.
	if _, err := f.Fetch(leftPad); err == nil {
		t.Fatal("the fetch succeeded with no downloader on PATH, so this test is not looking at a cache miss")
	}
	if info, err := os.Lstat(f.CacheDir()); err != nil || !info.IsDir() {
		t.Errorf("the fetch did not create the source cache at %s: %v", f.CacheDir(), err)
	}
	if left := tree(t, tmp); left != "" {
		t.Errorf("the fetch wrote into the temporary directory %s:\n%s", tmp, left)
	}
}

// TestSourceCacheWithoutAUserCacheDirectoryIsTheRunsOwn covers a user with no
// cache directory: no HOME, and none of the variables that name one.
//
// The source cache is then a directory of the run's own in the temporary
// directory, under a name nobody can choose in advance, and Close removes it.
// It must never fall back to a fixed path there, which every user of the
// machine shares.
func TestSourceCacheWithoutAUserCacheDirectoryIsTheRunsOwn(t *testing.T) {
	withoutFetchTools(t)
	tmp := t.TempDir()
	for _, name := range []string{"HOME", "XDG_CACHE_HOME", "LocalAppData"} {
		t.Setenv(name, "")
	}
	for _, name := range []string{"TMPDIR", "TMP", "TEMP"} {
		t.Setenv(name, tmp)
	}
	if dir, err := os.UserCacheDir(); err == nil {
		t.Fatalf("the fixture still has a user cache directory, %s", dir)
	}

	runs := []*Fetcher{NewFetcher(""), NewFetcher("")}
	for _, f := range runs {
		if _, err := f.Fetch(leftPad); err == nil {
			t.Fatal("the fetch succeeded with no downloader on PATH, so this test is not looking at a cache miss")
		}
	}
	first, second := runs[0].CacheDir(), runs[1].CacheDir()
	if names := dirNames(t, tmp); len(names) != 2 {
		t.Fatalf("two runs left %v in the temporary directory, want one directory each", names)
	}
	if first == second {
		t.Errorf("two runs share the source cache %s", first)
	}
	for _, dir := range []string{first, second} {
		if filepath.Dir(dir) != tmp {
			t.Errorf("the source cache %s is not in the temporary directory %s", dir, tmp)
		}
		info, err := os.Lstat(dir)
		if err != nil {
			t.Errorf("the source cache %s was not created: %v", dir, err)
			continue
		}
		if perm := info.Mode().Perm(); runtime.GOOS != "windows" && perm != 0o700 {
			t.Errorf("the source cache %s was created with mode %04o, want 0700", dir, perm)
		}
	}

	if err := runs[0].Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if _, err := os.Lstat(first); !os.IsNotExist(err) {
		t.Errorf("Close left the run's source cache %s in place: %v", first, err)
	}
	if _, err := os.Lstat(second); err != nil {
		t.Errorf("closing one run removed the source cache of another, %s: %v", second, err)
	}
	if err := runs[1].Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if names := dirNames(t, tmp); len(names) != 0 {
		t.Errorf("the temporary directory still holds %v after both runs closed", names)
	}
}

// TestCloseKeepsASourceCacheItDidNotCreate is the other half of the test
// above: a cache in the user's cache directory, or one the caller named, is a
// cache, and closing a fetcher must leave it for the next scan.
func TestCloseKeepsASourceCacheItDidNotCreate(t *testing.T) {
	withoutFetchTools(t)
	redirectUserCache(t)

	for _, tc := range []struct {
		name     string
		cacheDir string
	}{
		{"the per-user cache", ""},
		{"a cache the caller named", filepath.Join(t.TempDir(), "cache")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := NewFetcher(tc.cacheDir)
			if _, err := f.Fetch(leftPad); err == nil {
				t.Fatal("the fetch succeeded with no downloader on PATH, so this test is not looking at a cache miss")
			}
			root := f.CacheDir()
			if _, err := os.Lstat(root); err != nil {
				t.Fatalf("the fetch did not create the source cache %s, so there is nothing to keep: %v", root, err)
			}
			if err := f.Close(); err != nil {
				t.Fatalf("Close: %v", err)
			}
			if _, err := os.Lstat(root); err != nil {
				t.Errorf("Close removed the source cache %s: %v", root, err)
			}
		})
	}
}

// TestARefusedUserCacheDirectoryIsNotWorkedAround pins the edge of the
// fallback to a cache of the run's own. A per-user cache directory that cannot
// be created gives way to one; a directory that is there and is refused is
// reported, so the user learns what is in the way, and nothing is written.
func TestARefusedUserCacheDirectoryIsNotWorkedAround(t *testing.T) {
	withoutFetchTools(t)
	userCache, tmp := redirectUserCache(t)
	if err := os.MkdirAll(userCache, 0o700); err != nil {
		t.Fatalf("create the user cache directory: %v", err)
	}
	target := t.TempDir()
	symlink(t, target, filepath.Join(userCache, cacheDirName))

	_, err := NewFetcher("").Fetch(leftPad)
	assertRefused(t, err, "is a symbolic link")
	if names := dirNames(t, tmp); len(names) != 0 {
		t.Errorf("the refusal was worked around with a cache in the temporary directory: %v", names)
	}
	if after := tree(t, target); after != "" {
		t.Errorf("the fetch wrote through the link into %s:\n%s", target, after)
	}
}

// TestSourceCacheRefusesASymbolicLinkAtTheRoot covers a link planted where the
// cache root belongs, which would send every write of every fetch, and every
// read of a cache hit, to wherever it points.
func TestSourceCacheRefusesASymbolicLinkAtTheRoot(t *testing.T) {
	withoutFetchTools(t)
	dir := t.TempDir()
	target := filepath.Join(dir, "elsewhere")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatalf("create the link target: %v", err)
	}
	root := filepath.Join(dir, "cache")
	symlink(t, target, root)

	got, err := NewFetcher(root).Fetch(leftPad)
	assertRefused(t, err, "is a symbolic link")
	if got != "" {
		t.Errorf("returned %q alongside the refusal", got)
	}
	if after := tree(t, target); after != "" {
		t.Errorf("the fetch wrote through the link into %s:\n%s", target, after)
	}
}

// TestSourceCacheRefusesASymbolicLinkInAnEntry covers the same link one level
// down, at each directory between the root and a package's source.
//
// Each link points out of the cache at a directory laid out as a cache hit, so
// a fetcher that followed it would read that directory as the package's source
// and report what it found there.
func TestSourceCacheRefusesASymbolicLinkInAnEntry(t *testing.T) {
	withoutFetchTools(t)
	for _, tc := range []struct {
		name   string
		link   string // where the link is planted, relative to the cache root
		layout string // what the outside directory holds, relative to the link
	}{
		{"ecosystem directory", "npm", "left-pad/1.3.0/package"},
		{"package directory", "npm/left-pad", "1.3.0/package"},
		{"version entry", "npm/left-pad/1.3.0", "package"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			root := filepath.Join(dir, "cache")
			outside := filepath.Join(dir, "outside")
			makeDir(t, filepath.Join(outside, filepath.FromSlash(tc.layout)))
			link := filepath.Join(root, filepath.FromSlash(tc.link))
			if err := os.MkdirAll(filepath.Dir(link), 0o700); err != nil {
				t.Fatalf("create the directories above the link: %v", err)
			}
			symlink(t, outside, link)
			before := tree(t, outside)

			got, err := NewFetcher(root).Fetch(leftPad)
			if err == nil {
				t.Fatalf("the %s is a link out of the cache, and the fetch read %q through it", tc.name, got)
			}
			assertRefused(t, err, "is a symbolic link")
			if after := tree(t, outside); after != before {
				t.Errorf("the fetch changed %s through the link:\nbefore:\n%s\nafter:\n%s", outside, before, after)
			}
		})
	}
}

// TestSourceCacheRefusesAPathThatIsNotADirectory covers a file, or anything
// else that is not a directory, where the root or an entry directory belongs.
// It is refused and left as it is: removing it is the user's decision.
func TestSourceCacheRefusesAPathThatIsNotADirectory(t *testing.T) {
	withoutFetchTools(t)
	for _, tc := range []struct{ name, file string }{
		{"root", ""},
		{"ecosystem directory", "npm"},
		{"package directory", "npm/left-pad"},
		{"version entry", "npm/left-pad/1.3.0"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := filepath.Join(t.TempDir(), "cache")
			path := filepath.Join(root, filepath.FromSlash(tc.file))
			if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
				t.Fatalf("create the directories above the file: %v", err)
			}
			const content = "not a directory\n"
			if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
				t.Fatalf("plant a file at %s: %v", path, err)
			}

			_, err := NewFetcher(root).Fetch(leftPad)
			assertRefused(t, err, "is not a directory")
			if got, readErr := os.ReadFile(path); readErr != nil || string(got) != content {
				t.Errorf("the file at %s was removed or changed by the refused fetch: %q, %v", path, got, readErr)
			}
		})
	}
}
