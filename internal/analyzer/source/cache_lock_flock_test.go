// Copyright 2025-2026 CyberSecurity NonProfit (CSNP)
// SPDX-License-Identifier: Apache-2.0

//go:build darwin || dragonfly || freebsd || illumos || linux || netbsd || openbsd

package source

import (
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// helperCacheEnv names the cache that TestHelperFetchUntilKilled fetches into.
// It is set only in the process a test below starts, so in an ordinary run
// the helper skips.
const helperCacheEnv = "CRYPTODEPS_TEST_FETCH_UNTIL_KILLED"

// partialDownload is what the stub npm of startScanToKill leaves in the
// staging directory before it waits to be killed.
const partialDownload = "left-pad-1.3.0.tgz"

// TestHelperFetchUntilKilled is not a test of its own. It is the scan that the
// tests below run in a process of their own and kill during its download.
func TestHelperFetchUntilKilled(t *testing.T) {
	cache, ok := os.LookupEnv(helperCacheEnv)
	if !ok {
		t.Skip("the fetch that the interrupted-scan tests kill, run only in a process they start")
	}
	_, _ = NewFetcher(cache).Fetch(leftPad)
}

// scanToKill is a scan running TestHelperFetchUntilKilled in a process group
// of its own.
type scanToKill struct {
	cmd    *exec.Cmd
	output string
	ended  bool
}

// startScanToKill starts a scan that fetches leftPad into cache, with env
// added to its environment, and returns once its download has begun. The stub
// npm it runs writes part of an archive into the staging directory, as a
// download that is cut short does, and then waits to be killed.
func startScanToKill(t *testing.T, cache string, env ...string) *scanToKill {
	t.Helper()
	bin := t.TempDir()
	started := filepath.Join(t.TempDir(), "npm-started")
	stub := "#!/bin/sh\nprintf 'partial' > " + partialDownload + "\n: > '" + started + "'\nexec /bin/sleep 60\n"
	if err := os.WriteFile(filepath.Join(bin, "npm"), []byte(stub), 0o755); err != nil {
		t.Fatalf("write stub npm: %v", err)
	}

	s := &scanToKill{output: filepath.Join(t.TempDir(), "scan-output")}
	out, err := os.Create(s.output)
	if err != nil {
		t.Fatalf("create %s: %v", s.output, err)
	}
	defer out.Close()

	s.cmd = exec.Command(os.Args[0], "-test.run=^TestHelperFetchUntilKilled$")
	s.cmd.Env = append([]string{
		helperCacheEnv + "=" + cache,
		"PATH=" + bin,
		"GOCOVERDIR=" + t.TempDir(),
	}, env...)
	s.cmd.Stdout, s.cmd.Stderr = out, out
	// A process group of its own, so that the kill reaches the stub npm too
	// and leaves nothing of the scan running.
	s.cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := s.cmd.Start(); err != nil {
		t.Fatalf("start the scan to kill: %v", err)
	}
	t.Cleanup(s.kill)

	for deadline := time.Now().Add(time.Minute); ; time.Sleep(20 * time.Millisecond) {
		if _, err := os.Stat(started); err == nil {
			return s
		}
		if time.Now().After(deadline) {
			s.kill()
			t.Fatalf("the scan never started its download, so there is nothing to interrupt:\n%s", s.log())
		}
	}
}

// kill ends the scan with SIGKILL, as kill -9, a crash or a power loss would:
// no deferred function of the scan runs. The group is signalled only before
// the scan is waited for, while its process ID cannot have been reused.
func (s *scanToKill) kill() {
	if s.ended {
		return
	}
	s.ended = true
	_ = syscall.Kill(-s.cmd.Process.Pid, syscall.SIGKILL)
	_ = s.cmd.Wait()
}

// log returns what the scan has printed, for a failure message.
func (s *scanToKill) log() string {
	out, err := os.ReadFile(s.output)
	if err != nil {
		return err.Error()
	}
	return string(out)
}

// namesWithPrefix returns the names of the entries in dir that begin with
// prefix.
func namesWithPrefix(t *testing.T, dir, prefix string) []string {
	t.Helper()
	var names []string
	for _, name := range dirNames(t, dir) {
		if strings.HasPrefix(name, prefix) {
			names = append(names, name)
		}
	}
	return names
}

// isRegularFile reports whether path is a regular file, without following a
// link.
func isRegularFile(path string) bool {
	info, err := os.Lstat(path)
	return err == nil && info.Mode().IsRegular()
}

// fetchAndClose is one scan's fetch of leftPad, which with no downloader on
// PATH misses the cache and fails, followed by the Close a scan makes on exit.
func fetchAndClose(t *testing.T, f *Fetcher) {
	t.Helper()
	if _, err := f.Fetch(leftPad); err == nil {
		t.Fatal("the fetch succeeded with no downloader on PATH, so this test is not looking at a cache miss")
	}
	if err := f.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

// TestKilledScanLeavesNoStagingDirectoryForGood is the regression test for
// the staging directory of a scan that ends during its download.
//
// A fetch downloads into a staging directory in the cache root, and only the
// fetch that made it removed it. A scan killed during the download never got
// to, and no later scan looked at the directory, so it stayed in the cache for
// good, holding part of a download, one more for every interrupted scan. The
// next scan now removes it. A scan that runs while the download is still going
// must not, because the directory is a live fetch's until that fetch ends.
func TestKilledScanLeavesNoStagingDirectoryForGood(t *testing.T) {
	root := filepath.Join(t.TempDir(), "cache")
	scan := startScanToKill(t, root)

	staging := namesWithPrefix(t, root, stagingPrefix)
	if len(staging) != 1 {
		t.Fatalf("the scan to kill is staging in %v, want one directory\n%s", staging, scan.log())
	}
	download := filepath.Join(root, staging[0], partialDownload)

	withoutFetchTools(t)
	fetchAndClose(t, NewFetcher(root))
	if !isRegularFile(download) {
		t.Fatalf("a scan running beside a download removed %s from its staging directory", download)
	}

	scan.kill()
	// The kill has to leave the partial download behind, or the assertion
	// below is answered by a scan that cleaned up after itself.
	if !isRegularFile(download) {
		t.Fatalf("the killed scan left no partial download at %s, so there is nothing to remove", download)
	}

	fetchAndClose(t, NewFetcher(root))
	if left := namesWithPrefix(t, root, stagingPrefix); len(left) != 0 {
		t.Errorf("the staging directory of the killed scan is still in the cache root %s after the "+
			"next scan: %v", root, left)
	}
}

// TestKilledScanLeavesNoCacheOfItsOwnForGood is the same for a scan with no
// per-user cache directory. Its cache is then a directory of its own in the
// temporary directory, which Close removes, and a scan killed during its
// download never reaches Close. The next such scan now removes it, and one
// running beside the download leaves it alone.
func TestKilledScanLeavesNoCacheOfItsOwnForGood(t *testing.T) {
	tmp := t.TempDir()
	noUserCache := map[string]string{
		"HOME": "", "XDG_CACHE_HOME": "", "LocalAppData": "",
		"TMPDIR": tmp, "TMP": tmp, "TEMP": tmp,
	}
	var env []string
	for name, value := range noUserCache {
		env = append(env, name+"="+value)
	}
	scan := startScanToKill(t, "", env...)

	caches := namesWithPrefix(t, tmp, perRunPrefix)
	if len(caches) != 1 {
		t.Fatalf("the scan to kill has %v in the temporary directory, want one cache of its own\n%s",
			caches, scan.log())
	}
	killed := filepath.Join(tmp, caches[0])

	withoutFetchTools(t)
	for name, value := range noUserCache {
		t.Setenv(name, value)
	}
	if dir, err := os.UserCacheDir(); err == nil {
		t.Fatalf("the fixture still has a user cache directory, %s", dir)
	}

	fetchAndClose(t, NewFetcher(""))
	if _, err := os.Lstat(killed); err != nil {
		t.Fatalf("a scan running beside another removed the other's cache %s: %v", killed, err)
	}

	scan.kill()
	// As above, the kill has to leave part of a download behind.
	staging := namesWithPrefix(t, killed, stagingPrefix)
	if len(staging) != 1 {
		t.Fatalf("the killed scan left %v staging in its cache %s, want one directory", staging, killed)
	}
	if download := filepath.Join(killed, staging[0], partialDownload); !isRegularFile(download) {
		t.Fatalf("the killed scan left no partial download at %s, so there is nothing to remove", download)
	}

	fetchAndClose(t, NewFetcher(""))
	if left := dirNames(t, tmp); len(left) != 0 {
		t.Errorf("the temporary directory %s still holds %v after the next scan, want the killed "+
			"scan's cache %s removed by it and its own removed by Close", tmp, left, caches[0])
	}
}

// TestStagingDirectoryOfAFetcherInTheSameProcessIsKept covers two fetchers on
// one cache root in one process. The staging directory of one that is still
// fetching is left alone by the other, and once its fetcher has closed it is
// no live fetch's, and the next scan removes it.
func TestStagingDirectoryOfAFetcherInTheSameProcessIsKept(t *testing.T) {
	withoutFetchTools(t)
	root := filepath.Join(t.TempDir(), "cache")
	live := NewFetcher(root)
	staging, err := live.stagingDir()
	if err != nil {
		t.Fatalf("stage a download: %v", err)
	}
	download := filepath.Join(staging, partialDownload)
	if err := os.WriteFile(download, []byte("partial"), 0o600); err != nil {
		t.Fatalf("write %s: %v", download, err)
	}

	fetchAndClose(t, NewFetcher(root))
	if !isRegularFile(download) {
		t.Fatalf("a second fetcher in the process removed %s from the staging directory of a "+
			"fetcher that has not finished", download)
	}

	if err := live.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	fetchAndClose(t, NewFetcher(root))
	if _, err := os.Lstat(staging); !os.IsNotExist(err) {
		t.Errorf("the staging directory %s is still in the cache root after the fetcher that made "+
			"it closed and another scan ran: %v", staging, err)
	}
}

// TestOnlyStagingDirectoriesAreRemovedFromTheRoot bounds what that removal
// takes from the cache root: the directories named as staging directories,
// and nothing else. Not the cache entries beside them, not a file or a link
// that carries the name, and not what such a link points at.
func TestOnlyStagingDirectoriesAreRemovedFromTheRoot(t *testing.T) {
	withoutFetchTools(t)
	dir := t.TempDir()
	root := filepath.Join(dir, "cache")
	// A cache hit for the package fetched below, so that the fetch reads the
	// cache and stages nothing of its own.
	source := makeDir(t, filepath.Join(root, "npm", "left-pad", "1.3.0", npmExtractedDir))
	orphan := makeDir(t, filepath.Join(root, stagingPrefix+"orphan"))
	file := filepath.Join(root, stagingPrefix+"file")
	const content = "not a staging directory\n"
	if err := os.WriteFile(file, []byte(content), 0o600); err != nil {
		t.Fatalf("write %s: %v", file, err)
	}
	outside := makeDir(t, filepath.Join(dir, "outside"))
	link := filepath.Join(root, stagingPrefix+"link")
	symlink(t, outside, link)
	before := tree(t, outside)

	f := NewFetcher(root)
	got, err := f.Fetch(leftPad)
	if err != nil || got != source {
		t.Fatalf("the fetch did not read the cache hit %s: %q, %v", source, got, err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	if _, err := os.Lstat(orphan); !os.IsNotExist(err) {
		t.Errorf("the staging directory %s, which no fetch owns, is still in the cache root: %v", orphan, err)
	}
	if !isNonEmptyDir(source) {
		t.Errorf("the cache entry %s beside the staging directories was removed", source)
	}
	if got, err := os.ReadFile(file); err != nil || string(got) != content {
		t.Errorf("the file %s, named as a staging directory, was removed or changed: %q, %v", file, got, err)
	}
	if info, err := os.Lstat(link); err != nil || info.Mode()&fs.ModeSymlink == 0 {
		t.Errorf("the link %s, named as a staging directory, was removed or replaced: %v", link, err)
	}
	if after := tree(t, outside); after != before {
		t.Errorf("the directory a link named as a staging directory points at was changed:\n"+
			"before:\n%s\nafter:\n%s", before, after)
	}
}

// TestOnlyAbandonedCachesAreRemovedFromTheTemporaryDirectory bounds the same
// removal in the temporary directory, which other programs and, on most Unix
// systems, other users share. A directory named as a scan's cache of its own
// is removed only if it is private to the user running the scan, its scan
// marked it as locked, and the lock is free. Each case kept below differs from
// the abandoned cache in one of those, or is not a directory with the name,
// and has to be left exactly as it was.
func TestOnlyAbandonedCachesAreRemovedFromTheTemporaryDirectory(t *testing.T) {
	withoutFetchTools(t)
	tmp := t.TempDir()
	for _, name := range []string{"HOME", "XDG_CACHE_HOME", "LocalAppData"} {
		t.Setenv(name, "")
	}
	for _, name := range []string{"TMPDIR", "TMP", "TEMP"} {
		t.Setenv(name, tmp)
	}

	// runCache lays out at dir what a killed scan leaves: a cache of its own
	// with part of a download staged in it, marked as locked when marked is set.
	runCache := func(dir string, mode os.FileMode, marked bool) string {
		t.Helper()
		makeDir(t, filepath.Join(dir, stagingPrefix+"1"))
		if marked {
			if err := os.WriteFile(filepath.Join(dir, lockedMarker), nil, 0o600); err != nil {
				t.Fatalf("mark %s as locked: %v", dir, err)
			}
		}
		// chmod, unlike mkdir, is not narrowed by the umask.
		if err := os.Chmod(dir, mode); err != nil {
			t.Fatalf("set the mode of %s: %v", dir, err)
		}
		return dir
	}
	abandoned := runCache(filepath.Join(tmp, perRunPrefix+"abandoned"), 0o700, true)
	outside := runCache(filepath.Join(t.TempDir(), perRunPrefix+"outside"), 0o700, true)
	link := filepath.Join(tmp, perRunPrefix+"link")
	symlink(t, outside, link)
	file := filepath.Join(tmp, perRunPrefix+"file")
	const content = "not a cache\n"
	if err := os.WriteFile(file, []byte(content), 0o600); err != nil {
		t.Fatalf("write %s: %v", file, err)
	}
	kept := map[string]string{
		"a cache its scan did not mark as locked": runCache(filepath.Join(tmp, perRunPrefix+"unmarked"), 0o700, false),
		"a cache other users can write to":        runCache(filepath.Join(tmp, perRunPrefix+"writable"), 0o770, true),
		"a directory not named as a scan's cache": runCache(filepath.Join(tmp, "unrelated"), 0o700, true),
		"what a link named as a cache points at":  outside,
	}
	before := map[string]string{}
	for what, dir := range kept {
		before[what] = tree(t, dir)
	}

	fetchAndClose(t, NewFetcher(""))

	if _, err := os.Lstat(abandoned); !os.IsNotExist(err) {
		t.Errorf("the abandoned cache %s is still in the temporary directory: %v", abandoned, err)
	}
	for what, dir := range kept {
		if _, err := os.Lstat(dir); err != nil {
			t.Errorf("%s, %s, was removed: %v", what, dir, err)
			continue
		}
		if after := tree(t, dir); after != before[what] {
			t.Errorf("%s, %s, was changed:\nbefore:\n%s\nafter:\n%s", what, dir, before[what], after)
		}
	}
	if info, err := os.Lstat(link); err != nil || info.Mode()&fs.ModeSymlink == 0 {
		t.Errorf("the link %s, named as a scan's cache, was removed or replaced: %v", link, err)
	}
	if got, err := os.ReadFile(file); err != nil || string(got) != content {
		t.Errorf("the file %s, named as a scan's cache, was removed or changed: %q, %v", file, got, err)
	}
}
