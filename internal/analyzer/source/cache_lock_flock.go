// Copyright 2025-2026 CyberSecurity NonProfit (CSNP)
// SPDX-License-Identifier: Apache-2.0

//go:build darwin || dragonfly || freebsd || illumos || linux || netbsd || openbsd

package source

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// A fetch downloads into a staging directory of its own in the cache root, and
// only that fetch removes it, in a deferred call. A scan stopped during the
// download, by Ctrl-C (SIGINT), SIGTERM or SIGKILL, never makes the call, and
// no later scan looked at the directory, so each scan stopped that way left one
// more partial download in the cache. A scan's cache of its own in the
// temporary directory, which only its Close removes, stayed the same way.
//
// What tells such a directory from one that a live fetch is still filling is a
// lock. Every fetcher holds a shared flock on the cache root it stages in, for
// as long as it may stage there, and the kernel lets go of it when the process
// exits, a SIGKILL included. A fetcher that can take the lock exclusively
// therefore knows that no other fetcher, in this process or another, holds the
// root. Staging directories are removed then and only then, so that a scan
// running beside another leaves the other's download alone.

// lockedMarker is made in a cache of the run's own once its lock is held. A
// scan that finds the marker and the lock free knows that the run is gone, and
// not about to take the lock on a directory it has only just made.
const lockedMarker = ".locked"

// claimRoot takes the shared lock that this fetcher holds on root while it may
// stage downloads there, and returns it, or nil where the lock cannot be had.
//
// A root that scans share, the per-user one or one the caller named, has its
// staging directories removed first, when the lock can be taken exclusively.
// A cache of the run's own, ownRun, has none: it was made a moment ago. It is
// marked as locked instead, and then removeAbandonedRuns removes the caches of
// their own that other scans left in the temporary directory.
func claimRoot(root string, ownRun bool) *os.File {
	dir, err := openDir(root)
	if err != nil {
		return nil
	}
	if !ownRun && flock(dir, syscall.LOCK_EX|syscall.LOCK_NB) == nil {
		removeStaging(root)
	}
	// This turns the exclusive lock into a shared one, or, when another
	// fetcher holds the root, waits out any removal that fetcher is making.
	if flock(dir, syscall.LOCK_SH) != nil {
		dir.Close()
		return nil
	}
	if ownRun {
		// Without the marker, which a failed write leaves, the cache is never
		// taken for abandoned, so the error is not a reason to stop.
		_ = os.WriteFile(filepath.Join(root, lockedMarker), nil, 0o600)
		removeAbandonedRuns(root)
	}
	return dir
}

// removeStaging removes the staging directories in root. The caller holds the
// exclusive lock on root, so none of them is a live fetch's. A fetch stages in
// nothing but a directory, so a file or a link with the name is left alone.
func removeStaging(root string) {
	entries, err := os.ReadDir(root)
	if err != nil {
		return
	}
	for _, e := range entries {
		if e.IsDir() && strings.HasPrefix(e.Name(), stagingPrefix) {
			_ = os.RemoveAll(filepath.Join(root, e.Name()))
		}
	}
}

// removeAbandonedRuns removes the caches of their own that scans left beside
// own, this run's, in the temporary directory, when they ended before Close.
//
// The temporary directory is shared with every program on the machine and, on
// most Unix systems, with every user, so what is removed is held to more than
// its name: a private directory of this user's, marked as locked by its scan,
// with the lock free. Anything else there is left alone.
func removeAbandonedRuns(own string) {
	tmp := filepath.Dir(own)
	entries, err := os.ReadDir(tmp)
	if err != nil {
		return
	}
	for _, e := range entries {
		if e.IsDir() && strings.HasPrefix(e.Name(), perRunPrefix) && e.Name() != filepath.Base(own) {
			removeIfAbandoned(filepath.Join(tmp, e.Name()))
		}
	}
}

// removeIfAbandoned removes the cache of its own that a scan made at path, if
// that scan is gone.
func removeIfAbandoned(path string) {
	info, err := os.Lstat(path)
	if err != nil || checkPrivateDir(path, info) != nil {
		return
	}
	if _, err := os.Lstat(filepath.Join(path, lockedMarker)); err != nil {
		return
	}
	dir, err := openDir(path)
	if err != nil {
		return
	}
	defer dir.Close()
	if flock(dir, syscall.LOCK_EX|syscall.LOCK_NB) != nil {
		return
	}
	// What is removed has to be the directory whose lock was taken.
	if held, err := dir.Stat(); err != nil || !os.SameFile(held, info) {
		return
	}
	_ = os.RemoveAll(path)
}

// openDir opens the directory at path to lock it, refusing a link.
func openDir(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW, 0)
}

// flock takes the lock that how names on f, and takes it again when a signal
// interrupts the call.
func flock(f *os.File, how int) error {
	for {
		if err := syscall.Flock(int(f.Fd()), how); err != syscall.EINTR {
			return err
		}
	}
}
