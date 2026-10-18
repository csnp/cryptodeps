// Copyright 2025-2026 CyberSecurity NonProfit (CSNP)
// SPDX-License-Identifier: Apache-2.0

//go:build !(darwin || dragonfly || freebsd || illumos || linux || netbsd || openbsd)

package source

import "os"

// claimRoot takes no lock where the platform has no flock, Windows among them.
// Nothing then tells a staging directory that an interrupted scan left from one
// that a live fetch is filling, so none is removed. See cache_lock_flock.go.
func claimRoot(string, bool) *os.File {
	return nil
}
