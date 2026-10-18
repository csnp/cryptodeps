// Copyright 2025-2026 CyberSecurity NonProfit (CSNP)
// SPDX-License-Identifier: Apache-2.0

//go:build unix

package source

import (
	"fmt"
	"io/fs"
	"os"
	"syscall"
)

// ownerAndModeProblem says why a source cache directory is not private to the
// user running the scan, or returns "" when it is. It has to belong to that
// user, and nobody else may write to it.
func ownerAndModeProblem(info fs.FileInfo) string {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return "its owner cannot be determined"
	}
	if uid := int(st.Uid); uid != os.Geteuid() {
		return fmt.Sprintf("it belongs to another user (uid %d)", uid)
	}
	if perm := info.Mode().Perm(); perm&0o022 != 0 {
		return fmt.Sprintf("other users can write to it (mode %04o)", perm)
	}
	return ""
}
