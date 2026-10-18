// Copyright 2025-2026 CyberSecurity NonProfit (CSNP)
// SPDX-License-Identifier: Apache-2.0

//go:build !unix

package source

import "io/fs"

// ownerAndModeProblem is Unix only. On Windows the source cache relies on the
// per-user location to keep it to one user, and file modes there do not say
// who can write to a directory.
func ownerAndModeProblem(fs.FileInfo) string {
	return ""
}
