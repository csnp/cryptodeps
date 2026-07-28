// Copyright 2025-2026 CyberSecurity NonProfit (CSNP)
// SPDX-License-Identifier: Apache-2.0

package output

import (
	"os"
	"path/filepath"
	"strings"
)

// scanRootDir normalizes a scan root into the absolute directory that manifest
// paths are expressed relative to.
//
// Two shapes reach the formatters, and both have to be handled before any
// comparison against a manifest path is meaningful. Discovery absolutizes every
// manifest path, while the scan root is whatever the user typed: `cryptodeps
// analyze .` leaves the literal "." in RootPath, so relativizing against it
// silently produced no relative path at all and the absolute one was emitted
// instead. And `cryptodeps analyze ./package.json` puts a FILE in the root,
// which as a base directory made every path relative to itself.
//
// SARIF handled both and CBOM handled neither, which is why this lives in one
// place that both call rather than in each formatter.
func scanRootDir(root string) string {
	abs, err := filepath.Abs(root)
	if err != nil {
		return root
	}
	if info, statErr := os.Stat(abs); statErr == nil && !info.IsDir() {
		abs = filepath.Dir(abs)
	}
	return abs
}

// relativeToRoot expresses a manifest path relative to an absolute scan root, so
// that a document leaving this machine carries the repository layout rather than
// the operator's home directory or a CI runner's workspace path.
//
// absRoot must come from scanRootDir. The second return reports whether the
// manifest actually sits under the root; when it does not, the caller gets the
// absolute path, because a relative path would be a lie. Callers that need a URI
// add their own scheme: this returns a plain path.
func relativeToRoot(absRoot, manifest string) (path string, underRoot bool) {
	if manifest == "" {
		return "", false
	}
	absManifest, err := filepath.Abs(manifest)
	if err != nil {
		return filepath.ToSlash(manifest), false
	}
	rel, err := filepath.Rel(absRoot, absManifest)
	// rel == ".." and the "../" prefix mean the manifest is outside the root. A
	// bare HasPrefix(rel, "..") would also reject a directory legitimately named
	// something like "..config".
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return filepath.ToSlash(absManifest), false
	}
	return filepath.ToSlash(rel), true
}
