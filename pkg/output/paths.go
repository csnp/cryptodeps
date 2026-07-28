// Copyright 2025-2026 CyberSecurity NonProfit (CSNP)
// SPDX-License-Identifier: Apache-2.0

package output

import (
	"os"
	"path/filepath"
	"strconv"
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

// reportSafe renders a filesystem path, or an error string quoting one, for a
// plain-text report.
//
// Both are attacker-controlled. Any repository can hold a directory whose name
// carries newlines, and the scan report is published by the bundled GitHub
// Action, so a scanned repository could write its own lines into the document
// that judges it: a directory named with an embedded "## Scan result: CLEAN"
// put exactly that heading in the markdown report, above the real findings.
// Anything carrying a control character, a backtick or a pipe is rendered as a
// Go-quoted string, which is single-line, unambiguous and reversible. A path
// with none of those, which is every real one, is returned unchanged.
func reportSafe(s string) string {
	if !needsEscaping(s) {
		return s
	}
	return strconv.Quote(s)
}

// markdownSafe renders a string for the inside of a markdown code span.
//
// Its callers must put the result in one. That is the whole defence, and it is
// why this is not a list of markdown metacharacters to escape: inside a code
// span only two characters are active, a backtick which would close the span
// early and a pipe which GitHub-flavoured markdown splits a table cell on even
// inside one. Everywhere else, every markdown construct is live. Escaping
// characters one at a time is how the first version of this missed a path named
// "**CLEAN**", which reached a bare `##` heading with no trigger character in it
// and rendered as bold.
func markdownSafe(s string) string {
	out := reportSafe(s)
	out = strings.ReplaceAll(out, "`", `\x60`)
	out = strings.ReplaceAll(out, "|", `\|`)
	return out
}

// needsEscaping reports whether a string can break out of the line, the code
// span or the table cell it is about to be rendered into, or misrepresent what
// it names.
//
// ASCII control characters are not the whole set. U+2028 and U+2029 are line
// breaks to a renderer, so they inject lines exactly as \n does. The bidi
// controls reverse the visible order of a name, which is the Trojan Source
// trick: a report can be made to display a filename that is not the one it is
// talking about. The zero-width characters make two different paths render
// identically. U+FFFD is what invalid UTF-8 in a filename decodes to, and a
// filesystem does not require valid UTF-8.
func needsEscaping(s string) bool {
	for _, r := range s {
		switch {
		case r < 0x20, r == 0x7f:
			return true
		case r == '`', r == '|':
			return true
		case r == 0x85, r == 0x2028, r == 0x2029:
			return true
		case r >= 0x202a && r <= 0x202e, r >= 0x2066 && r <= 0x2069:
			return true
		case r >= 0x200b && r <= 0x200f, r == 0xfeff, r == 0xfffd:
			return true
		}
	}
	return false
}

// manifestForReport names a manifest inside a report.
//
// With a scan root it is expressed relative to it, matching every other surface
// of the same run. Standalone, which is what `--no-workspaces` and a
// single-manifest scan produce, there is no root to express it against and the
// absolute path is the only anchor the reader has.
func manifestForReport(root, manifest string) string {
	if root == "" {
		return manifest
	}
	return getRelativePath(root, manifest)
}
