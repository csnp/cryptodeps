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

// markdownCode renders a string for the inside of a markdown code span that is
// not in a table.
//
// Its callers must put the result in one. That is the whole defence, and it is
// why this is not a list of markdown metacharacters to escape: inside a code
// span only a backtick is active, and it would close the span early. Everywhere
// else every markdown construct is live, which is how the first version of this
// missed a path named "**CLEAN**": it had no trigger character, so it reached a
// bare `##` heading unescaped and rendered as bold.
func markdownCode(s string) string {
	return strings.ReplaceAll(reportSafe(s), "`", `\x60`)
}

// markdownCell renders a string for a code span inside a GitHub-flavoured
// markdown table cell, where a pipe splits the cell even inside the span.
//
// Separate from markdownCode because the pipe escape is a table rule and nothing
// else consumes it: applied to a bullet or a heading, the backslash renders
// literally, so the report displayed a name the filesystem does not have and the
// quoted form no longer round-tripped through strconv.Unquote.
func markdownCell(s string) string {
	return strings.ReplaceAll(markdownCode(s), "|", `\|`)
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
		// Everything Go does not consider printable: the ASCII controls, DEL,
		// U+0085, the Unicode line and paragraph separators, every bidi and
		// format control, the zero-width set, and the non-ASCII spaces that
		// render as an ordinary one. Enumerating these by hand missed U+061C,
		// U+2060, U+180E, the tag block and U+00A0 on the first attempt, all of
		// which belong to the classes the enumeration claimed to cover.
		case !strconv.IsPrint(r):
			return true
		// Printable, but active in the context this is rendered into.
		case r == '`', r == '|':
			return true
		// Printable, and what invalid UTF-8 in a filename decodes to. It injects
		// nothing; quoting marks the name as a rendering rather than the literal
		// bytes, which cannot be recovered.
		case r == 0xfffd:
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

// dependencyLabel renders "name@version", or just the name when no version was
// declared.
//
// One place, because both the table and markdown build this string and both had
// it interpolated raw. The pieces come from the manifest under scan, so they
// carry whatever the author of that manifest put in them.
func dependencyLabel(name, version string) string {
	if version == "" {
		return name
	}
	return name + "@" + version
}
