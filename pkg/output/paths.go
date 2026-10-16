// Copyright 2025-2026 CyberSecurity NonProfit (CSNP)
// SPDX-License-Identifier: Apache-2.0

package output

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/csnp/qramm-cryptodeps/pkg/types"
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

// RelativeToScanRoot names path the way every report names a manifest: relative
// to the scan root, or absolute when it does not sit under the root. root may be
// what the user typed, a directory or a manifest file.
//
// Exported for the analyzer, which writes each finding's location before any
// formatter runs. A JSON document carries that location verbatim, so it has to
// be expressed by the same rule SARIF and CBOM use for the manifest, or one run
// would name the same file two ways.
func RelativeToScanRoot(root, path string) string {
	rel, _ := relativeToRoot(scanRootDir(root), path)
	return rel
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

// declarationRef renders where a dependency is declared as "manifest:line", or
// as the manifest alone when the parser could not tell the line. ":0" would
// send the reader to a line that does not exist.
func declarationRef(manifest string, line int) string {
	if line < 1 {
		return manifest
	}
	return manifest + ":" + strconv.Itoa(line)
}

// declarationsOf returns each dependency in results that provides algorithm,
// once per declaration, in the order the manifest declares them. Dependencies
// whose line is not known come last, by name.
func declarationsOf(results []types.DependencyResult, algorithm string) []types.Dependency {
	seen := make(map[string]bool)
	var deps []types.Dependency
	for _, r := range results {
		if r.Analysis == nil {
			continue
		}
		for _, c := range r.Analysis.Crypto {
			if c.Algorithm != algorithm {
				continue
			}
			key := r.Dependency.Name + "\x00" + r.Dependency.Version + "\x00" + strconv.Itoa(r.Dependency.Line)
			if !seen[key] {
				seen[key] = true
				deps = append(deps, r.Dependency)
			}
			break
		}
	}
	sort.SliceStable(deps, func(i, j int) bool {
		a, b := deps[i], deps[j]
		if (a.Line == 0) != (b.Line == 0) {
			return a.Line != 0
		}
		if a.Line != b.Line {
			return a.Line < b.Line
		}
		if a.Name != b.Name {
			return a.Name < b.Name
		}
		return a.Version < b.Version
	})
	return deps
}

// verifyDeclarationCommand returns one command that prints the lines of
// manifest declaring deps, with their line numbers, so a reader can confirm a
// finding before acting on it. It runs from the scan root, which is what
// manifest is relative to, needs nothing installed beyond grep, and reads one
// local file. It returns "" when there is nothing to look for, and when the
// command could not be printed as it reads.
//
// It does not try to perform the fix. Replacing an algorithm is a change to the
// code that calls it, and no command can make that change safely.
func verifyDeclarationCommand(ecosystem types.Ecosystem, manifest string, deps []types.Dependency) string {
	if manifest == "" {
		return ""
	}
	// PyPI names are matched as a pattern, every other ecosystem's literally.
	args := []string{"grep", "-n", "-F"}
	if ecosystem == types.EcosystemPyPI {
		args = []string{"grep", "-n", "-i"}
	}
	seen := make(map[string]bool)
	for _, d := range deps {
		pattern := verifyPattern(ecosystem, d.Name)
		if pattern == "" || seen[pattern] {
			continue
		}
		seen[pattern] = true
		args = append(args, "-e", shellQuote(pattern))
	}
	if len(seen) == 0 {
		return ""
	}
	// Report paths are "./x" or absolute; this keeps any other shape from
	// being read as an option.
	if strings.HasPrefix(manifest, "-") {
		manifest = "./" + manifest
	}
	command := strings.Join(append(args, shellQuote(manifest)), " ")
	// Every word is quoted for the shell, but a report prints a string holding
	// a control character, a backtick or a pipe as a Go-quoted string, and
	// inside those double quotes "$(...)" and backticks are live again: the
	// printed line would run what the path or the name says. Such a command is
	// left out, and the Where line still names the file.
	if needsEscaping(command) {
		return ""
	}
	return command
}

// verifyPattern is the text a manifest declares name with.
func verifyPattern(ecosystem types.Ecosystem, name string) string {
	switch ecosystem {
	case types.EcosystemMaven:
		// The coordinate is written as separate groupId and artifactId
		// elements, so "group:artifact" never appears in the file. The
		// artifactId does, and it is the line the finding is reported at.
		if i := strings.LastIndex(name, ":"); i >= 0 {
			return name[i+1:]
		}
	case types.EcosystemPyPI:
		// The name has been through PEP 503 normalisation, and the file may
		// spell it in any case with any of "-", "_" or "." between words, so
		// a literal search for the normalised form would miss "PyNaCl" and
		// "typing_extensions". Each word is escaped for a basic regular
		// expression; the parsers admit no such characters, and this does not
		// rely on that.
		words := pypiWordSeparator.Split(name, -1)
		for i, word := range words {
			words[i] = basicRegexpEscaper.Replace(word)
		}
		return strings.Join(words, "[-_.]")
	}
	return name
}

// pypiWordSeparator matches the separators PEP 503 treats as equivalent.
var pypiWordSeparator = regexp.MustCompile(`[-_.]+`)

// basicRegexpEscaper escapes the characters special to a POSIX basic regular
// expression.
var basicRegexpEscaper = strings.NewReplacer(
	`\`, `\\`, `.`, `\.`, `[`, `\[`, `]`, `\]`, `*`, `\*`, `^`, `\^`, `$`, `\$`,
)

// shellSafeWord matches a word that every common shell reads literally. "~"
// and "=" are left out because bash and zsh expand them at the start of a
// word.
var shellSafeWord = regexp.MustCompile(`^[A-Za-z0-9@%+:,./_-]+$`)

// shellQuote renders s as one literal shell word.
//
// A dependency name comes from the manifest under scan, which anyone who can
// open a pull request can change, and the reader is being asked to paste this
// command into a shell. A name such as "x$(curl ...)" must therefore reach grep
// as text. Single quotes make every character literal, and the one character
// they cannot hold is closed, escaped and reopened.
func shellQuote(s string) string {
	if shellSafeWord.MatchString(s) {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
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
