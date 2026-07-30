// Copyright 2025-2026 CyberSecurity NonProfit (CSNP)
// SPDX-License-Identifier: Apache-2.0

package ast

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf8"
)

// TestGoDirectoryScanCountsOnlyFilesItParsed holds the meaning of FilesParsed.
//
// The count is what the rest of the tool uses to decide whether a package was
// examined, so counting a file the analyzer could not read would restore the
// defect it exists to close: a package would again be reported as examined on
// the strength of files nothing was learned from.
func TestGoDirectoryScanCountsOnlyFilesItParsed(t *testing.T) {
	dir := t.TempDir()

	readable := `package main

import "crypto/md5"

func hash(b []byte) [16]byte { return md5.Sum(b) }
`
	// Valid enough to be walked and offered to the parser, and not valid Go.
	unparsable := `package main

func broken( {
`
	if err := os.WriteFile(filepath.Join(dir, "readable.go"), []byte(readable), 0644); err != nil {
		t.Fatalf("write readable.go: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "unparsable.go"), []byte(unparsable), 0644); err != nil {
		t.Fatalf("write unparsable.go: %v", err)
	}

	scan, err := NewGoAnalyzer().AnalyzeDirectory(dir)
	if err != nil {
		t.Fatalf("AnalyzeDirectory: %v", err)
	}

	// Guard the fixture: if the parser accepts the broken file, this test is
	// measuring nothing.
	if scan.FilesFailed != 1 {
		t.Fatalf("FilesFailed = %d, so the fixture's unparsable file did not fail to "+
			"parse and this test cannot detect a walker that counts it", scan.FilesFailed)
	}
	if scan.FilesParsed != 1 {
		t.Errorf("FilesParsed = %d for one readable and one unparsable file", scan.FilesParsed)
	}
	if len(scan.Usages) == 0 {
		t.Errorf("the readable file's MD5 usage is missing, so one unparsable file " +
			"abandoned the whole directory")
	}
}

// TestDirectoryScanCountsOnlyTextItCouldRead is the regression test for the
// second attempt at the examination evidence.
//
// The first attempt counted files the analyzer OPENED. Three of the four
// analyzers are line scanners whose only failure mode was os.Open, so any
// openable file with a matching extension counted as parsed: a zero-byte
// Empty.java in a fetched archive produced filesAnalyzed 1 and the report said
// "no cryptographic usage detected in the 1 of 1 dependencies that were
// examined", which is the exact sentence this release exists to remove. An
// extension is a descriptor; accepting it as the thing itself is how the
// false-clean class survived its own fix.
func TestDirectoryScanCountsOnlyTextItCouldRead(t *testing.T) {
	cases := []struct {
		name     string
		file     string
		content  []byte
		analyzer func(string) (DirectoryScan, error)
	}{
		{"empty java", "Empty.java", []byte{}, func(d string) (DirectoryScan, error) {
			return NewJavaAnalyzer().AnalyzeDirectory(d)
		}},
		{"class bytes named java", "Hashing.java",
			[]byte{0xca, 0xfe, 0xba, 0xbe, 0x00, 0x00, 0x00, 0x34},
			func(d string) (DirectoryScan, error) { return NewJavaAnalyzer().AnalyzeDirectory(d) }},
		{"empty js", "index.js", []byte{}, func(d string) (DirectoryScan, error) {
			return NewJavaScriptAnalyzer().AnalyzeDirectory(d)
		}},
		{"binary named js", "index.js", []byte{0x00, 0x01, 0x02, 0xff, 0xfe},
			func(d string) (DirectoryScan, error) {
				return NewJavaScriptAnalyzer().AnalyzeDirectory(d)
			}},
		{"empty python", "mod.py", []byte{}, func(d string) (DirectoryScan, error) {
			return NewPythonAnalyzer().AnalyzeDirectory(d)
		}},
		{"binary named python", "mod.py", []byte{0x7f, 'E', 'L', 'F', 0x00, 0x01},
			func(d string) (DirectoryScan, error) { return NewPythonAnalyzer().AnalyzeDirectory(d) }},
		{"empty go", "main.go", []byte{}, func(d string) (DirectoryScan, error) {
			return NewGoAnalyzer().AnalyzeDirectory(d)
		}},
		// Larger than the head that is checked for being text, and carrying no
		// NUL byte, so neither the NUL test nor a head shorter than the boundary
		// catches it. The first version of the text check walked the head down
		// to nothing looking for a rune boundary and then called an empty slice
		// valid UTF-8, so every binary of this shape counted as parsed source.
		{"large binary named java without a NUL byte", "Big.java",
			bytes.Repeat([]byte{0xff}, 2000),
			func(d string) (DirectoryScan, error) { return NewJavaAnalyzer().AnalyzeDirectory(d) }},
		{"large binary named js without a NUL byte", "big.js",
			bytes.Repeat([]byte{0xfe}, 4096),
			func(d string) (DirectoryScan, error) {
				return NewJavaScriptAnalyzer().AnalyzeDirectory(d)
			}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, tc.file)
			if err := os.WriteFile(path, tc.content, 0644); err != nil {
				t.Fatalf("write fixture: %v", err)
			}
			// Guard the fixture: the walker has to reach this file at all, or a
			// zero count means only that nothing was looked at.
			if info, err := os.Stat(path); err != nil || info.Size() != int64(len(tc.content)) {
				t.Fatalf("fixture %s is not on disk as written: %v", path, err)
			}

			scan, err := tc.analyzer(dir)
			if err != nil {
				t.Fatalf("AnalyzeDirectory: %v", err)
			}
			if scan.FilesParsed != 0 {
				t.Errorf("FilesParsed = %d for a file holding %d bytes of %s; a caller reading "+
					"this count reports the package as examined", scan.FilesParsed,
					len(tc.content), tc.name)
			}
			if scan.FilesFailed != 1 {
				t.Errorf("FilesFailed = %d, so the file was not even attempted and this case "+
					"proves nothing", scan.FilesFailed)
			}
		})
	}
}

// TestDirectoryScanReadsSourceInASingleByteEncoding is the regression test for
// the third attempt at the examination evidence.
//
// The second attempt refused any file whose head was not valid UTF-8. These
// analyzers are line scanners matching ASCII identifiers, so they never needed
// valid UTF-8, and the check refused legitimate source in any single-byte
// encoding: one Latin-1 accent in a comment made a .java or .js file
// "not text this analyzer can read", its cryptography was never looked for, and
// the released 1.2.2 had found it. The evasion that follows is the reason this
// is a security test and not a nicety: a dependency that also ships one
// readable file is still reported as examined, so encoding the file that calls
// MD5 in Latin-1 hid it from the scanner entirely.
func TestDirectoryScanReadsSourceInASingleByteEncoding(t *testing.T) {
	// 0xe9 is 'e' with an acute accent in Latin-1 and is not valid UTF-8.
	latin1Comment := []byte("// author: Jos\xe9 Garc\xeda\n")

	cases := []struct {
		name     string
		file     string
		content  []byte
		analyzer func(string) (DirectoryScan, error)
	}{
		{"latin-1 java", "Hashing.java",
			append(latin1Comment, []byte(`import java.security.MessageDigest;
class Hashing { void f() throws Exception { MessageDigest.getInstance("MD5"); } }
`)...),
			func(d string) (DirectoryScan, error) { return NewJavaAnalyzer().AnalyzeDirectory(d) }},
		{"latin-1 javascript", "index.js",
			append(latin1Comment, []byte("const crypto = require('crypto');\n"+
				"function h(x) { return crypto.createHash('md5').update(x).digest('hex'); }\n")...),
			func(d string) (DirectoryScan, error) { return NewJavaScriptAnalyzer().AnalyzeDirectory(d) }},
		// Past the head boundary, so the file is judged on the head alone and the
		// accent sits inside it. The padding is ASCII, which is what a real
		// source file in a single-byte encoding looks like: code is ASCII even
		// when its comments are not.
		{"latin-1 javascript larger than the head", "big.js",
			append(append(latin1Comment, bytes.Repeat([]byte("// padding to pass the head boundary\n"), 40)...),
				[]byte("const crypto = require('crypto');\n"+
					"function h(x) { return crypto.createHash('md5').update(x).digest('hex'); }\n")...),
			func(d string) (DirectoryScan, error) { return NewJavaScriptAnalyzer().AnalyzeDirectory(d) }},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Guard the fixture in both directions. If the content were valid
			// UTF-8 this case would pass against the code it exists to catch,
			// and if it carried a NUL byte it would be refused for an unrelated
			// reason that this change does not and should not alter.
			if utf8.Valid(tc.content) {
				t.Fatalf("fixture is valid UTF-8, so it never reaches the branch under test")
			}
			if bytes.IndexByte(tc.content, 0) >= 0 {
				t.Fatalf("fixture carries a NUL byte, so it is refused as binary rather than " +
					"for its encoding")
			}

			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, tc.file), tc.content, 0644); err != nil {
				t.Fatalf("write fixture: %v", err)
			}

			scan, err := tc.analyzer(dir)
			if err != nil {
				t.Fatalf("AnalyzeDirectory: %v", err)
			}
			if scan.FilesParsed != 1 {
				t.Errorf("FilesParsed = %d for legitimate source in a single-byte encoding; "+
					"the file was refused and its cryptography was never looked for",
					scan.FilesParsed)
			}
			if scan.FilesFailed != 0 {
				t.Errorf("FilesFailed = %d for a readable source file", scan.FilesFailed)
			}
			if len(scan.Usages) == 0 {
				t.Errorf("the MD5 usage in a Latin-1 encoded file is missing, so a dependency " +
					"can hide its cryptography from this scanner by choosing an encoding")
			}
		})
	}
}

// TestDirectoryScanReadsAFileWithOneVeryLongLine is the regression test for a
// false negative on one of the tool's most common inputs.
//
// bufio's default token limit is 64 KiB. A line longer than that stops Scan and
// makes Err report it, the three line-scanning analyzers return that error, and
// the walk then discards every usage they had already found. So a bundled or
// minified dist file, which is normally one very long line, contributed nothing:
// a 70 KB single-line file calling crypto.createHash('md5') produced no finding,
// no warning, and a clean verdict, on this candidate and on 1.2.2.
func TestDirectoryScanReadsAFileWithOneVeryLongLine(t *testing.T) {
	// One line, comfortably past the 64 KiB default, with the call at the end so
	// that a scanner which gave up early cannot reach it. The require and the
	// call use the spelling this analyzer tracks: a fixture whose crypto is not
	// detectable at ALL would fail this test for a reason that has nothing to do
	// with the line length, which is how the first draft of it misled me.
	line := "const crypto = require('crypto'); /*" + strings.Repeat("a", 70000) + "*/ " +
		"crypto.createHash('md5').update('x').digest('hex');\n"

	dir := t.TempDir()
	// Not named .min.js: minified files are skipped by name, and this test is
	// about the line length rather than the naming convention.
	path := filepath.Join(dir, "bundle.js")
	if err := os.WriteFile(path, []byte(line), 0644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	// Guard the fixture: below the limit this test proves nothing.
	if len(line) <= 64*1024 {
		t.Fatalf("fixture line is %d bytes, at or below bufio's 64 KiB default, so it does "+
			"not reach the branch under test", len(line))
	}
	// Guard it the other way too: the same crypto call on a SHORT line has to be
	// detected, or a zero result below says only that the fixture is undetectable.
	short := t.TempDir()
	if err := os.WriteFile(filepath.Join(short, "small.js"),
		[]byte("const crypto = require('crypto');\ncrypto.createHash('md5');\n"), 0644); err != nil {
		t.Fatalf("write control fixture: %v", err)
	}
	if control, err := NewJavaScriptAnalyzer().AnalyzeDirectory(short); err != nil ||
		len(control.Usages) == 0 {
		t.Fatalf("the control fixture's MD5 is not detected on a short line (%d usages, %v), "+
			"so this test cannot attribute a miss to the line length",
			len(control.Usages), err)
	}

	scan, err := NewJavaScriptAnalyzer().AnalyzeDirectory(dir)
	if err != nil {
		t.Fatalf("AnalyzeDirectory: %v", err)
	}
	if scan.FilesParsed != 1 {
		t.Errorf("FilesParsed = %d for a single-line bundle this analyzer can read",
			scan.FilesParsed)
	}
	if len(scan.Usages) == 0 {
		t.Errorf("the MD5 call on a %d byte line is missing, so a bundled dist file "+
			"contributes nothing and the package is still reported as examined", len(line))
	}
}

// TestIsTextBracketsTheThreshold pins minTextFraction from BOTH sides.
//
// A fixture of pure 0xff has a printable fraction of zero, so it is refused by
// any threshold above zero and cannot detect one that has been loosened. That
// left the whole range between 0 and 0.75 unpinned: a mutation to 0.01 kept the
// suite green. Bracketing needs an input in the middle, and the natural one is
// what the threshold was measured against.
func TestIsTextBracketsTheThreshold(t *testing.T) {
	// Around 0.39 printable, which is what random bytes with the NUL removed
	// measure, and is the shape of compressed or encrypted content.
	var mixed []byte
	for i := 0; len(mixed) < 2000; i++ {
		if i%5 == 0 {
			mixed = append(mixed, byte('a'+i%26))
		} else {
			mixed = append(mixed, byte(0x80+i%0x7f))
		}
	}
	// Around 0.98 printable, which is what real source in a single-byte encoding
	// measures: ASCII code with the occasional accented byte in a comment.
	var sourceLike []byte
	for i := 0; len(sourceLike) < 2000; i++ {
		if i%50 == 0 {
			sourceLike = append(sourceLike, 0xe9)
		} else {
			sourceLike = append(sourceLike, byte('a'+i%26))
		}
	}

	for _, tc := range []struct {
		name    string
		content []byte
		want    bool
	}{
		{"mostly high bytes is not text", mixed, false},
		{"mostly ASCII with a few high bytes is text", sourceLike, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Guard both fixtures: each must be invalid UTF-8 and NUL-free, or it
			// is answered by a different branch than the one under test.
			if utf8.Valid(tc.content) {
				t.Fatalf("fixture is valid UTF-8, so the fraction is never consulted")
			}
			if bytes.IndexByte(tc.content, 0) >= 0 {
				t.Fatalf("fixture carries a NUL byte, so it is refused as binary")
			}
			// And assert where each sits relative to the threshold, so that a
			// change to minTextFraction fails here with its reason visible rather
			// than somewhere downstream.
			got := printableASCIIFraction(tc.content[:headBytes])
			if tc.want && got < minTextFraction {
				t.Fatalf("fixture meant to be text measures %.3f, below the %.2f threshold",
					got, minTextFraction)
			}
			if !tc.want && got >= minTextFraction {
				t.Fatalf("fixture meant to be binary measures %.3f, at or above the %.2f threshold",
					got, minTextFraction)
			}

			if isText(tc.content) != tc.want {
				t.Errorf("isText = %v, want %v for a head measuring %.3f printable ASCII",
					!tc.want, tc.want, got)
			}
		})
	}
}

// TestIsTextDoesNotTrimAHeadIntoValidity pins the bound on the rune-straddle
// allowance, which the fraction fallback would otherwise hide.
//
// The allowance trims up to the three continuation bytes a truncated rune can
// occupy. Unbounded, it walks a binary head down to whatever prefix happens to
// be valid: a file opening with a few ASCII bytes and continuing with 0xff is
// then accepted as text, which is the defect the bound was added to close. Pure
// 0xff cannot detect it, because trimming that reaches an empty head and the
// empty-head guard refuses it for an unrelated reason.
func TestIsTextDoesNotTrimAHeadIntoValidity(t *testing.T) {
	content := append([]byte("abc"), bytes.Repeat([]byte{0xff}, 2000)...)

	if bytes.IndexByte(content, 0) >= 0 {
		t.Fatalf("fixture carries a NUL byte, so it is refused as binary")
	}
	if len(content) <= headBytes {
		t.Fatalf("fixture is %d bytes, not past the head boundary, so no trimming happens",
			len(content))
	}
	// The guard that makes this fixture the right one: an unbounded trim WOULD
	// find a valid prefix here, so the test can tell a bounded loop from an
	// unbounded one.
	if !utf8.Valid(content[:3]) {
		t.Fatalf("fixture's ASCII prefix is not valid UTF-8, so an unbounded trim would not " +
			"reach validity and this test cannot detect the bound being removed")
	}

	if isText(content) {
		t.Errorf("a head of three ASCII bytes followed by 0xff was accepted as text; the " +
			"straddle allowance trimmed it into validity")
	}
}

// TestMaxSourceFileClearsRealSource pins the cap against the largest real source
// file measured, so that lowering it fails here rather than in a silent skip.
//
// aws-sdk-go v1.55.5 ships service/ec2/api.go at 7,771,273 bytes and has grown
// every release. A cap a real file is about to cross drops that file from the
// analysis, and until this test existed the value was unpinned in both
// directions: mutations to 1 MiB and to no cap at all both kept the suite green.
func TestMaxSourceFileClearsRealSource(t *testing.T) {
	const largestMeasured = 7_771_273 // aws-sdk-go v1.55.5 service/ec2/api.go
	// Headroom, not merely clearance. This file was 6,400,535 bytes at v1.44.0
	// and grows every release, so a cap that merely exceeds today's largest file
	// is a cap that starts silently dropping it during the life of a release.
	if maxSourceFile < 2*largestMeasured {
		t.Errorf("maxSourceFile = %d, less than twice the largest real source file measured "+
			"(%d); a generated file of this kind grows every release and would begin to be "+
			"counted unreadable rather than analyzed", maxSourceFile, largestMeasured)
	}
	// And the cap has to still be a cap, or an archive can exhaust the host.
	if maxSourceFile > 128<<20 {
		t.Errorf("maxSourceFile = %d, high enough that one file in a hostile archive can "+
			"exhaust memory", maxSourceFile)
	}
}

// TestDirectoryScanNamesTheFilesItCouldNotRead keeps the disclosure actionable.
//
// A count with no names is a dead end: the report says one file in a package
// went unread and gives the reader no way to learn which, or why. The coverage
// note promised the scan named them before it did.
func TestDirectoryScanNamesTheFilesItCouldNotRead(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "good.js"),
		[]byte("module.exports.x = 1;\n"), 0644); err != nil {
		t.Fatalf("write readable fixture: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "blob.js"),
		bytes.Repeat([]byte{0xff}, 2000), 0644); err != nil {
		t.Fatalf("write blob fixture: %v", err)
	}

	scan, err := NewJavaScriptAnalyzer().AnalyzeDirectory(dir)
	if err != nil {
		t.Fatalf("AnalyzeDirectory: %v", err)
	}
	if scan.FilesFailed != 1 || scan.FilesParsed != 1 {
		t.Fatalf("FilesParsed = %d, FilesFailed = %d; the fixture is not one readable file "+
			"and one refused one", scan.FilesParsed, scan.FilesFailed)
	}
	if len(scan.Unreadable) != 1 {
		t.Fatalf("Unreadable = %v, want one entry naming the refused file", scan.Unreadable)
	}
	if !strings.Contains(scan.Unreadable[0], "blob.js") {
		t.Errorf("the refusal does not name the file: %q", scan.Unreadable[0])
	}
	if !strings.Contains(scan.Unreadable[0], "not text") {
		t.Errorf("the refusal does not say why, so the reader cannot act on it: %q",
			scan.Unreadable[0])
	}
}

// TestDirectoryScanBoundsHowManyRefusalsItNames keeps a hostile archive from
// turning one warning into thousands, without ever understating the count.
func TestDirectoryScanBoundsHowManyRefusalsItNames(t *testing.T) {
	dir := t.TempDir()
	const blobs = maxUnreadableReported + 5
	for i := 0; i < blobs; i++ {
		name := filepath.Join(dir, fmt.Sprintf("blob%d.js", i))
		if err := os.WriteFile(name, bytes.Repeat([]byte{0xff}, 2000), 0644); err != nil {
			t.Fatalf("write blob %d: %v", i, err)
		}
	}

	scan, err := NewJavaScriptAnalyzer().AnalyzeDirectory(dir)
	if err != nil {
		t.Fatalf("AnalyzeDirectory: %v", err)
	}
	if scan.FilesFailed != blobs {
		t.Errorf("FilesFailed = %d, want the exact count %d: only the naming is bounded",
			scan.FilesFailed, blobs)
	}
	if len(scan.Unreadable) != maxUnreadableReported {
		t.Errorf("named %d refusals, want the bound of %d", len(scan.Unreadable),
			maxUnreadableReported)
	}
}

// TestIsTextRefusesNothing holds the empty-head guard directly.
//
// readSource refuses a zero-byte file before isText is reached, so the guard is
// unreachable through that path and a mutation of it survives the end-to-end
// tests. It is kept and asserted here anyway: utf8.Valid reports true for an
// empty slice, which is how the previous version of this check came to accept
// every NUL-free binary, and the next caller of isText should not have to
// rediscover that.
func TestIsTextRefusesNothing(t *testing.T) {
	for name, content := range map[string][]byte{"nil": nil, "empty": {}} {
		if isText(content) {
			t.Errorf("isText(%s) = true; an empty slice is valid UTF-8 and is not text", name)
		}
	}
}

// TestDirectoryScanDoesNotFollowSymlinks keeps an extracted archive's contents
// to the archive.
//
// filepath.Walk lstats, so a symlink is not a directory and falls through to
// the file analyzer, which opened whatever it pointed at. Both tar and unzip
// restore absolute symlink targets, so a package could ship Leak.java pointing
// at any file the scanning process can read and have this tool read it, count
// it as evidence of examination, and publish its contents as that dependency's
// source in JSON, SARIF and CBOM.
func TestDirectoryScanDoesNotFollowSymlinks(t *testing.T) {
	outside := t.TempDir()
	secret := filepath.Join(outside, "CONFIDENTIAL.java")
	if err := os.WriteFile(secret, []byte(
		"import java.security.MessageDigest;\n"+
			"class Secret { void f() throws Exception { MessageDigest.getInstance(\"MD5\"); } }\n"),
		0644); err != nil {
		t.Fatalf("write the file outside the archive: %v", err)
	}

	dir := t.TempDir()
	if err := os.Symlink(secret, filepath.Join(dir, "Leak.java")); err != nil {
		t.Skipf("this platform does not support symlinks: %v", err)
	}

	// Guard the fixture: the target must be readable and must carry the finding
	// this test is looking for, or its absence proves nothing.
	direct, err := NewJavaAnalyzer().AnalyzeFile(secret)
	if err != nil || len(direct) == 0 {
		t.Fatalf("the file outside the archive carries no finding to leak (%d usages, %v), "+
			"so this test cannot detect the leak", len(direct), err)
	}

	scan, err := NewJavaAnalyzer().AnalyzeDirectory(dir)
	if err != nil {
		t.Fatalf("AnalyzeDirectory: %v", err)
	}
	if scan.FilesParsed != 0 {
		t.Errorf("FilesParsed = %d for a directory holding only a symlink out of it",
			scan.FilesParsed)
	}
	for _, u := range scan.Usages {
		t.Errorf("a finding was read through a symlink out of the archive: %s at %s",
			u.Algorithm, u.Location.File)
	}
}

// TestJavaDirectoryScanReadsNothingFromCompiledClasses is the walker-level
// statement of the false clean this release closes.
//
// A Maven artifact with no sources JAR unpacks to compiled classes. Nothing
// here is readable by an analyzer that parses .java, .kt and .kts, and the
// walk has to say so rather than return an empty result that reads the same as
// a package with no cryptography in it.
func TestJavaDirectoryScanReadsNothingFromCompiledClasses(t *testing.T) {
	dir := t.TempDir()

	classDir := filepath.Join(dir, "com", "google", "common")
	if err := os.MkdirAll(classDir, 0755); err != nil {
		t.Fatalf("create class dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(classDir, "Hashing.class"),
		[]byte("\xca\xfe\xba\xbe\x00\x00\x00\x34"), 0644); err != nil {
		t.Fatalf("write class file: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "MANIFEST.MF"),
		[]byte("Manifest-Version: 1.0\n"), 0644); err != nil {
		t.Fatalf("write manifest: %v", err)
	}

	scan, err := NewJavaAnalyzer().AnalyzeDirectory(dir)
	if err != nil {
		t.Fatalf("AnalyzeDirectory: %v", err)
	}

	if scan.FilesParsed != 0 {
		t.Errorf("FilesParsed = %d for a directory holding no Java source at all; "+
			"a caller reading this count would report the package as examined",
			scan.FilesParsed)
	}
	if len(scan.Usages) != 0 {
		t.Errorf("compiled classes produced %d usages", len(scan.Usages))
	}
}
