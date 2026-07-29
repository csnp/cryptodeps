// Copyright 2025-2026 CyberSecurity NonProfit (CSNP)
// SPDX-License-Identifier: Apache-2.0

package ast

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
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
