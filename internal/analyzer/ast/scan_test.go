// Copyright 2025-2026 CyberSecurity NonProfit (CSNP)
// SPDX-License-Identifier: Apache-2.0

package ast

import (
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
