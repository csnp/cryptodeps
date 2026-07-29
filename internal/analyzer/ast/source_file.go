// Copyright 2025-2026 CyberSecurity NonProfit (CSNP)
// SPDX-License-Identifier: Apache-2.0

package ast

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"os"
	"unicode/utf8"
)

// maxSourceFile bounds what one file may contribute. A source file larger than
// this is not source in any sense this tool can act on, and reading it into
// memory to find out is how a scanner becomes a way to exhaust the host it runs
// on with an archive it was handed.
const maxSourceFile = 8 << 20 // 8 MiB

// openSource reads a file that an analyzer is about to walk line by line, and
// refuses one it cannot actually read.
//
// The distinction matters because "how many files did we parse" is the evidence
// behind every claim this tool makes about having examined a package. Three of
// the four analyzers are line scanners whose only failure mode was os.Open, so
// any openable file with a matching extension counted as parsed: a zero-byte
// Empty.java, or compiled class bytes under a .java name, both produced
// "no cryptographic usage detected in the 1 of 1 dependencies that were
// examined" for a scan that learned nothing. An extension is a descriptor, not
// the thing itself.
//
// A file counts as read when it holds text this tool can scan. Empty is not
// text, and neither is a binary blob: both are refused here so that the count
// they would have inflated stays at zero and the package is reported as not
// examined.
func openSource(filename string) (*bufio.Scanner, error) {
	content, err := readSource(filename)
	if err != nil {
		return nil, err
	}
	return bufio.NewScanner(bytes.NewReader(content)), nil
}

// readSource is openSource for an analyzer that needs the whole file, and is
// where every check described above actually lives.
func readSource(filename string) ([]byte, error) {
	info, err := os.Lstat(filename)
	if err != nil {
		return nil, err
	}
	// A symlink is not part of the archive it appears in. Following one reads
	// whatever it points at, which for an extracted package means any file the
	// scanning process can read: tar and unzip both restore absolute symlink
	// targets, so a package could ship Leak.java -> /etc/passwd and have this
	// tool publish the result as that dependency's source.
	if info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("%s is a symbolic link, which is not read: an extracted "+
			"package is analyzed from its own contents", filename)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", filename)
	}
	if info.Size() == 0 {
		return nil, fmt.Errorf("%s is empty, so nothing was read from it", filename)
	}
	if info.Size() > maxSourceFile {
		return nil, fmt.Errorf("%s is %d bytes, above the %d byte limit for one source file",
			filename, info.Size(), maxSourceFile)
	}

	content, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	if !isText(content) {
		return nil, fmt.Errorf("%s is not text this analyzer can read", filename)
	}

	return content, nil
}

// isText reports whether content is source text rather than a binary blob
// wearing a source file's extension.
func isText(content []byte) bool {
	if bytes.IndexByte(content, 0) >= 0 {
		return false
	}
	// Only the head is checked: it is where a magic number lives, and validating
	// megabytes of a legitimate file to reject the first eight bytes of a class
	// file is not a trade worth making.
	head := content
	if len(head) > 1024 {
		head = head[:1024]
		// Do not split a rune across the boundary and call the file binary for it.
		for len(head) > 0 && !utf8.Valid(head) && len(content) > len(head) {
			head = head[:len(head)-1]
		}
	}
	return utf8.Valid(head)
}

// scanErr reports a scanner failure that occurred after the file was opened,
// so that a truncated read is not silently counted as a complete one.
func scanErr(s *bufio.Scanner) error {
	if err := s.Err(); err != nil && err != io.EOF {
		return err
	}
	return nil
}
