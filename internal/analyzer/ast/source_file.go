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

// headBytes is how much of a file is checked for being text. A magic number
// lives in the first few bytes, and validating megabytes to reject the first
// eight is not a trade worth making.
const headBytes = 1024

// minTextFraction is how much of a head must be printable ASCII for a file that
// is not valid UTF-8 to still count as source.
//
// Measured rather than chosen. Across 140 real npm source files that carry
// non-ASCII characters, re-encoded to Latin-1, the lowest fraction was 0.904
// and the median 0.999, because source code is ASCII even when its comments and
// string literals are not. Random bytes with the NUL removed reached at most
// 0.453 over 200 samples, and real binaries with their NUL bytes stripped
// reached 0.286. The threshold sits in the gap with margin on both sides.
const minTextFraction = 0.75

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
//
// The question is whether these analyzers can read the file, and they are line
// scanners matching ASCII identifiers, so they neither need nor check valid
// UTF-8. Requiring it made the tool refuse legitimate source in any single-byte
// encoding: a .java or .js file holding one Latin-1 accent was reported as
// unreadable, its cryptography was never looked for, and 1.2.2 had found it.
// Worse, the refusal was silent for a package that also held a file this
// analyzer could read, so a dependency could hide its cryptography from the
// scanner by encoding one file in Latin-1 and still be reported as examined and
// clean. An encoding is not a language, and refusing to read one is not the same
// as there being nothing to read.
func isText(content []byte) bool {
	if bytes.IndexByte(content, 0) >= 0 {
		return false
	}
	// Only the head is checked: it is where a magic number lives, and validating
	// megabytes of a legitimate file to reject the first eight bytes of a class
	// file is not a trade worth making.
	head := content
	if len(head) > headBytes {
		head = head[:headBytes]
		// A rune can straddle the boundary, so trim up to the three continuation
		// bytes one can occupy rather than calling a legitimate file binary.
		//
		// Bounded deliberately: an unbounded "shrink while invalid" loop walks a
		// binary file's head down to nothing, and utf8.Valid on an empty slice
		// is true, so every NUL-free binary over headBytes passed as text. 2000
		// bytes of 0xff was accepted as source.
		for i := 0; i < utf8.UTFMax-1 && len(head) > 0 && !utf8.Valid(head); i++ {
			head = head[:len(head)-1]
		}
	}
	if len(head) == 0 {
		return false
	}
	if utf8.Valid(head) {
		return true
	}
	// Not valid UTF-8, which is not the same as not being source. A single-byte
	// encoding is still text these analyzers scan line by line, and what
	// separates it from a blob is how much of the head is ASCII rather than
	// whether every byte forms a rune. This is also what keeps the NUL-free
	// binary out: 2000 bytes of 0xff is 0 percent printable ASCII.
	return printableASCIIFraction(head) >= minTextFraction
}

// printableASCIIFraction is how much of head is ASCII a line scanner can match.
func printableASCIIFraction(head []byte) float64 {
	if len(head) == 0 {
		return 0
	}
	var printable int
	for _, b := range head {
		switch {
		case b >= 0x20 && b <= 0x7e, // printable ASCII
			b == '\t', b == '\n', b == '\r', b == '\v', b == '\f':
			printable++
		}
	}
	return float64(printable) / float64(len(head))
}

// scanErr reports a scanner failure that occurred after the file was opened,
// so that a truncated read is not silently counted as a complete one.
func scanErr(s *bufio.Scanner) error {
	if err := s.Err(); err != nil && err != io.EOF {
		return err
	}
	return nil
}
