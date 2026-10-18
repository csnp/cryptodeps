// Copyright 2025-2026 CyberSecurity NonProfit (CSNP)
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// apacheLicense is the text served at
// https://www.apache.org/licenses/LICENSE-2.0.txt on 2026-10-17, byte for byte.
const apacheLicense = "testdata/apache-license-2.0.txt"

// licenseTermsEnd is the line that closes the terms of the Apache License 2.0.
// The appendix after it tells how to apply the license to a work. LICENSE
// holds, in its place, the project's copyright line and the notice the
// appendix gives.
const licenseTermsEnd = "END OF TERMS AND CONDITIONS"

// licenseWord is a word of a license text and the line it is on.
type licenseWord struct {
	text string
	line int
}

// licenseTerms returns the words of a license text from its first line through
// the line that closes its terms.
func licenseTerms(t *testing.T, file, text string) []licenseWord {
	t.Helper()
	var words []licenseWord
	for i, line := range strings.Split(text, "\n") {
		for _, word := range strings.Fields(line) {
			words = append(words, licenseWord{word, i + 1})
		}
		if strings.TrimSpace(line) == licenseTermsEnd {
			return words
		}
	}
	t.Fatalf("%s has no %q line", file, licenseTermsEnd)
	return nil
}

// licenseExcerpt returns the i-th word of a license text with up to three
// words on each side of it.
func licenseExcerpt(words []licenseWord, i int) string {
	from, to := max(i-3, 0), min(i+4, len(words))
	text := make([]string, 0, to-from)
	for _, w := range words[from:to] {
		text = append(text, w.text)
	}
	return strings.Join(text, " ")
}

// TestLicenseHoldsTheApacheLicenseTermsWordForWord covers a LICENSE whose
// definition of Contribution read "submitted to the Licensor for inclusion in
// the Work", where the Apache License 2.0 reads "submitted to Licensor". The
// terms in LICENSE, from its first line through END OF TERMS AND CONDITIONS,
// are compared word for word with the same part of the license text. Line
// breaks and indentation are not compared.
func TestLicenseHoldsTheApacheLicenseTermsWordForWord(t *testing.T) {
	b, err := os.ReadFile(filepath.FromSlash(apacheLicense))
	if err != nil {
		t.Fatalf("reading %s: %v", apacheLicense, err)
	}
	want := licenseTerms(t, apacheLicense, string(b))
	got := licenseTerms(t, "LICENSE", readRepoFile(t, "LICENSE"))
	for i := 0; i < len(got) && i < len(want); i++ {
		if got[i].text != want[i].text {
			t.Fatalf("LICENSE:%d reads %q where the Apache License 2.0 (%s:%d) reads %q",
				got[i].line, licenseExcerpt(got, i), apacheLicense, want[i].line, licenseExcerpt(want, i))
		}
	}
	if len(got) != len(want) {
		t.Fatalf("the terms in LICENSE are %d words long, and those of the Apache License 2.0 (%s) are %d",
			len(got), apacheLicense, len(want))
	}
}
