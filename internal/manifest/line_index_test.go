// Copyright 2025-2026 CyberSecurity NonProfit (CSNP)
// SPDX-License-Identifier: Apache-2.0

package manifest

import (
	"bytes"
	"testing"
)

// TestLineIndexMatchesACountOfNewlines holds the line lookup to its plain
// definition: one more than the number of newlines before the offset, with an
// offset past the end counted to the end, and 0 for a negative offset.
func TestLineIndexMatchesACountOfNewlines(t *testing.T) {
	for _, doc := range []string{"", "a", "\n", "\n\n", "ab\ncd\n", "ab\ncd", "\nab\n\ncd\n\n"} {
		data := []byte(doc)
		index := newLineIndex(data)
		for offset := 0; offset <= len(data)+2; offset++ {
			end := offset
			if end > len(data) {
				end = len(data)
			}
			want := bytes.Count(data[:end], []byte("\n")) + 1
			if got := index.line(int64(offset)); got != want {
				t.Errorf("line(%d) in %q = %d, want %d", offset, doc, got, want)
			}
		}
		if got := index.line(-1); got != 0 {
			t.Errorf("line(-1) in %q = %d, want 0", doc, got)
		}
	}
}
