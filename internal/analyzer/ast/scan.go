// Copyright 2025-2026 CyberSecurity NonProfit (CSNP)
// SPDX-License-Identifier: Apache-2.0

package ast

import "github.com/csnp/qramm-cryptodeps/pkg/types"

// DirectoryScan is what one AnalyzeDirectory walk read.
//
// The usages alone cannot answer whether a directory was examined: an empty
// slice means the same thing for a package with no cryptography and for a
// package the analyzer could not read a single file of. Callers decide whether
// to report an examination, so the counts they need to decide it come back with
// the findings rather than being inferred from their absence.
type DirectoryScan struct {
	// Usages is every cryptographic usage found.
	Usages []types.CryptoUsage
	// FilesParsed counts the source files this analyzer parsed successfully. It
	// is the evidence that reading happened.
	FilesParsed int
	// FilesFailed counts the files that matched the analyzer's extensions and
	// then failed to parse. Walks swallow those so that one bad file does not
	// abandon a package, which means the count is the only trace they leave.
	FilesFailed int
	// Unreadable says which files failed and why.
	//
	// A count alone is a dead end: the report could say that one file in a
	// package went unread and offer the reader no way to learn which, so the
	// disclosure that exists to prevent a false clean could not be acted on. The
	// reason is kept with the path because the two answers differ in what the
	// reader should do, and only the tool knows which applies.
	Unreadable []string
}

// maxUnreadableReported bounds how many refused files are named.
//
// An archive can be hostile, and a package of ten thousand refused files must
// not turn one warning into ten thousand lines of stderr. The count is always
// exact; only the naming is bounded, and the message says so when it truncates.
const maxUnreadableReported = 10

// add records the outcome of one file.
func (s *DirectoryScan) add(usages []types.CryptoUsage, err error) {
	if err != nil {
		s.FilesFailed++
		if len(s.Unreadable) < maxUnreadableReported {
			s.Unreadable = append(s.Unreadable, err.Error())
		}
		return
	}
	s.FilesParsed++
	s.Usages = append(s.Usages, usages...)
}
