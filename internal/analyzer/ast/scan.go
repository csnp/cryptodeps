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
}

// add records the outcome of one file.
func (s *DirectoryScan) add(usages []types.CryptoUsage, err error) {
	if err != nil {
		s.FilesFailed++
		return
	}
	s.FilesParsed++
	s.Usages = append(s.Usages, usages...)
}
