// Copyright 2025-2026 CyberSecurity NonProfit (CSNP)
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"encoding/json"
	"regexp"
	"testing"

	"github.com/csnp/qramm-cryptodeps/pkg/output"
	"github.com/csnp/qramm-cryptodeps/pkg/types"
)

// TestDocsCBOMExampleShowsTheSpecVersionTheToolWrites covers the CBOM example
// on the output formats page, which showed specVersion 1.5 while the formatter
// writes 1.6. The version is read from a document the formatter writes, so the
// page has to follow any later change to it.
func TestDocsCBOMExampleShowsTheSpecVersionTheToolWrites(t *testing.T) {
	var buf bytes.Buffer
	if err := (&output.CBOMFormatter{}).Format(&types.ScanResult{}, &buf); err != nil {
		t.Fatalf("writing a CBOM: %v", err)
	}
	var bom struct {
		SpecVersion string `json:"specVersion"`
	}
	if err := json.Unmarshal(buf.Bytes(), &bom); err != nil {
		t.Fatalf("decoding the CBOM: %v", err)
	}
	if bom.SpecVersion == "" {
		t.Fatal("the CBOM carries no specVersion")
	}

	const file = "docs/output-formats.md"
	section := markdownSection(t, readRepoFile(t, file), file, "CBOM (Cryptographic Bill of Materials)")
	matches := regexp.MustCompile(`"specVersion":\s*"([^"]*)"`).FindAllStringSubmatch(section, -1)
	if len(matches) == 0 {
		t.Fatalf("the CBOM example in %s shows no specVersion", file)
	}
	for _, m := range matches {
		if m[1] != bom.SpecVersion {
			t.Errorf("the CBOM example in %s shows specVersion %q, the tool writes %q", file, m[1], bom.SpecVersion)
		}
	}
}
