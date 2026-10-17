// Copyright 2025-2026 CyberSecurity NonProfit (CSNP)
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/csnp/qramm-cryptodeps/pkg/types"
)

// helpExitCodes reads the "Exit codes" block of a command's long help into one
// description per code, with wrapped lines joined. The block ends at the first
// blank line.
func helpExitCodes(t *testing.T, long string) map[int]string {
	t.Helper()

	entry := regexp.MustCompile(`^\s*([0-9]+) - (.*)$`)
	codes := map[int]string{}
	inBlock := false
	current := -1
	for _, line := range strings.Split(long, "\n") {
		if !inBlock {
			inBlock = strings.HasPrefix(line, "Exit codes")
			continue
		}
		if strings.TrimSpace(line) == "" {
			break
		}
		if m := entry.FindStringSubmatch(line); m != nil {
			current, _ = strconv.Atoi(m[1])
			codes[current] = m[2]
			continue
		}
		if current >= 0 {
			codes[current] += " " + strings.TrimSpace(line)
		}
	}
	if len(codes) == 0 {
		t.Fatalf("analyze help has no Exit codes block:\n%s", long)
	}
	return codes
}

// TestAnalyzeHelpDescribesExitCodesForEveryFailOnThreshold covers help that
// described codes 0 and 3 only for the default threshold and left out the
// --offline case of code 2. Under --fail-on none a scan with quantum-vulnerable
// findings exits 0, under --fail-on any a project whose cryptography is all
// quantum-safe exits 3, and under --offline an argument that is not a local
// path exits 2.
//
// Which thresholds each line must name is computed from exitCodeForSummary over
// a vulnerable, a partial-risk and an all-safe scan.
func TestAnalyzeHelpDescribesExitCodesForEveryFailOnThreshold(t *testing.T) {
	vulnerable := types.ScanSummary{TotalDependencies: 1, WithCrypto: 1, QuantumVulnerable: 1}
	partial := types.ScanSummary{TotalDependencies: 1, WithCrypto: 1, QuantumPartial: 1}
	allSafe := types.ScanSummary{TotalDependencies: 1, WithCrypto: 1}

	codes := helpExitCodes(t, analyzeCmd.Long)
	for _, code := range []int{ExitSuccess, ExitVulnerable, ExitError, ExitPartial} {
		if _, ok := codes[code]; !ok {
			t.Errorf("analyze help Exit codes block has no line for code %d:\n%s", code, analyzeCmd.Long)
		}
	}
	for _, code := range []int{ExitSuccess, ExitVulnerable, ExitPartial} {
		if !strings.Contains(codes[code], "--fail-on") {
			t.Errorf("analyze help describes exit code %d without --fail-on: %q", code, codes[code])
		}
	}

	for _, threshold := range gateThresholds {
		word := regexp.MustCompile(`\b` + threshold + `\b`)

		// A threshold under which quantum-vulnerable findings exit 0 is named
		// on the code 0 line and excepted on the code 1 line.
		if exitCodeForSummary(vulnerable, threshold) == ExitSuccess {
			if !strings.Contains(codes[ExitSuccess], "--fail-on "+threshold) {
				t.Errorf("--fail-on %s exits 0 on quantum-vulnerable findings, and the "+
					"code 0 line does not say so: %q", threshold, codes[ExitSuccess])
			}
			if !word.MatchString(codes[ExitVulnerable]) {
				t.Errorf("--fail-on %s never exits 1, and the code 1 line does not "+
					"name it: %q", threshold, codes[ExitVulnerable])
			}
		}

		// Every threshold that can exit 3 is named on the code 3 line.
		for _, s := range []types.ScanSummary{vulnerable, partial, allSafe} {
			if exitCodeForSummary(s, threshold) == ExitPartial &&
				!strings.Contains(codes[ExitPartial], "--fail-on "+threshold) {
				t.Errorf("--fail-on %s can exit 3, and the code 3 line does not "+
					"name it: %q", threshold, codes[ExitPartial])
				break
			}
		}
		if exitCodeForSummary(allSafe, threshold) == ExitPartial &&
			!strings.Contains(codes[ExitPartial], "quantum-safe") {
			t.Errorf("--fail-on %s exits 3 when all cryptography is quantum-safe, and "+
				"the code 3 line does not say so: %q", threshold, codes[ExitPartial])
		}
	}

	// TestOfflineMakesNoConnectionForAnyArgument holds the behaviour.
	if !strings.Contains(codes[ExitError], "--offline") {
		t.Errorf("analyze help does not say that an argument that is not a local "+
			"path exits 2 under --offline: %q", codes[ExitError])
	}
}
