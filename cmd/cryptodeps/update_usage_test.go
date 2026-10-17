// Copyright 2025-2026 CyberSecurity NonProfit (CSNP)
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"strings"
	"testing"
)

// TestUpdateFailurePrintsTheErrorWithoutUsage is the regression test for a
// failed update following its error with the whole flag list, which pushed the
// error and its next step up the screen. The download is sent to a proxy that
// answers 502, so it fails without leaving the machine.
func TestUpdateFailurePrintsTheErrorWithoutUsage(t *testing.T) {
	proxy, log := startConnectionLog(t)

	stdout, stderr, code := runCLI(t, proxy, "update")

	if len(log.snapshot()) == 0 {
		t.Fatal("update opened no connection, so the download failure this test needs did not happen")
	}
	if code != ExitError {
		t.Errorf("exit code %d, want %d", code, ExitError)
	}
	if !strings.Contains(stderr, "Error: update failed:") {
		t.Errorf("stderr does not carry the update error:\n%s", stderr)
	}
	for name, out := range map[string]string{"stdout": stdout, "stderr": stderr} {
		if strings.Contains(out, "Usage:") || strings.Contains(out, "Flags:") {
			t.Errorf("%s carries the usage block after a runtime failure:\n%s", name, out)
		}
	}
}

// A mistyped flag is a usage mistake, so the flag list still follows it.
func TestUpdateUnknownFlagStillPrintsUsage(t *testing.T) {
	proxy, log := startConnectionLog(t)

	_, stderr, code := runCLI(t, proxy, "update", "--no-such-flag")

	if got := log.snapshot(); len(got) != 0 {
		t.Errorf("%d connection(s) for a rejected flag, want 0: %q", len(got), got)
	}
	if code != ExitError {
		t.Errorf("exit code %d, want %d", code, ExitError)
	}
	if !strings.Contains(stderr, "Usage:") {
		t.Errorf("stderr does not carry the usage block for an unknown flag:\n%s", stderr)
	}
}
