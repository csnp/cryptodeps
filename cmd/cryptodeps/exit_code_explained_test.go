// Copyright 2025-2026 CyberSecurity NonProfit (CSNP)
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// This file names nothing that did not exist before the exit code was
// explained, so it compiles against the earlier code and fails there at
// runtime. exit_explanation_test.go pins the wording of the helper itself.

// TestAnalyzeHelpSaysFiltersDoNotDecideTheExitCode holds the help to what
// exitCodeForSummary does. The help used to say the exit code was computed from
// what the filters leave, which is the opposite: a project with hidden
// quantum-vulnerable findings exits 1 under --risk partial while the summary
// above it reads "0 vulnerable".
func TestAnalyzeHelpSaysFiltersDoNotDecideTheExitCode(t *testing.T) {
	help := strings.Join(strings.Fields(analyzeCmd.Long), " ")

	if strings.Contains(help, "computed from what the filters leave") {
		t.Errorf("analyze help still says the exit code is computed from what the "+
			"filters leave; exitCodeForSummary counts withheld findings too:\n%s",
			analyzeCmd.Long)
	}
	for _, want := range []string{
		"The exit code counts every finding the scan made, including the ones a filter hid",
		"a filter never turns a failing build into a passing one",
	} {
		if !strings.Contains(help, want) {
			t.Errorf("analyze help does not say %q:\n%s", want, analyzeCmd.Long)
		}
	}
}

// analyzeRun is one runAnalyze call with its streams captured.
type analyzeRun struct {
	stdout, stderr string
	exit           int
}

// runAnalyzeCaptured runs the analyze command in-process with the given flag
// values, against the embedded database only, and captures stdout and stderr.
func runAnalyzeCaptured(t *testing.T, dir, risk, failOnValue string) analyzeRun {
	t.Helper()

	// An empty HOME means no cached database is loaded, so the embedded
	// database decides every classification, as in gate_filter_test.go.
	t.Setenv("HOME", t.TempDir())

	saved := struct {
		format, risk, minSev, failOn       string
		offline, deep, reach, noWorkspaces bool
		exit                               int
	}{formatFlag, riskFilter, minSeverity, failOn,
		offlineFlag, deepFlag, reachabilityFlag, noWorkspacesFlag, exitCode}
	t.Cleanup(func() {
		formatFlag, riskFilter, minSeverity, failOn = saved.format, saved.risk, saved.minSev, saved.failOn
		offlineFlag, deepFlag, reachabilityFlag, noWorkspacesFlag = saved.offline, saved.deep, saved.reach, saved.noWorkspaces
		exitCode = saved.exit
	})
	formatFlag, riskFilter, minSeverity, failOn = "table", risk, "", failOnValue
	offlineFlag, deepFlag, reachabilityFlag, noWorkspacesFlag = true, false, true, false
	exitCode = 0

	outR, outW, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	errR, errW, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	realOut, realErr := os.Stdout, os.Stderr
	os.Stdout, os.Stderr = outW, errW

	var outBuf, errBuf bytes.Buffer
	outDone := make(chan struct{})
	errDone := make(chan struct{})
	go func() { _, _ = io.Copy(&outBuf, outR); close(outDone) }()
	go func() { _, _ = io.Copy(&errBuf, errR); close(errDone) }()

	runErr := runAnalyze(analyzeCmd, []string{dir})

	os.Stdout, os.Stderr = realOut, realErr
	_ = outW.Close()
	_ = errW.Close()
	<-outDone
	<-errDone

	if runErr != nil {
		t.Fatalf("runAnalyze: %v\nstderr:\n%s", runErr, errBuf.String())
	}
	return analyzeRun{stdout: outBuf.String(), stderr: errBuf.String(), exit: exitCode}
}

// TestFailingExitCodeIsExplainedOnStderr runs the command the way a CI job does
// and asserts that a non-zero exit says what produced it, on stderr only. The
// --risk partial run is the shape from the new-user report: the summary reads
// "0 vulnerable" and the exit code is 1, and nothing said why.
func TestFailingExitCodeIsExplainedOnStderr(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "proj")
	writeManifest(t, dir, map[string]string{"crypto-js": "4.2.0", "node-forge": "1.3.1"})

	plain := runAnalyzeCaptured(t, dir, "", "vulnerable")
	if plain.exit != ExitVulnerable {
		t.Fatalf("fixture exited %d, want %d; it cannot exercise the explanation\nstdout:\n%s",
			plain.exit, ExitVulnerable, plain.stdout)
	}
	if !strings.Contains(plain.stderr, "Exit code 1") ||
		!strings.Contains(plain.stderr, "quantum-vulnerable finding") {
		t.Errorf("exit 1 printed no explanation on stderr:\n%q", plain.stderr)
	}
	if strings.Contains(plain.stdout, "Exit code") {
		t.Errorf("the explanation reached stdout, which JSON, SARIF and CBOM consumers "+
			"read:\n%s", plain.stdout)
	}

	filtered := runAnalyzeCaptured(t, dir, "partial", "vulnerable")
	if filtered.exit != ExitVulnerable {
		t.Fatalf("--risk partial exited %d, want %d (a filter must not change the gate)",
			filtered.exit, ExitVulnerable)
	}
	if !strings.Contains(filtered.stdout, "| 0 vulnerable |") {
		t.Fatalf("--risk partial was expected to hide every vulnerable finding from "+
			"the summary; stdout:\n%s", filtered.stdout)
	}
	if !strings.Contains(filtered.stderr, "Exit code 1") ||
		!strings.Contains(filtered.stderr, "--risk or --min-severity") {
		t.Errorf("exit 1 with every vulnerable finding hidden did not say the hidden "+
			"findings still count:\n%q", filtered.stderr)
	}
}

// TestPassingExitCodePrintsNothing guards the other direction: a clean result
// stays silent on stderr.
func TestPassingExitCodePrintsNothing(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "clean")
	writeManifest(t, dir, map[string]string{"left-pad": "1.3.0"})

	run := runAnalyzeCaptured(t, dir, "", "vulnerable")
	if run.exit != ExitSuccess {
		t.Fatalf("clean fixture exited %d, want %d\nstdout:\n%s", run.exit, ExitSuccess, run.stdout)
	}
	if run.stderr != "" {
		t.Errorf("exit 0 printed on stderr: %q", run.stderr)
	}
}
