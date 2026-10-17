// Copyright 2025-2026 CyberSecurity NonProfit (CSNP)
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/csnp/qramm-cryptodeps/internal/analyzer"
	"github.com/csnp/qramm-cryptodeps/internal/database"
	"github.com/csnp/qramm-cryptodeps/pkg/types"
)

// TestFetchedRepositoryScanSaysReachabilityWasNotAnalyzed is the regression
// test for a GitHub URL scan reporting reachability over source it never
// fetched.
//
// The fetch downloads a repository's manifests and none of its source. The
// scan of examples/vulnerable-demo fetched that way labelled all 19 findings
// AVAILABLE and said on stderr that 11 were in dependencies where no call from
// your code was found, where a local scan of the same directory labels 6 of
// them CONFIRMED. The options the command line gives the scan of a fetched
// repository now leave reachability unrun, the exit line makes no claim about
// calls, and a line on stderr says why reachability is missing. The options for
// a local path keep reachability, and nothing is said about it.
func TestFetchedRepositoryScanSaysReachabilityWasNotAnalyzed(t *testing.T) {
	previous := reachabilityFlag
	reachabilityFlag = true // the flag's default
	t.Cleanup(func() { reachabilityFlag = previous })

	// What the fetch writes for a Go repository: its go.mod, and no source.
	gomod := "module example.com/fetched\n\nrequire github.com/golang-jwt/jwt/v5 v5.2.0\n"
	fetchedDir := t.TempDir()
	writeTestFile(t, fetchedDir, "go.mod", gomod)

	fetched, err := analyzer.New(database.NewEmbedded(), analyzerOptions(true)).AnalyzeAll(fetchedDir)
	if err != nil {
		t.Fatalf("AnalyzeAll: %v", err)
	}
	if labelled := labelledFindings(fetched.Projects); len(labelled) != 0 {
		t.Errorf("findings labelled by reachability in a scan that read no source: %q", labelled)
	}
	if fetched.TotalSummary.ReachabilityAnalyzed {
		t.Error("the summary says reachability was analyzed")
	}

	code := determineExitCodeMulti(fetched, "vulnerable")
	if code != ExitVulnerable {
		t.Fatalf("exit code %d, want %d: the fixture no longer reaches the exit line", code, ExitVulnerable)
	}
	if line := exitExplanation(code, "vulnerable", fetched.TotalSummary, fetched.Projects); strings.Contains(line, "your code") {
		t.Errorf("the exit line describes calls from source that was never fetched:\n%s", line)
	}

	notice := reachabilityNotice(fetched.TotalSummary)
	for _, want := range []string{"Reachability was not analyzed", "only the manifest files were fetched", "scan the local copy"} {
		if !strings.Contains(notice, want) {
			t.Errorf("the notice does not say %q:\n%s", want, notice)
		}
	}
	// The Commands page quotes the line, so it must be the line printed.
	if doc := readRepoFile(t, "docs/commands.md"); notice != "" && !strings.Contains(doc, notice) {
		t.Errorf("docs/commands.md does not quote the notice as printed:\n%s", notice)
	}

	// A local copy of the same project, with its source.
	localDir := t.TempDir()
	writeTestFile(t, localDir, "go.mod", gomod)
	writeTestFile(t, localDir, "main.go", "package main\n\nimport \"github.com/golang-jwt/jwt/v5\"\n\n"+
		"func main() {\n\t_ = jwt.SigningMethodRS256\n}\n")

	local, err := analyzer.New(database.NewEmbedded(), analyzerOptions(false)).AnalyzeAll(localDir)
	if err != nil {
		t.Fatalf("AnalyzeAll: %v", err)
	}
	if !local.TotalSummary.ReachabilityAnalyzed {
		t.Error("reachability did not run for a local path")
	}
	if !strings.Contains(strings.Join(labelledFindings(local.Projects), " "), "RS256=CONFIRMED") {
		t.Errorf("RS256 is not CONFIRMED in the local scan: %q", labelledFindings(local.Projects))
	}
	if got := reachabilityNotice(local.TotalSummary); got != "" {
		t.Errorf("a local scan printed the notice: %q", got)
	}
}

func writeTestFile(t *testing.T, dir, name, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
}

// labelledFindings lists each finding that carries a reachability label, as
// algorithm=label.
func labelledFindings(projects []*types.ScanResult) []string {
	var labelled []string
	for _, p := range projects {
		for _, dep := range p.Dependencies {
			if dep.Analysis == nil {
				continue
			}
			for _, c := range dep.Analysis.Crypto {
				if c.Reachability != "" {
					labelled = append(labelled, c.Algorithm+"="+string(c.Reachability))
				}
			}
		}
	}
	return labelled
}
