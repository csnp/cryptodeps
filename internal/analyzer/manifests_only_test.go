// Copyright 2025-2026 CyberSecurity NonProfit (CSNP)
// SPDX-License-Identifier: Apache-2.0

package analyzer

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/csnp/qramm-cryptodeps/internal/database"
	"github.com/csnp/qramm-cryptodeps/pkg/types"
)

// fetchedGoMod is a go.mod as FetchGitHubManifests writes it: into the
// directory a GitHub repository is scanned from, beside no source file.
const fetchedGoMod = "module example.com/fetched\n\nrequire github.com/golang-jwt/jwt/v5 v5.2.0\n"

// localMain is the source a local copy of the same project holds. It refers to
// RS256 in main, so reachability that reads it labels RS256 CONFIRMED.
const localMain = `package main

import "github.com/golang-jwt/jwt/v5"

func main() {
	_ = jwt.SigningMethodRS256
}
`

func writeProject(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// TestManifestsOnlyScanRunsNoReachability is the regression test for a GitHub
// URL scan reporting reachability over source it never fetched.
//
// The fetch downloads a repository's manifests and none of its source, and
// reachability then ran over the directory holding them. It found no Go file,
// labelled every finding AVAILABLE and marked the scan as reachability-analyzed,
// so the line after the report said the findings were in dependencies where no
// call from your code was found. With ManifestsOnly, which the command line
// sets for a fetched repository, reachability is not run on either analysis
// path, and the summary records that it was skipped so the command line can say
// why.
func TestManifestsOnlyScanRunsNoReachability(t *testing.T) {
	dir := writeProject(t, map[string]string{"go.mod": fetchedGoMod})
	a := New(database.NewEmbedded(), Options{Reachability: true, ManifestsOnly: true})

	multi, err := a.AnalyzeAll(dir)
	if err != nil {
		t.Fatalf("AnalyzeAll: %v", err)
	}
	if len(multi.Projects) != 1 {
		t.Fatalf("AnalyzeAll found %d projects, want 1", len(multi.Projects))
	}
	single, err := a.Analyze(dir)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}

	for _, tc := range []struct {
		name    string
		summary types.ScanSummary
		project *types.ScanResult
	}{
		{"AnalyzeAll", multi.TotalSummary, multi.Projects[0]},
		{"Analyze", single.Summary, single},
	} {
		t.Run(tc.name, func(t *testing.T) {
			findings := 0
			for _, dep := range tc.project.Dependencies {
				if dep.Analysis == nil {
					continue
				}
				for _, c := range dep.Analysis.Crypto {
					findings++
					if c.Reachability != "" {
						t.Errorf("%s in %s is labelled %s from source that was never read",
							c.Algorithm, dep.Dependency.Name, c.Reachability)
					}
				}
			}
			if findings == 0 {
				t.Fatal("the fixture produced no findings, so it cannot show a label")
			}
			if tc.summary.ReachabilityAnalyzed {
				t.Error("the summary says reachability was analyzed")
			}
			if n := tc.summary.ConfirmedCrypto + tc.summary.ReachableCrypto + tc.summary.AvailableCrypto; n != 0 {
				t.Errorf("the summary counts %d findings by reachability, want 0", n)
			}
			if !tc.summary.ReachabilitySkipped {
				t.Error("the summary does not record that reachability was skipped")
			}
		})
	}
}

// TestReachabilitySkippedOnlyWhereItWouldHaveRun holds the other side of
// ManifestsOnly: a local project with source keeps its reachability, and the
// skip is recorded only where reachability was asked for, on an ecosystem it
// covers. Recorded anywhere else, the command line would explain the absence
// of an analysis a local scan does not run either.
func TestReachabilitySkippedOnlyWhereItWouldHaveRun(t *testing.T) {
	t.Run("local Go project with source", func(t *testing.T) {
		dir := writeProject(t, map[string]string{"go.mod": fetchedGoMod, "main.go": localMain})
		result, err := New(database.NewEmbedded(), Options{Reachability: true}).Analyze(dir)
		if err != nil {
			t.Fatalf("Analyze: %v", err)
		}
		if !result.Summary.ReachabilityAnalyzed {
			t.Error("reachability did not run on a local project with source")
		}
		if result.Summary.ReachabilitySkipped {
			t.Error("the summary records a skip for a scan that ran reachability")
		}
		rs256 := false
		for _, dep := range result.Dependencies {
			if dep.Analysis == nil {
				continue
			}
			for _, c := range dep.Analysis.Crypto {
				if c.Algorithm == "RS256" {
					rs256 = true
					if c.Reachability != types.ReachabilityConfirmed {
						t.Errorf("RS256 is labelled %q, want %s: main refers to it", c.Reachability, types.ReachabilityConfirmed)
					}
				}
			}
		}
		if !rs256 {
			t.Fatal("the fixture produced no RS256 finding")
		}
	})

	for _, tc := range []struct {
		name  string
		files map[string]string
		opts  Options
	}{
		{"fetched Go project with --reachability=false",
			map[string]string{"go.mod": fetchedGoMod},
			Options{ManifestsOnly: true}},
		{"fetched npm project",
			map[string]string{"package.json": `{"name": "fetched", "dependencies": {"jsonwebtoken": "9.0.0"}}`},
			Options{Reachability: true, ManifestsOnly: true}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			result, err := New(database.NewEmbedded(), tc.opts).Analyze(writeProject(t, tc.files))
			if err != nil {
				t.Fatalf("Analyze: %v", err)
			}
			if result.Summary.ReachabilitySkipped {
				t.Error("the summary records a skip of reachability that would not have run")
			}
			if result.Summary.ReachabilityAnalyzed {
				t.Error("the summary says reachability was analyzed")
			}
		})
	}
}
