// Copyright 2025-2026 CyberSecurity NonProfit (CSNP)
// SPDX-License-Identifier: Apache-2.0

package output

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/csnp/qramm-cryptodeps/pkg/types"
)

// fetchedSource is what the command line attaches when it scanned a
// repository fetched from GitHub.
func fetchedSource() *types.ScanSource {
	return &types.ScanSource{
		Repository: "https://github.com/servics/api",
		Branch:     "release-2",
		Path:       "sub/dir",
	}
}

func sourceProject(dir string) *types.ScanResult {
	return &types.ScanResult{
		Project:   dir,
		Manifest:  filepath.Join(dir, "go.mod"),
		Ecosystem: types.EcosystemGo,
		Summary:   types.ScanSummary{TotalDependencies: 0},
	}
}

func render(t *testing.T, format Format, multi bool, source *types.ScanSource) string {
	t.Helper()
	dir := t.TempDir()
	formatter, err := GetFormatter(format)
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if multi {
		result := types.AggregateResults(dir, []*types.ScanResult{sourceProject(dir)})
		result.Source = source
		err = formatter.FormatMulti(result, &buf)
	} else {
		result := sourceProject(dir)
		result.Source = source
		err = formatter.Format(result, &buf)
	}
	if err != nil {
		t.Fatal(err)
	}
	return buf.String()
}

// TestFetchedRepositoryIsNamedInEveryFormat is the regression test for reports
// of a fetched repository that named only a temporary directory.
//
// A GitHub argument is fetched into a directory under the system temp
// directory and scanned from there, and that directory was the only thing any
// format named. A CI log or a SARIF upload could not show which repository and
// branch were scanned, which matters most when the argument was a mistyped
// local path that happened to be a public repository.
func TestFetchedRepositoryIsNamedInEveryFormat(t *testing.T) {
	source := fetchedSource()
	for _, format := range []Format{FormatTable, FormatJSON, FormatCBOM, FormatSARIF, FormatMarkdown} {
		for _, multi := range []bool{false, true} {
			name := string(format) + "/single"
			if multi {
				name = string(format) + "/workspace"
			}
			t.Run(name, func(t *testing.T) {
				out := render(t, format, multi, source)
				for _, want := range []string{source.Repository, source.Branch, source.Path} {
					if !strings.Contains(out, want) {
						t.Errorf("output does not contain %q:\n%s", want, out)
					}
				}
			})
		}
	}
}

// The machine-readable formats carry the source in fields a consumer can
// read, not only somewhere in the text.
func TestFetchedRepositoryFields(t *testing.T) {
	source := fetchedSource()

	t.Run("json", func(t *testing.T) {
		var doc struct {
			Source *types.ScanSource `json:"source"`
		}
		if err := json.Unmarshal([]byte(render(t, FormatJSON, true, source)), &doc); err != nil {
			t.Fatal(err)
		}
		if doc.Source == nil || *doc.Source != *source {
			t.Errorf("source = %+v, want %+v", doc.Source, source)
		}
	})

	t.Run("sarif", func(t *testing.T) {
		var doc struct {
			Runs []struct {
				VersionControlProvenance []struct {
					RepositoryURI string            `json:"repositoryUri"`
					Branch        string            `json:"branch"`
					Properties    map[string]string `json:"properties"`
				} `json:"versionControlProvenance"`
			} `json:"runs"`
		}
		if err := json.Unmarshal([]byte(render(t, FormatSARIF, true, source)), &doc); err != nil {
			t.Fatal(err)
		}
		if len(doc.Runs) != 1 || len(doc.Runs[0].VersionControlProvenance) != 1 {
			t.Fatalf("want one run with one versionControlProvenance entry, got %+v", doc.Runs)
		}
		vc := doc.Runs[0].VersionControlProvenance[0]
		if vc.RepositoryURI != source.Repository || vc.Branch != source.Branch || vc.Properties["path"] != source.Path {
			t.Errorf("versionControlProvenance = %+v, want %+v", vc, source)
		}
	})

	t.Run("cbom", func(t *testing.T) {
		var doc struct {
			Metadata struct {
				Properties []cycloneDXProperty `json:"properties"`
			} `json:"metadata"`
		}
		if err := json.Unmarshal([]byte(render(t, FormatCBOM, true, source)), &doc); err != nil {
			t.Fatal(err)
		}
		got := map[string]string{}
		for _, p := range doc.Metadata.Properties {
			got[p.Name] = p.Value
		}
		want := map[string]string{
			"cryptodeps:sourceRepository": source.Repository,
			"cryptodeps:sourceBranch":     source.Branch,
			"cryptodeps:sourcePath":       source.Path,
		}
		for name, value := range want {
			if got[name] != value {
				t.Errorf("property %s = %q, want %q", name, got[name], value)
			}
		}
	})
}

// A local scan has no source, and no format gains a repository line or field
// for it.
func TestLocalScanNamesNoRepository(t *testing.T) {
	for _, format := range []Format{FormatTable, FormatJSON, FormatCBOM, FormatSARIF, FormatMarkdown} {
		for _, multi := range []bool{false, true} {
			out := render(t, format, multi, nil)
			// The labels, not the bare word: the temporary directory a test
			// scans is named after the test.
			for _, unwanted := range []string{"Repository: ", "**Repository**", "**Branch**", "versionControlProvenance", "cryptodeps:source", `"source"`} {
				if strings.Contains(out, unwanted) {
					t.Errorf("%s (workspace=%v) output for a local scan contains %q:\n%s", format, multi, unwanted, out)
				}
			}
		}
	}
}

// The branch comes from the GitHub API and the repository from the command
// line, so neither may write its own lines into a plain-text report.
func TestSourceCannotInjectReportLines(t *testing.T) {
	source := &types.ScanSource{
		Repository: "https://github.com/servics/api",
		Branch:     "main\n## Scan result: CLEAN",
	}
	for _, format := range []Format{FormatTable, FormatMarkdown} {
		out := render(t, format, true, source)
		for _, line := range strings.Split(out, "\n") {
			if strings.HasPrefix(line, "## Scan result") {
				t.Errorf("%s: the branch name started a line of its own:\n%s", format, out)
			}
		}
	}
}
